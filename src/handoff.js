import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { kindFromUrl, detectArtifact, verdexChain, preflightChain } from "./artifacts.js";
import { initLedger, loadLedger, appendLedger, addAsset, addFact, addIntent } from "./ledger.js";
import { headerGet } from "./util.js";

// Fairy ↔ Verdex 交接:web 侧捞到样本后,登记进账本,把 Verdex 工具链交给智能体执行。
// Fairy 不执行样本、不解析二进制;它负责"把东西交到对的手上"。

function sha256File(file) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(file);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
    stream.on("error", reject);
  });
}

function ensureLedger(projectDir) {
  try {
    return loadLedger(projectDir);
  } catch {
    return initLedger(projectDir).ledger;
  }
}

export async function handoffFile(projectDir, file, options = {}) {
  const target = path.resolve(String(file));
  if (!fs.existsSync(target)) throw new Error(`样本不存在:${target}`);
  const stat = fs.statSync(target);
  if (!stat.isFile()) throw new Error("path 必须指向一个文件");
  if (stat.size === 0) throw new Error("样本是空文件,拒绝交接");

  const kind = detectArtifact(target);
  const sha256 = await sha256File(target);
  const name = path.basename(target);
  const preflight = preflightChain(kind);
  ensureLedger(projectDir);

  const result = appendLedger(projectDir, (ledger) => {
    const assetTags = ["local", kind];
    if (options.source?.kind === "url") assetTags.push("downloaded", "url");
    const asset = addAsset(ledger, {
      type: "artifact",
      value: target,
      tags: assetTags,
    }).asset;

    const fact = addFact(ledger, {
      statement: `样本 ${name} 类型 ${kind} sha256 ${sha256.slice(0, 16)}… (${stat.size} bytes)`,
      confidence: "observed",
      tags: ["artifact", kind],
      asset_ids: [asset.id],
      evidence: [{ kind: "file", url: target, note: `${stat.size} bytes; sha256=${sha256}` }],
    }).fact;

    const intent = addIntent(ledger, {
      goal: `交给 Verdex 分析 ${name} (${kind}):按链解包/反编译/扫密钥,只读不执行`,
      asset_ids: [asset.id],
      risk: "low",
      requires_approval: false,
      stop_condition: "只读分析,不执行样本、不联网回连、不上传第三方",
    });

    return { asset, fact, intent };
  });

  return {
    ok: true,
    artifact: {
      path: target,
      name,
      bytes: stat.size,
      kind,
      sha256,
      source: options.source || { kind: "local" },
    },
    ledger: {
      asset_id: result.asset.id,
      fact_id: result.fact.id,
      intent_id: result.intent.id,
    },
    verdex: {
      next_tool: "mcp__verdex__analyze_target",
      next_arguments: { path: target },
      chain: verdexChain(kind),
      preflight,
      warnings: preflight
        .filter((item) => item.available === false)
        .map((item) => `${item.tool} 缺少 ${(item.missing || []).join("/")};该步可能失败`),
      note:
        kind === "pe"
          ? "PE 若带 CLR 元数据,.NET 程序集请改走 dotnet_decompile;不确定就先 analyze_target。"
          : "先调 analyze_target 确认类型,再按 chain 顺序执行;不要执行样本。",
    },
    note: "样本未执行。分析在 Verdex 侧进行;Fairy 只登记了资产/事实/意图。",
  };
}

export function suggestUrl(projectDir, url) {
  const kind = kindFromUrl(url);
  const target = String(url);
  return {
    ok: true,
    pending: true,
    url: target,
    kind,
    download: {
      tool: "fairy_handoff",
      arguments: { project: projectDir, url: target, confirm: true },
      note: "下载需要显式 confirm=true;Fairy 不会自动拉样本。",
    },
    next: kind
      ? { tool: "mcp__verdex__analyze_target", arguments: { path: "<下载后的本地路径>" }, chain: verdexChain(kind) }
      : { note: "扩展名不在样本清单;先用 web_probe 看 content-type / content-disposition 再决定。" },
    limitations: [
      "只按扩展名给出候选;真正类型由下载后的魔数判断。",
      "下载会向目标发一次 GET,仅限 scope 内,单文件上限 20MB。",
    ],
  };
}

export async function fetchArtifact(guard, options = {}) {
  const url = String(options.url || "");
  if (!url) throw new Error("需要 url");
  if (options.confirm !== true) {
    throw new Error("下载样本需要 confirm=true:它会向目标发一次 GET 并落盘,必须由你显式确认。");
  }
  const maxBytes = Math.min(Math.max(Number(options.maxBytes) || 20_000_000, 1024), 20_000_000);
  const response = await guard.download(url, { maxBytes });
  if (response.status !== 200) throw new Error(`样本下载失败:HTTP ${response.status}`);
  if (response.truncated) throw new Error(`样本超过 ${maxBytes} bytes 上限,已停止;请人工处理。`);

  const contentType = headerGet(response.headers, "content-type") || "";
  if (/text\/html/i.test(contentType) && response.body.length < 100_000) {
    throw new Error("返回的是 HTML,疑似错误页/登录页,不当作样本落盘。");
  }

  const sha256 = crypto.createHash("sha256").update(response.body).digest("hex");
  const kind = kindFromUrl(url) || detectArtifactBuffer(response.body) || "unknown-file";
  let name = "sample.bin";
  try {
    name = path.basename(new URL(url).pathname) || name;
  } catch {
    // keep default
  }
  name = name.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 80) || "sample.bin";
  const dir = path.join(guard.projectDir, ".fairy", "artifacts");
  fs.mkdirSync(dir, { recursive: true });
  const dest = path.join(dir, `${sha256.slice(0, 8)}-${name}`);
  fs.writeFileSync(dest, response.body, { mode: 0o600 });
  try {
    fs.chmodSync(dest, 0o600);
  } catch {
    // Windows 上可能不生效。
  }

  const handoff = await handoffFile(guard.projectDir, dest, {
    source: { kind: "url", url, request_id: response.request_id, content_type: contentType },
  });

  return {
    ...handoff,
    download: {
      request_id: response.request_id,
      status: response.status,
      bytes: response.body.length,
      content_type: contentType,
      sha256,
      saved_to: dest,
    },
    note: "样本已落盘但未执行;类型先按扩展名初判,交给 Verdex analyze_target 用魔数确认。",
  };
}

function detectArtifactBuffer(buffer) {
  const hex2 = buffer.subarray(0, 2).toString("hex");
  const hex4 = buffer.subarray(0, 4).toString("hex");
  if (hex4 === "7f454c46") return "elf";
  if (hex2 === "4d5a") return "pe";
  if (hex2 === "504b") return "zip";
  if (hex4 === "68737173" || hex4 === "73717368") return "firmware-squashfs";
  if (hex4 === "55424923") return "firmware-ubifs";
  return null;
}
