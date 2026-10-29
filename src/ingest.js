import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  appendLedger,
  addAsset,
  addFact,
  addFinding,
  initLedger,
  ingestScanReport,
  loadLedger,
  summary,
} from "./ledger.js";
import { enrichFindings } from "./taxonomy.js";
import { nowIso } from "./util.js";

// 统一证据入口:scan / param / WAF / 权限矩阵 / 可达性 / Verdex 的产出
// 都归一成账本里的 asset / fact / finding,带 source_run_id 与 source_id。
// 只写账本,不发请求;幂等靠 coverage.runs。

const SOURCE_BY_SCHEMA = {
  "FairyScan/v1": "web_scan",
  "FairyParam/v1": "web_param",
  "FairyMatrix/v1": "web_role_matrix",
  "FairyReachability/v1": "fairy_reachability",
  "FairyWaf/v1": "web_waf",
};

function ensureLedger(projectDir) {
  try {
    return loadLedger(projectDir);
  } catch {
    return initLedger(projectDir).ledger;
  }
}

function hashPayload(payload) {
  return crypto.createHash("sha256").update(JSON.stringify(payload)).digest("hex").slice(0, 16);
}

function normalizeSeverity(value) {
  const text = String(value || "").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(text)) return text;
  if (text === "moderate") return "medium";
  if (text === "error") return "high";
  if (text === "warning") return "medium";
  if (text === "note") return "info";
  return "medium";
}

function whereOf(finding) {
  if (finding.where) return String(finding.where);
  if (finding.url) return String(finding.url);
  if (finding.location && typeof finding.location === "object") {
    if (finding.location.url) return String(finding.location.url);
    if (finding.location.file) {
      return `${finding.location.file}${finding.location.line ? `:${finding.location.line}` : ""}`;
    }
  }
  if (finding.file) return `${finding.file}${finding.line ? `:${finding.line}` : ""}`;
  if (finding.path) return `${finding.path}${finding.line ? `:${finding.line}` : ""}`;
  return "";
}

function evidenceOf(finding, where) {
  const raw = finding.evidence;
  if (Array.isArray(raw)) return raw;
  if (raw && typeof raw === "object") {
    if (Array.isArray(raw.request_ids)) {
      return raw.request_ids.map((id) => ({ kind: "http", request_id: id, url: where }));
    }
    if (raw.request_id) {
      return [{ kind: "http", request_id: raw.request_id, url: where, snippet: raw.snippet || null }];
    }
  }
  if (finding.request_id) return [{ kind: "http", request_id: finding.request_id, url: where }];
  if (raw) return [{ kind: "note", note: String(raw).slice(0, 400) }];
  return [];
}

function normalizeFinding(finding, runId, source) {
  const where = whereOf(finding).slice(0, 500);
  return {
    title: String(finding.title || finding.name || finding.message || finding.rule || "未命名发现").slice(0, 200),
    kind: String(finding.kind || finding.category || finding.type || finding.rule_id || "unknown").slice(0, 80),
    severity: normalizeSeverity(finding.severity || finding.level),
    confidence: finding.confidence,
    where,
    detail: finding.detail || finding.description || finding.message || "",
    impact: finding.impact || "",
    remediation: finding.remediation || finding.fix || "",
    owasp: finding.owasp,
    cwe: finding.cwe,
    cvss: finding.cvss,
    status: "candidate",
    evidence: evidenceOf(finding, where),
    source,
    source_run_id: runId,
    source_id: finding.id || finding.rule_id || null,
  };
}

function addAssetsForWhere(ledger, where, source) {
  if (!where) return 0;
  const candidate = where.replace(/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+/i, "").split(/\s+/)[0];
  try {
    const url = new URL(candidate);
    const host = addAsset(ledger, { type: "host", value: url.host, tags: [source] });
    const endpoint = addAsset(ledger, {
      type: "endpoint",
      value: `${url.pathname}${url.search}`,
      parent_id: host.asset.id,
      tags: [source],
    });
    return Number(host.added) + Number(endpoint.added);
  } catch {
    if (/[\\/]/.test(where)) {
      const asset = addAsset(ledger, { type: "artifact", value: where, tags: [source, "path"] });
      return Number(asset.added);
    }
    return 0;
  }
}

function addSourceFacts(ledger, payload, source, findings) {
  if (source === "web_waf") {
    addFact(ledger, {
      statement: `WAF 画像:${payload.waf?.vendor || "unknown"} / ${payload.verdict || "unknown"}(${payload.param || "param"})`,
      confidence: "observed",
      tags: ["waf", payload.waf?.vendor || "unknown"],
      evidence: [{ kind: "http", url: payload.url, note: payload.verdict || "" }],
    });
  } else if (source === "fairy_reachability") {
    addFact(ledger, {
      statement: `最高授权可达性图:${payload.summary?.endpoints ?? 0} 端点 / ${payload.summary?.role_restricted ?? 0} 个角色受限`,
      confidence: "observed",
      tags: ["reachability", "high-auth"],
      evidence: [{ kind: "note", note: `approver=${payload.auth?.approver || "unknown"};expires=${payload.auth?.expires_at || "unknown"}` }],
    });
  } else if (source === "verdex") {
    addFact(ledger, {
      statement: `Verdex 分析 ${payload.root || payload.path || ""}:${findings.length} 条发现`.trim(),
      confidence: "observed",
      tags: ["verdex", "static"],
      evidence: [{ kind: "file", url: payload.path || payload.root || null, note: "verdex ingest" }],
    });
  } else if (source === "web_role_matrix") {
    addFact(ledger, {
      statement: `权限矩阵:${payload.matrix?.length ?? 0} 端点 / ${payload.identities?.length ?? 0} 个身份`,
      confidence: "observed",
      tags: ["authz", "matrix"],
      evidence: [{ kind: "note", note: "web_role_matrix" }],
    });
  }
}

export function ingestPayload(projectDir, payload, options = {}) {
  if (!payload || typeof payload !== "object") throw new Error("payload 必须是对象");
  ensureLedger(projectDir);

  if (payload.schema === "FairyScan/v1") {
    const result = ingestScanReport(projectDir, payload);
    return { ok: true, schema: payload.schema, source: "web_scan", ...result };
  }

  const schema = String(payload.schema || options.schema || "unknown");
  const source = String(
    options.source ||
      SOURCE_BY_SCHEMA[schema] ||
      (/verdex/i.test(schema) ? "verdex" : schema.toLowerCase()),
  );
  const rawFindings = Array.isArray(payload)
    ? payload
    : payload.findings || payload.results?.findings || payload.analysis?.findings || payload.issues || [];
  const findings = Array.isArray(rawFindings) ? rawFindings : [];
  const runId = String(payload.run_id || payload.scan_id || payload.id || `${source}-${hashPayload(payload)}`);

  return appendLedger(projectDir, (ledger) => {
    const already = ledger.coverage.runs.some((run) => run.run_id === runId && run.source === source);
    if (already) {
      return { ok: true, schema, source, run_id: runId, skipped: true, reason: "该 run/source 已导入过", summary: summary(ledger) };
    }

    const before = { assets: ledger.assets.length, facts: ledger.facts.length, findings: ledger.findings.length };
    let addedFindings = 0;
    let duplicateFindings = 0;

    for (const raw of findings) {
      const normalized = normalizeFinding(raw, runId, source);
      enrichFindings([normalized]);
      const result = addFinding(ledger, normalized);
      if (result.added) addedFindings += 1;
      else duplicateFindings += 1;
      addAssetsForWhere(ledger, normalized.where, source);
    }

    for (const asset of Array.isArray(payload.assets) ? payload.assets : []) {
      try {
        addAsset(ledger, {
          type: asset.type || "note",
          value: asset.value || asset.url || asset.path,
          tags: [source, ...(asset.tags || [])],
        });
      } catch {
        // 不合法的资产不阻断整个导入。
      }
    }

    addSourceFacts(ledger, payload, source, findings);
    ledger.coverage.runs.push({
      run_id: runId,
      source,
      imported_at: nowIso(),
      findings: findings.length,
      note: options.note ? String(options.note).slice(0, 200) : "",
    });

    return {
      ok: true,
      schema,
      source,
      run_id: runId,
      skipped: false,
      added: {
        assets: ledger.assets.length - before.assets,
        facts: ledger.facts.length - before.facts,
        findings: addedFindings,
      },
      duplicate_findings: duplicateFindings,
      summary: summary(ledger),
    };
  });
}

export function ingestFile(projectDir, file, options = {}) {
  const target = path.resolve(String(file));
  if (!fs.existsSync(target)) throw new Error(`文件不存在:${target}`);
  const payload = JSON.parse(fs.readFileSync(target, "utf8"));
  return ingestPayload(projectDir, payload, { ...options, path: target });
}
