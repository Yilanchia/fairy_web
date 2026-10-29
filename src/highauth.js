import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// 最高授权闸:不是一个 UI 开关,而是一份带 HMAC 的授权文件。
// 只有 read-only 动作能穿过这道闸;横向/凭据/持久化/隧道不在允许动作里。

export const HIGH_AUTH_SCHEMA = "FairyHighAuth/v1";
const ALLOWED_ACTIONS = new Set(["read-only"]);

function key() {
  const value = process.env.FAIRY_AUTH_KEY;
  if (!value || value.length < 16) {
    throw new Error("需要 FAIRY_AUTH_KEY(≥16 字符)才能创建/验证最高授权");
  }
  return value;
}

function canonical(payload) {
  return JSON.stringify(payload, Object.keys(payload).sort());
}

function sign(payload) {
  return crypto.createHmac("sha256", key()).update(canonical(payload)).digest("hex");
}

export function highAuthPath(projectDir) {
  return path.join(path.resolve(projectDir), ".fairy", "high-auth.json");
}

export function createHighAuth(projectDir, options = {}) {
  const basis = String(options.basis || "").trim();
  const approver = String(options.approver || "").trim();
  const assets = (Array.isArray(options.assets) ? options.assets : []).map(String).filter(Boolean);
  if (basis.length < 8) throw new Error("basis 至少 8 个字(写清楚授权依据)");
  if (!approver) throw new Error("需要 approver(谁批准了这次最高授权)");
  if (!assets.length) throw new Error("至少一个受权资产/主机");

  const hours = Math.min(Math.max(Number(options.hours) || 24, 1), 168);
  const issued = new Date();
  const payload = {
    schema: HIGH_AUTH_SCHEMA,
    tier: "highest",
    basis: basis.slice(0, 300),
    approver: approver.slice(0, 120),
    assets: assets.slice(0, 50),
    actions: ["read-only"],
    issued_at: issued.toISOString(),
    expires_at: new Date(issued.getTime() + hours * 3600 * 1000).toISOString(),
    nonce: crypto.randomBytes(12).toString("hex"),
  };
  const record = { schema: HIGH_AUTH_SCHEMA, payload, signature: sign(payload) };
  const file = highAuthPath(projectDir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return { path: file, payload };
}

function hostOf(value) {
  const text = String(value || "").trim();
  if (!text) return "";
  try {
    return new URL(text).hostname;
  } catch {
    return text.replace(/:\d+$/, "");
  }
}

export function verifyHighAuth(projectDir, options = {}) {
  const file = highAuthPath(projectDir);
  if (!fs.existsSync(file)) {
    throw new Error("没有最高授权:先由授权人执行 high-auth 生成 .fairy/high-auth.json");
  }
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  if (record.schema !== HIGH_AUTH_SCHEMA || !record.payload) throw new Error("最高授权文件 schema 不匹配");
  const payload = record.payload;
  if (payload.tier !== "highest") throw new Error("最高授权 tier 必须是 highest");
  if (!Array.isArray(payload.actions) || !payload.actions.every((action) => ALLOWED_ACTIONS.has(action))) {
    throw new Error("最高授权只允许 read-only 动作");
  }
  if (new Date(payload.expires_at).getTime() <= Date.now()) throw new Error("最高授权已过期");
  if (sign(payload) !== record.signature) throw new Error("最高授权签名不匹配");

  const action = String(options.action || "read-only");
  if (!payload.actions.includes(action)) throw new Error(`最高授权不允许动作:${action}`);

  const asset = hostOf(options.asset);
  if (asset && !payload.assets.map(hostOf).includes(asset)) {
    throw new Error(`资产 ${asset} 不在最高授权清单内`);
  }

  return {
    ok: true,
    tier: payload.tier,
    basis: payload.basis,
    approver: payload.approver,
    assets: payload.assets,
    actions: payload.actions,
    issued_at: payload.issued_at,
    expires_at: payload.expires_at,
  };
}
