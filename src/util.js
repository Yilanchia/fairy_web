import crypto from "node:crypto";

// 敏感头:落盘/出报告时脱敏,只在内存里用于重放。
export const SENSITIVE_HEADERS = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "x-auth-token",
  "api-key",
  "x-csrf-token",
]);

// URL 里出现这些参数名就按令牌处理(报告/审计展示时打码)。
export const SENSITIVE_QUERY = /^(?:token|access_token|refresh_token|id_token|api[_-]?key|apikey|key|secret|password|passwd|pwd|session|sessionid|auth|authorization|sig|signature|code)$/i;

export const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function severityRank(value) {
  return SEVERITY_ORDER[value] ?? 9;
}

export function headerAll(headers, name) {
  if (!Array.isArray(headers)) return [];
  const wanted = String(name).toLowerCase();
  return headers
    .filter((h) => String(h?.name || "").toLowerCase() === wanted)
    .map((h) => String(h?.value ?? ""));
}

export function headerGet(headers, name) {
  const hits = headerAll(headers, name);
  return hits.length ? hits.join(", ") : undefined;
}

export function headerObject(headers) {
  const out = {};
  for (const h of headers || []) {
    const name = String(h?.name || "").toLowerCase();
    if (!name) continue;
    const value = String(h?.value ?? "");
    out[name] = out[name] === undefined ? value : `${out[name]}, ${value}`;
  }
  return out;
}

export function redactHeaders(headers) {
  return (headers || []).map((h) => {
    const name = String(h?.name || "");
    const value = String(h?.value ?? "");
    return {
      name,
      value: SENSITIVE_HEADERS.has(name.toLowerCase()) ? `<redacted:${value.length}>` : value,
    };
  });
}

export function redactUrl(value) {
  try {
    const url = new URL(String(value));
    for (const [key] of [...url.searchParams]) {
      if (SENSITIVE_QUERY.test(key)) url.searchParams.set(key, "<redacted>");
    }
    return url.href;
  } catch {
    return String(value);
  }
}

export function shortHash(input, length = 8) {
  return crypto.createHash("sha256").update(String(input)).digest("hex").slice(0, length);
}

export function runId() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}-${shortHash(`${Date.now()}:${Math.random()}`, 6)}`;
}

export function nowIso() {
  return new Date().toISOString();
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function truncate(value, max = 300) {
  const text = String(value ?? "");
  return text.length <= max ? text : `${text.slice(0, max)}…(+${text.length - max})`;
}

export function snippetAround(text, needle, radius = 120) {
  const source = String(text ?? "");
  const at = source.indexOf(needle);
  if (at < 0) return "";
  return source.slice(Math.max(0, at - radius), Math.min(source.length, at + needle.length + radius));
}

export function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function decodeBody(buffer, contentType) {
  if (!buffer || !buffer.length) return "";
  const match = /charset\s*=\s*["']?([\w-]+)/i.exec(String(contentType || ""));
  const charset = (match && match[1]) || "utf-8";
  try {
    return new TextDecoder(charset, { fatal: false }).decode(buffer);
  } catch {
    return buffer.toString("utf8");
  }
}

// 请求头只允许影响内容协商/身份,不允许改写目标定位(host)或分帧(content-length 等)。
const FORBIDDEN_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "te",
  "trailer",
]);

export function sanitizeHeaders(input) {
  if (!input) return {};
  if (!isPlainObject(input)) throw new Error("headers 必须是对象");
  const out = {};
  for (const [rawKey, rawValue] of Object.entries(input)) {
    const key = String(rawKey).trim().toLowerCase();
    if (!key) continue;
    if (FORBIDDEN_HEADERS.has(key)) throw new Error(`不允许覆盖请求头 ${key}(会改变目标定位或消息分帧)`);
    const value = String(rawValue ?? "");
    if (/[\r\n]/.test(value) || /[\r\n]/.test(key)) throw new Error(`请求头 ${key} 含换行,已拒绝(防头注入)`);
    out[key] = value;
  }
  return out;
}

export function parseSetCookie(raw) {
  const parts = String(raw || "").split(";").map((p) => p.trim());
  const [pair, ...attrs] = parts;
  const eq = pair.indexOf("=");
  if (eq <= 0) return null;
  const name = pair.slice(0, eq).trim();
  const value = pair.slice(eq + 1).trim();
  if (!name) return null;
  const attributes = {};
  for (const attr of attrs) {
    const at = attr.indexOf("=");
    const key = (at < 0 ? attr : attr.slice(0, at)).trim().toLowerCase();
    const val = at < 0 ? "" : attr.slice(at + 1).trim();
    if (key) attributes[key] = val;
  }
  return { name, value, attributes };
}
