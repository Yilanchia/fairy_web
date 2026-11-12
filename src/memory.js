import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { nowIso } from "./util.js";

// 跨 engagement 记忆:只存 host 级非敏感元数据。
// 绝不存 cookie/凭据/对象数据/正文/marker;默认在 ~/.fairy/memory.json。

export const MEMORY_SCHEMA = "FairyMemory/v1";
const ARRAY_FIELDS = ["tech", "login_paths", "reflecting_params", "prior_finding_kinds"];

export function memoryDir() {
  return process.env.FAIRY_MEMORY_DIR
    ? path.resolve(process.env.FAIRY_MEMORY_DIR)
    : path.join(os.homedir(), ".fairy");
}

export function memoryPath() {
  return path.join(memoryDir(), "memory.json");
}

export function loadMemory() {
  const file = memoryPath();
  if (!fs.existsSync(file)) return { schema: MEMORY_SCHEMA, hosts: {} };
  const memory = JSON.parse(fs.readFileSync(file, "utf8"));
  if (memory.schema !== MEMORY_SCHEMA) throw new Error(`memory schema 不匹配:${memory.schema}`);
  if (!memory.hosts || typeof memory.hosts !== "object") memory.hosts = {};
  return memory;
}

function saveMemory(memory) {
  const file = memoryPath();
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(memory, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return file;
}

export function normalizeHost(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return "";
  try {
    return new URL(text).hostname;
  } catch {
    try {
      return new URL(`http://${text}`).hostname;
    } catch {
      return text.split("/")[0].split(":")[0];
    }
  }
}

function mergeList(current, incoming) {
  const values = [...(Array.isArray(current) ? current : []), ...(Array.isArray(incoming) ? incoming : [])]
    .map((item) => String(item).trim())
    .filter(Boolean);
  return [...new Set(values)].slice(0, 50);
}

export function rememberHost(host, patch = {}) {
  const memory = loadMemory();
  const key = normalizeHost(host);
  if (!key) throw new Error("host 为空");
  const entry = memory.hosts[key] || {};
  for (const field of ARRAY_FIELDS) {
    if (patch[field] !== undefined) entry[field] = mergeList(entry[field], patch[field]);
  }
  if (patch.waf !== undefined) entry.waf = String(patch.waf).slice(0, 80);
  entry.updated_at = nowIso();
  memory.hosts[key] = entry;
  const file = saveMemory(memory);
  return { file, host: key, entry };
}

function hostFromUrl(value) {
  const text = String(value || "")
    .replace(/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+/i, "")
    .split(/\s+/)[0];
  try {
    return new URL(text).hostname;
  } catch {
    return "";
  }
}

function queryNames(value) {
  const text = String(value || "")
    .replace(/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+/i, "")
    .split(/\s+/)[0];
  try {
    return [...new URL(text).searchParams.keys()];
  } catch {
    return [];
  }
}

export function rememberFromScan(result) {
  if (!result || !Array.isArray(result.pages)) return { file: memoryPath(), hosts: [] };
  const memory = loadMemory();
  const touched = new Set();

  for (const page of result.pages) {
    const host = hostFromUrl(page.url || page.requested_url);
    if (!host) continue;
    const entry = memory.hosts[host] || {};
    entry.tech = mergeList(entry.tech, (page.tech || []).map((item) => item.tech));
    try {
      const url = new URL(page.url || page.requested_url);
      if (/(login|signin|auth|sso)/i.test(url.pathname)) {
        entry.login_paths = mergeList(entry.login_paths, [url.pathname]);
      }
    } catch {
      // ignore malformed page URL
    }
    entry.updated_at = nowIso();
    memory.hosts[host] = entry;
    touched.add(host);
  }

  for (const finding of result.findings || []) {
    const host = hostFromUrl(finding.where);
    if (!host) continue;
    const entry = memory.hosts[host] || {};
    entry.prior_finding_kinds = mergeList(entry.prior_finding_kinds, [finding.kind]);
    if (finding.kind === "reflection") {
      entry.reflecting_params = mergeList(entry.reflecting_params, queryNames(finding.where));
    }
    entry.updated_at = nowIso();
    memory.hosts[host] = entry;
    touched.add(host);
  }

  const file = saveMemory(memory);
  return { file, hosts: [...touched] };
}

export function showMemory(host) {
  const memory = loadMemory();
  if (host) {
    const key = normalizeHost(host);
    return { schema: "FairyMemoryShow/v1", host: key, data: memory.hosts[key] || null };
  }
  return {
    schema: "FairyMemoryShow/v1",
    path: memoryPath(),
    hosts: Object.entries(memory.hosts).map(([key, value]) => ({ host: key, ...value })),
  };
}
