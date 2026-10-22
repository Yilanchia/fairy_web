import fs from "node:fs";
import path from "node:path";
import { redactUrl } from "./util.js";

// 把抓包里的请求按 scope 重放,做"当时 vs 现在"的差分。
// 默认只放 GET/HEAD;写方法必须 scope 显式授权 + allow_write。
// 不重放 Cookie/Authorization:认证态由命名 session 现取,避免旧令牌误导。

function applyReplace(text, replace) {
  let output = String(text ?? "");
  for (const [from, to] of Object.entries(replace || {})) {
    if (!from) continue;
    output = output.split(from).join(String(to));
  }
  return output;
}

function requestBody(request) {
  const postData = request.postData;
  if (!postData) return null;
  if (typeof postData.text === "string") return postData.text;
  if (Array.isArray(postData.params)) {
    return new URLSearchParams(postData.params.map((item) => [item.name, item.value])).toString();
  }
  return null;
}

export async function replayHar(guard, options = {}) {
  const file = path.resolve(String(options.file || ""));
  if (!fs.existsSync(file)) throw new Error(`HAR 文件不存在:${file}`);
  let har;
  try {
    har = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`HAR 解析失败:${error.message}`);
  }
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) throw new Error("不是有效 HAR:缺少 log.entries");

  const maxEntries = Math.min(Math.max(Number(options.maxEntries) || 50, 1), 500);
  const allowWrite = options.allowWrite === true;
  const replace = options.replace && typeof options.replace === "object" ? options.replace : {};
  const baseHeaders = options.headers || {};
  const hostFilter = Array.isArray(options.hosts) && options.hosts.length
    ? options.hosts.map((h) => String(h).toLowerCase())
    : null;

  const results = [];
  const skipped = { write_blocked: 0, method: 0, out_of_scope: 0, host_filter: 0 };
  let replayed = 0;

  for (const entry of entries) {
    if (replayed >= maxEntries) break;
    const request = entry.request || {};
    const method = String(request.method || "GET").toUpperCase();
    const originalUrl = String(request.url || "");
    if (!originalUrl) continue;

    let host = "";
    try {
      host = new URL(originalUrl).host.toLowerCase();
    } catch {
      continue;
    }
    if (hostFilter && !hostFilter.includes(host)) {
      skipped.host_filter += 1;
      continue;
    }
    if (!["GET", "HEAD"].includes(method) && !allowWrite) {
      skipped.write_blocked += 1;
      continue;
    }
    if (!guard.limits.methods.includes(method)) {
      skipped.method += 1;
      continue;
    }

    const url = applyReplace(originalUrl, replace);
    const rawBody = requestBody(request);
    const body = rawBody === null ? undefined : applyReplace(rawBody, replace);
    const headers = { ...baseHeaders };
    for (const header of request.headers || []) {
      const name = String(header.name || "").toLowerCase();
      if (["host", "content-length", "connection", "cookie", "authorization", "accept-encoding"].includes(name)) continue;
      headers[name] = String(header.value ?? "");
    }
    if (body !== undefined && !Object.keys(headers).some((key) => key.toLowerCase() === "content-type")) {
      headers["content-type"] = "application/x-www-form-urlencoded";
    }

    let response;
    try {
      response = await guard.request(url, { method, headers, body, follow: true });
    } catch (error) {
      if (["OUT_OF_SCOPE", "BLOCKED_ADDRESS", "PRIVATE_ADDRESS"].includes(error.code)) {
        skipped.out_of_scope += 1;
        continue;
      }
      results.push({ method, url: redactUrl(url), error: error.message });
      replayed += 1;
      continue;
    }

    replayed += 1;
    const originalResponse = entry.response || {};
    const originalStatus = Number(originalResponse.status || 0);
    const originalSize = Number(originalResponse.content?.size || 0);

    results.push({
      method,
      url: redactUrl(url),
      original: {
        status: originalStatus,
        mime: originalResponse.content?.mimeType || null,
        bytes: originalSize,
      },
      replay: {
        status: response.status,
        mime: response.content_type || null,
        bytes: response.body_bytes,
        request_id: response.request_id,
      },
      changed: response.status !== originalStatus,
      status_delta: response.status - originalStatus,
      bytes_delta: response.body_bytes - originalSize,
    });
  }

  const changed = results.filter((item) => item.changed).length;
  return {
    ok: true,
    file,
    stats: {
      entries: entries.length,
      replayed,
      changed,
      skipped,
    },
    results: results.slice(0, 200),
    note: "只重放,不导出正文;请求头里的 Cookie/Authorization 不会被沿用,认证态用 --session 现取。",
    limitations: [
      "重放会向目标发真实请求,仅限 scope 内;写方法需 scope 授权且 allow_write=true。",
      "HAR 里的旧令牌/动态参数可能导致 401/302,这不等于漏洞;用 replace 做标记替换后再判断。",
      "状态/长度差分是线索,不是结论;需结合业务与审计日志人工复核。",
    ],
  };
}
