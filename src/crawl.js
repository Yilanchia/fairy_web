import { URL } from "node:url";

const ASSET_EXT = /\.(?:css|js|mjs|map|png|jpe?g|gif|svg|webp|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf|zip|gz|tgz|rar|7z)$/i;
const SKIP_SCHEME = /^(?:javascript|mailto|tel|data|blob|about|file):/i;
const FATAL_CODES = new Set(["REQUEST_LIMIT", "METHOD_DENIED", "BAD_SCHEME"]);

export function normalizeUrl(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    url.hash = "";
    return url.href;
  } catch {
    return null;
  }
}

export function parseHtml(html, baseUrl) {
  const text = String(html || "");
  const base = new URL(baseUrl);
  const origin = base.origin;
  const title = (text.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || "")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 160);

  const links = new Set();
  const assets = new Set();
  const external = new Set();

  for (const match of text.matchAll(/\b(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))/gi)) {
    const value = match[1] ?? match[2] ?? match[3] ?? "";
    if (!value || value.startsWith("#") || SKIP_SCHEME.test(value)) continue;
    const resolved = normalizeUrl(value, baseUrl);
    if (!resolved) continue;
    const url = new URL(resolved);
    if (url.origin !== origin) {
      external.add(url.host);
      continue;
    }
    if (ASSET_EXT.test(url.pathname)) assets.add(resolved);
    else links.add(resolved);
  }

  const forms = [];
  for (const match of text.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = match[1] || "";
    const body = match[2] || "";
    const action = attrValue(attrs, "action") || baseUrl;
    const method = (attrValue(attrs, "method") || "GET").toUpperCase();
    const inputs = [];
    for (const input of body.matchAll(/<(?:input|select|textarea)\b([^>]*)>/gi)) {
      const name = attrValue(input[1] || "", "name");
      if (!name) continue;
      inputs.push({ name, type: attrValue(input[1] || "", "type") || null });
    }
    forms.push({ action: normalizeUrl(action, baseUrl) || baseUrl, method, inputs });
  }

  const endpoints = new Set();
  for (const match of text.matchAll(/["'`](\/[a-zA-Z0-9_\-./]{2,120}(?:\?[^"'`\s<>]{0,120})?)["'`]/g)) {
    if (endpoints.size >= 100) break;
    const path = match[1];
    if (ASSET_EXT.test(path.split("?")[0])) continue;
    endpoints.add(path);
  }

  return {
    title,
    links: [...links],
    assets: [...assets],
    external_hosts: [...external],
    forms,
    endpoints: [...endpoints],
  };
}

function attrValue(attrs, name) {
  const re = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'<>]+))`, "i");
  const match = re.exec(attrs || "");
  return match ? match[1] ?? match[2] ?? match[3] ?? "" : null;
}

export async function crawl(guard, seedUrl, options = {}) {
  const origin = new URL(seedUrl).origin;
  const maxDepth = Math.max(0, Math.min(Number(options.maxDepth ?? 2), 5));
  const maxPages = Math.max(1, Math.min(Number(options.maxPages ?? guard.limits.max_pages), 500));
  const headers = options.headers || {};
  const queue = [{ url: seedUrl, depth: 0 }];
  const visited = new Set();
  const pages = [];
  const endpoints = new Set();
  const forms = [];
  const externalHosts = new Set();
  const errors = [];

  while (queue.length && pages.length < maxPages) {
    const item = queue.shift();
    if (!item || visited.has(item.url)) continue;
    visited.add(item.url);

    let response;
    try {
      response = await guard.request(item.url, { headers });
    } catch (error) {
      if (FATAL_CODES.has(error.code)) throw error;
      errors.push({ url: item.url, error: error.message, code: error.code || null });
      continue;
    }

    let meta = { title: "", links: [], assets: [], external_hosts: [], forms: [], endpoints: [] };
    if (/html/i.test(response.content_type) && response.status < 400) {
      meta = parseHtml(response.body, response.url);
    }
    for (const endpoint of meta.endpoints) endpoints.add(endpoint);
    forms.push(...meta.forms.map((form) => ({ ...form, page: response.url })));
    for (const host of meta.external_hosts) externalHosts.add(host);

    pages.push({ ...response, ...meta, depth: item.depth, origin });

    if (item.depth < maxDepth) {
      for (const link of meta.links) {
        if (new URL(link).origin !== origin) continue;
        if (visited.has(link)) continue;
        queue.push({ url: link, depth: item.depth + 1 });
      }
    }
  }

  return {
    seed: seedUrl,
    origin,
    pages,
    endpoints: [...endpoints],
    forms,
    external_hosts: [...externalHosts],
    errors,
    exhausted: queue.length === 0,
  };
}

export async function probeUrls(guard, urls, options = {}) {
  const headers = options.headers || {};
  const pages = [];
  const endpoints = new Set();
  const forms = [];
  const externalHosts = new Set();
  const errors = [];

  for (const url of urls) {
    let response;
    try {
      response = await guard.request(url, { headers });
    } catch (error) {
      if (error.code === "REQUEST_LIMIT" || error.code === "METHOD_DENIED") throw error;
      errors.push({ url, error: error.message, code: error.code || null });
      continue;
    }
    let meta = { title: "", links: [], assets: [], external_hosts: [], forms: [], endpoints: [] };
    if (/html/i.test(response.content_type) && response.status < 400) {
      meta = parseHtml(response.body, response.url);
    }
    for (const endpoint of meta.endpoints) endpoints.add(endpoint);
    forms.push(...meta.forms.map((form) => ({ ...form, page: response.url })));
    for (const host of meta.external_hosts) externalHosts.add(host);
    pages.push({ ...response, ...meta, depth: 0, origin: new URL(response.url).origin });
  }

  return {
    seed: urls[0] || null,
    origin: pages[0] ? new URL(pages[0].url).origin : null,
    pages,
    endpoints: [...endpoints],
    forms,
    external_hosts: [...externalHosts],
    errors,
    exhausted: true,
  };
}
