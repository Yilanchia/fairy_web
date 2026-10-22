import fs from "node:fs";
import path from "node:path";
import { createContext, addFinding } from "./checks.js";
import { headerAll, headerGet, redactUrl, severityRank, truncate } from "./util.js";
import { enrichFindings } from "./taxonomy.js";

const SECURITY_HEADERS = [
  ["content-security-policy", "CSP"],
  ["x-frame-options", "X-Frame-Options"],
  ["x-content-type-options", "X-Content-Type-Options"],
  ["strict-transport-security", "HSTS"],
  ["referrer-policy", "Referrer-Policy"],
];

function toEntries(headers) {
  return (Array.isArray(headers) ? headers : []).map((h) => ({
    name: String(h?.name || ""),
    value: String(h?.value ?? ""),
  }));
}

function responseText(response) {
  const content = response?.content || {};
  const text = typeof content.text === "string" ? content.text : "";
  if (!text) return "";
  if (String(content.encoding || "").toLowerCase() === "base64") {
    try {
      return Buffer.from(text, "base64").toString("utf8");
    } catch {
      return "";
    }
  }
  return text;
}

export function ingestHar(file) {
  const abs = path.resolve(String(file));
  if (!fs.existsSync(abs)) throw new Error(`HAR 文件不存在:${abs}`);
  let har;
  try {
    har = JSON.parse(fs.readFileSync(abs, "utf8"));
  } catch (error) {
    throw new Error(`HAR 解析失败(应为 JSON):${error.message}`);
  }
  const entries = har?.log?.entries;
  if (!Array.isArray(entries)) throw new Error("不是有效 HAR:缺少 log.entries 数组");

  const ctx = createContext();
  const hosts = new Map();
  const endpoints = new Map();
  let totalBytes = 0;

  entries.forEach((entry, index) => {
    const request = entry?.request || {};
    const response = entry?.response || {};
    let url;
    try {
      url = new URL(String(request.url || ""));
    } catch {
      return;
    }
    const host = url.host.toLowerCase();
    const hostInfo = hosts.get(host) || { host, count: 0, schemes: new Set() };
    hostInfo.count += 1;
    hostInfo.schemes.add(url.protocol.replace(":", ""));
    hosts.set(host, hostInfo);

    const status = Number(response.status || 0);
    const requestHeaders = toEntries(request.headers);
    const responseHeaders = toEntries(response.headers);
    const text = responseText(response);
    totalBytes += text.length;

    const endpointKey = `${String(request.method || "GET").toUpperCase()} ${url.pathname}`;
    const endpoint = endpoints.get(endpointKey) || {
      method: String(request.method || "GET").toUpperCase(),
      path: url.pathname,
      count: 0,
      params: new Set(),
      statuses: new Set(),
      auth: false,
      sample_url: redactUrl(url.href),
    };
    endpoint.count += 1;
    endpoint.statuses.add(status);
    for (const [key] of url.searchParams) endpoint.params.add(key);
    if (headerGet(requestHeaders, "authorization")) endpoint.auth = true;
    endpoints.set(endpointKey, endpoint);

    const where = `#${index + 1} ${endpoint.method} ${redactUrl(url.href)}`;
    const isHtml = /html/i.test(headerGet(responseHeaders, "content-type") || "");

    if (url.protocol === "http:") {
      addFinding(ctx, {
        kind: "transport",
        severity: "medium",
        confidence: "high",
        title: "明文 HTTP 传输",
        where,
        detail: "抓包中该请求走 http,凭证/数据可被中间人读取。",
        evidence: { entry: index + 1 },
      });
    }

    if (isHtml && status >= 200 && status < 400) {
      for (const [name, label] of SECURITY_HEADERS) {
        if (name === "strict-transport-security" && url.protocol !== "https:") continue;
        if (headerGet(responseHeaders, name) === undefined) {
          addFinding(ctx, {
            kind: "security-header",
            severity: "low",
            confidence: "high",
            title: `缺失安全响应头:${label}`,
            where: url.origin,
            detail: "HAR 静态推断;同一站点只需修一次。",
            evidence: { entry: index + 1 },
          });
        }
      }
    }

    for (const raw of headerAll(responseHeaders, "set-cookie")) {
      const pair = String(raw).split(";")[0];
      const eq = pair.indexOf("=");
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      const missing = [];
      if (!/;\s*HttpOnly/i.test(raw)) missing.push("HttpOnly");
      if (!/;\s*Secure/i.test(raw)) missing.push("Secure");
      if (!/;\s*SameSite/i.test(raw)) missing.push("SameSite");
      if (!missing.length) continue;
      addFinding(ctx, {
        kind: "cookie",
        severity: missing.includes("HttpOnly") ? "medium" : "low",
        confidence: "high",
        title: `Cookie ${name} 缺少 ${missing.join("/")}`,
        where: url.origin,
        detail: "从 HAR 的 Set-Cookie 静态判断,未发送任何请求。",
        evidence: { entry: index + 1, cookie: name },
      });
    }

    const acao = headerGet(responseHeaders, "access-control-allow-origin");
    if (acao === "*") {
      addFinding(ctx, {
        kind: "cors",
        severity: /true/i.test(String(headerGet(responseHeaders, "access-control-allow-credentials"))) ? "high" : "medium",
        confidence: "high",
        title: "CORS 允许任意源",
        where: url.origin,
        detail: "HAR 中响应带 ACAO:*,涉及敏感数据时需收紧。",
        evidence: { entry: index + 1 },
      });
    }

    for (const [key, value] of url.searchParams) {
      if (/token|api[_-]?key|secret|password|session|auth|sig|code/i.test(key) && String(value).length >= 8) {
        addFinding(ctx, {
          kind: "info-exposure",
          severity: "medium",
          confidence: "medium",
          title: `URL 参数 ${key} 疑似携带令牌`,
          where: url.origin,
          detail: "令牌出现在 URL,会进日志/历史/Referer;需确认是否可改为 Header 传递。",
          evidence: { entry: index + 1 },
        });
        break;
      }
    }

    if (isHtml && status >= 200 && status < 400) {
      for (const [key, value] of url.searchParams) {
        if (String(value).length < 4) continue;
        if (text.includes(String(value))) {
          addFinding(ctx, {
            kind: "reflection",
            severity: "low",
            confidence: "low",
            title: `参数 ${key} 的值反射进响应`,
            where,
            detail: "HAR 静态比对:请求参数值出现在响应体。可能只是正常回显,需人工确认是否未转义。",
            evidence: { entry: index + 1, snippet: truncate(text, 200) },
          });
          break;
        }
      }
    }
  });

  ctx.findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title));
  ctx.findings.forEach((finding, index) => {
    finding.id = `H-${String(index + 1).padStart(3, "0")}`;
  });
  enrichFindings(ctx.findings);

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of ctx.findings) bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;

  return {
    schema: "FairyHar/v1",
    tool: "har_ingest",
    file: path.basename(abs),
    generated_at: new Date().toISOString(),
    stats: {
      entries: entries.length,
      hosts: hosts.size,
      endpoints: endpoints.size,
      bytes: totalBytes,
      findings: bySeverity,
    },
    hosts: [...hosts.values()]
      .map((h) => ({ host: h.host, count: h.count, schemes: [...h.schemes] }))
      .sort((a, b) => b.count - a.count),
    endpoints: [...endpoints.values()]
      .sort((a, b) => b.count - a.count)
      .slice(0, 100)
      .map((e) => ({
        ...e,
        params: [...e.params],
        statuses: [...e.statuses].sort(),
      })),
    findings: ctx.findings,
    limitations: [
      "只静态分析你提供的 HAR,不发起任何请求。",
      "反射/CORS/Cookie 判断基于抓包内容,需结合业务与转义上下文人工确认。",
      "hosts 清单可帮你起草 scope,但不会自动授权:scope 必须由你显式确认。",
    ],
  };
}

function redactHeaderList(headers) {
  const sensitive = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"]);
  return (headers || []).map((h) => ({
    name: String(h.name || ""),
    value: sensitive.has(String(h.name || "").toLowerCase()) ? "<redacted>" : String(h.value ?? ""),
  }));
}

export function buildHar(traffic, meta = {}) {
  return {
    log: {
      version: "1.2",
      creator: { name: "fairy-web", version: "0.1.0" },
      comment: "Fairy Web 采集流量。凭证类 Header 已脱敏,可直接喂给 Verdex har_analyze。",
      pages: [],
      entries: (traffic || []).map((item, index) => {
        let url;
        try {
          url = new URL(item.url);
        } catch {
          url = null;
        }
        const queryString = url
          ? [...url.searchParams].map(([name, value]) => ({
              name,
              value: /token|api[_-]?key|secret|password|session|auth|sig|code/i.test(name) ? "<redacted>" : value,
            }))
          : [];
        return {
          pageref: `fairy-${index + 1}`,
          startedDateTime: new Date().toISOString(),
          time: item.ms || 0,
          request: {
            method: item.method,
            url: item.url,
            httpVersion: item.httpVersion || "HTTP/1.1",
            cookies: [],
            headers: redactHeaderList(item.requestHeaders),
            queryString,
            headersSize: -1,
            bodySize: 0,
          },
          response: {
            status: item.status,
            statusText: item.statusText || "",
            httpVersion: item.httpVersion || "HTTP/1.1",
            cookies: [],
            headers: redactHeaderList(item.responseHeaders),
            content: {
              size: item.bodyText ? item.bodyText.length : 0,
              mimeType: item.mime || "application/octet-stream",
              text: String(item.bodyText || "").slice(0, 100_000),
            },
            redirectURL: item.redirects && item.redirects.length ? item.redirects[item.redirects.length - 1].to : "",
            headersSize: -1,
            bodySize: item.bodyText ? item.bodyText.length : 0,
          },
          cache: {},
          timings: { send: 0, wait: item.ms || 0, receive: 0 },
          _fairy: { run_id: meta.run_id || null, tool: "fairy-web" },
        };
      }),
    },
  };
}
