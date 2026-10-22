import { URL } from "node:url";
import { headerAll, headerGet, redactUrl, shortHash, snippetAround, truncate } from "./util.js";

// 所有检测都只做"确认存在 + 留证据",不推进到利用,不 dump 数据。

export function createContext() {
  return { findings: [], keys: new Set(), cookieKeys: new Set(), nextId: 0, errors: [] };
}

export function addFinding(ctx, finding) {
  const where = String(finding.where || "");
  const key = `${finding.kind}|${where}|${finding.title}`;
  if (ctx.keys.has(key)) return null;
  ctx.keys.add(key);
  const entry = {
    id: `F-${String(++ctx.nextId).padStart(3, "0")}`,
    severity: "medium",
    confidence: "medium",
    evidence: {},
    verify: "",
    ...finding,
    where,
  };
  ctx.findings.push(entry);
  return entry;
}

const SECURITY_HEADERS = [
  ["content-security-policy", "CSP", "缺少内容安全策略,削弱 XSS 纵深防御"],
  ["x-frame-options", "X-Frame-Options", "缺少点击劫持防护"],
  ["x-content-type-options", "X-Content-Type-Options", "缺少 MIME 嗅探防护(应为 nosniff)"],
  ["strict-transport-security", "HSTS", "缺少 HSTS,HTTPS 可被降级"],
  ["referrer-policy", "Referrer-Policy", "缺少引用来源策略,令牌可能随 Referer 外泄"],
];

const REDIRECT_PARAM = /^(?:next|url|uri|redirect|redirect_uri|return|returnurl|return_to|to|target|dest|destination|continue|callback|back|goto|ref)$/i;
const CANARY = "https://fairy-canary.invalid/fairy";
const CANARY_ORIGIN = "https://fairy-canary.invalid";

const EXPOSURES = [
  { path: "/.git/HEAD", severity: "high", rx: /^ref:\s+refs\//m, title: "Git 仓库暴露" },
  { path: "/.env", severity: "high", rx: /^[A-Z][A-Z0-9_]{1,}=/m, title: "环境变量文件暴露" },
  { path: "/server-status", severity: "high", rx: /Apache Server Status/i, title: "Apache server-status 暴露" },
  { path: "/actuator/env", severity: "high", rx: /"propertySources"|"activeProfiles"/, title: "Spring Actuator env 暴露" },
  { path: "/actuator/health", severity: "info", rx: /"status"\s*:\s*"UP"/, title: "Spring Actuator health 可访问" },
  { path: "/.DS_Store", severity: "medium", rx: /Bud1/, title: "macOS .DS_Store 暴露" },
  { path: "/robots.txt", severity: "info", rx: /User-agent:/i, title: "robots.txt 可访问(测绘信息)", silentDetail: true },
  { path: "/sitemap.xml", severity: "info", rx: /<urlset|<sitemapindex/i, title: "sitemap.xml 可访问(测绘信息)", silentDetail: true },
  { path: "/.well-known/security.txt", severity: "info", rx: /Contact:/i, title: "security.txt 存在" },
];

function isLoopbackHost(host) {
  return host === "127.0.0.1" || host === "localhost" || host === "::1" || host === "[::1]";
}

export function passiveChecks(page, ctx) {
  const url = new URL(page.url);
  const origin = url.origin;
  const isHtml = /html/i.test(page.content_type || "");

  if (url.protocol === "http:" && !isLoopbackHost(url.hostname)) {
    addFinding(ctx, {
      kind: "transport",
      severity: "medium",
      confidence: "high",
      title: "明文 HTTP 传输",
      where: origin,
      detail: "页面通过 http 提供,凭证与数据可能被中间人读取;需确认是否强制跳转 https。",
      evidence: { url: redactUrl(page.url), status: page.status },
      verify: "确认是否有 301 到 https,以及 HSTS 是否生效。",
    });
  }

  if (isHtml && page.status < 400) {
    for (const [name, label, note] of SECURITY_HEADERS) {
      if (name === "strict-transport-security" && url.protocol !== "https:") continue;
      if (headerGet(page.headers, name) === undefined) {
        addFinding(ctx, {
          kind: "security-header",
          severity: "low",
          confidence: "high",
          title: `缺失安全响应头:${label}`,
          where: origin,
          detail: note,
          evidence: { url: redactUrl(page.url), status: page.status },
          verify: "这是配置项,按业务风险评级;单独上报通常只算加固建议。",
        });
      }
    }
    const xcto = headerGet(page.headers, "x-content-type-options");
    if (xcto && !/nosniff/i.test(xcto)) {
      addFinding(ctx, {
        kind: "security-header",
        severity: "low",
        confidence: "high",
        title: "X-Content-Type-Options 非 nosniff",
        where: origin,
        detail: `当前值:${xcto}`,
        evidence: { url: redactUrl(page.url) },
      });
    }
    if (/^Index of \//im.test(page.body || "")) {
      addFinding(ctx, {
        kind: "directory-listing",
        severity: "medium",
        confidence: "high",
        title: "目录列表可浏览",
        where: redactUrl(page.url),
        detail: "响应体命中 'Index of /',目录内容可枚举。",
        evidence: { request_id: page.request_id, snippet: truncate(page.body, 300) },
        verify: "确认目录中是否有敏感文件;不要批量下载。",
      });
    }
  }

  const server = headerGet(page.headers, "server");
  if (server && /\d+\.\d+/.test(server)) {
    addFinding(ctx, {
      kind: "info-disclosure",
      severity: "info",
      confidence: "high",
      title: "服务端版本号暴露",
      where: origin,
      detail: `Server: ${server} —— 可辅助匹配已知 CVE,建议隐藏版本。`,
      evidence: { url: redactUrl(page.url) },
    });
  }
  const poweredBy = headerGet(page.headers, "x-powered-by");
  if (poweredBy) {
    addFinding(ctx, {
      kind: "info-disclosure",
      severity: "info",
      confidence: "high",
      title: "X-Powered-By 暴露技术栈",
      where: origin,
      detail: `X-Powered-By: ${poweredBy}`,
      evidence: { url: redactUrl(page.url) },
    });
  }

  for (const raw of headerAll(page.headers, "set-cookie")) {
    const pair = String(raw).split(";")[0];
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const name = pair.slice(0, eq).trim();
    const key = `${origin}|${name}`;
    if (ctx.cookieKeys.has(key)) continue;
    const flags = {
      httpOnly: /;\s*HttpOnly/i.test(raw),
      secure: /;\s*Secure/i.test(raw),
      sameSite: (/;\s*SameSite\s*=\s*([\w-]+)/i.exec(raw)?.[1] || null),
    };
    const missing = [];
    if (!flags.httpOnly) missing.push("HttpOnly");
    if (!flags.secure) missing.push("Secure");
    if (!flags.sameSite) missing.push("SameSite");
    if (!missing.length) continue;
    ctx.cookieKeys.add(key);
    addFinding(ctx, {
      kind: "cookie",
      severity: flags.httpOnly ? "low" : "medium",
      confidence: "high",
      title: `Cookie ${name} 缺少 ${missing.join("/")}`,
      where: origin,
      detail: `会话 Cookie 缺少安全属性,易被脚本读取、明文回传或跨站携带。SameSite=${flags.sameSite || "未设置"}`,
      evidence: { request_id: page.request_id, cookie: name, flags },
      verify: "确认该 Cookie 是否承载会话;非会话 Cookie 可降级。",
    });
  }
}

export async function activeChecks(guard, page, ctx, options = {}) {
  const headers = options.headers || {};
  // 用最初请求的 URL 做参数探测:跟随重定向后 page.url 可能已经丢了查询参数。
  const baseUrl = page.requested_url || page.url;
  const url = new URL(baseUrl);
  const origin = url.origin;

  // CORS:带一个不可能属于目标的 Origin,看服务端是否反射/放行。
  try {
    const res = await guard.request(baseUrl, {
      headers: { ...headers, origin: CANARY_ORIGIN },
      follow: false,
    });
    const allowOrigin = headerGet(res.headers, "access-control-allow-origin");
    const allowCred = headerGet(res.headers, "access-control-allow-credentials");
    if (allowOrigin === "*" || allowOrigin === CANARY_ORIGIN) {
      addFinding(ctx, {
        kind: "cors",
        severity: /true/i.test(String(allowCred)) ? "high" : "medium",
        confidence: "high",
        title: "CORS 允许任意源",
        where: origin,
        detail: `ACAO=${allowOrigin}, ACAC=${allowCred || "未设置"}${/true/i.test(String(allowCred)) ? " —— 携带凭证的跨站读取,高危" : ""}`,
        evidence: { request_id: res.request_id, url: redactUrl(baseUrl) },
        verify: "用一个登录态页面在恶意源发起 fetch 确认能否读到敏感响应;只在你有授权的双账号环境验证。",
      });
    }
  } catch (error) {
    ctx.errors.push({ stage: "cors", url: page.url, error: error.message });
  }

  if (!/html/i.test(page.content_type || "")) return;

  // 反射:只放无特殊字符的标记,不构成 XSS 载荷;确认反射点后交给人判断上下文。
  const params = [...url.searchParams.keys()].slice(0, 6);
  for (const name of params) {
    const marker = `fairy${shortHash(`${page.url}:${name}:${Date.now()}`, 8)}`;
    const probe = new URL(url.href);
    probe.searchParams.set(name, marker);
    let res;
    try {
      res = await guard.request(probe.href, { headers });
    } catch (error) {
      ctx.errors.push({ stage: "reflection", url: probe.href, error: error.message });
      continue;
    }
    if (res.status >= 400 || !(res.body || "").includes(marker)) continue;
    const context = reflectionContext(res.body, marker);
    addFinding(ctx, {
      kind: "reflection",
      severity: "medium",
      confidence: "low",
      title: `参数 ${name} 的值反射进响应`,
      where: `GET ${redactUrl(baseUrl)} (param: ${name})`,
      detail: `标记 ${marker} 原样出现在响应(${context})。反射本身不是漏洞;需在浏览器确认该处能否逃逸出当前上下文。`,
      evidence: {
        request_id: res.request_id,
        status: res.status,
        snippet: snippetAround(res.body, marker, 100),
      },
      verify: "浏览器打开该 URL,看标记落在 HTML 文本/属性/脚本里;确认可执行前不要下结论。",
    });
  }

  // 开放重定向:只对常见跳转参数放 canary,跟随 false,不真的跳出授权范围。
  for (const name of params.filter((p) => REDIRECT_PARAM.test(p)).slice(0, 4)) {
    const probe = new URL(url.href);
    probe.searchParams.set(name, CANARY);
    let res;
    try {
      res = await guard.request(probe.href, { headers, follow: false });
    } catch (error) {
      ctx.errors.push({ stage: "open-redirect", url: probe.href, error: error.message });
      continue;
    }
    const location = headerGet(res.headers, "location");
    if (!location || !location.includes("fairy-canary.invalid")) continue;
    addFinding(ctx, {
      kind: "open-redirect",
      severity: "medium",
      confidence: "high",
      title: `参数 ${name} 可控制跳转目标`,
      where: `GET ${redactUrl(baseUrl)} (param: ${name})`,
      detail: `服务端 3xx 跳转到外部 canary(${truncate(location, 120)})。可用于钓鱼链或 OAuth token 窃取,取决于业务。`,
      evidence: { request_id: res.request_id, status: res.status, location: truncate(location, 200) },
      verify: "确认跳转是否要求登录/白名单;用你自己的域名做落地页复现。",
    });
  }
}

function reflectionContext(body, marker) {
  const at = body.indexOf(marker);
  const before = body.slice(Math.max(0, at - 240), at);
  if (/<script\b[^>]*>[^<]*$/i.test(before)) return "JavaScript 上下文";
  if (/<style\b[^>]*>[^<]*$/i.test(before)) return "CSS 上下文";
  if (/<[a-z][^>]*=["'][^"']*$/i.test(before)) return "HTML 属性上下文";
  if (/<!--[\s\S]*$/.test(before)) return "HTML 注释";
  return "HTML 文本上下文";
}

export async function exposureChecks(guard, origin, ctx, options = {}) {
  const headers = options.headers || {};
  for (const item of EXPOSURES) {
    const probeUrl = new URL(item.path, origin).href;
    let res;
    try {
      res = await guard.request(probeUrl, { headers });
    } catch (error) {
      ctx.errors.push({ stage: "exposure", url: probeUrl, error: error.message });
      continue;
    }
    if (res.status !== 200) continue;
    const text = res.body || "";
    if (!item.rx.test(text)) continue;
    addFinding(ctx, {
      kind: "exposure",
      severity: item.severity,
      confidence: "high",
      title: item.title,
      where: probeUrl,
      detail: item.silentDetail
        ? "存在公开的测绘入口,本身不是漏洞;把路径并入侦察面。"
        : `路径可直接访问且命中内容特征,需确认是否应对外暴露。`,
      evidence: { request_id: res.request_id, status: res.status, snippet: truncate(text, 240) },
      verify: "只读确认内容类型,不要批量拉取;确属敏感数据时立即停止并上报。",
    });
  }
}

export function tlsCheck(page, ctx) {
  if (!page.tls) return;
  const host = new URL(page.url).host;
  if (page.tls.days_left !== null && page.tls.days_left < 0) {
    addFinding(ctx, {
      kind: "tls",
      severity: "high",
      confidence: "high",
      title: "TLS 证书已过期",
      where: host,
      detail: `证书有效期至 ${page.tls.valid_to},已过期 ${Math.abs(page.tls.days_left)} 天。`,
      evidence: { tls: page.tls },
    });
  } else if (page.tls.days_left !== null && page.tls.days_left < 30) {
    addFinding(ctx, {
      kind: "tls",
      severity: "medium",
      confidence: "high",
      title: "TLS 证书即将过期",
      where: host,
      detail: `剩余 ${page.tls.days_left} 天(至 ${page.tls.valid_to})。`,
      evidence: { tls: page.tls },
    });
  }
  if (page.tls.protocol && /TLSv1(?:\.1)?$/.test(page.tls.protocol)) {
    addFinding(ctx, {
      kind: "tls",
      severity: "medium",
      confidence: "high",
      title: `过时的 TLS 协议:${page.tls.protocol}`,
      where: host,
      detail: "建议只保留 TLS 1.2 及以上。",
      evidence: { tls: page.tls },
    });
  }
}
