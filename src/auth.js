import crypto from "node:crypto";
import { URL } from "node:url";
import { saveSession } from "./session.js";

// 认证态:单次登录(不重试、不爆破)+ 双会话差分(BOLA/IDOR 的证据骨架)。

function attr(attrs, name) {
  const rx = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'<>]+))`, "i");
  const match = rx.exec(attrs || "");
  return match ? match[1] ?? match[2] ?? match[3] ?? "" : "";
}

export function parseForms(html) {
  const forms = [];
  for (const match of String(html || "").matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = match[1] || "";
    const body = match[2] || "";
    const inputs = [];
    for (const input of body.matchAll(/<(input|button|textarea|select)\b([^>]*)>/gi)) {
      const name = attr(input[2] || "", "name");
      if (!name) continue;
      const type = (attr(input[2] || "", "type") || (input[1].toLowerCase() === "button" ? "submit" : "text")).toLowerCase();
      inputs.push({ name, type, value: attr(input[2] || "", "value") });
    }
    forms.push({
      action: attr(attrs, "action"),
      method: (attr(attrs, "method") || "GET").toUpperCase(),
      enctype: (attr(attrs, "enctype") || "").toLowerCase(),
      inputs,
      has_password: inputs.some((input) => input.type === "password"),
    });
  }
  return forms;
}

// 只做一次登录尝试。失败就返回失败,绝不重试/换字典。
export async function login(guard, options = {}) {
  const pageUrl = String(options.url || "");
  if (!pageUrl) throw new Error("需要登录页 URL");
  const sessionName = String(options.session || "");
  if (!sessionName) throw new Error("需要 session 名(如 alice / bob)");
  const extraHeaders = options.headers || {};
  const fields = options.fields && typeof options.fields === "object" ? options.fields : {};

  const page = await guard.request(pageUrl, { headers: extraHeaders });
  const forms = parseForms(page.body);
  const form = forms.find((item) => item.has_password) || forms.find((item) => item.inputs.length) || null;
  if (!form) {
    throw new Error("页面上没有可用表单。若是 JSON 登录或前端渲染,请用 web_probe + web_session(create) 手动建会话。");
  }

  const action = new URL(form.action || page.url, page.url).href;
  const method = String(options.method || form.method || "POST").toUpperCase();
  if (!["POST", "PUT", "PATCH"].includes(method)) {
    throw new Error(`登录表单方法是 ${method};Fairy 不自动提交非写方法表单,请确认后显式指定 method=POST。`);
  }
  if (!guard.limits.methods.includes(method)) {
    throw new Error(`scope 未授权 ${method}(当前:${guard.limits.methods.join(", ")})。登录是写操作,必须在 limits.methods 里显式加上 ${method}。`);
  }

  const data = {};
  for (const input of form.inputs) {
    if (["submit", "button", "reset", "file"].includes(input.type)) continue;
    if (input.type === "password") continue;
    if (input.value) data[input.name] = input.value;
  }
  Object.assign(data, fields);

  const isJson = options.json === true || /json/.test(form.enctype);
  const body = isJson ? JSON.stringify(data) : new URLSearchParams(data).toString();
  const headers = {
    ...extraHeaders,
    "content-type": isJson ? "application/json" : "application/x-www-form-urlencoded",
  };

  const response = await guard.request(action, { method, headers, body });
  let cookie = guard.jar.headerFor(response.url);
  let authHeader = null;

  if (!cookie && options.token_field) {
    try {
      const token = JSON.parse(response.body)?.[String(options.token_field)];
      if (typeof token === "string" && token) authHeader = `Bearer ${token}`;
    } catch {
      // 响应不是 JSON,按失败处理。
    }
  }

  if (!cookie && !authHeader) {
    throw new Error(
      `登录请求返回 HTTP ${response.status},但没有拿到新会话(Cookie/token)。常见原因:凭据错误、需要验证码/CSRF、或登录走前端接口。Fairy 不做重试或爆破。`,
    );
  }

  const sessionHeaders = {};
  if (cookie) sessionHeaders.cookie = cookie;
  if (authHeader) sessionHeaders.authorization = authHeader;
  if (extraHeaders.origin) sessionHeaders.origin = extraHeaders.origin;

  const saved = saveSession(guard.projectDir, sessionName, {
    headers: sessionHeaders,
    note: `login ${new URL(pageUrl).host}`,
  });

  return {
    ok: true,
    session: saved.name,
    enc: saved.enc,
    warning: saved.warning,
    status: response.status,
    final_url: response.url,
    header_names: Object.keys(sessionHeaders),
    request_id: response.request_id,
    attempts: 1,
    note: "只尝试了一次。Fairy 不会重试、不会换字典;会话值不在此输出。",
  };
}

function titleOf(html) {
  return (String(html || "").match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1] || "").replace(/\s+/g, " ").trim().slice(0, 120);
}

function words(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .filter(Boolean)
    .slice(0, 6000);
}

function shingles(list, size = 4) {
  const set = new Set();
  for (let i = 0; i + size <= list.length; i++) set.add(list.slice(i, i + size).join(" "));
  return set;
}

function jaccard(a, b) {
  if (!a.size && !b.size) return 1;
  let overlap = 0;
  const [small, large] = a.size <= b.size ? [a, b] : [b, a];
  for (const item of small) if (large.has(item)) overlap += 1;
  return overlap / (a.size + b.size - overlap);
}

function sha(text) {
  return crypto.createHash("sha256").update(String(text || "")).digest("hex");
}

export async function compare(guard, options = {}) {
  const url = String(options.url || "");
  if (!url) throw new Error("需要对比 URL");
  const method = String(options.method || "GET").toUpperCase();
  const marker = options.marker ? String(options.marker) : null;

  const a = await guard.request(url, { method, headers: options.aHeaders || {} });
  const b = await guard.request(url, { method, headers: options.bHeaders || {} });

  const similarity = Number(jaccard(shingles(words(a.body)), shingles(words(b.body))).toFixed(4));
  const markerA = marker ? a.body.includes(marker) : null;
  const markerB = marker ? b.body.includes(marker) : null;

  let verdict = "same";
  let interpretation = "两侧响应高度一致。";
  if (marker && markerA && markerB) {
    verdict = "marker-in-both";
    interpretation =
      "标记在 A、B 两侧都出现。若 A 是资源所有者、B 是另一个账号,这说明 B 能读到 A 的对象 —— 水平越权候选。";
  } else if (marker && markerB && !markerA) {
    verdict = "marker-only-in-b";
    interpretation = "标记只在 B 侧出现,通常不是越权;检查是否 B 才是所有者。";
  } else if (marker && markerA && !markerB) {
    verdict = "marker-only-in-a";
    interpretation = "只有 A 能看到标记;B 被正确拦截,未发现越权。";
  } else if (a.status !== b.status) {
    verdict = "status-diff";
    interpretation = `状态码不同(A=${a.status}, B=${b.status})。结合两侧角色判断是否越权/权限差异。`;
  } else if (similarity < 0.9) {
    verdict = "body-diff";
    interpretation = "状态码相同但正文差异明显,可能是按身份渲染的数据差异,需人工确认。";
  }

  const evidence = (item) => ({
    request_id: item.request_id,
    status: item.status,
    bytes: item.body_bytes,
    body_sha256: sha(item.body),
    title: titleOf(item.body),
  });

  return {
    ok: true,
    url: a.url,
    method,
    a: evidence(a),
    b: evidence(b),
    diff: {
      status_same: a.status === b.status,
      similarity,
      marker,
      marker_in_a: markerA,
      marker_in_b: markerB,
      bytes_delta: (b.body_bytes || 0) - (a.body_bytes || 0),
    },
    verdict,
    interpretation,
    snippets:
      options.include_snippet === true
        ? { a: a.body.slice(0, 200), b: b.body.slice(0, 200) }
        : null,
    note: "只返回哈希/长度/标记命中,不默认回传正文;证据可在审计日志按 request_id 回查。",
  };
}
