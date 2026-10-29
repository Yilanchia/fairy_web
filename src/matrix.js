import crypto from "node:crypto";
import { loadSession, listSessions } from "./session.js";
import { enrichFindings } from "./taxonomy.js";
import { nowIso, redactUrl } from "./util.js";

// 权限矩阵:多账号 × 多端点,只发 GET,比较状态/长度/正文哈希。
// 它发现的是"谁能到哪"的候选,不执行横向、不提权、不读取对象内容。

function sha(body) {
  return crypto.createHash("sha256").update(String(body || "")).digest("hex").slice(0, 16);
}

function titleOf(body) {
  const match = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(String(body || ""));
  return match ? match[1].trim().slice(0, 120) : null;
}

function pathOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

export async function runRoleMatrix(guard, options = {}) {
  const urls = (Array.isArray(options.urls) ? options.urls : []).map(String).filter(Boolean);
  if (!urls.length) throw new Error("至少一个 URL");
  const sessions = Array.isArray(options.sessions) && options.sessions.length
    ? options.sessions.map(String)
    : listSessions(guard.projectDir).map((item) => item.name);
  if (!sessions.length) throw new Error("至少一个 session(先 web_login 或 web_session create)");

  const maxUrls = Math.min(Math.max(Number(options.maxUrls) || 20, 1), 50);
  const maxSessions = Math.min(Math.max(Number(options.maxSessions) || 5, 1), 8);
  const selected = sessions.slice(0, maxSessions);
  const headersExtra = options.headers || {};
  const includeAnonymous = options.includeAnonymous !== false;
  const identities = [
    ...(includeAnonymous ? [{ name: "anonymous", headers: {} }] : []),
    ...selected.map((name) => ({ name, headers: loadSession(guard.projectDir, name).headers })),
  ];

  const matrix = [];
  const findings = [];
  const started = Date.now();
  let seq = 0;

  for (const url of urls.slice(0, maxUrls)) {
    const rows = [];
    for (const identity of identities) {
      const headers = { ...identity.headers, ...headersExtra };
      try {
        const response = await guard.request(url, { method: "GET", headers });
        rows.push({
          identity: identity.name,
          status: response.status,
          bytes: response.body_bytes,
          body_sha256: sha(response.body),
          title: titleOf(response.body),
          request_id: response.request_id,
          access: response.status >= 200 && response.status < 300 ? "allow" : [401, 403].includes(response.status) ? "deny" : "other",
        });
      } catch (error) {
        rows.push({
          identity: identity.name,
          status: null,
          bytes: null,
          body_sha256: null,
          title: null,
          request_id: null,
          access: "error",
          error: error.message,
        });
      }
    }

    const named = rows.filter((row) => row.identity !== "anonymous");
    const namedOk = named.filter((row) => row.access === "allow");
    const namedDenied = named.filter((row) => row.access === "deny");
    const anonymous = rows.find((row) => row.identity === "anonymous");
    const okHashes = new Set(namedOk.map((row) => row.body_sha256));
    const summary = {
      url,
      path: pathOf(url),
      access:
        namedOk.length && namedDenied.length
          ? "role-restricted"
          : anonymous && anonymous.access === "allow"
            ? "public"
            : namedOk.length
              ? "authenticated"
              : "blocked",
      allowed: namedOk.map((row) => row.identity),
      denied: namedDenied.map((row) => row.identity),
      anonymous: anonymous ? anonymous.access : null,
      distinct_bodies: okHashes.size,
    };
    matrix.push({ ...summary, rows });

    if (namedOk.length && namedDenied.length) {
      findings.push({
        id: `M-${String(++seq).padStart(3, "0")}`,
        kind: "authz",
        severity: "high",
        confidence: "medium",
        title: `角色访问差异:${summary.path}`,
        where: `GET ${redactUrl(url)}`,
        detail: `允许:${summary.allowed.join(", ")};拒绝:${summary.denied.join(", ")}。同一端点出现角色差异,可能是 BFLA 或权限矩阵配置错误。`,
        evidence: {
          request_ids: rows.filter((row) => row.request_id).map((row) => row.request_id),
          statuses: Object.fromEntries(rows.map((row) => [row.identity, row.status])),
        },
        verify: "用两个真实测试账号复核;确认不是租户/角色预期差异,不要尝试提权或读取他人数据。",
      });
    }

    if (namedOk.length >= 2 && okHashes.size > 1) {
      findings.push({
        id: `M-${String(++seq).padStart(3, "0")}`,
        kind: "data-diff",
        severity: "medium",
        confidence: "low",
        title: `登录态响应差异:${summary.path}`,
        where: `GET ${redactUrl(url)}`,
        detail: `${namedOk.length} 个账号均返回 2xx,但正文哈希有 ${okHashes.size} 种。可能是按身份渲染的正常差异,也可能是对象级越权候选。`,
        evidence: {
          request_ids: namedOk.map((row) => row.request_id),
          hashes: Object.fromEntries(namedOk.map((row) => [row.identity, row.body_sha256])),
        },
        verify: "确认差异是否来自对象归属;只看状态/哈希,不要批量拉取数据。",
      });
    }
  }

  enrichFindings(findings);

  return {
    schema: "FairyMatrix/v1",
    tool: "web_role_matrix",
    run_id: guard.runId,
    generated_at: nowIso(),
    identities: identities.map((identity) => identity.name),
    urls: urls.slice(0, maxUrls),
    matrix,
    findings,
    stats: {
      requests: guard.count,
      urls: matrix.length,
      identities: identities.length,
      duration_ms: Date.now() - started,
    },
    audit_path: guard.auditPath,
    limitations: [
      "只发 GET,只比较状态/长度/正文哈希;不读取对象内容、不执行横向、不提权。",
      "角色差异可能是有意设计;data-diff 是候选,不等于 IDOR。",
      "动态页面、时间戳、AB 测试都会造成正文差异,需人工复核。",
      "只覆盖提供的 URL 与账号,不代表完整权限矩阵。",
    ],
  };
}
