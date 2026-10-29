import { verifyHighAuth } from "./highauth.js";
import { runRoleMatrix } from "./matrix.js";
import { nowIso } from "./util.js";

// 最高授权后的"触手":把多个受权端点/账号画成只读可达性图。
// 只复用权限矩阵的 GET;没有横向执行、没有凭据、没有隧道。

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

function pathOf(url) {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}

export async function runReachability(guard, options = {}) {
  const urls = (Array.isArray(options.urls) ? options.urls : []).map(String).filter(Boolean);
  if (!urls.length) throw new Error("至少一个 URL");

  const hosts = [...new Set(urls.map(hostOf).filter(Boolean))];
  if (!hosts.length) throw new Error("URL 没有合法 host");
  const auth = hosts.map((host) => verifyHighAuth(guard.projectDir, { asset: host, action: "read-only" }))[0];

  const matrix = await runRoleMatrix(guard, {
    urls,
    sessions: options.sessions,
    includeAnonymous: options.includeAnonymous !== false,
    headers: options.headers || {},
  });

  const nodes = new Map();
  const edges = [];
  const addNode = (id, type, label, meta = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, type, label, ...meta });
  };

  for (const summary of matrix.matrix) {
    const host = hostOf(summary.url);
    const endpointId = `endpoint:${summary.path}`;
    addNode(`asset:${host}`, "asset", host);
    addNode(endpointId, "endpoint", summary.path, { url: summary.url, access: summary.access });
    edges.push({ from: endpointId, to: `asset:${host}`, type: "hosted_on" });

    for (const row of summary.rows) {
      const identityId = `identity:${row.identity}`;
      addNode(identityId, "identity", row.identity);
      edges.push({
        from: identityId,
        to: endpointId,
        type: "access",
        access: row.access,
        status: row.status,
        request_id: row.request_id,
      });
    }
  }

  const roleRestricted = matrix.matrix
    .filter((summary) => summary.access === "role-restricted")
    .map((summary) => ({
      url: summary.url,
      path: summary.path,
      allowed: summary.allowed,
      denied: summary.denied,
    }));

  const reachable = {};
  for (const summary of matrix.matrix) {
    for (const row of summary.rows) {
      if (row.identity === "anonymous" || row.access !== "allow") continue;
      if (!reachable[row.identity]) reachable[row.identity] = [];
      reachable[row.identity].push(summary.path);
    }
  }

  return {
    schema: "FairyReachability/v1",
    tool: "fairy_reachability",
    run_id: guard.runId,
    generated_at: nowIso(),
    auth: {
      tier: auth.tier,
      basis: auth.basis,
      approver: auth.approver,
      expires_at: auth.expires_at,
      assets: auth.assets,
      actions: auth.actions,
    },
    identities: matrix.identities,
    urls,
    nodes: [...nodes.values()],
    edges,
    summary: {
      assets: hosts.length,
      endpoints: matrix.matrix.length,
      identities: matrix.identities.length,
      role_restricted: roleRestricted.length,
      reachable,
    },
    role_restricted: roleRestricted,
    findings: matrix.findings,
    stats: matrix.stats,
    audit_path: matrix.audit_path,
    limitations: [
      "最高授权只解锁只读可达性,不解锁横向执行、凭据、持久化或隧道。",
      "图来自 GET 的状态/哈希差异;角色差异是候选,不等于可利用。",
      "只覆盖受权资产清单内的 URL;清单外会被拒绝。",
      "不读取对象内容,不尝试提权。",
    ],
  };
}
