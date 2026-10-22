import fs from "node:fs";
import net from "node:net";
import path from "node:path";

// 授权护照:没有它,Fairy 一个请求都不发。
// 设计原则和 Verdex 的 brief 一致——范围必须显式声明,而且不能声明成"全世界"。

export const SCOPE_FILE = "fairy.scope.json";

export const DEFAULT_LIMITS = {
  rps: 5,
  max_requests: 2000,
  timeout_ms: 10000,
  max_bytes: 2_000_000,
  max_redirects: 5,
  max_pages: 40,
  max_active_pages: 15,
  verify_tls: true,
  allow_private: false,
  allow_active_probes: false,
  methods: ["GET", "HEAD", "OPTIONS"],
};

const ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]);
const HOST_RE = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

const BLOCKED_IPS = new Set([
  "169.254.169.254", // AWS/GCP/Azure 元数据
  "169.254.170.2", // ECS task metadata
  "100.100.100.200", // 阿里云元数据
  "fd00:ec2::254", // AWS IPv6 元数据
]);

function clampInt(value, fallback, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

export function ipv4ToInt(ip) {
  const parts = String(ip).split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

export function ipInCidr(ip, cidr) {
  const [base, bitsRaw] = String(cidr).split("/");
  if (net.isIP(ip) !== 4 || net.isIP(base) !== 4) return false;
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 8 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToInt(ip) & mask) === (ipv4ToInt(base) & mask);
}

export function validHostPattern(pattern) {
  if (typeof pattern !== "string") return false;
  const p = pattern.trim().toLowerCase();
  if (!p || p === "*" || /\s/.test(p)) return false;
  if (p.includes("/")) {
    const [addr, bitsRaw] = p.split("/");
    const version = net.isIP(addr);
    const bits = Number(bitsRaw);
    if (!version || !Number.isInteger(bits)) return false;
    return version === 4 ? bits >= 8 && bits <= 32 : bits >= 16 && bits <= 128;
  }
  if (net.isIP(p)) return true;
  if (p.startsWith("*.")) {
    const rest = p.slice(2);
    return HOST_RE.test(rest) && rest.split(".").length >= 2 && !rest.includes("*");
  }
  return HOST_RE.test(p);
}

export function hostMatches(host, pattern) {
  const h = String(host || "").toLowerCase().replace(/^\[|\]$/g, "");
  const p = String(pattern || "").toLowerCase();
  if (!h || !p) return false;
  if (p.includes("/")) return net.isIP(h) === 4 ? ipInCidr(h, p) : false;
  if (net.isIP(p)) return h === p;
  if (p.startsWith("*.")) return h.endsWith(p.slice(1)) && h !== p.slice(2);
  return h === p;
}

export function isPrivateAddress(ip) {
  const value = String(ip || "").toLowerCase();
  if (value === "::1") return true;
  if (net.isIP(value) === 4) {
    const n = ipv4ToInt(value);
    if (n === null) return false;
    return (
      (n & 0xff000000) === 0x0a000000 || // 10/8
      (n & 0xfff00000) === 0xac100000 || // 172.16/12
      (n & 0xffff0000) === 0xc0a80000 || // 192.168/16
      (n & 0xff000000) === 0x7f000000 || // 127/8
      (n & 0xffff0000) === 0xa9fe0000 || // 169.254/16
      (n & 0xffc00000) === 0x64400000 // 100.64/10 CGNAT
    );
  }
  if (net.isIP(value) === 6) {
    if (value.startsWith("fc") || value.startsWith("fd")) return true;
    if (value.startsWith("fe8") || value.startsWith("fe9") || value.startsWith("fea") || value.startsWith("feb")) return true;
    if (value.startsWith("::ffff:")) return isPrivateAddress(value.slice(7));
  }
  return false;
}

export function isBlockedAddress(ip) {
  return BLOCKED_IPS.has(String(ip || "").toLowerCase());
}

function isPrivatePattern(pattern) {
  const p = String(pattern || "").toLowerCase();
  if (p === "localhost" || p === "::1") return true;
  if (p.includes("/")) {
    const [addr] = p.split("/");
    return isPrivateAddress(addr);
  }
  return isPrivateAddress(p);
}

export function normalizeScope(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("scope 必须是 JSON 对象");
  const authorization = raw.authorization || {};
  const basis = String(authorization.basis || "").trim();
  if (basis.length < 8) {
    throw new Error("scope.authorization.basis 必填且至少 8 字:写明授权依据(自建靶场 / SRC 项目号 / 书面授权)。Fairy 只对声明授权的目标动手。");
  }

  const include = Array.isArray(raw.include) ? raw.include : [];
  if (!include.length) throw new Error("scope.include 不能为空:至少声明一个授权主机/域名/IP/CIDR");
  const normalizedInclude = [...new Set(include.map((v) => String(v).trim().toLowerCase()).filter(Boolean))];
  for (const pattern of normalizedInclude) {
    if (!validHostPattern(pattern)) {
      throw new Error(`scope.include 含非法或过宽的模式:${pattern}(禁止单 *、禁止 *.com 这类顶级通配)`);
    }
  }

  const exclude = Array.isArray(raw.exclude)
    ? [...new Set(raw.exclude.map((v) => String(v).trim().toLowerCase()).filter(Boolean))]
    : [];
  for (const pattern of exclude) {
    if (!validHostPattern(pattern)) throw new Error(`scope.exclude 含非法模式:${pattern}`);
  }

  const inputLimits = raw.limits && typeof raw.limits === "object" ? raw.limits : {};
  const limits = {
    rps: clampInt(inputLimits.rps, DEFAULT_LIMITS.rps, 1, 50),
    max_requests: clampInt(inputLimits.max_requests, DEFAULT_LIMITS.max_requests, 1, 100000),
    timeout_ms: clampInt(inputLimits.timeout_ms, DEFAULT_LIMITS.timeout_ms, 1000, 60000),
    max_bytes: clampInt(inputLimits.max_bytes, DEFAULT_LIMITS.max_bytes, 1024, 20_000_000),
    max_redirects: clampInt(inputLimits.max_redirects, DEFAULT_LIMITS.max_redirects, 0, 10),
    max_pages: clampInt(inputLimits.max_pages, DEFAULT_LIMITS.max_pages, 1, 500),
    max_active_pages: clampInt(inputLimits.max_active_pages, DEFAULT_LIMITS.max_active_pages, 0, 200),
    verify_tls: inputLimits.verify_tls !== false,
    allow_private:
      inputLimits.allow_private === undefined
        ? normalizedInclude.some(isPrivatePattern)
        : inputLimits.allow_private === true,
    allow_active_probes: inputLimits.allow_active_probes === true,
    methods: DEFAULT_LIMITS.methods.slice(),
  };

  if (Array.isArray(inputLimits.methods) && inputLimits.methods.length) {
    limits.methods = [...new Set(inputLimits.methods.map((m) => String(m).toUpperCase()))];
    for (const method of limits.methods) {
      if (!ALLOWED_METHODS.has(method)) throw new Error(`scope.limits.methods 含不支持的方法:${method}`);
    }
    if (!limits.methods.includes("GET")) throw new Error("scope.limits.methods 必须包含 GET");
  }

  const expiresAt = authorization.expires_at ? String(authorization.expires_at) : null;
  if (expiresAt) {
    const ts = Date.parse(expiresAt);
    if (Number.isNaN(ts)) throw new Error("scope.authorization.expires_at 不是合法时间(建议 RFC3339)");
    if (ts < Date.now()) throw new Error(`授权已过期(${expiresAt}),拒绝启动。请更新 scope 或重新授权。`);
  }

  return {
    schema: "FairyScope/v1",
    authorization: {
      basis,
      operator: String(authorization.operator || "").trim(),
      expires_at: expiresAt,
      note: String(authorization.note || "").trim(),
    },
    include: normalizedInclude,
    exclude,
    limits,
  };
}

export function scopePath(projectDir) {
  return path.join(path.resolve(projectDir), SCOPE_FILE);
}

export function loadScope(projectDir) {
  const file = scopePath(projectDir);
  if (!fs.existsSync(file)) {
    throw new Error(`未找到授权护照 ${file}。先运行 \`fairy init\` 声明 include 与授权依据,Fairy 不会发送未授权请求。`);
  }
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`授权护照不是合法 JSON:${error.message}`);
  }
  return normalizeScope(raw);
}

export function saveScope(projectDir, spec) {
  const scope = normalizeScope(spec);
  const dir = path.resolve(projectDir);
  fs.mkdirSync(dir, { recursive: true });
  const file = scopePath(dir);
  fs.writeFileSync(file, `${JSON.stringify(scope, null, 2)}\n`, "utf8");
  return { path: file, scope };
}

export function scopeSummary(scope) {
  return {
    authorization: scope.authorization,
    include: scope.include,
    exclude: scope.exclude,
    limits: scope.limits,
  };
}
