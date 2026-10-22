import http from "node:http";
import https from "node:https";
import zlib from "node:zlib";
import { decodeBody, parseSetCookie } from "./util.js";

export const USER_AGENT = "fairy-web/0.1 (authorized security testing)";

// 低层请求:不发重定向、不管 scope、不算限速——这些在外层 Guard 里做。
export function rawRequest({
  url,
  method = "GET",
  headers = {},
  body,
  timeoutMs = 10000,
  verifyTls = true,
  maxBytes = 2_000_000,
}) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(url);
    } catch {
      reject(new Error(`无效 URL:${url}`));
      return;
    }
    const lib = target.protocol === "https:" ? https : target.protocol === "http:" ? http : null;
    if (!lib) {
      reject(new Error(`仅支持 http/https,收到 ${target.protocol}`));
      return;
    }

    const started = process.hrtime.bigint();
    const requestHeaders = { ...headers };
    if (!Object.keys(requestHeaders).some((k) => k.toLowerCase() === "user-agent")) {
      requestHeaders["user-agent"] = USER_AGENT;
    }

    const req = lib.request(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || undefined,
        path: `${target.pathname}${target.search}`,
        method,
        headers: requestHeaders,
        servername: target.hostname,
        rejectUnauthorized: verifyTls,
        timeout: timeoutMs,
      },
      (res) => {
        const tls = readTls(res);
        const chunks = [];
        let size = 0;
        let truncated = false;
        res.on("data", (chunk) => {
          if (size < maxBytes) {
            const room = maxBytes - size;
            chunks.push(chunk.length > room ? chunk.subarray(0, room) : chunk);
            size += Math.min(chunk.length, room);
            if (chunk.length > room) truncated = true;
          } else {
            truncated = true;
          }
        });
        res.on("end", () => {
          let raw = Buffer.concat(chunks);
          const encoding = String(res.headers["content-encoding"] || "").toLowerCase();
          try {
            if (encoding === "gzip") raw = zlib.gunzipSync(raw);
            else if (encoding === "deflate") raw = zlib.inflateSync(raw);
            else if (encoding === "br") raw = zlib.brotliDecompressSync(raw);
          } catch {
            // 解压失败就保留原字节,交给上层按文本读取。
          }
          const headersArr = [];
          for (let i = 0; i < res.rawHeaders.length; i += 2) {
            headersArr.push({ name: res.rawHeaders[i], value: res.rawHeaders[i + 1] });
          }
          resolve({
            status: res.statusCode || 0,
            statusText: res.statusMessage || "",
            httpVersion: res.httpVersion,
            headers: headersArr,
            body: raw,
            truncated,
            timingMs: Number(process.hrtime.bigint() - started) / 1e6,
            tls,
          });
        });
        res.on("error", reject);
      },
    );

    req.on("timeout", () => req.destroy(new Error(`请求超时(${timeoutMs}ms)`)));
    req.on("error", reject);
    if (body !== undefined && body !== null && method !== "GET" && method !== "HEAD") req.write(body);
    req.end();
  });
}

function readTls(res) {
  try {
    const socket = res.socket;
    if (!socket || typeof socket.getPeerCertificate !== "function") return null;
    const cert = socket.getPeerCertificate();
    if (!cert || !cert.subject) return null;
    const expiresAt = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
    return {
      protocol: typeof socket.getProtocol === "function" ? socket.getProtocol() : null,
      subject: cert.subject?.CN || null,
      issuer: cert.issuer?.O || cert.issuer?.CN || null,
      valid_from: cert.valid_from || null,
      valid_to: cert.valid_to || null,
      days_left: Number.isNaN(expiresAt) ? null : Math.floor((expiresAt - Date.now()) / 86_400_000),
      san: cert.subjectaltname || null,
      authorized: typeof socket.authorized === "boolean" ? socket.authorized : null,
    };
  } catch {
    return null;
  }
}

export function bodyText(res) {
  const contentType = (res.headers || []).find((h) => String(h.name).toLowerCase() === "content-type")?.value || "";
  return decodeBody(res.body, contentType);
}

export class CookieJar {
  constructor() {
    this.cookies = [];
  }

  setFrom(url, setCookieValues) {
    let target;
    try {
      target = new URL(url);
    } catch {
      return;
    }
    for (const raw of setCookieValues || []) {
      const parsed = parseSetCookie(raw);
      if (!parsed) continue;
      const hostOnly = !parsed.attributes.domain;
      const domain = String(parsed.attributes.domain || target.hostname).replace(/^\./, "").toLowerCase();
      const cookie = {
        name: parsed.name,
        value: parsed.value,
        domain,
        hostOnly,
        path: parsed.attributes.path || "/",
        secure: "secure" in parsed.attributes,
        httpOnly: "httponly" in parsed.attributes,
        sameSite: parsed.attributes.samesite || null,
        maxAge: parsed.attributes["max-age"] || null,
        expires: parsed.attributes.expires || null,
      };
      this.cookies = this.cookies.filter(
        (c) => !(c.name === cookie.name && c.domain === cookie.domain && c.path === cookie.path),
      );
      if (cookie.maxAge === "0") continue;
      this.cookies.push(cookie);
    }
  }

  headerFor(url) {
    let target;
    try {
      target = new URL(url);
    } catch {
      return "";
    }
    const host = target.hostname.toLowerCase();
    const pathname = target.pathname || "/";
    return this.cookies
      .filter((c) => {
        const domainOk = c.hostOnly ? host === c.domain : host === c.domain || host.endsWith(`.${c.domain}`);
        const pathOk = pathname.startsWith(c.path);
        const secureOk = !c.secure || target.protocol === "https:";
        return domainOk && pathOk && secureOk;
      })
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");
  }

  dump() {
    return this.cookies.map((c) => ({
      name: c.name,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
    }));
  }

  // 仅供会话持久化:包含值,调用方必须落加密文件,绝不进报告/审计。
  series() {
    return this.cookies.map((c) => ({
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path,
      secure: c.secure,
      httpOnly: c.httpOnly,
      sameSite: c.sameSite,
    }));
  }
}
