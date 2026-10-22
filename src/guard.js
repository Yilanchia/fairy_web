import fs from "node:fs";
import dns from "node:dns/promises";
import net from "node:net";
import path from "node:path";
import { loadScope, hostMatches, isPrivateAddress, isBlockedAddress } from "./scope.js";
import { rawRequest, CookieJar, bodyText } from "./http.js";
import {
  headerAll,
  headerGet,
  headerObject,
  redactHeaders,
  redactUrl,
  runId as makeRunId,
  nowIso,
  sleep,
  sanitizeHeaders,
} from "./util.js";

// 每次请求都从这里过:授权检查 → 限速 → 发请求 → 写审计。没有旁路。

export class GuardError extends Error {
  constructor(message, code = "GUARD") {
    super(message);
    this.name = "GuardError";
    this.code = code;
  }
}

const TRAFFIC_LIMIT = 300;
const TRAFFIC_BODY_LIMIT = 200_000;

export class Guard {
  constructor(projectDir, options = {}) {
    this.projectDir = path.resolve(projectDir);
    this.scope = options.scope || loadScope(this.projectDir);
    this.runId = options.runId || makeRunId();
    this.jar = new CookieJar();
    this.useJar = options.useJar !== false;
    this.count = 0;
    this.blocked = 0;
    this.traffic = [];
    this.lastAt = 0;
    this.dnsCache = new Map();
    this.auditPath = path.join(this.projectDir, ".fairy", "audit", `${this.runId}.jsonl`);
    fs.mkdirSync(path.dirname(this.auditPath), { recursive: true });
    this._audit({ kind: "start", ts: nowIso(), run_id: this.runId, include: this.scope.include, limits: this.scope.limits });
  }

  get limits() {
    return this.scope.limits;
  }

  async request(url, options = {}) {
    const limits = this.scope.limits;
    const method = String(options.method || "GET").toUpperCase();
    if (!limits.methods.includes(method)) {
      throw new GuardError(
        `方法 ${method} 未在 scope.limits.methods 授权(当前:${limits.methods.join(", ")});Fairy 默认只发只读方法。`,
        "METHOD_DENIED",
      );
    }
    const headers = sanitizeHeaders(options.headers || {});
    const body = options.body === undefined || options.body === null ? undefined : String(options.body);
    const follow = options.follow !== false;
    const maxHops = follow ? limits.max_redirects : 0;

    let current = String(url);
    const originalUrl = current;
    let currentMethod = method;
    let currentBody = body;
    let redirects = [];

    for (let hop = 0; hop <= maxHops; hop++) {
      let target;
      try {
        target = await this._check(current);
      } catch (error) {
        this.blocked += 1;
        this._audit({
          kind: "request",
          ts: nowIso(),
          run_id: this.runId,
          hop,
          allowed: false,
          method: currentMethod,
          url: redactUrl(current),
          reason: error.message,
          code: error.code,
        });
        throw error;
      }

      await this._throttle();
      this.count += 1;
      if (this.count > limits.max_requests) {
        this._audit({
          kind: "request",
          ts: nowIso(),
          run_id: this.runId,
          allowed: false,
          method: currentMethod,
          url: redactUrl(current),
          reason: `达到 max_requests=${limits.max_requests}`,
          code: "REQUEST_LIMIT",
        });
        throw new GuardError(`请求数超过 scope 上限 ${limits.max_requests},已停止(防止失控扫描)`, "REQUEST_LIMIT");
      }

      const reqId = `R${String(this.count).padStart(4, "0")}`;
      const requestHeaders = { accept: "*/*", "accept-encoding": "identity", ...headers };
      if (this.useJar && !requestHeaders.cookie) {
        const jarCookie = this.jar.headerFor(current);
        if (jarCookie) requestHeaders.cookie = jarCookie;
      }

      const started = Date.now();
      let raw;
      try {
        raw = await rawRequest({
          url: current,
          method: currentMethod,
          headers: requestHeaders,
          body: currentBody,
          timeoutMs: limits.timeout_ms,
          verifyTls: limits.verify_tls,
          maxBytes: limits.max_bytes,
        });
      } catch (error) {
        this._audit({
          kind: "request",
          ts: nowIso(),
          run_id: this.runId,
          req_id: reqId,
          allowed: true,
          method: currentMethod,
          url: redactUrl(current),
          error: error.message,
          ms: Date.now() - started,
        });
        throw new GuardError(`请求失败 ${redactUrl(current)}:${error.message}`, "REQUEST_FAILED");
      }

      const ms = Date.now() - started;
      if (this.useJar) this.jar.setFrom(current, headerAll(raw.headers, "set-cookie"));

      const text = bodyText(raw);
      const page = {
        request_id: reqId,
        method: currentMethod,
        url: current,
        requested_url: originalUrl,
        status: raw.status,
        status_text: raw.statusText,
        http_version: raw.httpVersion,
        content_type: headerGet(raw.headers, "content-type") || "",
        headers: raw.headers,
        headers_obj: headerObject(raw.headers),
        request_headers: redactHeaders(Object.entries(requestHeaders).map(([name, value]) => ({ name, value }))),
        body: text,
        body_bytes: raw.body.length,
        truncated: raw.truncated,
        timing_ms: Math.round(raw.timingMs),
        redirects: redirects.slice(),
        tls: raw.tls,
      };

      this._audit({
        kind: "request",
        ts: nowIso(),
        run_id: this.runId,
        req_id: reqId,
        hop,
        allowed: true,
        method: currentMethod,
        url: redactUrl(current),
        status: raw.status,
        bytes: raw.body.length,
        ms: Math.round(raw.timingMs),
      });
      this._capture(page, requestHeaders);

      if (raw.status >= 300 && raw.status < 400) {
        const location = headerGet(raw.headers, "location");
        if (location) {
          let next;
          try {
            next = new URL(location, current).href;
          } catch {
            return page;
          }
          page.next_location = next;
          if (hop >= maxHops) {
            page.redirect_blocked = follow ? "达到 max_redirects 上限" : "未跟随重定向(follow=false)";
            return page;
          }
          try {
            await this._check(next);
          } catch (error) {
            page.redirect_blocked = error.message;
            this._audit({
              kind: "redirect_blocked",
              ts: nowIso(),
              run_id: this.runId,
              from: redactUrl(current),
              to: redactUrl(next),
              reason: error.message,
            });
            return page;
          }
          redirects.push({ status: raw.status, from: current, to: next });
          if (
            raw.status === 303 ||
            ((raw.status === 301 || raw.status === 302) && currentMethod !== "GET" && currentMethod !== "HEAD")
          ) {
            currentMethod = "GET";
            currentBody = undefined;
          }
          current = next;
          continue;
        }
      }
      return page;
    }

    throw new GuardError("重定向处理异常", "REDIRECT_LOOP");
  }

  // 浏览器运行时用:只校验、不发请求;真正的请求由 CDP 发出,但一样过审计。
  async authorize(rawUrl) {
    return this._check(rawUrl);
  }

  async registerBrowserRequest(url, meta = {}) {
    await this._throttle();
    this.count += 1;
    if (this.count > this.scope.limits.max_requests) {
      throw new GuardError(`请求数超过 scope 上限 ${this.scope.limits.max_requests},已停止(防止失控扫描)`, "REQUEST_LIMIT");
    }
    this._audit({
      kind: "browser",
      ts: nowIso(),
      run_id: this.runId,
      req_id: `B${String(this.count).padStart(4, "0")}`,
      method: meta.method || "GET",
      url: redactUrl(url),
      resource_type: meta.resourceType || null,
      allowed: true,
    });
    return this.count;
  }

  // 样本下载:只读 GET、单文件、硬上限,不进 traffic/HAR,避免把大文件拖进报告。
  async download(url, options = {}) {
    const maxBytes = Math.min(Math.max(Number(options.maxBytes) || 20_000_000, 1024), 20_000_000);
    await this._check(url);
    await this._throttle();
    this.count += 1;
    if (this.count > this.scope.limits.max_requests) {
      throw new GuardError(`请求数超过 scope 上限 ${this.scope.limits.max_requests}`, "REQUEST_LIMIT");
    }
    const reqId = `D${String(this.count).padStart(4, "0")}`;
    const started = Date.now();
    const raw = await rawRequest({
      url,
      method: "GET",
      headers: { accept: "*/*", "accept-encoding": "identity" },
      timeoutMs: this.scope.limits.timeout_ms,
      verifyTls: this.scope.limits.verify_tls,
      maxBytes,
    });
    this._audit({
      kind: "download",
      ts: nowIso(),
      run_id: this.runId,
      req_id: reqId,
      method: "GET",
      url: redactUrl(url),
      status: raw.status,
      bytes: raw.body.length,
      ms: Date.now() - started,
    });
    return {
      request_id: reqId,
      url,
      status: raw.status,
      headers: raw.headers,
      body: raw.body,
      truncated: raw.truncated,
      tls: raw.tls,
    };
  }

  blockBrowserRequest(url, error, meta = {}) {
    this.blocked += 1;
    this._audit({
      kind: "browser",
      ts: nowIso(),
      run_id: this.runId,
      method: meta.method || "GET",
      url: redactUrl(url),
      resource_type: meta.resourceType || null,
      allowed: false,
      reason: error?.message || String(error),
      code: error?.code || null,
    });
  }

  async _check(rawUrl) {
    let target;
    try {
      target = new URL(String(rawUrl));
    } catch {
      throw new GuardError(`URL 非法:${rawUrl}`, "BAD_URL");
    }
    if (target.protocol !== "http:" && target.protocol !== "https:") {
      throw new GuardError(`只允许 http/https,收到 ${target.protocol}`, "BAD_SCHEME");
    }
    if (target.username || target.password) {
      throw new GuardError("URL 不允许携带 userinfo(会绕过主机判断)", "BAD_URL");
    }
    const host = target.hostname.toLowerCase();
    if (this.scope.exclude.some((pattern) => hostMatches(host, pattern))) {
      throw new GuardError(`${host} 命中 scope.exclude,拒绝请求`, "OUT_OF_SCOPE");
    }
    if (!this.scope.include.some((pattern) => hostMatches(host, pattern))) {
      throw new GuardError(
        `${host} 不在 scope.include 内(已授权:${this.scope.include.join(", ")}),拒绝请求`,
        "OUT_OF_SCOPE",
      );
    }
    const ip = net.isIP(host) ? host : await this._resolve(host);
    if (ip && isBlockedAddress(ip)) {
      throw new GuardError(`${host} 解析到受限地址 ${ip}(云元数据/凭据端点),拒绝请求`, "BLOCKED_ADDRESS");
    }
    if (ip && isPrivateAddress(ip) && !this.scope.limits.allow_private) {
      throw new GuardError(
        `${host} 解析到内网地址 ${ip};若这是你的自建靶场,在 scope.limits.allow_private 显式设为 true`,
        "PRIVATE_ADDRESS",
      );
    }
    return { url: target, host, ip };
  }

  async _resolve(host) {
    if (this.dnsCache.has(host)) {
      const cached = this.dnsCache.get(host);
      if (!cached) throw new GuardError(`${host} DNS 解析失败`, "DNS_FAILED");
      return cached;
    }
    try {
      const records = await dns.lookup(host, { all: true, verbatim: true });
      const ip = records && records[0] ? records[0].address : null;
      this.dnsCache.set(host, ip);
      if (!ip) throw new Error("no record");
      return ip;
    } catch {
      this.dnsCache.set(host, null);
      throw new GuardError(`${host} DNS 解析失败(离线或域名不存在)`, "DNS_FAILED");
    }
  }

  async _throttle() {
    const interval = 1000 / this.scope.limits.rps;
    const wait = Math.ceil(this.lastAt + interval - Date.now());
    if (wait > 0) await sleep(wait);
    this.lastAt = Date.now();
  }

  _capture(page, requestHeaders) {
    if (this.traffic.length >= TRAFFIC_LIMIT) return;
    this.traffic.push({
      id: page.request_id,
      method: page.method,
      url: page.url,
      requestHeaders: Object.entries(requestHeaders).map(([name, value]) => ({ name, value: String(value) })),
      status: page.status,
      statusText: page.status_text,
      httpVersion: page.http_version,
      responseHeaders: page.headers,
      bodyText: page.body.slice(0, TRAFFIC_BODY_LIMIT),
      mime: page.content_type || "application/octet-stream",
      ms: page.timing_ms,
      redirects: page.redirects,
    });
  }

  _audit(record) {
    try {
      fs.appendFileSync(this.auditPath, `${JSON.stringify(record)}\n`, "utf8");
    } catch {
      // 审计写失败不应静默:抛出会打断扫描,这里保留最后手段——stderr。
      process.stderr.write(`fairy: audit write failed ${this.auditPath}\n`);
    }
  }

  summary() {
    return {
      run_id: this.runId,
      requests: this.count,
      blocked: this.blocked,
      audit_path: this.auditPath,
      cookies: this.jar.dump(),
    };
  }

  close() {
    const info = this.summary();
    this._audit({ kind: "summary", ts: nowIso(), ...info });
    return info;
  }
}
