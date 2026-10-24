import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { redactUrl, truncate } from "./util.js";

// 浏览器运行时:直接走 Chrome DevTools Protocol,零依赖。
// 关键点:Document / XHR / Fetch / WebSocket 全部在浏览器网络层过 scope 闸门;
// 图片/CSS/字体等渲染子资源放行(否则页面根本渲染不出来),但会计入阻断记录之外的白名单策略。

const GATED_TYPES = new Set(["Document", "XHR", "Fetch", "WebSocket"]);
const COMMAND_TIMEOUT = 20_000;

const CANDIDATES = () => [
  process.env.FAIRY_BROWSER,
  path.join(process.env["ProgramFiles(x86)"] || "", "Microsoft", "Edge", "Application", "msedge.exe"),
  path.join(process.env.ProgramFiles || "", "Microsoft", "Edge", "Application", "msedge.exe"),
  path.join(process.env.ProgramFiles || "", "Google", "Chrome", "Application", "chrome.exe"),
  path.join(process.env["ProgramFiles(x86)"] || "", "Google", "Chrome", "Application", "chrome.exe"),
  path.join(process.env.LOCALAPPDATA || "", "Google", "Chrome", "Application", "chrome.exe"),
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
];

export function findBrowser() {
  if (typeof WebSocket !== "function") {
    throw new Error("浏览器运行时需要 Node.js >= 22(内置 WebSocket);当前 Node 版本不满足。");
  }
  for (const candidate of CANDIDATES()) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }
  throw new Error("找不到 Chrome/Edge。设置 FAIRY_BROWSER 指向浏览器可执行文件。");
}

export function browserAvailable() {
  try {
    return findBrowser();
  } catch {
    return null;
  }
}

class Connection {
  constructor(ws) {
    this.ws = ws;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Map();
    ws.onmessage = (event) => this._dispatch(JSON.parse(String(event.data)));
    ws.onclose = () => {
      for (const entry of this.pending.values()) {
        clearTimeout(entry.timer);
        entry.reject(new Error("CDP 连接已关闭"));
      }
      this.pending.clear();
    };
  }

  send(method, params = {}, sessionId) {
    const id = this.nextId++;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP 超时:${method}`));
      }, COMMAND_TIMEOUT);
      this.pending.set(id, { resolve, reject, timer });
      this.ws.send(JSON.stringify(payload));
    });
  }

  on(method, handler) {
    const set = this.listeners.get(method) || new Set();
    set.add(handler);
    this.listeners.set(method, set);
    return () => set.delete(handler);
  }

  _dispatch(message) {
    if (message.id && this.pending.has(message.id)) {
      const entry = this.pending.get(message.id);
      clearTimeout(entry.timer);
      this.pending.delete(message.id);
      if (message.error) entry.reject(new Error(message.error.message || "CDP 错误"));
      else entry.resolve(message.result);
      return;
    }
    if (message.method) {
      const set = this.listeners.get(message.method);
      if (set) for (const handler of [...set]) Promise.resolve(handler(message.params || {}, message.sessionId)).catch(() => {});
    }
  }
}

function waitForEvent(conn, method, sessionId, timeoutMs) {
  return new Promise((resolve) => {
    const off = conn.on(method, (params, sid) => {
      if (sessionId && sid && sid !== sessionId) return;
      clearTimeout(timer);
      off();
      resolve(params);
    });
    const timer = setTimeout(() => {
      off();
      resolve(null);
    }, timeoutMs);
  });
}

async function evaluate(conn, sessionId, expression) {
  const result = await conn.send(
    "Runtime.evaluate",
    { expression, returnByValue: true, awaitPromise: true },
    sessionId,
  );
  if (result.exceptionDetails) {
    throw new Error(`页面脚本异常:${result.exceptionDetails.text || "unknown"}`);
  }
  return result.result ? result.result.value : undefined;
}

function parseCookieHeader(header) {
  return String(header || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((pair) => {
      const at = pair.indexOf("=");
      if (at <= 0) return null;
      return { name: pair.slice(0, at).trim(), value: pair.slice(at + 1).trim() };
    })
    .filter(Boolean);
}

async function launch(projectDir) {
  const exe = findBrowser();
  const userDataDir = path.join(projectDir, ".fairy", "browser", `profile-${Date.now()}`);
  fs.mkdirSync(userDataDir, { recursive: true });

  const args = [
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-dev-shm-usage",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-extensions",
    "--mute-audio",
    "--hide-scrollbars",
    "--remote-allow-origins=*",
    "--window-size=1280,800",
    `--user-data-dir=${userDataDir}`,
    "--remote-debugging-port=0",
    "about:blank",
  ];

  const child = spawn(exe, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const wsUrl = await new Promise((resolve, reject) => {
    let buffer = "";
    let settled = false;
    const timer = setTimeout(() => {
      if (!settled) reject(new Error("浏览器启动超时(20s)"));
    }, 20_000);
    const onData = (chunk) => {
      buffer += chunk.toString();
      const match = /DevTools listening on (ws:\/\/\S+)/.exec(buffer);
      if (match && !settled) {
        settled = true;
        clearTimeout(timer);
        resolve(match[1]);
      }
    };
    child.stdout.on("data", onData);
    child.stderr.on("data", onData);
    child.on("exit", (code) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        reject(new Error(`浏览器进程退出(code=${code})`));
      }
    });
  });

  const ws = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error("CDP WebSocket 连接失败"));
  });
  const conn = new Connection(ws);

  const { targetId } = await conn.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await conn.send("Target.attachToTarget", { targetId, flatten: true });

  await conn.send("Page.enable", {}, sessionId);
  await conn.send("Runtime.enable", {}, sessionId);
  await conn.send("Network.enable", {}, sessionId);
  await conn.send("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] }, sessionId);
  await conn.send(
    "Emulation.setDeviceMetricsOverride",
    { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false },
    sessionId,
  );

  return {
    exe,
    ws,
    conn,
    sessionId,
    child,
    userDataDir,
    close: async () => {
      try {
        // Browser.close 在异常连接上可能永远不回;硬超时后直接杀进程。
        await Promise.race([conn.send("Browser.close"), delay(3000)]);
      } catch {
        // 已经关了就算了。
      }
      try {
        child.kill();
      } catch {
        // ignore
      }
      try {
        ws.close();
      } catch {
        // ignore
      }
      try {
        fs.rmSync(userDataDir, { recursive: true, force: true });
      } catch {
        // 用户数据目录可能仍被占用,留到下次清理。
      }
    },
  };
}

export async function browse(guard, options = {}) {
  const url = String(options.url || "");
  if (!url) throw new Error("需要 URL");
  await guard.authorize(url);

  const actions = Array.isArray(options.actions) ? options.actions : [];
  const waitMs = Number.isFinite(Number(options.waitMs)) ? Number(options.waitMs) : 800;
  const timeoutMs = Number.isFinite(Number(options.timeoutMs)) ? Number(options.timeoutMs) : 20_000;
  const wantScreenshot = options.screenshot !== false;
  const sessionName = options.session ? String(options.session) : null;
  const session = options.sessionHeaders || null;

  const browser = await launch(guard.projectDir);
  const { conn, sessionId } = browser;

  const network = new Map();
  const blocked = [];
  const consoleErrors = [];
  let gatedCount = 0;

  const continueRequest = async (requestId) => {
    try {
      await conn.send("Fetch.continueRequest", { requestId }, sessionId);
    } catch {
      // 请求可能已被页面取消。
    }
  };

  conn.on("Fetch.requestPaused", async (params, sid) => {
    const request = params.request || {};
    const requestUrl = request.url || "";
    const requestId = params.requestId;
    if (!/^https?:/i.test(requestUrl)) return continueRequest(requestId);
    if (!GATED_TYPES.has(params.resourceType)) return continueRequest(requestId);
    try {
      await guard.authorize(requestUrl);
      await guard.registerBrowserRequest(requestUrl, { method: request.method, resourceType: params.resourceType });
      gatedCount += 1;
      await conn.send("Fetch.continueRequest", { requestId }, sid);
    } catch (error) {
      blocked.push({
        url: redactUrl(requestUrl),
        method: request.method || "GET",
        resource_type: params.resourceType || null,
        reason: error.message,
      });
      guard.blockBrowserRequest(requestUrl, error, { method: request.method, resourceType: params.resourceType });
      try {
        await conn.send("Fetch.failRequest", { requestId, errorReason: "BlockedByClient" }, sid);
      } catch {
        // ignore
      }
    }
  });

  conn.on("Network.requestWillBeSent", (params) => {
    if (!params.request) return;
    network.set(params.requestId, {
      url: params.request.url,
      method: params.request.method,
      type: params.type || null,
      status: null,
      mime: null,
      failed: null,
    });
  });
  conn.on("Network.responseReceived", (params) => {
    const entry = network.get(params.requestId);
    if (!entry) return;
    entry.status = params.response.status;
    entry.mime = params.response.mimeType;
    entry.headers = params.response.headers || null;
  });
  conn.on("Network.loadingFailed", (params) => {
    const entry = network.get(params.requestId);
    if (entry) entry.failed = params.errorText || "failed";
  });
  conn.on("Runtime.exceptionThrown", (params) => {
    const text = params.exceptionDetails?.exception?.description || params.exceptionDetails?.text || "";
    if (text) consoleErrors.push(truncate(text, 300));
  });
  conn.on("Runtime.consoleAPICalled", (params) => {
    if (params.type !== "error") return;
    const text = (params.args || [])
      .map((arg) => arg.value ?? arg.description ?? "")
      .join(" ")
      .trim();
    if (text) consoleErrors.push(truncate(text, 300));
  });

  try {
    if (session) {
      for (const cookie of parseCookieHeader(session.cookie)) {
        try {
          await conn.send("Network.setCookie", { name: cookie.name, value: cookie.value, url, path: "/" }, sessionId);
        } catch {
          // 单个 Cookie 失败不影响整体。
        }
      }
      const extra = {};
      if (session.authorization) extra.Authorization = session.authorization;
      if (Object.keys(extra).length) {
        await conn.send("Network.setExtraHTTPHeaders", { headers: extra }, sessionId);
      }
    }

    const load = waitForEvent(conn, "Page.loadEventFired", sessionId, timeoutMs);
    const nav = await conn.send("Page.navigate", { url }, sessionId);
    if (nav && nav.errorText) throw new Error(`导航失败:${nav.errorText}`);
    await load;
    await delay(waitMs);

    for (const action of actions) {
      const type = String(action.type || "");
      if (type === "wait") {
        await delay(Math.min(10_000, Math.max(0, Number(action.ms) || 500)));
      } else if (type === "fill") {
        const expression = `(() => { const el = document.querySelector(${JSON.stringify(String(action.selector || ""))}); if (!el) return false; el.focus(); el.value = ${JSON.stringify(String(action.value ?? ""))}; el.dispatchEvent(new Event('input', { bubbles: true })); el.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`;
        const ok = await evaluate(conn, sessionId, expression);
        if (!ok) throw new Error(`fill 找不到元素:${action.selector}`);
        await delay(200);
      } else if (type === "click") {
        const expression = `(() => { const el = document.querySelector(${JSON.stringify(String(action.selector || ""))}); if (!el) return false; el.click(); return true; })()`;
        const ok = await evaluate(conn, sessionId, expression);
        if (!ok) throw new Error(`click 找不到元素:${action.selector}`);
        await delay(400);
      } else if (type === "eval") {
        await evaluate(conn, sessionId, String(action.expression || "undefined"));
        await delay(200);
      } else {
        throw new Error(`未知浏览器动作:${type}`);
      }
    }

    let capture = null;
    if (options.captureExpression) {
      capture = await evaluate(conn, sessionId, String(options.captureExpression));
    }

    const snapshot = await evaluate(
      conn,
      sessionId,
      `(() => {
        const links = [...document.querySelectorAll('a[href]')].slice(0, 150).map((a) => a.href);
        const forms = [...document.querySelectorAll('form')].slice(0, 40).map((form) => ({
          action: form.action,
          method: (form.method || 'GET').toUpperCase(),
          inputs: [...form.querySelectorAll('input,select,textarea')].map((i) => i.name).filter(Boolean)
        }));
        return {
          title: document.title,
          ready: document.readyState,
          href: location.href,
          text: (document.body ? document.body.innerText : '').slice(0, 4000),
          links,
          forms
        };
      })()`,
    );

    let screenshotPath = null;
    if (wantScreenshot) {
      const shot = await conn.send("Page.captureScreenshot", { format: "png" }, sessionId);
      if (shot && shot.data) {
        const dir = path.join(guard.projectDir, ".fairy", "browser", guard.runId);
        fs.mkdirSync(dir, { recursive: true });
        screenshotPath = path.join(dir, "page.png");
        fs.writeFileSync(screenshotPath, Buffer.from(shot.data, "base64"));
      }
    }

    const documents = [...network.values()].filter((entry) => entry.type === "Document");
    const main = documents.find((entry) => entry.url === snapshot?.href) || documents[documents.length - 1] || null;
    const xhr = [...network.values()]
      .filter((entry) => (entry.type === "XHR" || entry.type === "Fetch") && entry.url)
      .slice(0, 200)
      .map((entry) => ({
        method: entry.method,
        url: redactUrl(entry.url),
        status: entry.status,
        mime: entry.mime,
        failed: entry.failed,
      }));

    return {
      ok: true,
      url,
      final_url: snapshot?.href || url,
      status: main ? main.status : null,
      title: snapshot?.title || "",
      ready_state: snapshot?.ready || null,
      text_excerpt: snapshot?.text || "",
      links: snapshot?.links || [],
      forms: snapshot?.forms || [],
      xhr,
      console_errors: consoleErrors.slice(0, 50),
      blocked: blocked.slice(0, 50),
      capture,
      response_headers: main ? main.headers : null,
      counts: {
        network: network.size,
        gated: gatedCount,
        blocked: blocked.length,
        xhr: xhr.length,
      },
      screenshot_path: screenshotPath,
      session: sessionName,
      browser: path.basename(browser.exe),
      note: "Document/XHR/Fetch/WebSocket 在浏览器网络层过 scope;渲染子资源放行以便页面可渲染。默认不抓响应正文。",
    };
  } finally {
    await browser.close();
  }
}
