import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { login } from "../src/auth.js";
import { browse, browserAvailable } from "../src/browser.js";
import { loadSession } from "../src/session.js";
import { startLab } from "./fixture-server.mjs";

const BROWSER = browserAvailable();
const browserTest = (name, fn) => test(name, { skip: BROWSER ? false : "未找到 Chrome/Edge" }, fn);

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-browser-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场浏览器测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, ...limits },
  });
  return dir;
}

browserTest("无头浏览器渲染 SPA:标题/动态链接/XHR/截图", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const out = await browse(guard, { url: `${lab.url}/spa`, waitMs: 1200 });
    assert.equal(out.status, 200);
    assert.equal(out.title, "SPA Ready");
    assert.ok(out.links.some((link) => link.endsWith("/dynamic")), "应看到 JS 动态插入的链接");
    assert.ok(out.xhr.some((item) => item.url.includes("/api/data")), "应记录 XHR");
    assert.ok(out.screenshot_path && fs.existsSync(out.screenshot_path));
    assert.ok(fs.statSync(out.screenshot_path).size > 1000);
  } finally {
    guard.close();
    await lab.close();
  }
});

browserTest("会话注入:浏览器带登录态访问 /account", async () => {
  const lab = await startLab();
  const dir = tmpProject({ methods: ["GET", "HEAD", "OPTIONS", "POST"] });
  const loginGuard = new Guard(dir);
  try {
    await login(loginGuard, {
      url: `${lab.url}/login`,
      session: "alice",
      fields: { username: "alice", password: "secret" },
    });
  } finally {
    loginGuard.close();
  }

  const guard = new Guard(dir);
  try {
    const out = await browse(guard, {
      url: `${lab.url}/account`,
      session: "alice",
      sessionHeaders: loadSession(dir, "alice").headers,
      waitMs: 200,
    });
    assert.equal(out.status, 200);
    assert.match(out.text_excerpt, /alice account/);
  } finally {
    guard.close();
    await lab.close();
  }
});

browserTest("浏览器网络层 scope:页面 fetch 越界域名被阻断", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const out = await browse(guard, { url: `${lab.url}/fetch-out`, waitMs: 1200 });
    assert.equal(out.title, "Out");
    assert.ok(out.counts.blocked >= 1, "应阻断越界 fetch");
    assert.ok(out.blocked.some((item) => item.url.includes("example.invalid")));
  } finally {
    guard.close();
    await lab.close();
  }
});

browserTest("初始 URL 越界时不启动浏览器", async () => {
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    await assert.rejects(() => browse(guard, { url: "http://example.invalid/" }), /不在 scope/);
  } finally {
    guard.close();
  }
});
