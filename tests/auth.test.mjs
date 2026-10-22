import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { login, compare } from "../src/auth.js";
import { saveSession, loadSession, listSessions, describeSession } from "../src/session.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-auth-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场认证态测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 50, ...limits },
  });
  return dir;
}

test("会话加密落盘:list/show/文件都不回显值", () => {
  const dir = tmpProject();
  process.env.FAIRY_SESSION_KEY = "test-key-123456";
  try {
    const saved = saveSession(dir, "alice", {
      headers: { cookie: "sid=alice-secret", authorization: "Bearer TOPSECRET" },
    });
    assert.equal(saved.enc, "aes-256-gcm");
    const raw = fs.readFileSync(saved.path, "utf8");
    assert.ok(!raw.includes("alice-secret"));
    assert.ok(!raw.includes("TOPSECRET"));

    const loaded = loadSession(dir, "alice");
    assert.equal(loaded.headers.cookie, "sid=alice-secret");
    assert.equal(loaded.headers.authorization, "Bearer TOPSECRET");

    const shown = describeSession(dir, "alice");
    assert.deepEqual(shown.header_names.sort(), ["authorization", "cookie"]);
    assert.ok(!JSON.stringify(shown).includes("alice-secret"));
    assert.ok(!JSON.stringify(listSessions(dir)).includes("alice-secret"));
  } finally {
    delete process.env.FAIRY_SESSION_KEY;
  }
});

test("登录只尝试一次,拿到会话后可带登录态访问", async () => {
  const lab = await startLab();
  const dir = tmpProject({ methods: ["GET", "HEAD", "OPTIONS", "POST"] });
  const guard = new Guard(dir);
  try {
    const out = await login(guard, {
      url: `${lab.url}/login`,
      session: "alice",
      fields: { username: "alice", password: "secret" },
    });
    assert.equal(out.ok, true);
    assert.equal(out.attempts, 1);
    assert.equal(out.enc, "none");
    assert.ok(!JSON.stringify(out).includes("secret"), "输出不能带密码");

    const session = loadSession(dir, "alice");
    assert.match(session.headers.cookie, /sid=alice/);

    const page = await guard.request(`${lab.url}/account`, { headers: session.headers });
    assert.equal(page.status, 200);
    assert.match(page.body, /alice account/);
  } finally {
    guard.close();
    await lab.close();
  }
});

test("scope 未授权 POST 时拒绝登录", async () => {
  const lab = await startLab();
  const dir = tmpProject(); // 默认只有 GET/HEAD/OPTIONS
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () =>
        login(guard, {
          url: `${lab.url}/login`,
          session: "alice",
          fields: { username: "alice", password: "secret" },
        }),
      /未授权 POST/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("双会话差分:B 能读到 A 的对象 → BOLA 候选", async () => {
  const lab = await startLab();
  const dir = tmpProject({ methods: ["GET", "HEAD", "OPTIONS", "POST"] });
  const loginGuard = new Guard(dir);
  try {
    await login(loginGuard, {
      url: `${lab.url}/login`,
      session: "bob",
      fields: { username: "bob", password: "secret" },
    });
    await login(loginGuard, {
      url: `${lab.url}/login`,
      session: "alice",
      fields: { username: "alice", password: "secret" },
    });
  } finally {
    loginGuard.close();
  }

  const compareGuard = new Guard(dir, { useJar: false });
  try {
    const out = await compare(compareGuard, {
      url: `${lab.url}/api/orders/2`,
      aHeaders: loadSession(dir, "bob").headers,
      bHeaders: loadSession(dir, "alice").headers,
      marker: "BOB-ORDER-2",
    });
    assert.equal(out.verdict, "marker-in-both");
    assert.equal(out.diff.marker_in_b, true);
    assert.equal(out.snippets, null);
    assert.ok(out.a.request_id && out.b.request_id);
    assert.ok(out.interpretation.includes("水平越权"));
  } finally {
    compareGuard.close();
    await lab.close();
  }
});

test("双会话差分:正常鉴权阻断 → status-diff", async () => {
  const lab = await startLab();
  const dir = tmpProject({ methods: ["GET", "HEAD", "OPTIONS", "POST"] });
  const loginGuard = new Guard(dir);
  try {
    await login(loginGuard, {
      url: `${lab.url}/login`,
      session: "alice",
      fields: { username: "alice", password: "secret" },
    });
    await login(loginGuard, {
      url: `${lab.url}/login`,
      session: "bob",
      fields: { username: "bob", password: "secret" },
    });
  } finally {
    loginGuard.close();
  }

  const compareGuard = new Guard(dir, { useJar: false });
  try {
    const out = await compare(compareGuard, {
      url: `${lab.url}/api/orders/1`,
      aHeaders: loadSession(dir, "alice").headers,
      bHeaders: loadSession(dir, "bob").headers,
      marker: "ALICE-ORDER-1",
    });
    assert.equal(out.verdict, "marker-only-in-a");
    assert.equal(out.a.status, 200);
    assert.equal(out.b.status, 403);
  } finally {
    compareGuard.close();
    await lab.close();
  }
});

test("MCP:认证态工具已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  const names = list.result.tools.map((t) => t.name);
  for (const name of ["web_login", "web_session", "web_compare"]) {
    assert.ok(names.includes(name), `缺少 ${name}`);
  }
});
