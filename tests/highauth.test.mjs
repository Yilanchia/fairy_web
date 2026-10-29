import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { saveSession } from "../src/session.js";
import { createHighAuth, verifyHighAuth, highAuthPath } from "../src/highauth.js";
import { Guard } from "../src/guard.js";
import { runReachability } from "../src/reachability.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

process.env.FAIRY_AUTH_KEY = "fairy-test-key-0123456789";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-highauth-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场最高授权测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  return dir;
}

test("最高授权:签名、资产清单、动作白名单", () => {
  const dir = tmpProject();
  const created = createHighAuth(dir, {
    basis: "自建靶场最高授权测试",
    approver: "fairy-test",
    assets: ["127.0.0.1"],
    hours: 1,
  });
  assert.equal(created.payload.tier, "highest");
  assert.ok(fs.existsSync(highAuthPath(dir)));

  const ok = verifyHighAuth(dir, { asset: "127.0.0.1", action: "read-only" });
  assert.equal(ok.ok, true);
  assert.equal(ok.tier, "highest");

  assert.throws(() => verifyHighAuth(dir, { asset: "example.com" }), /不在最高授权清单/);
  assert.throws(() => verifyHighAuth(dir, { action: "lateral" }), /不允许动作/);

  const record = JSON.parse(fs.readFileSync(highAuthPath(dir), "utf8"));
  record.signature = "00";
  fs.writeFileSync(highAuthPath(dir), JSON.stringify(record));
  assert.throws(() => verifyHighAuth(dir, { asset: "127.0.0.1" }), /签名不匹配/);
});

test("最高授权:没有文件时拒绝", () => {
  const dir = tmpProject();
  assert.throws(() => verifyHighAuth(dir, { asset: "127.0.0.1" }), /没有最高授权/);
});

test("reachability:最高授权下生成只读可达性图", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  for (const name of ["alice", "admin"]) {
    saveSession(dir, name, { headers: { cookie: `sid=${name}` } });
  }
  createHighAuth(dir, {
    basis: "自建靶场 reachability 测试",
    approver: "fairy-test",
    assets: ["127.0.0.1"],
    hours: 1,
  });

  const guard = new Guard(dir);
  try {
    const out = await runReachability(guard, {
      urls: [`${lab.url}/account`, `${lab.url}/admin`],
      sessions: ["alice", "admin"],
    });
    assert.equal(out.schema, "FairyReachability/v1");
    assert.equal(out.auth.tier, "highest");
    assert.ok(out.nodes.some((node) => node.id.startsWith("asset:127.0.0.1")));
    assert.ok(out.summary.role_restricted >= 1);
    assert.ok(out.role_restricted.some((item) => item.path === "/admin"));
    assert.ok(out.edges.every((edge) => edge.type !== "lateral"));
    assert.ok(out.findings.some((finding) => finding.kind === "authz"));
    assert.ok(out.limitations.some((line) => line.includes("不解锁横向执行")));
  } finally {
    guard.close();
    await lab.close();
  }
});

test("reachability:资产不在最高授权清单时拒绝", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  saveSession(dir, "alice", { headers: { cookie: "sid=alice" } });
  createHighAuth(dir, {
    basis: "自建靶场 reachability 测试",
    approver: "fairy-test",
    assets: ["example.com"],
    hours: 1,
  });
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => runReachability(guard, { urls: [`${lab.url}/account`], sessions: ["alice"] }),
      /不在最高授权清单/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("MCP:fairy_reachability 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_reachability"));
});
