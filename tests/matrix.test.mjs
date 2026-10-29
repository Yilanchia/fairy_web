import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { saveSession } from "../src/session.js";
import { Guard } from "../src/guard.js";
import { runRoleMatrix } from "../src/matrix.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-matrix-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场权限矩阵测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  for (const name of ["alice", "bob", "admin"]) {
    saveSession(dir, name, { headers: { cookie: `sid=${name}` } });
  }
  return dir;
}

test("权限矩阵:识别角色差异与登录态差异,不读正文", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const out = await runRoleMatrix(guard, {
      urls: [`${lab.url}/account`, `${lab.url}/admin`, `${lab.url}/api/orders/1`],
      sessions: ["alice", "bob", "admin"],
    });

    assert.equal(out.schema, "FairyMatrix/v1");
    assert.deepEqual(out.identities, ["anonymous", "alice", "bob", "admin"]);
    assert.equal(out.matrix.length, 3);
    assert.equal(out.matrix[0].rows.length, 4);
    assert.ok(out.matrix.every((url) => url.rows.every((row) => !("body" in row))));

    const admin = out.matrix.find((url) => url.path === "/admin");
    assert.equal(admin.access, "role-restricted");
    assert.deepEqual(admin.allowed, ["admin"]);
    assert.deepEqual(admin.denied, ["alice", "bob"]);

    const account = out.matrix.find((url) => url.path === "/account");
    assert.equal(account.distinct_bodies, 3);

    assert.ok(out.findings.some((finding) => finding.kind === "authz"));
    assert.ok(out.findings.some((finding) => finding.kind === "data-diff"));
    assert.ok(out.findings.every((finding) => finding.owasp && finding.cwe));
    assert.ok(out.limitations.some((line) => line.includes("不执行横向")));
  } finally {
    guard.close();
    await lab.close();
  }
});

test("权限矩阵:匿名关闭时只跑账号", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const out = await runRoleMatrix(guard, {
      urls: [`${lab.url}/admin`],
      sessions: ["alice", "admin"],
      includeAnonymous: false,
    });
    assert.deepEqual(out.identities, ["alice", "admin"]);
    assert.equal(out.matrix[0].rows.length, 2);
    assert.equal(out.matrix[0].access, "role-restricted");
  } finally {
    guard.close();
    await lab.close();
  }
});

test("MCP:web_role_matrix 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "web_role_matrix"));
});
