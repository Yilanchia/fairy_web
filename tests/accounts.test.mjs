import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { loadLedger, initLedger } from "../src/ledger.js";
import { listSessions } from "../src/session.js";
import {
  loadAccounts,
  provisionAccounts,
  showAccounts,
  bolaPairs,
} from "../src/accounts.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

process.env.FAIRY_ACCT_ALICE = "secret";
process.env.FAIRY_ACCT_BOB = "secret";
process.env.FAIRY_ACCT_ADMIN = "secret";

function setup(lab, methods = ["GET", "POST"]) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-accounts-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场账号编排测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, methods },
  });
  fs.mkdirSync(path.join(dir, ".fairy"), { recursive: true });
  const accounts = {
    schema: "FairyAccounts/v1",
    base_url: lab.url,
    accounts: [
      {
        name: "alice",
        role: "user",
        login: {
          url: `${lab.url}/login`,
          method: "POST",
          fields: { username: "alice" },
          password_env: "FAIRY_ACCT_ALICE",
        },
        owns: [{ marker: "ALICE-ORDER-7001", url: "/api/orders/7001", note: "alice 的订单" }],
      },
      {
        name: "bob",
        role: "user",
        login: {
          url: `${lab.url}/login`,
          method: "POST",
          fields: { username: "bob" },
          password_env: "FAIRY_ACCT_BOB",
        },
      },
      {
        name: "admin",
        role: "admin",
        login: {
          url: `${lab.url}/login`,
          method: "POST",
          fields: { username: "admin" },
          password_env: "FAIRY_ACCT_ADMIN",
        },
      },
    ],
  };
  fs.writeFileSync(path.join(dir, ".fairy", "accounts.json"), JSON.stringify(accounts, null, 2));
  initLedger(dir);
  return dir;
}

test("账号编排:批量登录成命名会话,账本记录账号与归属", async () => {
  const lab = await startLab();
  const dir = setup(lab);
  try {
    const out = await provisionAccounts(dir);
    assert.equal(out.provisioned.length, 3);
    assert.equal(out.failed.length, 0);
    assert.deepEqual(
      out.provisioned.map((item) => item.name).sort(),
      ["admin", "alice", "bob"],
    );

    const sessions = listSessions(dir).map((session) => session.name).sort();
    assert.deepEqual(sessions, ["admin", "alice", "bob"]);

    const ledger = loadLedger(dir);
    assert.equal(ledger.assets.filter((asset) => asset.type === "account").length, 3);
    assert.ok(ledger.facts.some((fact) => fact.statement.includes("alice 拥有对象 ALICE-ORDER-7001")));

    const shown = JSON.stringify(showAccounts(dir));
    assert.doesNotMatch(shown, /secret/);
    assert.doesNotMatch(shown, /sid=/);
    assert.doesNotMatch(shown, /cookie/i);
    assert.match(shown, /ALICE-ORDER-7001/);
  } finally {
    await lab.close();
  }
});

test("bolaPairs:从归属关系生成 owner→viewer 的 compare work", async () => {
  const lab = await startLab();
  const dir = setup(lab);
  try {
    const pairs = bolaPairs(loadAccounts(dir));
    assert.equal(pairs.length, 2, "alice 的对象应对 bob/admin 各生成一条对照");
    for (const pair of pairs) {
      assert.equal(pair.action, "compare");
      assert.equal(pair.args.session_a, "alice");
      assert.ok(["bob", "admin"].includes(pair.args.session_b));
      assert.equal(pair.args.marker, "ALICE-ORDER-7001");
      assert.equal(pair.args.url, `${lab.url}/api/orders/7001`);
    }
  } finally {
    await lab.close();
  }
});

test("账号编排:scope 未授权 POST 时拒绝登录", async () => {
  const lab = await startLab();
  const dir = setup(lab, ["GET"]);
  try {
    const out = await provisionAccounts(dir);
    assert.equal(out.provisioned.length, 0);
    assert.equal(out.failed.length, 3);
    assert.ok(out.failed.every((item) => /未授权 POST/.test(item.error)));
    assert.equal(listSessions(dir).length, 0);
  } finally {
    await lab.close();
  }
});

test("accounts:show 不暴露登录信息", async () => {
  const lab = await startLab();
  const dir = setup(lab);
  try {
    const shown = showAccounts(dir);
    assert.deepEqual(shown.accounts.map((item) => item.name).sort(), ["admin", "alice", "bob"]);
    assert.ok(shown.accounts.every((item) => item.session_ready === false));
    assert.ok(shown.accounts.every((item) => !("login" in item) && !("password" in item)));
    assert.equal(shown.bola_pairs.length, 2);
  } finally {
    await lab.close();
  }
});

test("MCP:fairy_accounts_provision / fairy_accounts_show 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  const names = list.result.tools.map((tool) => tool.name);
  assert.ok(names.includes("fairy_accounts_provision"));
  assert.ok(names.includes("fairy_accounts_show"));
});
