import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import {
  initLedger,
  loadLedger,
  saveLedger,
  addIntent,
  claimNextIntent,
} from "../src/ledger.js";
import { saveSession } from "../src/session.js";
import { runWorkerAction } from "../src/worker.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-facts-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 worker 事实回灌测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  initLedger(dir);
  return dir;
}

function activate(dir, goal) {
  const ledger = loadLedger(dir);
  const intent = addIntent(ledger, { goal, risk: "low" });
  const claimed = claimNextIntent(ledger);
  assert.equal(claimed.id, intent.id);
  saveLedger(dir, ledger);
  return claimed;
}

test("worker probe 200 后回灌 git 配置事实", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const intent = activate(dir, "检查 git 配置是否可读");
    const out = await runWorkerAction(dir, {
      intentId: intent.id,
      action: "probe",
      url: `${lab.url}/.git/config`,
    });
    assert.equal(out.facts, 1);
    const ledger = loadLedger(dir);
    assert.ok(ledger.facts.some((fact) => fact.statement.includes("git 配置可读")));
    assert.ok(ledger.facts.some((fact) => fact.tags.includes("git")));
  } finally {
    await lab.close();
  }
});

test("worker compare marker-in-both 后回灌越权事实,且重复执行幂等", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  saveSession(dir, "alice", { headers: { cookie: "sid=alice" } });
  saveSession(dir, "bob", { headers: { cookie: "sid=bob" } });
  try {
    const first = activate(dir, "对比 bob 的订单是否被 alice 读取");
    const out = await runWorkerAction(dir, {
      intentId: first.id,
      action: "compare",
      url: `${lab.url}/api/orders/2`,
      session_a: "bob",
      session_b: "alice",
      marker: "BOB-ORDER-2",
    });
    assert.equal(out.result.verdict, "marker-in-both");
    assert.equal(out.facts, 1);

    const second = activate(dir, "重复检查越权事实");
    await runWorkerAction(dir, {
      intentId: second.id,
      action: "compare",
      url: `${lab.url}/api/orders/2`,
      session_a: "bob",
      session_b: "alice",
      marker: "BOB-ORDER-2",
    });
    const ledger = loadLedger(dir);
    const facts = ledger.facts.filter((fact) => fact.statement.includes("标记在两账号均可见"));
    assert.equal(facts.length, 1, "同一观察不应重复生成 fact");
  } finally {
    await lab.close();
  }
});
