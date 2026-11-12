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
  addAsset,
  addFinding,
} from "../src/ledger.js";
import { saveSession } from "../src/session.js";
import { deriveContext } from "../src/work.js";
import { materializeChain } from "../src/planner.js";
import { autoRun } from "../src/auto.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-work-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场账本派生 context 测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  const { ledger } = initLedger(dir);
  const host = addAsset(ledger, { type: "host", value: "127.0.0.1:8080" }).asset;
  addAsset(ledger, { type: "endpoint", value: "/item?id=1", parent_id: host.id });
  saveLedger(dir, ledger);
  saveSession(dir, "alice", { headers: { cookie: "sid=alice" } });
  saveSession(dir, "bob", { headers: { cookie: "sid=bob" } });
  return dir;
}

test("deriveContext:从 host/endpoint/session 派生 base_url/url/param/session", () => {
  const dir = tmpProject();
  const context = deriveContext(loadLedger(dir), { sessions: ["alice", "bob"] });
  assert.equal(context.base_url, "http://127.0.0.1:8080");
  assert.equal(context.url, "http://127.0.0.1:8080/item?id=1");
  assert.equal(context.param, "id");
  assert.equal(context.session_a, "alice");
  assert.equal(context.session_b, "bob");
});

test("deriveContext:显式 context 覆盖派生值", () => {
  const dir = tmpProject();
  const context = deriveContext(loadLedger(dir), {
    sessions: ["alice"],
    context: { base_url: "https://override.example", session_a: "custom" },
  });
  assert.equal(context.base_url, "https://override.example");
  assert.equal(context.session_a, "custom");
  assert.equal(context.session_b, undefined);
});

test("autoRun:不传 context 也能从账本派生并执行 git 链第一步", async () => {
  const lab = await startLab();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-work-auto-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场账本自走测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  const { ledger } = initLedger(dir);
  addAsset(ledger, { type: "host", value: new URL(lab.url).host });
  addFinding(ledger, {
    title: "Git 仓库暴露",
    kind: "exposure",
    severity: "high",
    where: `${lab.url}/.git/HEAD`,
  });
  saveLedger(dir, ledger);

  try {
    const out = await autoRun(dir, { maxSteps: 1 });
    assert.equal(out.steps.length, 1);
    assert.equal(out.steps[0].action, "probe");
    assert.equal(out.steps[0].status, "done");
    const ledger = loadLedger(dir);
    const first = ledger.intents.find((intent) => intent.chain_id === "git-source-leak" && intent.step_index === 1);
    assert.equal(first.status, "done");
    assert.ok(ledger.facts.some((fact) => fact.statement.includes("git 配置可读")));
  } finally {
    await lab.close();
  }
});

test("materializeChain:不传 context 也能从账本派生 git 链第一步", () => {
  const dir = tmpProject();
  const ledger = loadLedger(dir);
  addFinding(ledger, {
    title: "Git 仓库暴露",
    kind: "exposure",
    severity: "high",
    where: "http://127.0.0.1:8080/.git/HEAD",
  });
  saveLedger(dir, ledger);

  const materialized = materializeChain(dir, "git-source-leak");
  const first = materialized.intents[0];
  assert.equal(first.work.action, "probe");
  assert.equal(first.work.args.url, "http://127.0.0.1:8080/.git/config");
  assert.equal(first.work.inferred, true);
});
