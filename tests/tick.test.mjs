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
  addFinding,
  addAsset,
  claimNextIntent,
  approveIntent,
  completeIntent,
} from "../src/ledger.js";
import { plannerTick } from "../src/planner.js";
import { dispatch } from "../src/mcp.js";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-tick-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 planner tick 测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
  });
  const { ledger } = initLedger(dir);
  addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1:8080" });
  addFinding(ledger, { title: "Cookie sid 缺少 HttpOnly", kind: "cookie", severity: "medium", where: "http://127.0.0.1:8080" });
  addAsset(ledger, { type: "param", value: "id" });
  saveLedger(dir, ledger);
  return dir;
}

test("tick:先提示落单,落单后给出下一条意图", () => {
  const dir = tmpProject();

  const before = plannerTick(dir);
  assert.equal(before.schema, "FairyPlanner/v1");
  assert.ok(before.ready_chains.some((chain) => chain.id === "cors-credential-read"));
  assert.ok(before.unmaterialized_chains.includes("cors-credential-read"));
  assert.equal(before.next_intent, null);
  assert.equal(before.recommendation, "materialize");

  const after = plannerTick(dir, { materialize: true });
  assert.equal(after.materialized.length, 1);
  assert.ok(after.next_intent);
  assert.equal(after.recommendation, "claim_next");
});

test("tick:需要审批时先提示 approve,批准后给出下一步", () => {
  const dir = tmpProject();
  const materialized = plannerTick(dir, { materialize: true });
  const firstId = materialized.next_intent.id;

  const ledger = loadLedger(dir);
  const first = claimNextIntent(ledger);
  assert.equal(first.id, firstId);
  completeIntent(ledger, firstId, { status: "done", note: "步骤 1" });
  saveLedger(dir, ledger);

  const waiting = plannerTick(dir);
  assert.equal(waiting.next_intent, null);
  assert.equal(waiting.recommendation, "approve");
  assert.ok(waiting.waiting_approval.length >= 1);

  const secondId = waiting.waiting_approval[0].id;
  const current = loadLedger(dir);
  approveIntent(current, secondId);
  saveLedger(dir, current);

  const ready = plannerTick(dir);
  assert.equal(ready.next_intent.id, secondId);
  assert.equal(ready.recommendation, "claim_next");
});

test("tick:materialize 幂等", () => {
  const dir = tmpProject();
  plannerTick(dir, { materialize: true });
  const again = plannerTick(dir, { materialize: true });
  assert.equal(again.materialized.length, 0);
  assert.ok(again.next_intent);
});

test("MCP:fairy_planner_tick 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_planner_tick"));
});
