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
import { planChains } from "../src/playbooks.js";
import { materializeChain } from "../src/planner.js";
import { dispatch } from "../src/mcp.js";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-planner-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 planner 测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
  });
  return dir;
}

function seedCorsChain(dir) {
  const { ledger } = initLedger(dir);
  addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1:8080" });
  addFinding(ledger, { title: "Cookie sid 缺少 HttpOnly", kind: "cookie", severity: "medium", where: "http://127.0.0.1:8080" });
  addAsset(ledger, { type: "param", value: "id" });
  saveLedger(dir, ledger);
}

test("把 ready 链落成有依赖的意图序列,且幂等", () => {
  const dir = tmpProject();
  seedCorsChain(dir);

  const chain = planChains(loadLedger(dir)).find((item) => item.id === "cors-credential-read");
  assert.equal(chain.readiness, "ready");

  const first = materializeChain(dir, "cors-credential-read");
  assert.equal(first.existing, false);
  assert.equal(first.intents.length, chain.steps.length);
  assert.equal(first.intents[0].depends_on.length, 0);
  assert.deepEqual(first.intents[1].depends_on, [first.intents[0].id]);
  assert.equal(first.intents[0].chain_id, "cors-credential-read");
  assert.equal(first.intents[0].step_index, 1);
  assert.equal(first.intents[1].requires_approval, true);

  const again = materializeChain(dir, "cors-credential-read");
  assert.equal(again.existing, true);
  assert.deepEqual(
    again.intents.map((intent) => intent.id),
    first.intents.map((intent) => intent.id),
  );
});

test("worker 只能领取前置完成的下一步", () => {
  const dir = tmpProject();
  seedCorsChain(dir);
  const materialized = materializeChain(dir, "cors-credential-read");
  const ledger = loadLedger(dir);

  const first = claimNextIntent(ledger);
  assert.equal(first.id, materialized.intents[0].id);
  assert.equal(claimNextIntent(ledger), null, "第二步前置未完成,不应被领取");

  completeIntent(ledger, first.id, { status: "done", note: "步骤 1 完成" });
  assert.equal(claimNextIntent(ledger), null, "第二步需要审批");
  approveIntent(ledger, materialized.intents[1].id);
  const second = claimNextIntent(ledger);
  assert.equal(second.id, materialized.intents[1].id);
});

test("blocked 链拒绝落单", () => {
  const dir = tmpProject();
  seedCorsChain(dir);
  assert.throws(() => materializeChain(dir, "idor-bola"), /未就绪|缺少/);
});

test("MCP:fairy_chain_materialize 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_chain_materialize"));
});
