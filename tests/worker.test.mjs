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
} from "../src/ledger.js";
import { materializeChain } from "../src/planner.js";
import { runWorkerAction } from "../src/worker.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-worker-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 worker 测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  const { ledger } = initLedger(dir);
  addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1:8080" });
  addFinding(ledger, { title: "Cookie sid 缺少 HttpOnly", kind: "cookie", severity: "medium", where: "http://127.0.0.1:8080" });
  addAsset(ledger, { type: "param", value: "id" });
  saveLedger(dir, ledger);

  const materialized = materializeChain(dir, "cors-credential-read");
  const current = loadLedger(dir);
  const first = claimNextIntent(current);
  saveLedger(dir, current);
  return { dir, materialized, first };
}

test("worker 执行 active 意图,结果写回并结单", async () => {
  const lab = await startLab();
  const { dir, first } = setup();
  try {
    const out = await runWorkerAction(dir, {
      intentId: first.id,
      action: "probe",
      url: `${lab.url}/`,
    });
    assert.equal(out.ok, true);
    assert.equal(out.result.status, 200);
    assert.equal(out.intent.status, "done");
    assert.match(out.intent.result, /request_id=/);
    const ledger = loadLedger(dir);
    assert.equal(ledger.intents.find((intent) => intent.id === first.id).status, "done");
  } finally {
    await lab.close();
  }
});

test("worker 拒绝未审批的 requires_approval 意图", async () => {
  const lab = await startLab();
  const { dir, materialized } = setup();
  try {
    const ledger = loadLedger(dir);
    const second = ledger.intents.find((intent) => intent.id === materialized.intents[1].id);
    second.status = "active";
    saveLedger(dir, ledger);

    await assert.rejects(
      () =>
        runWorkerAction(dir, {
          intentId: second.id,
          action: "probe",
          url: `${lab.url}/`,
        }),
      /需要审批/,
    );
  } finally {
    await lab.close();
  }
});

test("worker 拒绝 todo 状态与非白名单动作", async () => {
  const lab = await startLab();
  const { dir, materialized, first } = setup();
  try {
    await assert.rejects(
      () =>
        runWorkerAction(dir, {
          intentId: materialized.intents[1].id,
          action: "probe",
          url: `${lab.url}/`,
        }),
      /先 claim/,
    );
    await assert.rejects(
      () =>
        runWorkerAction(dir, {
          intentId: first.id,
          action: "shell",
          url: `${lab.url}/`,
        }),
      /未知 worker 动作/,
    );
  } finally {
    await lab.close();
  }
});

test("MCP:fairy_worker_run 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_worker_run"));
});
