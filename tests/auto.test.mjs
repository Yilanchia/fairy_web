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
} from "../src/ledger.js";
import { autoRun } from "../src/auto.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-auto-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 auto 测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  const { ledger } = initLedger(dir);
  addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1:8080" });
  addFinding(ledger, { title: "Cookie sid 缺少 HttpOnly", kind: "cookie", severity: "medium", where: "http://127.0.0.1:8080" });
  addAsset(ledger, { type: "param", value: "id" });
  saveLedger(dir, ledger);
  return dir;
}

test("auto:执行声明的 work,遇到审批门就停", async () => {
  const lab = await startLab();
  const dir = setup();
  try {
    const out = await autoRun(dir, {
      maxSteps: 2,
      work: [{ step: 1, action: "probe", args: { url: `${lab.url}/` } }],
    });
    assert.equal(out.schema, "FairyAuto/v1");
    assert.equal(out.status, "approve");
    assert.equal(out.steps.length, 1);
    assert.equal(out.steps[0].action, "probe");
    assert.equal(out.steps[0].status, "done");

    const ledger = loadLedger(dir);
    const first = ledger.intents.find((intent) => intent.chain_id === "cors-credential-read" && intent.step_index === 1);
    assert.equal(first.status, "done");
    assert.match(first.result, /request_id=/);
  } finally {
    await lab.close();
  }
});

test("auto:没有 work 时停在 needs_action", async () => {
  const lab = await startLab();
  const dir = setup();
  try {
    const out = await autoRun(dir, { maxSteps: 2 });
    assert.equal(out.status, "needs_action");
    assert.equal(out.steps.length, 0);
    assert.ok(out.intent);
    const ledger = loadLedger(dir);
    const active = ledger.intents.find((intent) => intent.id === out.intent.id);
    assert.equal(active.status, "active");
  } finally {
    await lab.close();
  }
});

test("auto:审批未过时不执行第二步", async () => {
  const lab = await startLab();
  const dir = setup();
  try {
    const out = await autoRun(dir, {
      maxSteps: 2,
      work: [
        { step: 1, action: "probe", args: { url: `${lab.url}/` } },
        { step: 2, action: "probe", args: { url: `${lab.url}/account` } },
      ],
    });
    assert.equal(out.status, "approve");
    assert.equal(out.steps.length, 1, "第二步需要审批,不应执行");
    assert.ok(out.tick.waiting_approval.length >= 1);
  } finally {
    await lab.close();
  }
});

test("MCP:fairy_auto_run 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_auto_run"));
});
