import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { initLedger, loadLedger, saveLedger, addFinding } from "../src/ledger.js";
import { inferWork } from "../src/work.js";
import { autoRun } from "../src/auto.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(seed = true) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-infer-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 work 推断测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  if (seed) {
    const { ledger } = initLedger(dir);
    addFinding(ledger, {
      title: "Git 仓库暴露",
      kind: "exposure",
      severity: "high",
      where: "http://127.0.0.1:8080/.git/HEAD",
    });
    saveLedger(dir, ledger);
  }
  return dir;
}

test("inferWork:有 context 才推断,且只推断只读动作", () => {
  const git = inferWork("git-source-leak", 1, { base_url: "http://127.0.0.1:8080" });
  assert.equal(git.action, "probe");
  assert.equal(git.args.url, "http://127.0.0.1:8080/.git/config");
  assert.equal(git.inferred, true);

  const idor = inferWork("idor-bola", 2, {
    url: "http://127.0.0.1:8080/api/orders/2",
    session_a: "bob",
    session_b: "alice",
    marker: "BOB-ORDER-2",
  });
  assert.equal(idor.action, "compare");
  assert.equal(idor.args.session_a, "bob");
  assert.equal(idor.args.marker, "BOB-ORDER-2");

  const xss = inferWork("reflected-xss", 1, { url: "http://127.0.0.1:8080/search?q=x" });
  assert.equal(xss.action, "browser");

  assert.equal(inferWork("git-source-leak", 1, {}), null);
});

test("auto 用 context 推断 git 链第一步并执行", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const out = await autoRun(dir, {
      maxSteps: 2,
      context: { base_url: lab.url },
    });
    assert.equal(out.schema, "FairyAuto/v1");
    assert.equal(out.status, "approve");
    assert.equal(out.steps.length, 1);
    assert.equal(out.steps[0].action, "probe");
    assert.equal(out.steps[0].status, "done");

    const ledger = loadLedger(dir);
    const first = ledger.intents.find((intent) => intent.chain_id === "git-source-leak" && intent.step_index === 1);
    assert.equal(first.status, "done");
    assert.match(first.result, /probe/);
  } finally {
    await lab.close();
  }
});

test("没有 context 时不推断,停在 needs_action", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const out = await autoRun(dir, { maxSteps: 1 });
    assert.equal(out.status, "needs_action");
    assert.equal(out.steps.length, 0);
  } finally {
    await lab.close();
  }
});
