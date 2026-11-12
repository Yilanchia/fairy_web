import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { initLedger, loadLedger, saveLedger, addFinding } from "../src/ledger.js";
import { browserAvailable } from "../src/browser.js";
import { proofFinding, classifyProof } from "../src/proof.js";
import { writeLedgerReport } from "../src/evidence-report.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

const BROWSER = browserAvailable();
const browserTest = (name, fn) => test(name, { skip: BROWSER ? false : "未找到 Chrome/Edge" }, fn);

function setup(url) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-proof-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场证据深度测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  const { ledger } = initLedger(dir);
  const finding = addFinding(ledger, {
    title: "参数反射候选",
    kind: "reflection",
    severity: "medium",
    where: url,
    detail: "参数值反射进响应",
  }).finding;
  saveLedger(dir, ledger);
  return { dir, finding };
}

browserTest("proof:script 上下文 + 无 CSP → provable,confidence 升 high", async () => {
  const lab = await startLab();
  const { dir, finding } = setup(`GET ${lab.url}/dom?q=hello (param: q)`);
  try {
    const out = await proofFinding(dir, finding.id);
    assert.equal(out.status, "provable");
    assert.equal(out.provable, true);
    assert.equal(out.context.context, "script");
    assert.equal(out.csp_present, false);

    const ledger = loadLedger(dir);
    const updated = ledger.findings.find((item) => item.id === finding.id);
    assert.equal(updated.confidence, "high");
    assert.equal(updated.proof.status, "provable");
    assert.ok(updated.proof.fact_id);
    assert.ok(ledger.facts.some((fact) => fact.tags.includes("proof")));

    const summary = classifyProof(ledger);
    assert.equal(summary.counts.provable, 1);
    assert.equal(summary.items[0].finding_id, finding.id);

    const files = writeLedgerReport(dir);
    const markdown = fs.readFileSync(files.markdown, "utf8");
    assert.match(markdown, /## 证据深度/);
    assert.match(markdown, /可证:1/);
  } finally {
    await lab.close();
  }
});

browserTest("proof:文本上下文 → needs-review,不升级", async () => {
  const lab = await startLab();
  const { dir, finding } = setup(`GET ${lab.url}/dom-text?q=hello (param: q)`);
  try {
    const out = await proofFinding(dir, finding.id);
    assert.equal(out.status, "needs-review");
    assert.equal(out.provable, false);
    const updated = loadLedger(dir).findings.find((item) => item.id === finding.id);
    assert.equal(updated.confidence, "medium");
    assert.equal(updated.proof.status, "needs-review");
  } finally {
    await lab.close();
  }
});

test("MCP:fairy_proof 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_proof"));
});
