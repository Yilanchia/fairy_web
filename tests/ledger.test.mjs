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
  addFact,
  addFinding,
  addIntent,
  claimNextIntent,
  approveIntent,
  completeIntent,
  summary,
  ingestScanReport,
} from "../src/ledger.js";
import { planChains } from "../src/playbooks.js";
import { executeScan } from "../src/scan.js";
import { writeReport } from "../src/report.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-ledger-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场账本测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 50 },
  });
  return dir;
}

test("账本需要先有授权护照", () => {
  const bare = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-bare-"));
  assert.throws(() => initLedger(bare), /授权护照/);
});

test("资产/事实/发现去重并分配编号", () => {
  const dir = tmpProject();
  const { ledger } = initLedger(dir);
  const a1 = addAsset(ledger, { type: "host", value: "127.0.0.1:8080" });
  const a2 = addAsset(ledger, { type: "host", value: "127.0.0.1:8080" });
  assert.equal(a1.added, true);
  assert.equal(a2.added, false);
  assert.equal(a1.asset.id, "AS-001");

  const f1 = addFact(ledger, { statement: "站点使用 nginx", tags: ["tech"] });
  const f2 = addFact(ledger, { statement: "站点使用 nginx", tags: ["tech"] });
  assert.equal(f1.added, true);
  assert.equal(f2.added, false);

  const v1 = addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1:8080" });
  const v2 = addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1:8080" });
  assert.equal(v1.added, true);
  assert.equal(v2.added, false);
  assert.equal(v1.finding.id, "V-001");

  saveLedger(dir, ledger);
  const s = summary(loadLedger(dir));
  assert.equal(s.counts.assets, 1);
  assert.equal(s.counts.facts, 1);
  assert.equal(s.counts.findings, 1);
  assert.equal(s.findings.by_severity.high, 1);
});

test("意图依赖:只领取前置已完成的下一步", () => {
  const dir = tmpProject();
  const { ledger } = initLedger(dir);
  const i1 = addIntent(ledger, { goal: "枚举登录入口", risk: "low" });
  const i2 = addIntent(ledger, { goal: "验证 BOLA", depends_on: [i1.id], risk: "medium", requires_approval: true });
  const i3 = addIntent(ledger, { goal: "整理报告", depends_on: [i2.id] });

  const first = claimNextIntent(ledger);
  assert.equal(first.id, i1.id);
  assert.equal(first.status, "active");
  assert.equal(claimNextIntent(ledger), null, "I-002 的前置未完成,不应被领取");

  completeIntent(ledger, i1.id, { status: "done", note: "找到 /login" });
  assert.equal(claimNextIntent(ledger), null, "requires_approval 未批准时不应被领取");
  approveIntent(ledger, i2.id);
  const second = claimNextIntent(ledger);
  assert.equal(second.id, i2.id);

  completeIntent(ledger, i2.id, { status: "skipped", note: "无两个账号" });
  const third = claimNextIntent(ledger);
  assert.equal(third.id, i3.id);
  assert.equal(claimNextIntent(ledger), null);
});

test("攻击链:命中 CORS+凭证、BOLA、SSRF 的前置条件", () => {
  const dir = tmpProject();
  const { ledger } = initLedger(dir);
  addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1:8080" });
  addFinding(ledger, { title: "Cookie sid 缺少 HttpOnly", kind: "cookie", severity: "medium", where: "http://127.0.0.1:8080" });
  addAsset(ledger, { type: "param", value: "id" });
  addAsset(ledger, { type: "account", value: "test-a@example.test" });
  addFact(ledger, { statement: "已准备两个测试账号 A/B", tags: ["accounts"] });
  addFact(ledger, { statement: "canary 监听已就绪", tags: ["canary"] });

  const chains = planChains(ledger);
  const byId = new Map(chains.map((c) => [c.id, c]));
  assert.equal(byId.get("cors-credential-read")?.readiness, "ready");
  assert.equal(byId.get("idor-bola")?.readiness, "ready");
  assert.equal(byId.get("ssrf-canary")?.readiness, "ready");
  assert.ok(byId.get("cors-credential-read").stop.includes("即停"));
  assert.ok(byId.get("idor-bola").steps.some((s) => s.approval === true));
  assert.ok(chains.every((c) => c.steps.length > 0 && c.safety.length > 0));
});

test("导入扫描报告:资产/技术栈/候选发现/覆盖", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    initLedger(dir);
    const { result, traffic } = await executeScan(dir, { urls: [`${lab.url}/`, `${lab.url}/cors`, `${lab.url}/login`] });
    const files = writeReport(dir, { result, traffic });
    const report = JSON.parse(fs.readFileSync(files.json, "utf8"));

    const ingested = ingestScanReport(dir, report);
    assert.ok(ingested.added.assets >= 2);
    assert.ok(ingested.added.findings >= 3);

    const ledger = loadLedger(dir);
    assert.ok(ledger.assets.some((a) => a.type === "host"));
    assert.ok(ledger.facts.some((f) => (f.tags || []).includes("tech")));
    assert.equal(ledger.coverage.runs.length, 1);
    assert.equal(ledger.findings[0].status, "candidate");

    const chains = planChains(ledger);
    assert.ok(chains.some((c) => c.id === "cors-credential-read" && c.readiness === "ready"));
  } finally {
    await lab.close();
  }
});

test("MCP:账本与链规划工具已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  const names = list.result.tools.map((t) => t.name);
  for (const name of ["fairy_ledger_init", "fairy_ledger_show", "fairy_ledger_add", "fairy_ledger_advance", "fairy_chain_plan", "fairy_ledger_ingest"]) {
    assert.ok(names.includes(name), `缺少 ${name}`);
  }
});
