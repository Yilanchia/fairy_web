import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { initLedger, loadLedger } from "../src/ledger.js";
import { ingestPayload, ingestFile } from "../src/ingest.js";
import { writeLedgerReport } from "../src/evidence-report.js";
import { dispatch } from "../src/mcp.js";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-ingest-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场统一入账测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  initLedger(dir);
  return dir;
}

test("ingest:FairyParam 入账,保留 request_id 且幂等", () => {
  const dir = tmpProject();
  const payload = {
    schema: "FairyParam/v1",
    run_id: "param-test-1",
    targets: ["http://127.0.0.1:8080/sqli?q=1"],
    findings: [
      {
        id: "P-001",
        kind: "sqli",
        severity: "high",
        confidence: "high",
        title: "参数 q 触发 SQL 错误",
        where: "GET http://127.0.0.1:8080/sqli?q=1 (param: q)",
        detail: "命中 SQL 错误签名",
        evidence: { request_id: "R0002", status: 500, snippet: "SQL syntax" },
      },
    ],
  };

  const first = ingestPayload(dir, payload);
  assert.equal(first.added.findings, 1);
  const ledger = loadLedger(dir);
  const finding = ledger.findings.find((item) => item.title === "参数 q 触发 SQL 错误");
  assert.equal(finding.source, "web_param");
  assert.equal(finding.source_run_id, "param-test-1");
  assert.equal(finding.evidence[0].request_id, "R0002");

  const second = ingestPayload(dir, payload);
  assert.equal(second.skipped, true);
  assert.equal(loadLedger(dir).findings.length, 1);
});

test("ingest:Verdex findings 映射到 file:line 与 verdex 来源", () => {
  const dir = tmpProject();
  const payload = {
    schema: "VerdexScan/v1",
    run_id: "verdex-test-1",
    root: "D:\\samples\\app",
    findings: [
      {
        id: "F-001",
        title: "Hardcoded API key",
        severity: "high",
        category: "hardcoded-secret",
        file: "src/config.js",
        line: 12,
        description: "疑似硬编码密钥",
      },
    ],
  };

  const out = ingestPayload(dir, payload);
  assert.equal(out.added.findings, 1);
  const ledger = loadLedger(dir);
  const finding = ledger.findings.find((item) => item.title === "Hardcoded API key");
  assert.equal(finding.where, "src/config.js:12");
  assert.equal(finding.source, "verdex");
  assert.equal(finding.source_run_id, "verdex-test-1");
  assert.ok(ledger.facts.some((fact) => fact.statement.includes("Verdex 分析")));
});

test("ingest:WAF 结果入账为事实,不硬造漏洞", () => {
  const dir = tmpProject();
  const payload = {
    schema: "FairyWaf/v1",
    run_id: "waf-test-1",
    url: "http://127.0.0.1:8080/waf?q=x",
    param: "q",
    verdict: "normalization-gap",
    waf: { vendor: "generic" },
  };
  const out = ingestPayload(dir, payload);
  assert.equal(out.added.findings, 0);
  const ledger = loadLedger(dir);
  assert.ok(ledger.facts.some((fact) => fact.tags.includes("waf")));
});

test("bundle:跨工具证据报告包含所有来源", () => {
  const dir = tmpProject();
  ingestPayload(dir, {
    schema: "FairyParam/v1",
    run_id: "param-test-2",
    findings: [
      {
        id: "P-002",
        kind: "sqli",
        severity: "high",
        title: "SQLi 候选",
        where: "http://127.0.0.1:8080/sqli?q=1",
        evidence: { request_id: "R0003" },
      },
    ],
  });
  ingestPayload(dir, {
    schema: "VerdexScan/v1",
    run_id: "verdex-test-2",
    findings: [
      { id: "F-002", title: "硬编码密钥", severity: "medium", category: "secret", file: "src/a.js", line: 3 },
    ],
  });

  const files = writeLedgerReport(dir, { title: "测试证据总账" });
  assert.ok(fs.existsSync(files.json));
  assert.ok(fs.existsSync(files.markdown));
  assert.ok(fs.existsSync(files.html));
  const report = JSON.parse(fs.readFileSync(files.json, "utf8"));
  assert.equal(report.schema, "FairyBundleReport/v1");
  assert.ok(report.findings.some((finding) => finding.source === "verdex"));
  const markdown = fs.readFileSync(files.markdown, "utf8");
  assert.match(markdown, /SQLi 候选/);
  assert.match(markdown, /硬编码密钥/);
});

test("ingestFile:从本地 JSON 读取", () => {
  const dir = tmpProject();
  const file = path.join(dir, "verdex.json");
  fs.writeFileSync(file, JSON.stringify({ schema: "VerdexScan/v1", run_id: "vdx-file", findings: [] }));
  const out = ingestFile(dir, file);
  assert.equal(out.source, "verdex");
  assert.equal(out.skipped, false);
});

test("MCP:fairy_ingest / fairy_report_bundle 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  const names = list.result.tools.map((tool) => tool.name);
  assert.ok(names.includes("fairy_ingest"));
  assert.ok(names.includes("fairy_report_bundle"));
});
