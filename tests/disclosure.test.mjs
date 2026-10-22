import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { initLedger, loadLedger, saveLedger, addFinding } from "../src/ledger.js";
import { writeDisclosure } from "../src/disclosure.js";
import { dispatch } from "../src/mcp.js";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-disclose-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场披露测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
  });
  return dir;
}

test("没有 verified 发现时拒绝生成披露", () => {
  const dir = tmpProject();
  const { ledger } = initLedger(dir);
  addFinding(ledger, { title: "CORS 允许任意源", kind: "cors", severity: "high", where: "http://127.0.0.1" });
  saveLedger(dir, ledger);
  assert.throws(() => writeDisclosure(dir), /没有可披露的发现/);
});

test("披露文档只带分类/复现/修复,不带证据正文", () => {
  const dir = tmpProject();
  const { ledger } = initLedger(dir);
  const added = addFinding(ledger, {
    title: "CORS 允许任意源",
    kind: "cors",
    severity: "high",
    where: "http://127.0.0.1",
    impact: "跨站读取登录态数据",
    remediation: "按白名单返回 ACAO",
    evidence: [{ kind: "http", request_id: "R0007", snippet: "SECRET-TOKEN-DO-NOT-LEAK" }],
  });
  added.finding.status = "verified";
  added.finding.cvss = 8.1;
  added.finding.owasp = "A05:2021 Security Misconfiguration";
  added.finding.cwe = "CWE-942";
  added.finding.repro = ["重放 http://127.0.0.1", "回查 request_id=R0007"];
  saveLedger(dir, ledger);

  const out = writeDisclosure(dir);
  assert.ok(fs.existsSync(out.file));
  const text = fs.readFileSync(out.file, "utf8");
  assert.match(text, /CORS 允许任意源/);
  assert.match(text, /8\.1/);
  assert.match(text, /CWE-942/);
  assert.match(text, /按白名单返回 ACAO/);
  assert.ok(!text.includes("SECRET-TOKEN-DO-NOT-LEAK"), "披露文档不能带证据正文");
  assert.equal(out.stats.findings, 1);
});

test("MCP:fairy_disclose 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_disclose"));
});
