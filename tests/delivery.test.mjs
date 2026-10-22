import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { executeScan, scan } from "../src/scan.js";
import { writeReport } from "../src/report.js";
import { initLedger, loadLedger, ingestScanReport } from "../src/ledger.js";
import { replayHar } from "../src/replay.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-delivery-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场交付测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, ...limits },
  });
  return dir;
}

function writeHar(dir, lab) {
  const file = path.join(dir, "capture.har");
  const har = {
    log: {
      version: "1.2",
      entries: [
        {
          request: { method: "GET", url: `${lab.url}/`, headers: [] },
          response: { status: 200, headers: [{ name: "Content-Type", value: "text/html" }], content: { mimeType: "text/html", size: 400 } },
        },
        {
          request: { method: "GET", url: `${lab.url}/search?q=hello`, headers: [] },
          response: { status: 200, headers: [{ name: "Content-Type", value: "text/html" }], content: { mimeType: "text/html", size: 200 } },
        },
        {
          request: { method: "GET", url: `${lab.url}/admin`, headers: [] },
          response: { status: 403, headers: [{ name: "Content-Type", value: "text/html" }], content: { mimeType: "text/html", size: 30 } },
        },
        {
          request: {
            method: "POST",
            url: `${lab.url}/login`,
            headers: [{ name: "Content-Type", value: "application/x-www-form-urlencoded" }],
            postData: { text: "username=alice&password=secret" },
          },
          response: { status: 302, headers: [{ name: "Content-Type", value: "text/html" }], content: { mimeType: "text/html", size: 0 } },
        },
        {
          request: { method: "GET", url: "http://example.invalid/", headers: [] },
          response: { status: 200, headers: [], content: { mimeType: "text/html", size: 10 } },
        },
      ],
    },
  };
  fs.writeFileSync(file, JSON.stringify(har), "utf8");
  return file;
}

test("报告补 OWASP/CWE/CVSS/修复/复现", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const { result, traffic } = await executeScan(dir, {
      urls: [`${lab.url}/`, `${lab.url}/cors`, `${lab.url}/login`],
    });
    assert.ok(result.findings.length > 0);
    for (const finding of result.findings) {
      assert.ok(finding.owasp, `${finding.title} 缺 OWASP`);
      assert.ok(finding.cwe, `${finding.title} 缺 CWE`);
      assert.ok(Number.isFinite(finding.cvss), `${finding.title} 缺 CVSS`);
      assert.ok(finding.remediation, `${finding.title} 缺修复建议`);
      assert.ok(Array.isArray(finding.repro) && finding.repro.length >= 2);
    }

    const files = writeReport(dir, { result, traffic });
    const html = fs.readFileSync(files.html, "utf8");
    assert.match(html, /CVSS 估计/);
    assert.match(html, /修复/);
    assert.match(html, /复现/);
    const md = fs.readFileSync(files.markdown, "utf8");
    assert.match(md, /OWASP|CVSS/);

    initLedger(dir);
    ingestScanReport(dir, result);
    const ledger = loadLedger(dir);
    assert.ok(ledger.findings.every((finding) => finding.cvss !== null && finding.owasp));
  } finally {
    await lab.close();
  }
});

test("HAR 重放:默认只放只读,越界与写方法跳过", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const file = writeHar(dir, lab);
    const out = await replayHar(guard, { file, maxEntries: 10 });
    assert.equal(out.stats.replayed, 3);
    assert.equal(out.stats.skipped.write_blocked, 1);
    assert.equal(out.stats.skipped.out_of_scope, 1);
    assert.deepEqual(
      out.results.map((item) => item.replay.status).sort((a, b) => a - b),
      [200, 200, 403],
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("HAR 重放:scope 授权 POST 后可重放登录请求", async () => {
  const lab = await startLab();
  const dir = tmpProject({ methods: ["GET", "HEAD", "OPTIONS", "POST"] });
  const guard = new Guard(dir);
  try {
    const file = writeHar(dir, lab);
    const out = await replayHar(guard, { file, maxEntries: 10, allowWrite: true });
    assert.equal(out.stats.replayed, 4);
    const login = out.results.find((item) => item.method === "POST");
    assert.ok(login, "应重放 POST /login");
    assert.equal(login.original.status, 302);
    assert.equal(login.replay.status, 200);
    assert.equal(login.changed, true);
  } finally {
    guard.close();
    await lab.close();
  }
});

test("MCP:web_replay 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "web_replay"));
});
