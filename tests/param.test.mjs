import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { runParamProbes } from "../src/probe.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-param-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场参数探测测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, ...limits },
  });
  return dir;
}

test("未开启 allow_active_probes 时拒绝参数探测", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => runParamProbes(guard, { urls: [`${lab.url}/sqli?q=1`], confirm: true }),
      /allow_active_probes/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("需要 confirm=true", async () => {
  const lab = await startLab();
  const dir = tmpProject({ allow_active_probes: true });
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => runParamProbes(guard, { urls: [`${lab.url}/sqli?q=1`] }),
      /confirm=true/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("错误型 SQL 注入:单引号触发数据库错误", async () => {
  const lab = await startLab();
  const dir = tmpProject({ allow_active_probes: true });
  const guard = new Guard(dir);
  try {
    const out = await runParamProbes(guard, {
      urls: [`${lab.url}/sqli?q=1`],
      confirm: true,
      classes: ["sqli"],
    });
    const finding = out.findings.find((item) => item.kind === "sqli");
    assert.ok(finding, "应命中 SQL 错误");
    assert.equal(finding.confidence, "high");
    assert.ok(finding.evidence.request_id);
    assert.match(finding.detail, /SQL/i);
    assert.ok(out.limitations.some((line) => line.includes("不")));
  } finally {
    guard.close();
    await lab.close();
  }
});

test("布尔差分:真/假条件响应显著不同", async () => {
  const lab = await startLab();
  const dir = tmpProject({ allow_active_probes: true });
  const guard = new Guard(dir);
  try {
    const out = await runParamProbes(guard, {
      urls: [`${lab.url}/boolean?q=1`],
      confirm: true,
      classes: ["sqli"],
    });
    const finding = out.findings.find((item) => item.kind === "sqli");
    assert.ok(finding, "应命中布尔差分");
    assert.equal(finding.confidence, "medium");
    assert.ok(finding.evidence.similarity.true > finding.evidence.similarity.false);
  } finally {
    guard.close();
    await lab.close();
  }
});

test("SSTI:{{7*7}} 被求值", async () => {
  const lab = await startLab();
  const dir = tmpProject({ allow_active_probes: true });
  const guard = new Guard(dir);
  try {
    const out = await runParamProbes(guard, {
      urls: [`${lab.url}/ssti?q=hello`],
      confirm: true,
      classes: ["ssti"],
    });
    const finding = out.findings.find((item) => item.kind === "ssti");
    assert.ok(finding, "应命中模板注入候选");
    assert.equal(finding.severity, "high");
    assert.ok(finding.owasp.includes("A03"));
  } finally {
    guard.close();
    await lab.close();
  }
});

test("正常反射参数不误报", async () => {
  const lab = await startLab();
  const dir = tmpProject({ allow_active_probes: true });
  const guard = new Guard(dir);
  try {
    const out = await runParamProbes(guard, {
      urls: [`${lab.url}/safe?q=hello`],
      confirm: true,
    });
    assert.equal(out.findings.length, 0);
  } finally {
    guard.close();
    await lab.close();
  }
});

test("MCP:web_param 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "web_param"));
});
