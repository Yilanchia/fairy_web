import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { analyzeWaf } from "../src/waf.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-waf-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 WAF 行为测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, ...limits },
  });
  return dir;
}

test("未开启 allow_waf_probe 时拒绝 WAF 分析", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => analyzeWaf(guard, { url: `${lab.url}/waf?q=hello`, param: "q", confirm: true }),
      /allow_waf_probe/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("需要 confirm=true", async () => {
  const lab = await startLab();
  const dir = tmpProject({ allow_waf_probe: true });
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => analyzeWaf(guard, { url: `${lab.url}/waf?q=hello`, param: "q" }),
      /confirm=true/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("识别拦截并测出编码规范化差异", async () => {
  const lab = await startLab();
  const dir = tmpProject({ allow_waf_probe: true });
  const guard = new Guard(dir);
  try {
    const out = await analyzeWaf(guard, {
      url: `${lab.url}/waf?q=hello`,
      param: "q",
      confirm: true,
    });

    assert.equal(out.schema, "FairyWaf/v1");
    assert.equal(out.waf.detected, true);
    assert.equal(out.verdict, "normalization-gap");

    const tag = out.shapes.find((shape) => shape.shape === "tag");
    assert.ok(tag, "应有 HTML 标签形状");
    assert.equal(tag.raw_blocked, true);
    assert.ok(tag.passed_transforms.includes("双重 URL 编码"), "双重编码应通过");
    assert.ok(tag.passed_transforms.length >= 1);

    assert.ok(out.matrix.every((row) => row.request_id || row.error));
    assert.ok(out.limitations.some((line) => line.includes("不生成利用载荷")));
    assert.ok(out.stop.includes("即停"));
  } finally {
    guard.close();
    await lab.close();
  }
});

test("MCP:web_waf 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "web_waf"));
});
