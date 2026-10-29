import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { analyzeWaf } from "../src/waf.js";
import { runAdaptiveParamProbes } from "../src/probe.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-adaptive-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场自适应探测测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, allow_active_probes: true, allow_waf_probe: true, ...limits },
  });
  return dir;
}

test("自适应探测需要 allow_active_probes + allow_waf_probe + confirm", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () =>
        runAdaptiveParamProbes(guard, {
          url: `${lab.url}/waf-sqli?q=hello`,
          param: "q",
        }),
      /confirm=true/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("没有 WAF 画像时拒绝自适应探测", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () =>
        runAdaptiveParamProbes(guard, {
          url: `${lab.url}/waf-sqli?q=hello`,
          param: "q",
          confirm: true,
        }),
      /没有 WAF 画像/,
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("WAF 画像 + 双重编码 → 命中只读 SQLi 探针", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const wafGuard = new Guard(dir);
  let profile;
  try {
    profile = await analyzeWaf(wafGuard, {
      url: `${lab.url}/waf-sqli?q=hello`,
      param: "q",
      confirm: true,
    });
  } finally {
    wafGuard.close();
  }

  assert.ok(profile.rules.recommended_transforms.includes("double"), "建议变体应包含 double");
  assert.ok(fs.existsSync(profile.profile_path));

  const guard = new Guard(dir);
  try {
    const out = await runAdaptiveParamProbes(guard, {
      url: `${lab.url}/waf-sqli?q=hello`,
      param: "q",
      confirm: true,
      classes: ["sqli"],
    });
    assert.equal(out.tool, "web_param_adaptive");
    assert.ok(out.transforms_tested.includes("double"));
    const finding = out.findings.find((item) => item.kind === "sqli");
    assert.ok(finding, "应命中 SQLi 探针");
    assert.equal(finding.evidence.transform, "double");
    assert.match(finding.where, /transform: double/);
    assert.ok(out.limitations.some((line) => line.includes("存在性检测")));
  } finally {
    guard.close();
    await lab.close();
  }
});

test("MCP:web_param_adaptive 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "web_param_adaptive"));
});
