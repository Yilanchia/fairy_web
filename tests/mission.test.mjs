import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { runMission } from "../src/mission.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-mission-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 mission 测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  return dir;
}

test("mission:扫描 → 报告 → 入账 → 链规划", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const out = await runMission(dir, {
      urls: [`${lab.url}/`, `${lab.url}/cors`],
    });
    assert.equal(out.schema, "FairyMission/v1");
    assert.equal(out.status, "completed");
    assert.deepEqual(
      out.phases.map((phase) => phase.name),
      ["scan", "report", "ledger", "plan"],
    );
    assert.ok(out.stats.requests > 0);
    assert.ok(out.report && fs.existsSync(out.report.html));
    assert.ok(out.ledger.added.assets >= 1);
    assert.ok(Array.isArray(out.next));
    assert.ok(fs.existsSync(out.path));
  } finally {
    await lab.close();
  }
});

test("mission:report=false 时只入账", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const out = await runMission(dir, {
      urls: [`${lab.url}/`],
      report: false,
    });
    assert.equal(out.report, null);
    assert.ok(out.phases.every((phase) => phase.name !== "report"));
    assert.ok(out.ledger.added.assets >= 1);
  } finally {
    await lab.close();
  }
});

test("MCP:fairy_mission 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_mission"));
});
