import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { browserAvailable } from "../src/browser.js";
import { inspectDomContext } from "../src/domxss.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

const BROWSER = browserAvailable();
const browserTest = (name, fn) => test(name, { skip: BROWSER ? false : "未找到 Chrome/Edge" }, fn);

function tmpProject() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-dom-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场 DOM 上下文测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100 },
  });
  return dir;
}

browserTest("DOM 上下文:反射落在 script 文本", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const out = await inspectDomContext(guard, { url: `${lab.url}/dom?q=hello`, param: "q" });
    assert.equal(out.reflected, true);
    assert.equal(out.verdict, "candidate-script-context");
    assert.equal(out.context.context, "script");
    assert.equal(out.context.tag, "script");
    assert.equal(out.csp_present, false);
    assert.equal(out.risk, "high");
  } finally {
    guard.close();
    await lab.close();
  }
});

browserTest("DOM 上下文:反射落在 HTML 文本", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const out = await inspectDomContext(guard, { url: `${lab.url}/dom-text?q=hello`, param: "q" });
    assert.equal(out.reflected, true);
    assert.equal(out.verdict, "html-text");
    assert.equal(out.risk, "low");
  } finally {
    guard.close();
    await lab.close();
  }
});

browserTest("DOM 上下文:反射落在普通属性", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    const out = await inspectDomContext(guard, { url: `${lab.url}/dom-attr?q=hello`, param: "q" });
    assert.equal(out.reflected, true);
    assert.equal(out.verdict, "attribute-context");
    assert.equal(out.context.attr, "data-x");
  } finally {
    guard.close();
    await lab.close();
  }
});

test("MCP:web_dom_context 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "web_dom_context"));
});
