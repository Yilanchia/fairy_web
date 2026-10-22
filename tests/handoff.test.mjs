import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { detectArtifact } from "../src/artifacts.js";
import { handoffFile, fetchArtifact } from "../src/handoff.js";
import { scan } from "../src/scan.js";
import { loadLedger, initLedger, ingestScanReport } from "../src/ledger.js";
import { planChains } from "../src/playbooks.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-handoff-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场样本交接测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, ...limits },
  });
  return dir;
}

test("样本类型识别:ELF/PE/APK", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-magic-"));
  const elf = path.join(dir, "libx.so");
  fs.writeFileSync(elf, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]));
  assert.equal(detectArtifact(elf), "elf");

  const pe = path.join(dir, "tool.exe");
  fs.writeFileSync(pe, Buffer.from([0x4d, 0x5a, 0, 0, 0, 0, 0, 0]));
  assert.equal(detectArtifact(pe), "pe");

  const apk = path.join(dir, "app.apk");
  fs.writeFileSync(apk, Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0]));
  assert.equal(detectArtifact(apk), "android-apk");
});

test("本地样本交接:登记账本 + 给 Verdex 链", async () => {
  const dir = tmpProject();
  const file = path.join(dir, "libsample.so");
  fs.writeFileSync(file, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 0, 0, 0, 0]));

  const out = await handoffFile(dir, file);
  assert.equal(out.ok, true);
  assert.equal(out.artifact.kind, "elf");
  assert.match(out.artifact.sha256, /^[a-f0-9]{64}$/);
  assert.equal(out.verdex.next_tool, "mcp__verdex__analyze_target");
  assert.equal(out.verdex.chain[0].tool, "mcp__verdex__bin_info");
  assert.ok(Array.isArray(out.verdex.preflight));
  assert.ok(out.verdex.preflight.some((item) => item.tool === "mcp__verdex__bin_info"));
  assert.ok(Array.isArray(out.verdex.warnings));

  const ledger = loadLedger(dir);
  assert.ok(ledger.assets.some((asset) => asset.type === "artifact"));
  assert.ok(ledger.facts.some((fact) => (fact.tags || []).includes("artifact")));
  assert.ok(ledger.intents.some((intent) => intent.goal.includes("Verdex")));

  const chains = planChains(ledger);
  assert.ok(chains.some((chain) => chain.id === "binary-artifact" && chain.readiness === "ready"));
});

test("URL 样本:不 confirm 不下载;confirm 后落盘并交接", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => fetchArtifact(guard, { url: `${lab.url}/downloads/app.apk` }),
      /confirm=true/,
    );

    const out = await fetchArtifact(guard, { url: `${lab.url}/downloads/app.apk`, confirm: true });
    assert.equal(out.ok, true);
    assert.equal(out.artifact.kind, "android-apk");
    assert.equal(out.download.status, 200);
    assert.ok(fs.existsSync(out.download.saved_to));
    assert.ok(fs.statSync(out.download.saved_to).size > 0);
    assert.ok(out.verdex.chain.some((step) => step.tool === "mcp__verdex__mobile_unpack"));

    const ledger = loadLedger(dir);
    assert.ok(ledger.assets.some((asset) => asset.type === "artifact" && asset.tags.includes("url")));
  } finally {
    guard.close();
    await lab.close();
  }
});

test("扫描发现样本链接并入账", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    initLedger(dir);
    const result = await scan(dir, { urls: [`${lab.url}/`], active: false });
    const artifact = result.attack_surface.artifacts.find((item) => item.url.endsWith("/downloads/app.apk"));
    assert.ok(artifact, "应发现 app.apk 链接");
    assert.equal(artifact.kind, "android-apk");

    ingestScanReport(dir, result);
    const ledger = loadLedger(dir);
    assert.ok(ledger.facts.some((fact) => (fact.tags || []).includes("artifact")));
    assert.ok(planChains(ledger).some((chain) => chain.id === "binary-artifact"));
  } finally {
    await lab.close();
  }
});

test("MCP:fairy_handoff 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_handoff"));
});
