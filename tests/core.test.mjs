import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { normalizeScope, saveScope, loadScope } from "../src/scope.js";
import { Guard } from "../src/guard.js";
import { crawl, parseHtml } from "../src/crawl.js";
import { scan } from "../src/scan.js";
import { executeScan } from "../src/scan.js";
import { writeReport } from "../src/report.js";
import { ingestHar } from "../src/har.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

function tmpProject(limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-"));
  saveScope(dir, {
    schema: "FairyScope/v1",
    authorization: { basis: "自建靶场(fixture)测试授权", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 50, ...limits },
  });
  return dir;
}

test("scope 拒绝过宽声明与缺失授权依据", () => {
  const base = { authorization: { basis: "自建靶场授权测试" } };
  assert.throws(() => normalizeScope({ ...base, include: ["*"] }), /非法或过宽/);
  assert.throws(() => normalizeScope({ ...base, include: ["*.com"] }), /非法或过宽/);
  assert.throws(() => normalizeScope({ include: ["127.0.0.1"] }), /basis/);
  assert.throws(() => normalizeScope({ authorization: { basis: "短" }, include: ["127.0.0.1"] }), /basis/);
  assert.throws(() => normalizeScope({ authorization: { basis: "自建靶场授权测试" }, include: [] }), /include/);
  const ok = normalizeScope({ authorization: { basis: "自建靶场授权测试" }, include: ["127.0.0.1", "*.lab.local"] });
  assert.equal(ok.limits.allow_private, true);
  assert.deepEqual(ok.limits.methods, ["GET", "HEAD", "OPTIONS"]);
});

test("scope 落盘后可读回,默认不放开内网", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-"));
  saveScope(dir, {
    authorization: { basis: "某 SRC 项目 #123 授权" },
    include: ["example.test"],
    exclude: ["admin.example.test"],
    limits: { allow_private: false, rps: 3 },
  });
  const loaded = loadScope(dir);
  assert.equal(loaded.include[0], "example.test");
  assert.equal(loaded.limits.allow_private, false);
  assert.equal(loaded.limits.rps, 3);
});

test("Guard 拒绝 scope 外目标且不发起连接", async () => {
  const dir = tmpProject();
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => guard.request("https://not-in-scope.example/"),
      (error) => error.code === "OUT_OF_SCOPE",
    );
  } finally {
    guard.close();
  }
});

test("Guard 拒绝云元数据地址与未放行的内网地址", async () => {
  const metaDir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-"));
  saveScope(metaDir, {
    authorization: { basis: "云元数据拦截单元测试" },
    include: ["169.254.169.254"],
    limits: { allow_private: true, rps: 50 },
  });
  const metaGuard = new Guard(metaDir);
  await assert.rejects(
    () => metaGuard.request("http://169.254.169.254/latest/meta-data/"),
    (error) => error.code === "BLOCKED_ADDRESS",
  );
  metaGuard.close();

  const privateDir = tmpProject({ allow_private: false });
  const privateGuard = new Guard(privateDir);
  await assert.rejects(
    () => privateGuard.request("http://127.0.0.1/"),
    (error) => error.code === "PRIVATE_ADDRESS",
  );
  privateGuard.close();
});

test("HTML 解析提取标题/链接/表单/资源", () => {
  const meta = parseHtml(
    '<title>T</title><a href="/x">x</a><form action="/f" method="post"><input name="a"></form><script src="/app.js"></script>',
    "http://127.0.0.1/",
  );
  assert.equal(meta.title, "T");
  assert.ok(meta.links.includes("http://127.0.0.1/x"));
  assert.ok(meta.assets.includes("http://127.0.0.1/app.js"));
  assert.equal(meta.forms[0].method, "POST");
  assert.deepEqual(meta.forms[0].inputs.map((i) => i.name), ["a"]);
});

test("对自建靶场跑一轮检测,命中预期类型并留审计", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const urls = [
      `${lab.url}/`,
      `${lab.url}/search?q=hello`,
      `${lab.url}/redirect?next=/home`,
      `${lab.url}/login`,
      `${lab.url}/cors`,
      `${lab.url}/api/data`,
    ];
    const result = await scan(dir, { urls });
    const kinds = new Set(result.findings.map((f) => f.kind));
    for (const kind of ["security-header", "cookie", "reflection", "open-redirect", "cors", "exposure"]) {
      assert.ok(kinds.has(kind), `缺少检测类型 ${kind},实际:${[...kinds].join(",")}`);
    }

    const cors = result.findings.find((f) => f.kind === "cors");
    assert.equal(cors.severity, "high");
    const git = result.findings.find((f) => f.kind === "exposure" && f.title.includes("Git"));
    assert.ok(git, "应命中 .git/HEAD 暴露");
    assert.equal(git.severity, "high");

    assert.ok(result.stats.requests > 10);
    assert.ok(fs.existsSync(result.audit_path));
    const lines = fs.readFileSync(result.audit_path, "utf8").trim().split("\n").filter(Boolean);
    assert.ok(lines.length >= result.stats.requests);
    assert.ok(lines.some((line) => line.includes(git.evidence.request_id)), "request_id 应能在审计日志回查");
    assert.ok(result.findings.every((f) => f.id && f.where));
  } finally {
    await lab.close();
  }
});

test("max_requests 生效:超过上限立即停止", async () => {
  const lab = await startLab();
  const dir = tmpProject({ max_requests: 3 });
  const guard = new Guard(dir);
  try {
    await assert.rejects(
      () => crawl(guard, `${lab.url}/`, { maxPages: 5 }),
      (error) => error.code === "REQUEST_LIMIT",
    );
  } finally {
    guard.close();
    await lab.close();
  }
});

test("HAR 静态分析:主机/端点/发现", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-"));
  const file = path.join(dir, "capture.har");
  const har = {
    log: {
      version: "1.2",
      entries: [
        {
          request: {
            method: "GET",
            url: "http://lab.example.test/api?token=abcdef123456",
            headers: [{ name: "Authorization", value: "Bearer secret" }],
          },
          response: {
            status: 200,
            headers: [
              { name: "Content-Type", value: "text/html" },
              { name: "Set-Cookie", value: "sid=abc; Path=/" },
              { name: "Access-Control-Allow-Origin", value: "*" },
            ],
            content: { mimeType: "text/html", text: "<html><body>hello</body></html>" },
          },
        },
        {
          request: { method: "POST", url: "https://lab.example.test/login", headers: [] },
          response: { status: 302, headers: [{ name: "Content-Type", value: "text/html" }], content: { text: "" } },
        },
      ],
    },
  };
  fs.writeFileSync(file, JSON.stringify(har), "utf8");
  const out = ingestHar(file);
  assert.equal(out.stats.entries, 2);
  assert.equal(out.stats.hosts, 1);
  assert.equal(out.hosts[0].host, "lab.example.test");
  const kinds = new Set(out.findings.map((f) => f.kind));
  for (const kind of ["transport", "cookie", "cors", "info-exposure"]) {
    assert.ok(kinds.has(kind), `HAR 缺少 ${kind}`);
  }
  assert.ok(out.endpoints.some((e) => e.path === "/api" && e.auth === true));
});

test("报告落盘:json/md/html/har 齐全", async () => {
  const lab = await startLab();
  const dir = tmpProject();
  try {
    const { result, traffic } = await executeScan(dir, { urls: [`${lab.url}/`, `${lab.url}/.git/HEAD`] });
    const files = writeReport(dir, { result, traffic });
    for (const file of [files.json, files.markdown, files.html, files.scope, files.har]) {
      assert.ok(file && fs.existsSync(file), `缺少产物 ${file}`);
    }
    const html = fs.readFileSync(files.html, "utf8");
    assert.match(html, /FAIRY/);
    assert.match(html, /授权记录/);
    const md = fs.readFileSync(files.markdown, "utf8");
    assert.match(md, /Fairy Web 证据报告/);
    const har = JSON.parse(fs.readFileSync(files.har, "utf8"));
    assert.equal(har.log.version, "1.2");
    assert.ok(har.log.entries.length > 0);
    assert.ok(har.log.entries.every((e) => e.request.headers.every((h) => !/cookie/i.test(h.name) || h.value === "<redacted>")));
  } finally {
    await lab.close();
  }
});

test("MCP:工具发现、scope 初始化、web_scan 端到端", async () => {
  const lab = await startLab();
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-"));
  try {
    const init = await dispatch({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
    assert.equal(init.result.serverInfo.name, "fairy");

    const list = await dispatch({ id: 2, method: "tools/list" });
    const names = list.result.tools.map((t) => t.name);
    assert.ok(names.includes("web_scan") && names.includes("fairy_scope_init") && names.includes("har_ingest"));

    const missing = await dispatch({
      id: 3,
      method: "tools/call",
      params: { name: "web_scan", arguments: { project: dir, urls: [`${lab.url}/`] } },
    });
    assert.equal(missing.result.isError, true);
    assert.match(missing.result.content[0].text, /授权护照/);

    const created = await dispatch({
      id: 4,
      method: "tools/call",
      params: {
        name: "fairy_scope_init",
        arguments: {
          project: dir,
          include: ["127.0.0.1"],
          basis: "自建靶场(MCP 测试)",
          limits: { rps: 50 },
        },
      },
    });
    assert.equal(created.result.isError, undefined);

    const scanned = await dispatch({
      id: 5,
      method: "tools/call",
      params: { name: "web_scan", arguments: { project: dir, urls: [`${lab.url}/`] } },
    });
    assert.equal(scanned.result.isError, undefined);
    const parsed = JSON.parse(scanned.result.content[0].text);
    assert.equal(parsed.schema, "FairyScan/v1");
    assert.ok(parsed.findings.length > 0);
    assert.ok(parsed.stats.requests > 0);
  } finally {
    await lab.close();
  }
});
