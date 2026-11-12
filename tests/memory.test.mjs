import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { showMemory, rememberHost, rememberFromScan, memoryPath } from "../src/memory.js";
import { dispatch } from "../src/mcp.js";

process.env.FAIRY_MEMORY_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-memory-"));

test("memory:只存 host 元数据,忽略凭据字段", () => {
  rememberHost("https://Example.com:8443/path", {
    tech: ["nginx", "php"],
    waf: "cloudflare",
    login_paths: ["/auth/login"],
    reflecting_params: ["q"],
    prior_finding_kinds: ["cors"],
    cookie: "sid=secret",
    password: "secret",
    raw: "SHOULD_NOT_STORE",
  });

  const out = showMemory("example.com");
  assert.equal(out.data.tech.includes("nginx"), true);
  assert.equal(out.data.waf, "cloudflare");
  assert.equal(out.data.login_paths[0], "/auth/login");
  assert.equal("cookie" in out.data, false);
  assert.equal("password" in out.data, false);

  const text = fs.readFileSync(memoryPath(), "utf8");
  assert.doesNotMatch(text, /sid=secret/);
  assert.doesNotMatch(text, /SHOULD_NOT_STORE/);
  assert.doesNotMatch(text, /password/);
});

test("memory:scan 后记住 tech/login/reflection 参数", () => {
  rememberFromScan({
    pages: [
      {
        url: "https://app.example/login",
        requested_url: "https://app.example/login",
        tech: [{ tech: "nginx" }, { tech: "react" }],
      },
    ],
    findings: [
      {
        kind: "reflection",
        where: "GET https://app.example/search?q=x&lang=zh (param: q)",
      },
    ],
  });

  const out = showMemory("app.example");
  assert.equal(out.data.tech.includes("nginx"), true);
  assert.equal(out.data.tech.includes("react"), true);
  assert.deepEqual(out.data.login_paths, ["/login"]);
  assert.deepEqual(out.data.reflecting_params, ["q", "lang"]);
  assert.ok(out.data.prior_finding_kinds.includes("reflection"));

  const all = showMemory();
  assert.ok(all.hosts.some((host) => host.host === "app.example"));
});

test("MCP:fairy_memory_show 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_memory_show"));
});
