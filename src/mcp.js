import readline from "node:readline";
import path from "node:path";
import { saveScope, loadScope, scopeSummary } from "./scope.js";
import { Guard } from "./guard.js";
import { crawl } from "./crawl.js";
import { ingestHar } from "./har.js";
import { executeScan, scan } from "./scan.js";
import { writeReport } from "./report.js";

const PROTOCOL_VERSION = "2024-11-05";
const SERVER_INFO = { name: "fairy", version: "0.1.0" };
let defaultProject = null;

const HEADER_SCHEMA = { type: "object", additionalProperties: { type: "string" }, description: "额外请求头(如 Cookie 做认证态测试);host/content-length 等被拒绝。" };

const LIMITS_SCHEMA = {
  type: "object",
  description: "限速与上限:rps / max_requests / timeout_ms / max_pages / max_active_pages / allow_private / verify_tls / methods",
  properties: {
    rps: { type: "number" },
    max_requests: { type: "number" },
    timeout_ms: { type: "number" },
    max_pages: { type: "number" },
    max_active_pages: { type: "number" },
    allow_private: { type: "boolean" },
    verify_tls: { type: "boolean" },
    methods: { type: "array", items: { type: "string" } },
  },
};

function projectOf(args) {
  return path.resolve(String(args.project || process.env.FAIRY_PROJECT || defaultProject || process.cwd()));
}

function summarizePages(pages) {
  return pages.map((p) => ({
    url: p.url,
    status: p.status,
    title: p.title,
    content_type: p.content_type,
    depth: p.depth,
    tech: (p.tech || []).map((t) => t.tech),
  }));
}

const TOOLS = [
  {
    name: "fairy_scope_init",
    description:
      "创建授权护照(scope)。必须先声明 include 与授权依据 basis,否则 Fairy 不会发任何请求。禁止单 * 与 *.com 这类顶级通配;支持域名/IP/CIDR/通配子域。默认只读方法、5 rps、2000 请求上限,全部落审计。",
    inputSchema: {
      type: "object",
      required: ["project", "include", "basis"],
      properties: {
        project: { type: "string", description: "作业目录:scope、审计与报告都落在这里。" },
        include: {
          type: "array",
          items: { type: "string" },
          description: "授权目标:主机/域名/IP/CIDR,如 127.0.0.1、*.lab.example.com、10.0.0.0/24。",
        },
        basis: { type: "string", description: "授权依据(≥8 字):自建靶场 / SRC 项目号 / 书面授权。" },
        operator: { type: "string", description: "操作者标识(写进报告与审计)。" },
        exclude: { type: "array", items: { type: "string" }, description: "排除项,优先级高于 include。" },
        limits: LIMITS_SCHEMA,
        expires_at: { type: "string", description: "授权到期时间(RFC3339);过期后拒绝启动。" },
      },
    },
    run: async (args) => {
      const saved = saveScope(projectOf(args), {
        schema: "FairyScope/v1",
        authorization: { basis: args.basis, operator: args.operator, expires_at: args.expires_at },
        include: args.include,
        exclude: args.exclude || [],
        limits: args.limits || {},
      });
      return { ok: true, scope_file: saved.path, scope: scopeSummary(saved.scope) };
    },
  },
  {
    name: "fairy_scope_show",
    description: "显示当前授权护照:依据、include/exclude、限速与上限。不发请求。",
    inputSchema: { type: "object", required: ["project"], properties: { project: { type: "string" } } },
    run: async (args) => ({ ok: true, scope: scopeSummary(loadScope(projectOf(args))) }),
  },
  {
    name: "web_probe",
    description:
      "在授权范围内发一次请求并回证据(状态/头/正文片段/重定向/TLS/request_id)。跟随重定向时每一跳都会重新校验 scope;跨 scope 的跳转会停下并记录。默认 GET/HEAD/OPTIONS,方法必须在 scope 授权内。",
    inputSchema: {
      type: "object",
      required: ["project", "url"],
      properties: {
        project: { type: "string" },
        url: { type: "string", description: "目标 URL(http/https)。" },
        method: { type: "string", description: "默认 GET;需在 scope.limits.methods 内。" },
        headers: HEADER_SCHEMA,
        body: { type: "string", description: "请求体(仅非 GET/HEAD 且方法已授权时使用)。" },
        follow_redirects: { type: "boolean", description: "默认 true;false 时只取第一跳。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        const page = await guard.request(args.url, {
          method: args.method || "GET",
          headers: args.headers || {},
          body: args.body,
          follow: args.follow_redirects !== false,
        });
        return {
          ok: true,
          request_id: page.request_id,
          url: page.url,
          status: page.status,
          status_text: page.status_text,
          content_type: page.content_type,
          headers: page.headers_obj,
          body_snippet: page.body.slice(0, 6000),
          body_bytes: page.body_bytes,
          timing_ms: page.timing_ms,
          redirects: page.redirects,
          next_location: page.next_location || null,
          tls: page.tls,
          audit_path: guard.auditPath,
        };
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_crawl",
    description:
      "从种子 URL 做同源爬取:标题/链接/表单/JS 内联端点/外链主机,给攻击面草图。遵守 scope 限速与页数上限,只发 GET。",
    inputSchema: {
      type: "object",
      required: ["project", "url"],
      properties: {
        project: { type: "string" },
        url: { type: "string", description: "种子 URL(必须在 scope 内)。" },
        max_pages: { type: "number", description: "最多抓取页数,默认取 scope.limits.max_pages。" },
        max_depth: { type: "number", description: "链接深度,默认 2。" },
        headers: HEADER_SCHEMA,
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        const result = await crawl(guard, args.url, {
          maxPages: args.max_pages,
          maxDepth: args.max_depth,
          headers: args.headers || {},
        });
        return {
          ok: true,
          seed: result.seed,
          pages: summarizePages(result.pages),
          endpoints: result.endpoints.slice(0, 200),
          forms: result.forms.slice(0, 100),
          external_hosts: result.external_hosts.slice(0, 50),
          errors: result.errors.slice(0, 50),
          requests: guard.count,
          audit_path: guard.auditPath,
        };
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_scan",
    description:
      "一轮证据优先的 web 检测:安全头/Cookie/CORS/反射/开放重定向/常见暴露面/TLS,按严重度输出候选并带 request_id。只发只读方法与无害标记;不注入载荷、不爆破、不 dump。发现均为待人工复核的候选。",
    inputSchema: {
      type: "object",
      required: ["project", "urls"],
      properties: {
        project: { type: "string" },
        urls: { type: "array", items: { type: "string" }, description: "目标 URL 列表(每个都必须在 scope 内)。" },
        crawl: { type: "boolean", description: "true 时先爬第一个 URL 再做检测。" },
        max_pages: { type: "number" },
        max_depth: { type: "number" },
        headers: HEADER_SCHEMA,
        active: { type: "boolean", description: "默认 true;false 时只做被动检查(不发探测请求)。" },
      },
    },
    run: async (args) => {
      const urls = Array.isArray(args.urls) ? args.urls : [];
      if (!urls.length) throw new Error("urls 至少一个目标");
      return scan(projectOf(args), {
        urls,
        crawl: args.crawl === true,
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        headers: args.headers || {},
        active: args.active !== false,
      });
    },
  },
  {
    name: "web_report",
    description:
      "跑一轮 web_scan 并把不可变快照写进 .fairy/runs/<run_id>/:report.json / report.md / 自包含 report.html / scope.json / traffic.har。traffic.har 已脱敏,可直接交给 Verdex har_analyze 做静态复核。",
    inputSchema: {
      type: "object",
      required: ["project", "urls"],
      properties: {
        project: { type: "string" },
        urls: { type: "array", items: { type: "string" } },
        crawl: { type: "boolean" },
        max_pages: { type: "number" },
        max_depth: { type: "number" },
        headers: HEADER_SCHEMA,
      },
    },
    run: async (args) => {
      const urls = Array.isArray(args.urls) ? args.urls : [];
      if (!urls.length) throw new Error("urls 至少一个目标");
      const project = projectOf(args);
      const { result, traffic } = await executeScan(project, {
        urls,
        crawl: args.crawl === true,
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        headers: args.headers || {},
      });
      const files = writeReport(project, { result, traffic });
      return {
        ok: true,
        run_id: result.run_id,
        stats: result.stats,
        findings: result.findings.map((f) => ({
          id: f.id,
          severity: f.severity,
          title: f.title,
          where: f.where,
        })),
        files,
      };
    },
  },
  {
    name: "har_ingest",
    description:
      "静态分析你导出的 HAR(Burp/DevTools):主机清单、端点清单(方法/参数/状态/是否带认证)、缺失安全头、Cookie 标志、CORS、URL 令牌、反射候选。不发请求;hosts 可帮你起草 scope,但不会自动授权。",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: { path: { type: "string", description: "本地 HAR 文件路径。" } },
    },
    run: async (args) => ingestHar(args.path),
  },
];

const READ_ONLY = new Set(["fairy_scope_show", "har_ingest"]);
const CLOSED_WORLD = new Set(["fairy_scope_init", "fairy_scope_show", "har_ingest"]);

function annotationsFor(name) {
  return {
    title: name,
    readOnlyHint: READ_ONLY.has(name),
    destructiveHint: false,
    idempotentHint: READ_ONLY.has(name),
    openWorldHint: !CLOSED_WORLD.has(name),
  };
}

const TOOL_MAP = new Map(TOOLS.map((tool) => [tool.name, tool]));

function ok(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function fail(id, code, message) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

async function callTool(id, params) {
  const tool = TOOL_MAP.get(params?.name);
  if (!tool) return fail(id, -32602, `未知工具:${params?.name}`);
  try {
    const output = await tool.run(params?.arguments || {});
    return ok(id, { content: [{ type: "text", text: JSON.stringify(output, null, 2) }] });
  } catch (error) {
    return ok(id, { isError: true, content: [{ type: "text", text: `Fairy 拒绝或失败:${error.message}` }] });
  }
}

export async function dispatch(message) {
  const { id, method, params } = message || {};
  if (method === "initialize") {
    return ok(id, {
      protocolVersion: params?.protocolVersion || PROTOCOL_VERSION,
      capabilities: { tools: {} },
      serverInfo: SERVER_INFO,
    });
  }
  if (method === "tools/list") {
    return ok(id, {
      tools: TOOLS.map(({ name, description, inputSchema }) => ({
        name,
        description,
        inputSchema,
        annotations: annotationsFor(name),
      })),
    });
  }
  if (method === "tools/call") return callTool(id, params);
  if (method === "ping") return ok(id, {});
  if (method === "notifications/initialized") return null;
  if (id !== undefined && id !== null) return fail(id, -32601, `不支持的方法:${method}`);
  return null;
}

export function startMcpServer(options = {}) {
  if (options.project) defaultProject = path.resolve(String(options.project));
  const rl = readline.createInterface({ input: process.stdin });
  rl.on("line", async (line) => {
    const text = line.trim();
    if (!text) return;
    let message;
    try {
      message = JSON.parse(text);
    } catch {
      process.stdout.write(`${JSON.stringify({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "解析错误:无效 JSON" } })}\n`);
      return;
    }
    const response = await dispatch(message);
    if (response) process.stdout.write(`${JSON.stringify(response)}\n`);
  });
  process.stderr.write(`fairy mcp server ready (stdio)${defaultProject ? ` project=${defaultProject}` : ""}\n`);
}
