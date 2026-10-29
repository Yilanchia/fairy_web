import fs from "node:fs";
import readline from "node:readline";
import path from "node:path";
import { saveScope, loadScope, scopeSummary } from "./scope.js";
import { Guard } from "./guard.js";
import { crawl } from "./crawl.js";
import { ingestHar } from "./har.js";
import { executeScan, scan } from "./scan.js";
import { writeReport } from "./report.js";
import { login, compare } from "./auth.js";
import { browse } from "./browser.js";
import { replayHar } from "./replay.js";
import { handoffFile, fetchArtifact, suggestUrl } from "./handoff.js";
import { runParamProbes, runAdaptiveParamProbes } from "./probe.js";
import { analyzeWaf } from "./waf.js";
import { inspectDomContext } from "./domxss.js";
import { writeDisclosure } from "./disclosure.js";
import { runMission } from "./mission.js";
import {
  loadSession,
  saveSession,
  listSessions,
  describeSession,
  deleteSession,
} from "./session.js";
import {
  initLedger,
  loadLedger,
  appendLedger,
  addAsset,
  addFact,
  addFinding,
  addIntent,
  claimNextIntent,
  approveIntent,
  completeIntent,
  updateFinding,
  summary as ledgerSummary,
  ingestScanReport,
  sortFindings,
} from "./ledger.js";
import { planChains } from "./playbooks.js";
import { materializeChain } from "./planner.js";

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
    allow_active_probes: { type: "boolean" },
    allow_waf_probe: { type: "boolean" },
    verify_tls: { type: "boolean" },
    methods: { type: "array", items: { type: "string" } },
  },
};

function projectOf(args) {
  return path.resolve(String(args.project || process.env.FAIRY_PROJECT || defaultProject || process.cwd()));
}

function withSession(project, sessionName, headers = {}) {
  if (!sessionName) return headers;
  const session = loadSession(project, sessionName);
  return { ...session.headers, ...headers };
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
    name: "fairy_ledger_init",
    description:
      "建立作战账本(.fairy/ledger.json):资产/事实/发现/意图/覆盖。需要已有授权护照。账本是 engagement 级的,报告与审计都围绕它组织。",
    inputSchema: {
      type: "object",
      required: ["project"],
      properties: {
        project: { type: "string" },
        name: { type: "string", description: "engagement 名称,默认取目录名。" },
      },
    },
    run: async (args) => {
      const result = initLedger(projectOf(args), { name: args.name });
      return { ok: true, created: result.created, summary: ledgerSummary(result.ledger) };
    },
  },
  {
    name: "fairy_ledger_show",
    description:
      "查看账本。view=summary 给计数/覆盖/下一条意图(最省上下文);assets/facts/findings/intents/coverage 给对应明细。只读。",
    inputSchema: {
      type: "object",
      required: ["project"],
      properties: {
        project: { type: "string" },
        view: { type: "string", enum: ["summary", "assets", "facts", "findings", "intents", "coverage"] },
      },
    },
    run: async (args) => {
      const ledger = loadLedger(projectOf(args));
      const view = args.view || "summary";
      if (view === "summary") return { ok: true, summary: ledgerSummary(ledger) };
      if (view === "assets") return { ok: true, assets: ledger.assets.slice(0, 300) };
      if (view === "facts") return { ok: true, facts: ledger.facts.slice(-150) };
      if (view === "findings") return { ok: true, findings: sortFindings(ledger.findings).slice(0, 150) };
      if (view === "intents") return { ok: true, intents: ledger.intents };
      if (view === "coverage") {
        return {
          ok: true,
          coverage: ledger.coverage,
          tested_assets: ledger.assets.filter((a) => a.tested).slice(0, 200),
          untested_assets: ledger.assets.filter((a) => !a.tested).slice(0, 200),
        };
      }
      throw new Error(`未知 view:${view}`);
    },
  },
  {
    name: "fairy_ledger_add",
    description:
      "向账本追加记录。kind=asset{type,value,parent_id?,tags?} / fact{statement,confidence?,tags?,asset_ids?,evidence?} / finding{title,severity,kind,where,detail?,impact?,owasp?,cvss?,remediation?,evidence?} / intent{goal,depends_on?,asset_ids?,risk?,requires_approval?,stop_condition?}。自动去重并分配 AS/FT/V/I 编号。",
    inputSchema: {
      type: "object",
      required: ["project", "kind", "data"],
      properties: {
        project: { type: "string" },
        kind: { type: "string", enum: ["asset", "fact", "finding", "intent"] },
        data: { type: "object", description: "按 kind 的结构传字段。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const kind = String(args.kind || "");
      const data = args.data || {};
      const result = appendLedger(project, (ledger) => {
        if (kind === "asset") return addAsset(ledger, data);
        if (kind === "fact") return addFact(ledger, data);
        if (kind === "finding") return addFinding(ledger, data);
        if (kind === "intent") return addIntent(ledger, data);
        throw new Error(`未知 kind:${kind}`);
      });
      return { ok: true, kind, result, summary: ledgerSummary(loadLedger(project)) };
    },
  },
  {
    name: "fairy_ledger_advance",
    description:
      "推进账本。action=claim 领取下一条依赖已满足的意图;approve 批准 requires_approval 的意图;done/blocked/skipped 结单(需 intent_id,note 可写结论);finding-status 改发现状态(需 finding_id,status=candidate/verified/false-positive/remediated/accepted-risk,patch 可带 impact/remediation/cvss/owasp)。",
    inputSchema: {
      type: "object",
      required: ["project", "action"],
      properties: {
        project: { type: "string" },
        action: { type: "string", enum: ["claim", "approve", "done", "blocked", "skipped", "finding-status"] },
        intent_id: { type: "string" },
        finding_id: { type: "string" },
        status: { type: "string" },
        note: { type: "string" },
        patch: { type: "object" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const action = String(args.action || "");
      const result = appendLedger(project, (ledger) => {
        if (action === "claim") {
          const intent = claimNextIntent(ledger);
          return intent || { none: true, reason: "没有依赖已满足的 todo 意图" };
        }
        if (action === "approve") {
          if (!args.intent_id) throw new Error("需要 intent_id");
          return approveIntent(ledger, args.intent_id);
        }
        if (["done", "blocked", "skipped"].includes(action)) {
          if (!args.intent_id) throw new Error("需要 intent_id");
          return completeIntent(ledger, args.intent_id, { status: action, note: args.note });
        }
        if (action === "finding-status") {
          if (!args.finding_id) throw new Error("需要 finding_id");
          if (!args.status) throw new Error("需要 status");
          return updateFinding(ledger, args.finding_id, { ...(args.patch || {}), status: args.status });
        }
        throw new Error(`未知 action:${action}`);
      });
      return { ok: true, action, result, summary: ledgerSummary(loadLedger(project)) };
    },
  },
  {
    name: "fairy_disclose",
    description:
      "从作战账本生成披露文档(.fairy/disclosure.md):默认只取 status=verified 的发现,带 OWASP/CWE/CVSS/复现/修复,不带请求响应正文。",
    inputSchema: {
      type: "object",
      required: ["project"],
      properties: {
        project: { type: "string" },
        include_candidates: { type: "boolean", description: "是否把 candidate 也写进去;默认 false。" },
      },
    },
    run: async (args) => {
      const result = writeDisclosure(projectOf(args), {
        includeCandidates: args.include_candidates === true,
      });
      return { ok: true, file: result.file, stats: result.stats, markdown: result.markdown };
    },
  },
  {
    name: "fairy_handoff",
    description:
      "web ↔ binary 交接:本地样本(path)登记进账本并给出 Verdex 工具链;URL 需 confirm=true 才下载(单文件≤20MB、落 .fairy/artifacts、算 sha256),再交给智能体调 mcp__verdex__analyze_target。Fairy 不执行样本、不解析二进制。",
    inputSchema: {
      type: "object",
      required: ["project"],
      properties: {
        project: { type: "string" },
        path: { type: "string", description: "本地样本路径(已下载的 APK/ELF/PE/固件等)。" },
        url: { type: "string", description: "样本 URL;不带 confirm 时只给建议、不下载。" },
        confirm: { type: "boolean", description: "下载样本必须显式 true。" },
        max_bytes: { type: "number", description: "下载上限,默认/最高 20MB。" },
        note: { type: "string" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      if (args.path) return handoffFile(project, args.path, { note: args.note });
      if (args.url) {
        if (args.confirm === true) {
          const guard = new Guard(project);
          try {
            return await fetchArtifact(guard, { url: args.url, confirm: true, maxBytes: args.max_bytes });
          } finally {
            guard.close();
          }
        }
        return suggestUrl(project, args.url);
      }
      throw new Error("需要 path 或 url");
    },
  },
  {
    name: "fairy_chain_plan",
    description:
      "基于账本里的发现与事实匹配 web 攻击链知识库(CORS+凭证、开放重定向+OAuth、反射 XSS、Git 泄露、BOLA、SSRF、API 文档、SourceMap),输出 ready/blocked、每步的最小证明、风险、审批要求与停止点。只产计划,不发请求。",
    inputSchema: { type: "object", required: ["project"], properties: { project: { type: "string" } } },
    run: async (args) => {
      const project = projectOf(args);
      const ledger = loadLedger(project);
      const chains = planChains(ledger);
      return {
        ok: true,
        ready: chains.filter((c) => c.readiness === "ready").length,
        blocked: chains.filter((c) => c.readiness === "blocked").length,
        chains,
      };
    },
  },
  {
    name: "fairy_chain_materialize",
    description:
      "把一条 ready 攻击链落成有依赖的意图序列(步骤 1 → 2 → 3)。worker 只领取依赖已满足的下一步;重复调用幂等。blocked 链会被拒绝。",
    inputSchema: {
      type: "object",
      required: ["project", "chain_id"],
      properties: {
        project: { type: "string" },
        chain_id: { type: "string", description: "fairy_chain_plan 返回的 chain id。" },
        asset_ids: { type: "array", items: { type: "string" }, description: "可选:把意图锚定到账本资产。" },
      },
    },
    run: async (args) => {
      const result = materializeChain(projectOf(args), args.chain_id, {
        asset_ids: args.asset_ids || [],
      });
      return { ok: true, ...result };
    },
  },
  {
    name: "fairy_ledger_ingest",
    description:
      "把最近一次 web_scan/web_report 的 report.json 导入账本(资产/技术栈/候选发现/覆盖),让攻击链规划有素材。只读报告,写账本。",
    inputSchema: {
      type: "object",
      required: ["project"],
      properties: {
        project: { type: "string" },
        report_path: { type: "string", description: "可选:指定 report.json;默认取 .fairy/runs 下最新一次。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      let file = args.report_path ? path.resolve(String(args.report_path)) : null;
      if (!file) {
        const runsDir = path.join(project, ".fairy", "runs");
        if (!fs.existsSync(runsDir)) throw new Error("还没有报告可导入:先跑 web_report");
        const runs = fs
          .readdirSync(runsDir)
          .filter((name) => fs.existsSync(path.join(runsDir, name, "report.json")))
          .sort();
        if (!runs.length) throw new Error("还没有报告可导入:先跑 web_report");
        file = path.join(runsDir, runs[runs.length - 1], "report.json");
      }
      const report = JSON.parse(fs.readFileSync(file, "utf8"));
      const result = ingestScanReport(project, report);
      return { ok: true, report: file, ...result };
    },
  },
  {
    name: "fairy_mission",
    description:
      "一次有边界的任务:扫描 → 报告 → 入账 → 链规划,返回可执行的下一步。默认不登录、不跑参数探测、不跑 WAF 画像;主动步骤仍需单独授权。",
    inputSchema: {
      type: "object",
      required: ["project", "urls"],
      properties: {
        project: { type: "string" },
        urls: { type: "array", items: { type: "string" } },
        crawl: { type: "boolean" },
        session: { type: "string" },
        max_pages: { type: "number" },
        max_depth: { type: "number" },
        headers: HEADER_SCHEMA,
        report: { type: "boolean", description: "默认 true;false 时只入账不产报告。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      return runMission(project, {
        urls: args.urls,
        crawl: args.crawl === true,
        session: args.session || null,
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        headers: withSession(project, args.session, args.headers || {}),
        report: args.report !== false,
      });
    },
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
        session: { type: "string", description: "可选:已保存的会话名(web_login / web_session)。" },
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
          headers: withSession(project, args.session, args.headers || {}),
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
    name: "web_login",
    description:
      "对授权目标执行一次登录,把会话存成命名 profile(默认加密)。只尝试一次,不重试、不换字典、不爆破;登录是写操作,scope.limits.methods 必须显式包含 POST。凭据与会话值不会出现在输出里。",
    inputSchema: {
      type: "object",
      required: ["project", "url", "session", "fields"],
      properties: {
        project: { type: "string" },
        url: { type: "string", description: "登录页 URL(HTML 表单)或登录接口 URL。" },
        session: { type: "string", description: "会话名,如 alice / bob / admin。后续 web_scan/web_compare 用这个名字引用。" },
        fields: { type: "object", additionalProperties: { type: "string" }, description: "表单字段,如 {username:'alice',password:'...'};隐藏字段(CSRF)会自动带上。" },
        method: { type: "string", description: "默认按表单方法(通常是 POST),需在 scope.limits.methods 内。" },
        headers: HEADER_SCHEMA,
        json: { type: "boolean", description: "按 JSON 提交(前端 API 登录)。" },
        token_field: { type: "string", description: "若登录返回 JSON token,指定字段名(如 access_token),会存成 Authorization: Bearer。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        return await login(guard, {
          url: args.url,
          session: args.session,
          fields: args.fields,
          method: args.method,
          headers: args.headers || {},
          json: args.json === true,
          token_field: args.token_field,
        });
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_session",
    description:
      "管理命名会话 profile:list 列出、show 看元数据(只给头名,不给值)、create 手动塞 Cookie/Authorization、delete 删除。会话默认 AES-256-GCM(设 FAIRY_SESSION_KEY)或 0600 明文并带警告。",
    inputSchema: {
      type: "object",
      required: ["project", "action"],
      properties: {
        project: { type: "string" },
        action: { type: "string", enum: ["list", "show", "create", "delete"] },
        name: { type: "string" },
        headers: HEADER_SCHEMA,
        note: { type: "string" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const action = String(args.action || "list");
      if (action === "list") return { ok: true, sessions: listSessions(project) };
      if (action === "show") {
        if (!args.name) throw new Error("需要 name");
        return { ok: true, session: describeSession(project, args.name) };
      }
      if (action === "delete") {
        if (!args.name) throw new Error("需要 name");
        return { ok: true, ...deleteSession(project, args.name) };
      }
      if (action === "create") {
        if (!args.name) throw new Error("需要 name");
        const headers = args.headers || {};
        if (!Object.keys(headers).length) throw new Error("create 需要 headers(如 {Cookie:'sid=...'})");
        const saved = saveSession(project, args.name, { headers, note: args.note || "manual session" });
        return { ok: true, session: saved.name, enc: saved.enc, warning: saved.warning, header_names: Object.keys(headers) };
      }
      throw new Error(`未知 action:${action}`);
    },
  },
  {
    name: "web_compare",
    description:
      "用两个命名会话请求同一 URL 并做证据差分(BOLA/IDOR/BFLA):状态码、长度、正文哈希、相似度、标记命中。默认不回传正文。A 通常是资源所有者、B 是另一个账号;marker 是只在 A 对象里出现的唯一串。",
    inputSchema: {
      type: "object",
      required: ["project", "url", "session_a", "session_b"],
      properties: {
        project: { type: "string" },
        url: { type: "string" },
        session_a: { type: "string", description: "会话 A(资源所有者/参照)。" },
        session_b: { type: "string", description: "会话 B(另一个账号)。" },
        method: { type: "string", description: "默认 GET。" },
        marker: { type: "string", description: "只在 A 的对象里出现的唯一标记(如订单号/用户名)。" },
        headers: HEADER_SCHEMA,
        include_snippet: { type: "boolean", description: "是否附带 200 字正文片段;默认 false。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      if (!args.session_a || !args.session_b) throw new Error("需要 session_a 与 session_b");
      if (args.session_a === args.session_b) throw new Error("session_a 与 session_b 不能相同");
      const guard = new Guard(project, { useJar: false });
      try {
        return await compare(guard, {
          url: args.url,
          method: args.method,
          marker: args.marker,
          aHeaders: withSession(project, args.session_a, args.headers || {}),
          bHeaders: withSession(project, args.session_b, args.headers || {}),
          include_snippet: args.include_snippet === true,
        });
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_dom_context",
    description:
      "DOM 反射上下文判定:构造 fairy<hex> 标记,用无头浏览器看它落在 script / 事件属性 / 普通属性 / 文本 / 注释,并读 CSP。只判定,不生成 XSS 载荷、不执行证明。",
    inputSchema: {
      type: "object",
      required: ["project", "url", "param"],
      properties: {
        project: { type: "string" },
        url: { type: "string", description: "含该查询参数的页面 URL。" },
        param: { type: "string", description: "要判定上下文的查询参数名。" },
        session: { type: "string" },
        wait_ms: { type: "number" },
        screenshot: { type: "boolean" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        const session = args.session ? loadSession(project, args.session) : null;
        return await inspectDomContext(guard, {
          url: args.url,
          param: args.param,
          session: args.session || null,
          sessionHeaders: session ? session.headers : null,
          waitMs: args.wait_ms,
          screenshot: args.screenshot === true,
        });
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_waf",
    description:
      "WAF 行为分析:指纹识别、拦截状态、单/双 URL 编码、HTML 实体、JS Unicode 的规范化差异。需要 scope.limits.allow_waf_probe=true 且 confirm=true。只发带标记的语法形状,不生成利用载荷,不自动绕过。",
    inputSchema: {
      type: "object",
      required: ["project", "url", "param", "confirm"],
      properties: {
        project: { type: "string" },
        url: { type: "string" },
        param: { type: "string", description: "要分析的查询参数名。" },
        confirm: { type: "boolean", description: "必须 true:会发少量带标记的请求。" },
        session: { type: "string" },
        headers: HEADER_SCHEMA,
        max_probes: { type: "number", description: "最多探测数,默认 24,上限 60。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        return await analyzeWaf(guard, {
          url: args.url,
          param: args.param,
          confirm: args.confirm === true,
          headers: withSession(project, args.session, args.headers || {}),
          maxProbes: args.max_probes,
        });
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_param",
    description:
      "参数级主动探测(只判存在):SQL 错误签名/布尔差分、SSTI {{7*7}} 求值。必须 scope.limits.allow_active_probes=true 且 confirm=true。不做 UNION、堆叠、时间盲注、数据提取;每类证到即停。",
    inputSchema: {
      type: "object",
      required: ["project", "urls", "confirm"],
      properties: {
        project: { type: "string" },
        urls: { type: "array", items: { type: "string" } },
        confirm: { type: "boolean", description: "必须 true:会向目标发少量探测请求。" },
        classes: { type: "array", items: { type: "string", enum: ["sqli", "ssti"] } },
        session: { type: "string" },
        headers: HEADER_SCHEMA,
        max_params: { type: "number", description: "每个 URL 最多测多少参数,默认 20。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        return await runParamProbes(guard, {
          urls: args.urls,
          confirm: args.confirm === true,
          classes: args.classes,
          headers: withSession(project, args.session, args.headers || {}),
          maxParams: args.max_params,
        });
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_param_adaptive",
    description:
      "用 web_waf 生成的 WAF 画像,把通过验证的编码变体应用到 SQLi/SSTI 检测探针。需要 allow_active_probes + allow_waf_probe + confirm;只判存在,不取数据,不套真实攻击载荷。",
    inputSchema: {
      type: "object",
      required: ["project", "url", "param", "confirm"],
      properties: {
        project: { type: "string" },
        url: { type: "string" },
        param: { type: "string", description: "要探测的查询参数名(需与 web_waf 画像一致)。" },
        confirm: { type: "boolean" },
        classes: { type: "array", items: { type: "string", enum: ["sqli", "ssti"] } },
        session: { type: "string" },
        headers: HEADER_SCHEMA,
        max_transforms: { type: "number", description: "最多尝试多少个编码变体,默认 3。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        return await runAdaptiveParamProbes(guard, {
          url: args.url,
          param: args.param,
          confirm: args.confirm === true,
          classes: args.classes,
          headers: withSession(project, args.session, args.headers || {}),
          maxTransforms: args.max_transforms,
        });
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_replay",
    description:
      "把 HAR 里的请求按 scope 重放,做当时 vs 现在的状态/长度差分。默认只放 GET/HEAD;写方法需 scope 授权且 allow_write=true。HAR 里的 Cookie/Authorization 不沿用,认证态用 session 现取;不回传正文。",
    inputSchema: {
      type: "object",
      required: ["project", "path"],
      properties: {
        project: { type: "string" },
        path: { type: "string", description: "本地 HAR 文件。" },
        session: { type: "string", description: "可选:用已保存会话重放。" },
        headers: HEADER_SCHEMA,
        max_entries: { type: "number", description: "最多重放多少条,默认 50,上限 500。" },
        allow_write: { type: "boolean", description: "允许重放 POST/PUT 等写方法(仍需 scope 授权)。默认 false。" },
        replace: { type: "object", additionalProperties: { type: "string" }, description: "重放前替换 URL/body 里的字符串,如 {\"OLD_ID\":\"NEW_ID\"}。" },
        hosts: { type: "array", items: { type: "string" }, description: "只重放这些 host(可选;scope 仍强制)。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        return await replayHar(guard, {
          file: args.path,
          headers: withSession(project, args.session, args.headers || {}),
          maxEntries: args.max_entries,
          allowWrite: args.allow_write === true,
          replace: args.replace || {},
          hosts: args.hosts || [],
        });
      } finally {
        guard.close();
      }
    },
  },
  {
    name: "web_browser",
    description:
      "真实无头浏览器(本机 Chrome/Edge,CDP 零依赖):渲染 JS/SPA,采集标题/正文/链接/表单/XHR/控制台错误/截图。Document/XHR/Fetch/WebSocket 在浏览器网络层过 scope,越界请求直接阻断并记录;渲染子资源放行。可带 session 注入登录态,actions 支持 fill/click/eval/wait。默认不抓响应正文。",
    inputSchema: {
      type: "object",
      required: ["project", "url"],
      properties: {
        project: { type: "string" },
        url: { type: "string" },
        session: { type: "string", description: "可选:已保存的会话名,注入 Cookie/Authorization。" },
        actions: {
          type: "array",
          description: "页面动作序列:fill/click/wait/eval。",
          items: {
            type: "object",
            required: ["type"],
            properties: {
              type: { type: "string", enum: ["fill", "click", "wait", "eval"] },
              selector: { type: "string" },
              value: { type: "string" },
              expression: { type: "string" },
              ms: { type: "number" },
            },
          },
        },
        wait_ms: { type: "number", description: "load 后额外等待毫秒,默认 800。" },
        timeout_ms: { type: "number", description: "页面加载超时,默认 20000。" },
        screenshot: { type: "boolean", description: "是否截图,默认 true(只落本地 .fairy/browser)。" },
      },
    },
    run: async (args) => {
      const project = projectOf(args);
      const guard = new Guard(project);
      try {
        const session = args.session ? loadSession(project, args.session) : null;
        return await browse(guard, {
          url: args.url,
          session: args.session || null,
          sessionHeaders: session ? session.headers : null,
          actions: Array.isArray(args.actions) ? args.actions : [],
          waitMs: args.wait_ms,
          timeoutMs: args.timeout_ms,
          screenshot: args.screenshot !== false,
        });
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
        session: { type: "string", description: "可选:已保存的会话名(登录后爬取)。" },
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
          headers: withSession(project, args.session, args.headers || {}),
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
        session: { type: "string", description: "可选:已保存的会话名,用登录态扫描。" },
        headers: HEADER_SCHEMA,
        active: { type: "boolean", description: "默认 true;false 时只做被动检查(不发探测请求)。" },
      },
    },
    run: async (args) => {
      const urls = Array.isArray(args.urls) ? args.urls : [];
      if (!urls.length) throw new Error("urls 至少一个目标");
      const project = projectOf(args);
      return scan(project, {
        urls,
        crawl: args.crawl === true,
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        headers: withSession(project, args.session, args.headers || {}),
        auth_label: args.session || null,
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
        session: { type: "string", description: "可选:已保存的会话名,用登录态扫描。" },
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
        headers: withSession(project, args.session, args.headers || {}),
        auth_label: args.session || null,
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

const READ_ONLY = new Set(["fairy_scope_show", "har_ingest", "fairy_ledger_show", "fairy_chain_plan"]);
const CLOSED_WORLD = new Set([
  "fairy_scope_init",
  "fairy_scope_show",
  "har_ingest",
  "fairy_ledger_init",
  "fairy_ledger_show",
  "fairy_ledger_add",
  "fairy_ledger_advance",
  "fairy_chain_plan",
  "fairy_ledger_ingest",
  "fairy_chain_materialize",
  "web_session",
  "fairy_disclose",
]);

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
