#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { saveScope, loadScope, scopeSummary, SCOPE_FILE } from "./scope.js";
import { Guard } from "./guard.js";
import { crawl, probeUrls } from "./crawl.js";
import { ingestHar } from "./har.js";
import { executeScan, scan } from "./scan.js";
import { writeReport } from "./report.js";
import { login, compare } from "./auth.js";
import { browse } from "./browser.js";
import { replayHar } from "./replay.js";
import { handoffFile, fetchArtifact } from "./handoff.js";
import { runParamProbes, runAdaptiveParamProbes } from "./probe.js";
import { analyzeWaf } from "./waf.js";
import { inspectDomContext } from "./domxss.js";
import { writeDisclosure } from "./disclosure.js";
import { runMission } from "./mission.js";
import { materializeChain, plannerTick } from "./planner.js";
import { runWorkerAction } from "./worker.js";
import { autoRun } from "./auto.js";
import { loadSession, saveSession, listSessions, describeSession, deleteSession } from "./session.js";
import { startMcpServer } from "./mcp.js";

const HELP = `Fairy Web — 授权范围内的 web 侦察/检测手

用法:
  node src/cli.js init   <project> --include <a,b> --basis "<授权依据>" [--operator 名字] [--rps 5] [--max 2000]
  node src/cli.js show   <project>
  node src/cli.js probe  <project> <url> [--method GET] [--header "K: V"] [--cookie "..." ]
  node src/cli.js crawl  <project> <url> [--pages 40] [--depth 2]
  node src/cli.js scan   <project> <url...> [--crawl] [--pages 40] [--depth 2] [--session alice]
  node src/cli.js report <project> <url...> [--crawl] [--pages 40] [--session alice]
  node src/cli.js mission <project> <url...> [--crawl] [--pages 40] [--session alice] [--no-report]
  node src/cli.js browser <project> <url> [--session alice] [--screenshot false] [--eval "..."] [--click "sel"] [--fill "sel=value"]
  node src/cli.js login  <project> <url> --session alice --data "username=alice&password=..."
  node src/cli.js session <project> list|show|delete|create [name] [--header "Cookie: ..."]
  node src/cli.js compare <project> <url> --a alice --b bob [--marker "ALICE-ORDER-1"]
  node src/cli.js dom    <project> <url> --param q [--session alice]
  node src/cli.js waf    <project> <url> --param q --confirm [--session alice]
  node src/cli.js param  <project> <url...> --confirm [--classes sqli,ssti] [--max-params 20] [--session alice]
  node src/cli.js param-adaptive <project> <url> --param q --confirm [--classes sqli,ssti] [--session alice]
  node src/cli.js tick <project> [--materialize] [--max 1]
  node src/cli.js auto <project> [--max 3] [--work work.json]
  node src/cli.js materialize <project> <chain_id>
  node src/cli.js worker <project> <intent_id> --action probe --url <url> [--session alice] [--a alice --b bob --marker X]
  node src/cli.js disclose <project> [--include-candidates]
  node src/cli.js handoff <project> <path|url> [--confirm] [--max-bytes 20000000]
  node src/cli.js replay <project> <file.har> [--max 50] [--allow-write] [--session alice] [--replace "OLD=NEW"]
  node src/cli.js har    <project> <file.har>
  node src/cli.js mcp    [--project <dir>]

原则:没有 ${SCOPE_FILE} 不发请求;只读方法;每条请求写审计;发现敏感数据即停。
`;

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const eq = token.indexOf("=");
      let key;
      let value;
      if (eq > 0) {
        key = token.slice(2, eq);
        value = token.slice(eq + 1);
      } else {
        key = token.slice(2);
        const next = argv[i + 1];
        value = next !== undefined && !next.startsWith("--") ? argv[++i] : true;
      }
      if (out[key] === undefined) out[key] = value;
      else if (Array.isArray(out[key])) out[key].push(value);
      else out[key] = [out[key], value];
    } else {
      out._.push(token);
    }
  }
  return out;
}

function headersOf(args) {
  const headers = {};
  const raw = args.header === undefined ? [] : Array.isArray(args.header) ? args.header : [args.header];
  for (const line of raw) {
    const at = String(line).indexOf(":");
    if (at <= 0) throw new Error(`--header 需要 "Name: Value" 形式:${line}`);
    headers[String(line).slice(0, at).trim()] = String(line).slice(at + 1).trim();
  }
  if (args.cookie) headers.cookie = String(args.cookie);
  return headers;
}

function sessionHeaders(project, name, headers) {
  if (!name) return headers;
  return { ...loadSession(project, name).headers, ...headers };
}

function boolOption(value, fallback = false) {
  if (value === undefined) return fallback;
  if (value === true) return true;
  return String(value).toLowerCase() !== "false";
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

const command = process.argv[2] || "help";
const args = parseArgs(process.argv.slice(3));

try {
  if (command === "mcp") {
    startMcpServer({ project: args.project });
  } else if (command === "help" || command === "--help") {
    process.stdout.write(HELP);
  } else if (command === "init") {
    const project = path.resolve(args._[0] || process.cwd());
    const include = String(args.include || "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
    if (!include.length) throw new Error('init 需要 --include,例如 --include "127.0.0.1,*.lab.local"');
    const limits = {};
    if (args.rps !== undefined) limits.rps = Number(args.rps);
    if (args.max !== undefined) limits.max_requests = Number(args.max);
    if (args.pages !== undefined) limits.max_pages = Number(args.pages);
    if (args.methods !== undefined) limits.methods = String(args.methods).split(",").map((s) => s.trim());
    if (args["allow-private"] !== undefined) limits.allow_private = boolOption(args["allow-private"]);
    if (args["allow-active-probes"] !== undefined) {
      limits.allow_active_probes = boolOption(args["allow-active-probes"]);
    }
    if (args["allow-waf-probe"] !== undefined) {
      limits.allow_waf_probe = boolOption(args["allow-waf-probe"]);
    }
    const saved = saveScope(project, {
      schema: "FairyScope/v1",
      authorization: {
        basis: args.basis,
        operator: args.operator,
        expires_at: args.expires,
        note: args.note,
      },
      include,
      exclude: String(args.exclude || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      limits,
    });
    print({ ok: true, scope_file: saved.path, scope: scopeSummary(saved.scope) });
  } else if (command === "show") {
    const project = path.resolve(args._[0] || process.cwd());
    print({ ok: true, scope: scopeSummary(loadScope(project)) });
  } else if (command === "probe") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url) throw new Error("probe 需要 URL");
    const guard = new Guard(project);
    try {
      const page = await guard.request(url, {
        method: args.method || "GET",
        headers: headersOf(args),
        follow: boolOption(args.follow, true),
      });
      print({
        ok: true,
        request_id: page.request_id,
        url: page.url,
        status: page.status,
        status_text: page.status_text,
        content_type: page.content_type,
        headers: page.headers_obj,
        body_snippet: page.body.slice(0, 8000),
        body_bytes: page.body_bytes,
        timing_ms: page.timing_ms,
        redirects: page.redirects,
        next_location: page.next_location || null,
        tls: page.tls,
        audit_path: guard.auditPath,
      });
    } finally {
      guard.close();
    }
  } else if (command === "crawl") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url) throw new Error("crawl 需要种子 URL");
    const guard = new Guard(project);
    try {
      const result = await crawl(guard, url, {
        maxPages: args.pages,
        maxDepth: args.depth,
        headers: headersOf(args),
      });
      print({
        ok: true,
        seed: result.seed,
        pages: result.pages.map((p) => ({
          url: p.url,
          status: p.status,
          title: p.title,
          content_type: p.content_type,
          depth: p.depth,
          body_bytes: p.body_bytes,
        })),
        endpoints: result.endpoints.slice(0, 200),
        forms: result.forms.slice(0, 100),
        external_hosts: result.external_hosts.slice(0, 50),
        errors: result.errors,
        requests: guard.count,
        audit_path: guard.auditPath,
      });
    } finally {
      guard.close();
    }
  } else if (command === "scan") {
    const project = path.resolve(args._[0] || process.cwd());
    const urls = args._.slice(1);
    if (!urls.length) throw new Error("scan 需要至少一个 URL");
    const result = await scan(project, {
      urls,
      crawl: boolOption(args.crawl, false),
      max_pages: args.pages,
      max_depth: args.depth,
      headers: sessionHeaders(project, args.session, headersOf(args)),
      auth_label: args.session || null,
      active: !args["no-active"],
    });
    print(result);
  } else if (command === "mission") {
    const project = path.resolve(args._[0] || process.cwd());
    const urls = args._.slice(1);
    if (!urls.length) throw new Error("mission 需要至少一个 URL");
    print(
      await runMission(project, {
        urls,
        crawl: boolOption(args.crawl, false),
        session: args.session || null,
        max_pages: args.pages,
        max_depth: args.depth,
        headers: sessionHeaders(project, args.session, headersOf(args)),
        report: !args["no-report"],
      }),
    );
  } else if (command === "report") {
    const project = path.resolve(args._[0] || process.cwd());
    const urls = args._.slice(1);
    if (!urls.length) throw new Error("report 需要至少一个 URL");
    const { result, traffic } = await executeScan(project, {
      urls,
      crawl: boolOption(args.crawl, false),
      max_pages: args.pages,
      max_depth: args.depth,
      headers: sessionHeaders(project, args.session, headersOf(args)),
      auth_label: args.session || null,
    });
    const files = writeReport(project, { result, traffic });
    print({
      ok: true,
      run_id: result.run_id,
      stats: result.stats,
      findings: result.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, where: f.where })),
      files,
    });
  } else if (command === "browser") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url) throw new Error("browser 需要 URL");
    const actions = [];
    if (args.eval) actions.push({ type: "eval", expression: String(args.eval) });
    if (args.click) actions.push({ type: "click", selector: String(args.click) });
    if (args.fill) {
      const text = String(args.fill);
      const at = text.indexOf("=");
      if (at <= 0) throw new Error('--fill 需要 "selector=value" 形式');
      actions.push({ type: "fill", selector: text.slice(0, at), value: text.slice(at + 1) });
    }
    if (args.wait) actions.push({ type: "wait", ms: Number(args.wait) });
    const guard = new Guard(project);
    try {
      const session = args.session ? loadSession(project, args.session) : null;
      print(
        await browse(guard, {
          url,
          session: args.session || null,
          sessionHeaders: session ? session.headers : null,
          actions,
          waitMs: args["wait-ms"],
          screenshot: boolOption(args.screenshot, true),
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "login") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url) throw new Error("login 需要登录页 URL");
    if (!args.session) throw new Error("login 需要 --session 名字");
    const fields = {};
    for (const [key, value] of new URLSearchParams(String(args.data || ""))) fields[key] = value;
    const guard = new Guard(project);
    try {
      print(
        await login(guard, {
          url,
          session: args.session,
          fields,
          headers: headersOf(args),
          method: args.method,
          json: boolOption(args.json, false),
          token_field: args["token-field"],
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "session") {
    const project = path.resolve(args._[0] || process.cwd());
    const action = args._[1] || "list";
    const name = args._[2];
    if (action === "list") print({ ok: true, sessions: listSessions(project) });
    else if (action === "show") print({ ok: true, session: describeSession(project, name) });
    else if (action === "delete") print({ ok: true, ...deleteSession(project, name) });
    else if (action === "create") {
      const headers = headersOf(args);
      if (!Object.keys(headers).length) throw new Error('session create 需要 --header "Cookie: ..."');
      print({ ok: true, ...saveSession(project, name, { headers, note: args.note || "manual session" }) });
    } else throw new Error(`未知 session 动作:${action}`);
  } else if (command === "compare") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url || !args.a || !args.b) throw new Error("compare 需要 URL 与 --a <session> --b <session>");
    const baseHeaders = headersOf(args);
    const guard = new Guard(project, { useJar: false });
    try {
      print(
        await compare(guard, {
          url,
          method: args.method,
          marker: args.marker,
          aHeaders: sessionHeaders(project, args.a, baseHeaders),
          bHeaders: sessionHeaders(project, args.b, baseHeaders),
          include_snippet: boolOption(args["include-snippet"], false),
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "dom") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url || !args.param) throw new Error('dom 需要 URL 与 --param <参数名>');
    const guard = new Guard(project);
    try {
      const session = args.session ? loadSession(project, args.session) : null;
      print(
        await inspectDomContext(guard, {
          url,
          param: args.param,
          session: args.session || null,
          sessionHeaders: session ? session.headers : null,
          waitMs: args["wait-ms"],
          screenshot: boolOption(args.screenshot, false),
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "param-adaptive") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url || !args.param) throw new Error("param-adaptive 需要 URL 与 --param <参数名>");
    const guard = new Guard(project);
    try {
      print(
        await runAdaptiveParamProbes(guard, {
          url,
          param: args.param,
          confirm: boolOption(args.confirm, false),
          classes: args.classes ? String(args.classes).split(",") : undefined,
          headers: sessionHeaders(project, args.session, headersOf(args)),
          maxTransforms: args["max-transforms"],
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "waf") {
    const project = path.resolve(args._[0] || process.cwd());
    const url = args._[1];
    if (!url || !args.param) throw new Error('waf 需要 URL 与 --param <参数名>');
    const guard = new Guard(project);
    try {
      print(
        await analyzeWaf(guard, {
          url,
          param: args.param,
          confirm: boolOption(args.confirm, false),
          headers: sessionHeaders(project, args.session, headersOf(args)),
          maxProbes: args["max-probes"],
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "param") {
    const project = path.resolve(args._[0] || process.cwd());
    const urls = args._.slice(1);
    if (!urls.length) throw new Error("param 需要至少一个 URL");
    const guard = new Guard(project);
    try {
      print(
        await runParamProbes(guard, {
          urls,
          confirm: boolOption(args.confirm, false),
          classes: args.classes ? String(args.classes).split(",") : undefined,
          headers: sessionHeaders(project, args.session, headersOf(args)),
          maxParams: args["max-params"],
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "auto") {
    const project = path.resolve(args._[0] || process.cwd());
    const work = args.work ? JSON.parse(fs.readFileSync(path.resolve(args.work), "utf8")) : [];
    print(
      await autoRun(project, {
        maxSteps: args.max,
        materialize: !args["no-materialize"],
        work: Array.isArray(work) ? work : [],
      }),
    );
  } else if (command === "tick") {
    const project = path.resolve(args._[0] || process.cwd());
    print(plannerTick(project, {
      materialize: boolOption(args.materialize, false),
      maxChains: args.max,
    }));
  } else if (command === "materialize") {
    const project = path.resolve(args._[0] || process.cwd());
    const chainId = args._[1];
    if (!chainId) throw new Error("materialize 需要 chain_id(先跑 chain plan)");
    print({ ok: true, ...materializeChain(project, chainId) });
  } else if (command === "worker") {
    const project = path.resolve(args._[0] || process.cwd());
    const intentId = args._[1];
    if (!intentId || !args.action) throw new Error("worker 需要 intent_id 与 --action");
    print(
      await runWorkerAction(project, {
        intentId,
        action: args.action,
        url: args.url,
        session: args.session,
        session_a: args.a,
        session_b: args.b,
        marker: args.marker,
        param: args.param,
        classes: args.classes ? String(args.classes).split(",") : undefined,
        headers: headersOf(args),
        method: args.method,
        wait_ms: args["wait-ms"],
        complete: !args["no-complete"],
      }),
    );
  } else if (command === "disclose") {
    const project = path.resolve(args._[0] || process.cwd());
    const out = writeDisclosure(project, {
      includeCandidates: boolOption(args["include-candidates"], false),
    });
    print({ ok: true, file: out.file, stats: out.stats });
  } else if (command === "handoff") {
    const project = path.resolve(args._[0] || process.cwd());
    const target = args._[1];
    if (!target) throw new Error("handoff 需要本地样本路径或 URL");
    if (/^https?:\/\//i.test(target)) {
      const guard = new Guard(project);
      try {
        print(
          await fetchArtifact(guard, {
            url: target,
            confirm: boolOption(args.confirm, false),
            maxBytes: args["max-bytes"],
          }),
        );
      } finally {
        guard.close();
      }
    } else {
      print(await handoffFile(project, target));
    }
  } else if (command === "replay") {
    const project = path.resolve(args._[0] || process.cwd());
    const file = args._[1];
    if (!file) throw new Error("replay 需要 HAR 文件路径");
    const replace = {};
    for (const pair of String(args.replace || "").split(",").filter(Boolean)) {
      const at = pair.indexOf("=");
      if (at > 0) replace[pair.slice(0, at)] = pair.slice(at + 1);
    }
    const guard = new Guard(project);
    try {
      print(
        await replayHar(guard, {
          file,
          headers: sessionHeaders(project, args.session, headersOf(args)),
          maxEntries: args.max,
          allowWrite: boolOption(args["allow-write"], false),
          replace,
          hosts: args.hosts ? String(args.hosts).split(",") : [],
        }),
      );
    } finally {
      guard.close();
    }
  } else if (command === "har") {
    const file = args._[1] || args._[0];
    if (!file) throw new Error("har 需要文件路径");
    print(ingestHar(file));
  } else {
    throw new Error(`未知命令:${command}\n\n${HELP}`);
  }
} catch (error) {
  process.stderr.write(`fairy: ${error.message}\n`);
  process.exitCode = 1;
}
