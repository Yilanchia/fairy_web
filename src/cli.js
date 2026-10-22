#!/usr/bin/env node
import path from "node:path";
import { saveScope, loadScope, scopeSummary, SCOPE_FILE } from "./scope.js";
import { Guard } from "./guard.js";
import { crawl, probeUrls } from "./crawl.js";
import { ingestHar } from "./har.js";
import { executeScan, scan } from "./scan.js";
import { writeReport } from "./report.js";
import { startMcpServer } from "./mcp.js";

const HELP = `Fairy Web — 授权范围内的 web 侦察/检测手

用法:
  node src/cli.js init   <project> --include <a,b> --basis "<授权依据>" [--operator 名字] [--rps 5] [--max 2000]
  node src/cli.js show   <project>
  node src/cli.js probe  <project> <url> [--method GET] [--header "K: V"] [--cookie "..." ]
  node src/cli.js crawl  <project> <url> [--pages 40] [--depth 2]
  node src/cli.js scan   <project> <url...> [--crawl] [--pages 40] [--depth 2] [--no-active]
  node src/cli.js report <project> <url...> [--crawl] [--pages 40]
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
      headers: headersOf(args),
      active: !args["no-active"],
    });
    print(result);
  } else if (command === "report") {
    const project = path.resolve(args._[0] || process.cwd());
    const urls = args._.slice(1);
    if (!urls.length) throw new Error("report 需要至少一个 URL");
    const { result, traffic } = await executeScan(project, {
      urls,
      crawl: boolOption(args.crawl, false),
      max_pages: args.pages,
      max_depth: args.depth,
      headers: headersOf(args),
    });
    const files = writeReport(project, { result, traffic });
    print({
      ok: true,
      run_id: result.run_id,
      stats: result.stats,
      findings: result.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, where: f.where })),
      files,
    });
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
