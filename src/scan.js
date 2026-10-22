import { Guard } from "./guard.js";
import { crawl, probeUrls } from "./crawl.js";
import { fingerprint } from "./fingerprint.js";
import {
  createContext,
  passiveChecks,
  activeChecks,
  exposureChecks,
  tlsCheck,
} from "./checks.js";
import { scopeSummary } from "./scope.js";
import { nowIso, redactHeaders, severityRank } from "./util.js";
import { enrichFindings } from "./taxonomy.js";

function serializePage(page) {
  return {
    request_id: page.request_id,
    url: page.url,
    requested_url: page.requested_url || page.url,
    status: page.status,
    content_type: page.content_type,
    title: page.title || "",
    bytes: page.body_bytes,
    timing_ms: page.timing_ms,
    depth: page.depth,
    tech: page.tech || [],
    redirects: (page.redirects || []).map((r) => ({ status: r.status, to: r.to })),
  };
}

export async function executeScan(projectDir, options = {}) {
  const urls = (Array.isArray(options.urls) ? options.urls : []).map((u) => String(u || "").trim()).filter(Boolean);
  if (!urls.length) throw new Error("至少提供一个目标 URL");
  const guard = new Guard(projectDir);
  const ctx = createContext();
  const started = Date.now();

  try {
    const collected = options.crawl
      ? await crawl(guard, urls[0], {
          maxPages: options.max_pages,
          maxDepth: options.max_depth,
          headers: options.headers,
        })
      : await probeUrls(guard, urls, { headers: options.headers });

    if (options.crawl && urls.length > 1) {
      const extra = await probeUrls(guard, urls.slice(1), { headers: options.headers });
      collected.pages.push(...extra.pages);
      collected.endpoints.push(...extra.endpoints);
      collected.forms.push(...extra.forms);
      collected.errors.push(...extra.errors);
      for (const host of extra.external_hosts) {
        if (!collected.external_hosts.includes(host)) collected.external_hosts.push(host);
      }
    }

    // 表单按 method+action+字段去重(同一表单可能被爬到又被显式探测)。
    const seenForms = new Set();
    collected.forms = collected.forms.filter((form) => {
      const key = `${form.method} ${form.action} ${(form.inputs || []).map((i) => i.name).join(",")}`;
      if (seenForms.has(key)) return false;
      seenForms.add(key);
      return true;
    });

    // 同一 URL 可能既被爬到又被显式列出,按最初请求去重,避免重复探测与重复报告。
    const seenPages = new Set();
    collected.pages = collected.pages.filter((page) => {
      const key = page.requested_url || page.url;
      if (seenPages.has(key)) return false;
      seenPages.add(key);
      return true;
    });

    for (const page of collected.pages) {
      page.tech = fingerprint(page);
      passiveChecks(page, ctx);
    }

    const activeBudget =
      options.active === false ? 0 : Math.min(collected.pages.length, guard.limits.max_active_pages);
    let activeRan = 0;
    for (let i = 0; i < activeBudget; i++) {
      await activeChecks(guard, collected.pages[i], ctx, { headers: options.headers });
      activeRan += 1;
    }

    const origins = [...new Set(collected.pages.map((p) => new URL(p.url).origin))].slice(0, 5);
    for (const origin of origins) {
      await exposureChecks(guard, origin, ctx, { headers: options.headers });
    }

    const tlsPage = collected.pages.find((p) => p.tls);
    if (tlsPage) tlsCheck(tlsPage, ctx);

    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of ctx.findings) bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    ctx.findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title));
    ctx.findings.forEach((finding, index) => {
      finding.id = `F-${String(index + 1).padStart(3, "0")}`;
    });
    enrichFindings(ctx.findings);

    const result = {
      schema: "FairyScan/v1",
      tool: "web_scan",
      run_id: guard.runId,
      generated_at: nowIso(),
      scope: scopeSummary(guard.scope),
      targets: urls,
      mode: options.crawl ? "crawl" : "probe",
      auth: options.auth_label ? { session: options.auth_label } : null,
      pages: collected.pages.map(serializePage),
      attack_surface: {
        endpoints: [...new Set(collected.endpoints)].slice(0, 200),
        forms: collected.forms.slice(0, 100),
        external_hosts: collected.external_hosts.slice(0, 50),
        probe_errors: collected.errors.concat(ctx.errors).slice(0, 50),
      },
      findings: ctx.findings,
      stats: {
        requests: guard.count,
        blocked: guard.blocked,
        pages: collected.pages.length,
        origins: origins.length,
        active_pages: activeRan,
        findings: bySeverity,
        duration_ms: Date.now() - started,
      },
      audit_path: guard.auditPath,
      evidence_note: "每条发现都带 request_id,可在 .fairy/audit/<run_id>.jsonl 里回查对应请求。",
      limitations: [
        "基于单次请求 + 启发式规则的候选,反射/CORS/跳转需人工在浏览器复核后才能定级。",
        "只发只读方法(GET/HEAD/OPTIONS)与无特殊字符标记;不做注入载荷、不爆破、不 dump 数据。",
        "覆盖受 max_pages / max_active_pages / rps 限制,不代表站点完整攻击面。",
        "主动检测会向目标发包,仅限 scope 内、且遵守项目规则(限速/禁爆破/测试时段)。",
      ],
    };

    return {
      result,
      traffic: guard.traffic,
      guardInfo: guard.close(),
      requestHeaders: redactHeaders(
        Object.entries(options.headers || {}).map(([name, value]) => ({ name, value: String(value) })),
      ),
    };
  } catch (error) {
    guard.close();
    throw error;
  }
}

export async function scan(projectDir, options = {}) {
  const { result } = await executeScan(projectDir, options);
  return result;
}
