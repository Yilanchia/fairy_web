import { nowIso, redactUrl, shortHash, snippetAround, truncate } from "./util.js";

// WAF 行为分析:只测"规范化差异",不生成利用载荷。
// 通过带标记的语法形状 + 通用编码变体,观察哪些请求被拦截、哪些到达后端。
// 结论只说明 WAF 与后端解码不一致,不等于可绕过;验证必须由人在授权范围内完成。

const BLOCK_STATUS = new Set([403, 406, 429, 501]);

const SIGNATURES = [
  {
    vendor: "Cloudflare",
    confidence: "high",
    test: ({ h, b, c }) => {
      const evidence = [];
      if (h["cf-ray"]) evidence.push("header cf-ray");
      if (c.some((name) => /^__cf_bm$/i.test(name))) evidence.push("cookie __cf_bm");
      if (/Attention Required!?\s*\|\s*Cloudflare/i.test(b)) evidence.push("body Cloudflare block page");
      return evidence;
    },
  },
  {
    vendor: "Akamai",
    confidence: "high",
    test: ({ h, b }) => {
      const evidence = [];
      if (h["akamai-grn"] || h["x-akamai-request-id"]) evidence.push("header akamai-grn / x-akamai-request-id");
      if (/Access Denied[\s\S]{0,80}akamai/i.test(b)) evidence.push("body Akamai access denied");
      return evidence;
    },
  },
  {
    vendor: "Imperva",
    confidence: "high",
    test: ({ h, b, c }) => {
      const evidence = [];
      if (h["x-iinfo"]) evidence.push("header x-iinfo");
      if (c.some((name) => /^(visid_incap_|incap_ses_)/i.test(name))) evidence.push("cookie incap_ses_/visid_incap_");
      if (/Incapsula/i.test(b)) evidence.push("body Incapsula");
      return evidence;
    },
  },
  {
    vendor: "F5 BIG-IP",
    confidence: "high",
    test: ({ h, b }) => {
      const evidence = [];
      if (h["x-wa-info"]) evidence.push("header x-wa-info");
      if (/The requested URL was rejected/i.test(b)) evidence.push("body F5 rejection page");
      return evidence;
    },
  },
  {
    vendor: "Sucuri",
    confidence: "high",
    test: ({ h, b }) => {
      const evidence = [];
      if (h["x-sucuri-id"]) evidence.push("header x-sucuri-id");
      if (/Sucuri WebSite Firewall/i.test(b)) evidence.push("body Sucuri block page");
      return evidence;
    },
  },
  {
    vendor: "FortiWeb",
    confidence: "high",
    test: ({ b, c }) => {
      const evidence = [];
      if (c.some((name) => /^FORTIWAFSID$/i.test(name))) evidence.push("cookie FORTIWAFSID");
      if (/FortiWeb/i.test(b)) evidence.push("body FortiWeb");
      return evidence;
    },
  },
  {
    vendor: "Azure Front Door",
    confidence: "medium",
    test: ({ h, b }) => {
      const evidence = [];
      if (h["x-azure-ref"]) evidence.push("header x-azure-ref");
      if (/Azure Front Door/i.test(b)) evidence.push("body Azure Front Door");
      return evidence;
    },
  },
  {
    vendor: "ModSecurity",
    confidence: "medium",
    test: ({ b }) => (/ModSecurity|Not Acceptable!?[\s\S]{0,80}Apache/i.test(b) ? ["body ModSecurity"] : []),
  },
  {
    vendor: "Barracuda",
    confidence: "medium",
    test: ({ b, c }) => {
      const evidence = [];
      if (c.some((name) => /^barra_counter_session$/i.test(name))) evidence.push("cookie barra_counter_session");
      if (/Barracuda/i.test(b)) evidence.push("body Barracuda");
      return evidence;
    },
  },
  {
    vendor: "Aliyun WAF",
    confidence: "medium",
    test: ({ b }) => (/errors\.aliyun\.com|aliyun[\s\S]{0,40}(block|拦截)/i.test(b) ? ["body Aliyun WAF"] : []),
  },
  {
    vendor: "Tencent Cloud WAF",
    confidence: "medium",
    test: ({ b }) => (/腾讯云|waf\.tencent/i.test(b) ? ["body Tencent Cloud WAF"] : []),
  },
  {
    vendor: "SafeLine",
    confidence: "medium",
    test: ({ b }) => (/SafeLine|雷池/i.test(b) ? ["body SafeLine"] : []),
  },
  {
    vendor: "Safedog",
    confidence: "medium",
    test: ({ b }) => (/安全狗|safedog/i.test(b) ? ["body Safedog"] : []),
  },
  {
    vendor: "Yunaq",
    confidence: "medium",
    test: ({ b }) => (/知道创宇|yunaq/i.test(b) ? ["body Yunaq"] : []),
  },
  {
    vendor: "generic",
    confidence: "low",
    test: ({ h, b }) => {
      const evidence = [];
      if (/waf/i.test(h.server || "")) evidence.push(`header server: ${h.server}`);
      if (/web application firewall|request blocked|access denied|not acceptable|非法请求|请求被拦截|拦截/i.test(b)) {
        evidence.push("body generic block page");
      }
      return evidence;
    },
  },
];

function headerMap(headers) {
  const map = {};
  for (const header of headers || []) {
    const name = String(header.name || "").toLowerCase();
    if (!name) continue;
    const value = String(header.value ?? "");
    map[name] = map[name] ? `${map[name]}, ${value}` : value;
  }
  return map;
}

function cookieNames(headers) {
  return (headers || [])
    .filter((header) => String(header.name || "").toLowerCase() === "set-cookie")
    .map((header) => String(header.value || "").split("=")[0]);
}

export function fingerprintWaf(headers, body) {
  const context = { h: headerMap(headers), b: String(body || ""), c: cookieNames(headers) };
  const matches = [];
  for (const signature of SIGNATURES) {
    const evidence = signature.test(context) || [];
    if (!evidence.length) continue;
    matches.push({ vendor: signature.vendor, confidence: signature.confidence, evidence });
  }
  const best = matches[0] || null;
  return {
    detected: matches.length > 0,
    vendor: best ? best.vendor : null,
    confidence: best ? best.confidence : null,
    vendors: matches.map((match) => match.vendor),
    evidence: matches.flatMap((match) => match.evidence),
  };
}

const SHAPES = [
  { id: "tag", label: "HTML 标签", make: (marker) => `<${marker}>` },
  { id: "quote", label: "单引号", make: (marker) => `'${marker}` },
  { id: "traversal", label: "路径穿越", make: (marker) => `../${marker}` },
  { id: "template", label: "模板表达式", make: (marker) => `{{7*7}}${marker}` },
];

const TRANSFORMS = [
  { id: "single", label: "单次 URL 编码(标准)", apply: (value) => value },
  { id: "double", label: "双重 URL 编码", apply: (value) => encodeURIComponent(value) },
  {
    id: "html",
    label: "HTML 实体",
    apply: (value) =>
      value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"),
  },
  {
    id: "unicode",
    label: "JS Unicode 转义",
    apply: (value) =>
      value.replace(/</g, "\\u003C").replace(/>/g, "\\u003E").replace(/"/g, "\\u0022").replace(/'/g, "\\u0027"),
  },
];

function withParam(href, name, value) {
  const url = new URL(href);
  url.searchParams.set(name, value);
  return url.href;
}

function blockInfo(page, baseline) {
  const waf = fingerprintWaf(page.headers, page.body);
  const statusHit = BLOCK_STATUS.has(page.status);
  const generic = /web application firewall|request blocked|access denied|not acceptable|非法请求|请求被拦截|拦截/i.test(
    page.body || "",
  );
  const statusChanged = Boolean(baseline && page.status !== baseline.status);
  const blocked = statusHit && (waf.detected || generic || (statusChanged && baseline.status < 400));
  return {
    blocked,
    waf,
    snippet: blocked ? truncate(page.body, 160) : null,
    reason: blocked
      ? `HTTP ${page.status}${waf.vendor ? ` / ${waf.vendor}` : ""}${generic ? " / block page" : ""}`
      : null,
  };
}

export async function analyzeWaf(guard, options = {}) {
  if (guard.limits.allow_waf_probe !== true) {
    throw new Error(
      "WAF 行为分析未授权:在 scope.limits.allow_waf_probe 设为 true(CLI: init --allow-waf-probe true)后重试。",
    );
  }
  if (options.confirm !== true) {
    throw new Error("WAF 行为分析需要 confirm=true:它会向目标发少量带标记的请求,必须显式确认。");
  }

  const url = String(options.url || "");
  const param = String(options.param || "");
  if (!url) throw new Error("需要 URL");
  if (!param) throw new Error("需要 param(要分析的查询参数名)");

  const marker = `fairywaf${shortHash(`${url}:${param}:${Date.now()}`, 8)}`;
  const headers = options.headers || {};
  const maxProbes = Math.min(Math.max(Number(options.maxProbes) || 24, 1), 60);
  const started = Date.now();

  const baseline = await guard.request(withParam(url, param, marker), { headers });
  const baselineWaf = fingerprintWaf(baseline.headers, baseline.body);

  const rows = [];
  let blockedCount = 0;

  outer: for (const shape of SHAPES) {
    for (const transform of TRANSFORMS) {
      if (rows.length >= maxProbes) break outer;
      const value = transform.apply(shape.make(marker));
      const probeUrl = withParam(url, param, value);
      let response;
      try {
        response = await guard.request(probeUrl, { headers });
      } catch (error) {
        rows.push({
          shape: shape.id,
          shape_label: shape.label,
          transform: transform.id,
          transform_label: transform.label,
          error: error.message,
          blocked: null,
          passed: false,
        });
        continue;
      }
      const info = blockInfo(response, baseline);
      if (info.blocked) blockedCount += 1;
      rows.push({
        shape: shape.id,
        shape_label: shape.label,
        transform: transform.id,
        transform_label: transform.label,
        status: response.status,
        bytes: response.body_bytes,
        blocked: info.blocked,
        passed: !info.blocked && response.status < 400,
        reflected: response.body.includes(marker),
        reason: info.reason,
        snippet: info.snippet,
        waf_vendor: info.waf.vendor,
        waf_evidence: info.waf.evidence,
        request_id: response.request_id,
      });
    }
  }

  const shapes = [];
  const observations = [];
  for (const shape of SHAPES) {
    const entries = rows.filter((row) => row.shape === shape.id);
    if (!entries.length) continue;
    const raw = entries.find((row) => row.transform === "single");
    const passed = entries
      .filter((row) => row.transform !== "single" && row.passed)
      .map((row) => row.transform_label);
    const blocked = entries.filter((row) => row.blocked).map((row) => row.transform_label);
    shapes.push({
      shape: shape.id,
      label: shape.label,
      raw_blocked: Boolean(raw && raw.blocked),
      blocked_transforms: blocked,
      passed_transforms: passed,
    });
    if (raw && raw.blocked && passed.length) {
      observations.push(`${shape.label}:单次编码被拦截;${passed.join(" / ")} 通过(规范化差异)`);
    } else if (raw && raw.blocked) {
      observations.push(`${shape.label}:所有变体均被拦截`);
    } else {
      observations.push(`${shape.label}:未见拦截`);
    }
  }

  const wafEvidence = [...baselineWaf.evidence];
  const vendors = new Set(baselineWaf.vendors);
  for (const row of rows) {
    if (!row.blocked) continue;
    if (row.waf_vendor) vendors.add(row.waf_vendor);
    for (const evidence of row.waf_evidence || []) wafEvidence.push(evidence);
  }

  const normalizationGap = observations.some((line) => line.includes("规范化差异"));
  const waf = {
    detected: baselineWaf.detected || blockedCount > 0,
    vendor: baselineWaf.vendor || (blockedCount ? "unknown" : null),
    confidence: baselineWaf.confidence || (blockedCount ? "low" : null),
    vendors: [...vendors],
    evidence: [...new Set(wafEvidence)].slice(0, 12),
  };

  return {
    schema: "FairyWaf/v1",
    tool: "web_waf",
    run_id: guard.runId,
    generated_at: nowIso(),
    url,
    param,
    marker,
    baseline: {
      status: baseline.status,
      bytes: baseline.body_bytes,
      request_id: baseline.request_id,
      waf: baselineWaf,
    },
    waf,
    shapes,
    matrix: rows,
    verdict: normalizationGap
      ? "normalization-gap"
      : blockedCount
        ? "waf-present"
        : baselineWaf.detected
          ? "waf-fingerprint-only"
          : "no-waf-signal",
    observations,
    stats: {
      requests: guard.count,
      blocked: blockedCount,
      duration_ms: Date.now() - started,
    },
    audit_path: guard.auditPath,
    limitations: [
      "只测规范化差异与拦截行为,不生成利用载荷,不做 payload 混淆。",
      "编码差异只说明 WAF 与后端解码不一致,不等于可绕过;需人工在授权范围验证。",
      "规则可能按路径、方法、参数变化;结论只覆盖本次 URL 与参数。",
      "WAF 指纹可能误报,尤其是只有通用 server 头的场景。",
    ],
    stop: "发现规范化差异即停。不要用真实攻击载荷验证;需要时由人工在授权范围内完成。",
  };
}
