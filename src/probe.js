import { URL } from "node:url";
import { nowIso, redactUrl, severityRank, snippetAround, truncate } from "./util.js";
import { enrichFindings } from "./taxonomy.js";
import { applyTransform, loadWafProfile, TRANSFORM_IDS } from "./waf.js";

// 参数级主动探测:只判"存在",不取数据。
// 手法限定为:错误签名、布尔差分、模板求值。不做 UNION、堆叠、盲注、命令执行。
// 必须 scope.limits.allow_active_probes=true 且调用方 confirm=true 才会发。

const SQL_ERRORS = [
  /You have an error in your SQL syntax[^<]{0,120}/i,
  /SQL syntax[^<]{0,80}MySQL/i,
  /Warning:\s*mysql_[a-z_]+\(\)[^<]{0,120}/i,
  /unclosed quotation mark[^<]{0,120}/i,
  /quoted string not properly terminated/i,
  /ORA-\d{4,5}[^<]{0,120}/,
  /PostgreSQL[^<]{0,40}ERROR[^<]{0,120}/i,
  /SQLite\/JDBCDriver[^<]{0,120}/i,
  /Microsoft OLE DB Provider for SQL Server[^<]{0,120}/i,
  /ODBC SQL Server Driver[^<]{0,120}/i,
  /syntax error at or near[^<]{0,120}/i,
];

const SUPPORTED = new Set(["sqli", "ssti"]);

function tokenize(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .split(" ")
    .filter(Boolean)
    .slice(0, 4000);
}

function shingles(list, size = 4) {
  const set = new Set();
  for (let i = 0; i + size <= list.length; i++) set.add(list.slice(i, i + size).join(" "));
  return set;
}

function similarity(a, b) {
  const left = shingles(tokenize(a));
  const right = shingles(tokenize(b));
  if (!left.size && !right.size) return 1;
  let overlap = 0;
  const [small, large] = left.size <= right.size ? [left, right] : [right, left];
  for (const item of small) if (large.has(item)) overlap += 1;
  return overlap / (left.size + right.size - overlap);
}

function withParam(href, name, value) {
  const url = new URL(href);
  url.searchParams.set(name, value);
  return url.href;
}

function whereFor(target, name, transform) {
  const suffix = transform && transform !== "single" ? `, transform: ${transform}` : "";
  return `GET ${redactUrl(target)} (param: ${name}${suffix})`;
}

export async function runParamProbes(guard, options = {}) {
  if (guard.limits.allow_active_probes !== true) {
    throw new Error(
      "参数级主动探测未授权:在 scope.limits.allow_active_probes 设为 true(CLI: init --allow-active-probes true)后重试。",
    );
  }
  if (options.confirm !== true) {
    throw new Error("参数级主动探测需要 confirm=true:它会向目标发少量探测请求,必须显式确认。");
  }

  const urls = (Array.isArray(options.urls) ? options.urls : []).map(String).filter(Boolean);
  if (!urls.length) throw new Error("至少一个 URL");
  const requested = (Array.isArray(options.classes) && options.classes.length ? options.classes : ["sqli", "ssti"]).map(
    (value) => String(value).toLowerCase(),
  );
  const classes = requested.filter((value) => SUPPORTED.has(value));
  if (!classes.length) throw new Error(`classes 只支持:${[...SUPPORTED].join("/")}`);

  const requestedTransforms = Array.isArray(options.transforms) && options.transforms.length
    ? options.transforms
    : ["single"];
  const transforms = [...new Set(requestedTransforms.map((value) => String(value)))];
  for (const transform of transforms) {
    if (!TRANSFORM_IDS.includes(transform)) throw new Error(`未知编码变体:${transform}(支持:${TRANSFORM_IDS.join("/")})`);
  }
  if (transforms.some((transform) => transform !== "single") && guard.limits.allow_waf_probe !== true) {
    throw new Error("使用编码变体探测需要 scope.limits.allow_waf_probe=true;先跑 web_waf 并显式授权。");
  }

  const headers = options.headers || {};
  const maxParams = Math.min(Math.max(Number(options.maxParams) || 20, 1), 100);
  const findings = [];
  const keys = new Set();
  let seq = 0;
  let paramsTested = 0;
  const started = Date.now();

  const add = (finding) => {
    const key = `${finding.kind}|${finding.where}|${finding.title}`;
    if (keys.has(key)) return null;
    keys.add(key);
    const entry = {
      id: `P-${String(++seq).padStart(3, "0")}`,
      confidence: "medium",
      evidence: {},
      ...finding,
    };
    findings.push(entry);
    return entry;
  };

  for (const target of urls) {
    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      continue;
    }
    const names = [...parsed.searchParams.keys()]
      .filter((name) => !options.paramFilter || name === options.paramFilter)
      .slice(0, maxParams);
    if (!names.length) continue;

    let baseline;
    try {
      baseline = await guard.request(target, { headers });
    } catch {
      continue;
    }

    const done = new Set();
    for (const name of names) {
      if (classes.every((value) => done.has(value))) break;
      paramsTested += 1;
      const original = parsed.searchParams.get(name) ?? "";

      for (const transform of transforms) {
        if (classes.every((value) => done.has(value))) break;
        if (classes.includes("sqli") && !done.has("sqli")) {
          const found = await sqliProbes(guard, {
            target: parsed.href,
            name,
            original,
            baseline,
            headers,
            transform,
            add,
          });
          if (found) done.add("sqli");
        }
        if (classes.includes("ssti") && !done.has("ssti")) {
          const found = await sstiProbe(guard, {
            target: parsed.href,
            name,
            original,
            baseline,
            headers,
            transform,
            add,
          });
          if (found) done.add("ssti");
        }
      }
    }
  }

  enrichFindings(findings);
  findings.sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;

  return {
    schema: "FairyParam/v1",
    tool: "web_param",
    run_id: guard.runId,
    generated_at: nowIso(),
    targets: urls,
    classes,
    transforms,
    params_tested: paramsTested,
    findings,
    stats: {
      requests: guard.count,
      blocked: guard.blocked,
      findings: bySeverity,
      duration_ms: Date.now() - started,
    },
    audit_path: guard.auditPath,
    limitations: [
      "只做存在性判断:错误签名 / 布尔差分 / 模板求值。不做 UNION、堆叠、时间盲注、数据提取。",
      "布尔差分可能被动态页面干扰;证据带 request_id,需人工复核后再定级。",
      "只测 URL 查询参数(GET),不自动提交表单或 JSON body。",
      "编码变体只用于存在性检测,不套真实攻击载荷;通过 WAF 不等于存在漏洞。",
      "主动探测会向目标发请求,仅限 scope 内且已显式开启 allow_active_probes。",
    ],
  };
}

async function sqliProbes(guard, context) {
  const { target, name, original, baseline, headers, transform, add } = context;

  const quoteUrl = withParam(target, name, applyTransform(transform, `${original}'`));
  let quote;
  try {
    quote = await guard.request(quoteUrl, { headers });
  } catch {
    return false;
  }

  const match = SQL_ERRORS.map((rx) => rx.exec(quote.body || "")).find(Boolean);
  const baselineHasError = SQL_ERRORS.some((rx) => rx.test(baseline.body || ""));
  if (match && !baselineHasError) {
    add({
      kind: "sqli",
      severity: "high",
      confidence: "high",
      title: `参数 ${name} 触发 SQL 错误`,
      where: whereFor(target, name, transform),
      detail: `注入单引号后响应命中数据库错误签名:${truncate(match[0], 160)}${transform !== "single" ? `(编码变体:${transform})` : ""}`,
      evidence: {
        request_id: quote.request_id,
        status: quote.status,
        transform,
        snippet: snippetAround(quote.body, match[0].slice(0, 20), 120),
      },
      verify: "确认错误由该参数引起、且未做统一错误页;不要继续注入取数。",
    });
    return true;
  }

  const trueUrl = withParam(target, name, applyTransform(transform, `${original}' AND '1'='1`));
  const falseUrl = withParam(target, name, applyTransform(transform, `${original}' AND '1'='2`));
  let trueRes;
  let falseRes;
  try {
    trueRes = await guard.request(trueUrl, { headers });
    falseRes = await guard.request(falseUrl, { headers });
  } catch {
    return false;
  }

  const simTrue = similarity(baseline.body, trueRes.body);
  const simFalse = similarity(baseline.body, falseRes.body);
  const simPair = similarity(trueRes.body, falseRes.body);
  if (simTrue > 0.85 && simFalse < 0.7 && simPair < 0.7 && simTrue - simFalse > 0.2) {
    add({
      kind: "sqli",
      severity: "high",
      confidence: "medium",
      title: `参数 ${name} 存在布尔差分`,
      where: whereFor(target, name, transform),
      detail: `真/假条件响应显著不同(与基线相似度 true=${simTrue.toFixed(2)}, false=${simFalse.toFixed(2)}, 两者=${simPair.toFixed(2)})${transform !== "single" ? `;编码变体:${transform}` : ""}。`,
      evidence: {
        request_id: trueRes.request_id,
        false_request_id: falseRes.request_id,
        transform,
        similarity: { true: simTrue, false: simFalse, pair: simPair },
      },
      verify: "手工对比两次响应的业务含义;动态页面/缓存可能造成假阳性。",
    });
    return true;
  }
  return false;
}

async function sstiProbe(guard, context) {
  const { target, name, original, baseline, headers, transform, add } = context;
  const expression = "{{7*7}}";
  if (original.includes(expression)) return false;

  const probeUrl = withParam(target, name, applyTransform(transform, `${original}${expression}`));
  let response;
  try {
    response = await guard.request(probeUrl, { headers });
  } catch {
    return false;
  }
  const body = response.body || "";
  const rendered = /\b49\b/.test(body) && !body.includes(expression);
  const baselineHas49 = /\b49\b/.test(baseline.body || "");
  if (!rendered || baselineHas49) return false;

  add({
    kind: "ssti",
    severity: "high",
    confidence: "medium",
    title: `参数 ${name} 疑似模板注入`,
    where: whereFor(target, name, transform),
    detail: `提交 {{7*7}} 后响应出现 49,且原始表达式未原样回显。这是模板求值候选。${transform !== "single" ? `(编码变体:${transform})` : ""}`,
    evidence: {
      request_id: response.request_id,
      status: response.status,
      transform,
      snippet: snippetAround(body, "49", 80),
    },
    verify: "手工确认 49 来自模板求值而非页面原有内容;不要继续执行系统命令。",
  });
  return true;
}

export async function runAdaptiveParamProbes(guard, options = {}) {
  if (guard.limits.allow_active_probes !== true) {
    throw new Error("自适应参数探测需要 scope.limits.allow_active_probes=true。");
  }
  if (guard.limits.allow_waf_probe !== true) {
    throw new Error("自适应参数探测需要 scope.limits.allow_waf_probe=true;先跑 web_waf 并显式授权。");
  }
  if (options.confirm !== true) {
    throw new Error("自适应参数探测需要 confirm=true。");
  }

  const url = String(options.url || "");
  const param = String(options.param || "");
  if (!url || !param) throw new Error("需要 url 与 param");

  const profile = loadWafProfile(guard.projectDir, { url, param });
  const recommended = Array.isArray(profile.recommended_transforms) ? profile.recommended_transforms : [];
  const transforms = [...new Set(["single", ...recommended])].slice(
    0,
    Math.min(Math.max(Number(options.maxTransforms) || 3, 1), 4),
  );

  const result = await runParamProbes(guard, {
    urls: [url],
    confirm: true,
    classes: options.classes,
    headers: options.headers,
    maxParams: 1,
    paramFilter: param,
    transforms,
  });

  return {
    ...result,
    tool: "web_param_adaptive",
    transforms_tested: transforms,
    waf_profile: {
      url: profile.url,
      param: profile.param,
      verdict: profile.verdict,
      recommended_transforms: recommended,
    },
    limitations: [
      ...result.limitations,
      "编码变体来自 WAF profile 的通过项;只用于存在性检测,不改变探针的检测目的。",
    ],
  };
}
