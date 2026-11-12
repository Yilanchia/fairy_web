import { loadLedger, appendLedger, addFact } from "./ledger.js";
import { Guard } from "./guard.js";
import { loadSession } from "./session.js";
import { inspectDomContext } from "./domxss.js";
import { nowIso } from "./util.js";

// 证据深度:只把“已经观察到的反射”推进到上下文判定,不生成 XSS 载荷。
// 只有 script/事件属性 + 无有效 CSP 才标 provable;finding 仍是 candidate,
// verified 永远由人工 fairy_ledger_advance 决定。

function targetUrl(finding, options) {
  if (options.url) return String(options.url);
  const raw = String(finding.where || "")
    .replace(/^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+/i, "")
    .split(/\s+/)[0];
  try {
    return new URL(raw).href;
  } catch {
    return null;
  }
}

function firstParam(url) {
  try {
    return [...new URL(url).searchParams.keys()][0] || null;
  } catch {
    return null;
  }
}

export async function proofFinding(projectDir, findingId, options = {}) {
  const ledger = loadLedger(projectDir);
  const finding = ledger.findings.find((item) => item.id === findingId);
  if (!finding) throw new Error(`finding 不存在:${findingId}`);

  if (finding.kind === "sqli") {
    const result = {
      schema: "FairyProof/v1",
      finding_id: finding.id,
      status: "needs-review",
      reason: "SQLi 只做到存在性;影响需要人工在授权范围内确认。",
      kind: finding.kind,
      at: nowIso(),
    };
    appendLedger(projectDir, (current) => {
      const target = current.findings.find((item) => item.id === findingId);
      target.proof = { status: result.status, reason: result.reason, at: result.at };
      target.updated_at = nowIso();
    });
    return result;
  }

  if (!["reflection", "xss"].includes(finding.kind)) {
    return {
      schema: "FairyProof/v1",
      finding_id: finding.id,
      status: "unsupported",
      reason: `类型 ${finding.kind} 不在 proof 上下文判定范围(reflection/xss/sqli)。`,
      kind: finding.kind,
    };
  }

  const url = targetUrl(finding, options);
  const param = String(options.param || (url ? firstParam(url) : "") || "");
  if (!url) throw new Error("finding.where 不是可解析的 URL;请用 url 参数指定");
  if (!param) throw new Error("没有可判定的查询参数;请用 param 参数指定");

  const session = options.session ? loadSession(projectDir, options.session) : null;
  const guard = new Guard(projectDir);
  let dom;
  try {
    dom = await inspectDomContext(guard, {
      url,
      param,
      session: options.session || null,
      sessionHeaders: session ? session.headers : null,
      waitMs: options.waitMs,
      screenshot: false,
    });
  } finally {
    guard.close();
  }

  const executable = ["candidate-script-context", "candidate-event-handler"].includes(dom.verdict);
  const weakCsp = !dom.csp_present || /unsafe-inline/i.test(dom.csp || "");
  const provable = executable && weakCsp;
  const status = provable ? "provable" : "needs-review";
  const reason = provable
    ? `反射落在 ${dom.context.context} 上下文,且 CSP ${dom.csp_present ? "含 unsafe-inline" : "缺失"}。`
    : executable
      ? `反射落在可执行上下文,但 CSP 限制较强;需人工复核 nonce/hash。`
      : `反射落在 ${dom.context.context || "未知"} 上下文,当前不构成可执行证明。`;

  const fact = appendLedger(projectDir, (current) => {
    const target = current.findings.find((item) => item.id === findingId);
    const added = addFact(current, {
      statement: `XSS 上下文判定 ${findingId}:${dom.verdict} / ${reason}`,
      confidence: "observed",
      tags: ["xss", "proof", dom.verdict],
      evidence: [{ kind: "browser", url: dom.url, note: `context=${dom.context.context || "none"};csp=${dom.csp_present}` }],
    });
    target.proof = {
      status,
      reason,
      verdict: dom.verdict,
      context: dom.context.context || null,
      tag: dom.context.tag || null,
      attr: dom.context.attr || null,
      csp: dom.csp || null,
      fact_id: added.fact.id,
      at: nowIso(),
    };
    if (provable) target.confidence = "high";
    target.updated_at = nowIso();
    return added.fact;
  });

  return {
    schema: "FairyProof/v1",
    finding_id: findingId,
    status,
    provable,
    reason,
    url: dom.url,
    param,
    reflected: dom.reflected,
    context: dom.context,
    csp: dom.csp,
    csp_present: dom.csp_present,
    verdict: dom.verdict,
    fact_id: fact.id,
    note: "只升置信/写事实,不自动改 verified,不生成载荷。",
  };
}

export function classifyProof(ledger) {
  const relevant = ledger.findings.filter((finding) =>
    ["reflection", "xss", "sqli"].includes(finding.kind),
  );
  const items = relevant.map((finding) => ({
    finding_id: finding.id,
    title: finding.title,
    kind: finding.kind,
    status: finding.proof?.status || "unclassified",
    reason: finding.proof?.reason || "尚未做上下文/影响判定",
    fact_id: finding.proof?.fact_id || null,
  }));
  const counts = { provable: 0, "needs-review": 0, unsupported: 0, unclassified: 0 };
  for (const item of items) counts[item.status] = (counts[item.status] || 0) + 1;
  return { schema: "FairyProofSummary/v1", counts, items };
}
