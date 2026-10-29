import { loadLedger, appendLedger, completeIntent } from "./ledger.js";
import { Guard } from "./guard.js";
import { loadSession } from "./session.js";
import { compare } from "./auth.js";
import { browse } from "./browser.js";
import { runParamProbes, runAdaptiveParamProbes } from "./probe.js";

// Worker:执行一条已经 active、且审批门已满足的意图。
// 动作是白名单;执行完把结果写回意图并结单。没有隐式重试,没有自选目标。

const ACTIONS = new Set(["probe", "compare", "browser", "param", "param_adaptive"]);

function withSession(projectDir, name, headers = {}) {
  if (!name) return headers;
  return { ...loadSession(projectDir, name).headers, ...headers };
}

function summarize(action, output) {
  if (action === "probe") {
    return `probe ${output.url} → HTTP ${output.status}, ${output.body_bytes} bytes, request_id=${output.request_id}`;
  }
  if (action === "compare") {
    return `compare ${output.url} → ${output.verdict}, similarity=${output.diff?.similarity ?? "n/a"}, request_ids=${output.a?.request_id}/${output.b?.request_id}`;
  }
  if (action === "browser") {
    return `browser ${output.final_url} → HTTP ${output.status}, title="${output.title}", xhr=${output.xhr?.length ?? 0}, blocked=${output.counts?.blocked ?? 0}`;
  }
  if (action === "param" || action === "param_adaptive") {
    const ids = (output.findings || []).map((finding) => finding.id).join(",") || "none";
    return `${action} ${output.targets?.[0] || ""} → findings=${output.findings?.length ?? 0} (${ids}), requests=${output.stats?.requests ?? 0}`;
  }
  return `${action} → completed`;
}

export async function runWorkerAction(projectDir, options = {}) {
  const intentId = String(options.intentId || "");
  const action = String(options.action || "");
  if (!intentId) throw new Error("需要 intent_id(先 claim)");
  if (!ACTIONS.has(action)) throw new Error(`未知 worker 动作:${action}(支持:${[...ACTIONS].join("/")})`);

  const ledger = loadLedger(projectDir);
  const intent = ledger.intents.find((item) => item.id === intentId);
  if (!intent) throw new Error(`intent 不存在:${intentId}`);
  if (intent.status !== "active") {
    throw new Error(`intent ${intentId} 当前是 ${intent.status};先 claim 再执行。`);
  }
  if (intent.requires_approval && !intent.approved) {
    throw new Error(`intent ${intentId} 需要审批:先 fairy_ledger_advance(action="approve")。`);
  }

  const url = String(options.url || "");
  const headers = withSession(projectDir, options.session, options.headers || {});
  const guard = new Guard(projectDir);
  let output;
  try {
    if (action === "probe") {
      if (!url) throw new Error("probe 需要 url");
      output = await guard.request(url, { method: options.method || "GET", headers });
    } else if (action === "compare") {
      if (!url || !options.session_a || !options.session_b) throw new Error("compare 需要 url + session_a + session_b");
      guard.useJar = false;
      output = await compare(guard, {
        url,
        marker: options.marker,
        aHeaders: withSession(projectDir, options.session_a, options.headers || {}),
        bHeaders: withSession(projectDir, options.session_b, options.headers || {}),
      });
    } else if (action === "browser") {
      if (!url) throw new Error("browser 需要 url");
      const session = options.session ? loadSession(projectDir, options.session) : null;
      output = await browse(guard, {
        url,
        session: options.session || null,
        sessionHeaders: session ? session.headers : null,
        waitMs: options.wait_ms,
        screenshot: options.screenshot !== false,
      });
    } else if (action === "param") {
      if (!url || !options.param) throw new Error("param 需要 url + param");
      output = await runParamProbes(guard, {
        urls: [url],
        confirm: true,
        classes: options.classes,
        headers,
        maxParams: 1,
        paramFilter: options.param,
      });
    } else if (action === "param_adaptive") {
      if (!url || !options.param) throw new Error("param_adaptive 需要 url + param");
      output = await runAdaptiveParamProbes(guard, {
        url,
        param: options.param,
        confirm: true,
        classes: options.classes,
        headers,
      });
    }
  } finally {
    guard.close();
  }

  const note = summarize(action, output).slice(0, 900);
  const saved = appendLedger(projectDir, (current) => {
    const target = current.intents.find((item) => item.id === intentId);
    if (!target) throw new Error(`intent 不存在:${intentId}`);
    if (options.complete === false) return target;
    return completeIntent(current, intentId, { status: "done", note });
  });

  return {
    ok: true,
    intent_id: intentId,
    action,
    result: output,
    intent: saved,
    note: options.complete === false ? "结果已返回,意图保持 active" : "结果已写回,意图已完成",
  };
}
