import { loadLedger, appendLedger, addIntent } from "./ledger.js";
import { planChains } from "./playbooks.js";

// Planner:把一条 ready 链落成有依赖的意图序列。
// Worker 不直接"打整条链",只领取依赖已满足的下一步;每完成一步再唤醒下一步。

function summarize(chain) {
  return {
    id: chain.id,
    title: chain.title,
    goal: chain.goal,
    readiness: chain.readiness,
    stop: chain.stop,
    budget: chain.budget,
  };
}

export function materializeChain(projectDir, chainId, options = {}) {
  if (!chainId) throw new Error("需要 chain_id(先跑 fairy_chain_plan 查看)");

  return appendLedger(projectDir, (ledger) => {
    const chains = planChains(ledger);
    const chain = chains.find((item) => item.id === chainId);
    if (!chain) throw new Error(`链不存在或当前未命中:${chainId}`);
    if (chain.readiness !== "ready") {
      throw new Error(`链 ${chainId} 未就绪,缺少前置:${(chain.missing || []).join(" / ") || "未知"}`);
    }

    const existing = ledger.intents
      .filter((intent) => intent.chain_id === chainId)
      .sort((a, b) => (a.step_index || 0) - (b.step_index || 0));
    if (existing.length) {
      return { chain: summarize(chain), intents: existing, existing: true };
    }

    const intents = [];
    let dependsOn = [];
    for (let index = 0; index < chain.steps.length; index++) {
      const step = chain.steps[index];
      const goal = `${chain.title} · 步骤 ${index + 1}:${step.action}`.slice(0, 300);
      const intent = addIntent(ledger, {
        goal,
        depends_on: dependsOn,
        asset_ids: options.asset_ids || [],
        risk: step.risk,
        requires_approval: step.approval,
        stop_condition: chain.stop,
        chain_id: chainId,
        step_index: index + 1,
      });
      intents.push(intent);
      dependsOn = [intent.id];
    }

    return { chain: summarize(chain), intents, existing: false };
  });
}

function claimable(ledger) {
  const done = new Set(
    ledger.intents.filter((intent) => intent.status === "done" || intent.status === "skipped").map((intent) => intent.id),
  );
  return ledger.intents.filter(
    (intent) =>
      intent.status === "todo" &&
      (intent.depends_on || []).every((dependency) => done.has(dependency)) &&
      (!intent.requires_approval || intent.approved),
  );
}

export function plannerTick(projectDir, options = {}) {
  let ledger = loadLedger(projectDir);
  let chains = planChains(ledger);
  const materialized = [];

  if (options.materialize === true) {
    const maxChains = Math.min(Math.max(Number(options.maxChains) || 1, 1), 5);
    const pending = chains.filter(
      (chain) => chain.readiness === "ready" && !ledger.intents.some((intent) => intent.chain_id === chain.id),
    );
    for (const chain of pending.slice(0, maxChains)) {
      materialized.push(materializeChain(projectDir, chain.id));
    }
    ledger = loadLedger(projectDir);
    chains = planChains(ledger);
  }

  const ready = chains.filter((chain) => chain.readiness === "ready");
  const blocked = chains.filter((chain) => chain.readiness === "blocked");
  const nextIntent = claimable(ledger)[0] || null;
  const waitingApproval = ledger.intents.filter(
    (intent) =>
      intent.status === "todo" &&
      intent.requires_approval &&
      !intent.approved &&
      (intent.depends_on || []).every((dependency) => {
        const dep = ledger.intents.find((item) => item.id === dependency);
        return dep && (dep.status === "done" || dep.status === "skipped");
      }),
  );
  const active = ledger.intents.filter((intent) => intent.status === "active");
  const unmaterialized = ready.filter((chain) => !ledger.intents.some((intent) => intent.chain_id === chain.id));

  let recommendation = "idle";
  if (nextIntent) recommendation = "claim_next";
  else if (waitingApproval.length) recommendation = "approve";
  else if (unmaterialized.length) recommendation = "materialize";
  else if (active.length) recommendation = "wait_active";
  else if (ready.length) recommendation = "review_ready";

  return {
    schema: "FairyPlanner/v1",
    generated_at: new Date().toISOString(),
    ready_chains: ready.map(summarize),
    blocked_chains: blocked.map((chain) => ({ id: chain.id, title: chain.title, missing: chain.missing })),
    unmaterialized_chains: unmaterialized.map((chain) => chain.id),
    materialized: materialized.map((item) => ({
      chain: item.chain,
      intents: item.intents.map((intent) => intent.id),
      existing: item.existing,
    })),
    next_intent: nextIntent
      ? {
          id: nextIntent.id,
          goal: nextIntent.goal,
          chain_id: nextIntent.chain_id,
          step_index: nextIntent.step_index,
          risk: nextIntent.risk,
          requires_approval: nextIntent.requires_approval,
        }
      : null,
    waiting_approval: waitingApproval.map((intent) => ({
      id: intent.id,
      goal: intent.goal,
      chain_id: intent.chain_id,
      step_index: intent.step_index,
    })),
    active_intents: active.map((intent) => intent.id),
    recommendation,
    note: "tick 只读账本/落单/挑选下一步,不执行请求;执行交给 fairy_worker_run。",
  };
}
