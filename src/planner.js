import { appendLedger, addIntent } from "./ledger.js";
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
