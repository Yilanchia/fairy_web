import { plannerTick } from "./planner.js";
import { appendLedger, claimNextIntent, loadLedger } from "./ledger.js";
import { runWorkerAction } from "./worker.js";

// 自动循环:planner tick → claim → 执行已声明的 work → 再 tick。
// 只执行意图里预先写好的 work;没有 work 就停,需要审批就停。
// 不自动 approve,不自动推断动作,不重试。

function summarizeIntent(intent) {
  return {
    id: intent.id,
    goal: intent.goal,
    chain_id: intent.chain_id,
    step_index: intent.step_index,
    risk: intent.risk,
    requires_approval: intent.requires_approval,
    approved: intent.approved,
    work: intent.work || null,
  };
}

export async function autoRun(projectDir, options = {}) {
  const maxSteps = Math.min(Math.max(Number(options.maxSteps) || 3, 1), 10);
  const steps = [];
  const started = Date.now();
  let tick = null;

  for (let index = 0; index < maxSteps; index++) {
    tick = plannerTick(projectDir, {
      materialize: options.materialize !== false,
      maxChains: 1,
      work: options.work,
    });

    if (tick.recommendation !== "claim_next") {
      return {
        schema: "FairyAuto/v1",
        status: tick.recommendation,
        steps,
        tick,
        note: "循环停在规划器的建议点;没有自动审批、没有自动推断动作。",
        stats: { steps: steps.length, duration_ms: Date.now() - started },
      };
    }

    const intent = appendLedger(projectDir, (ledger) => claimNextIntent(ledger));
    if (!intent) {
      return {
        schema: "FairyAuto/v1",
        status: "no_claimable_intent",
        steps,
        tick,
        stats: { steps: steps.length, duration_ms: Date.now() - started },
      };
    }

    if (!intent.work || !intent.work.action) {
      return {
        schema: "FairyAuto/v1",
        status: "needs_action",
        steps,
        tick,
        intent: summarizeIntent(intent),
        note: "意图没有声明 work;请提供 action/args,或手工执行 fairy_worker_run。",
        stats: { steps: steps.length, duration_ms: Date.now() - started },
      };
    }

    try {
      const { action, args } = intent.work;
      const result = await runWorkerAction(projectDir, {
        ...(args || {}),
        intentId: intent.id,
        action,
      });
      steps.push({
        intent_id: intent.id,
        action,
        status: "done",
        note: result.note,
      });
    } catch (error) {
      return {
        schema: "FairyAuto/v1",
        status: "error",
        steps,
        error: error.message,
        intent: summarizeIntent(loadLedger(projectDir).intents.find((item) => item.id === intent.id) || intent),
        tick,
        note: "执行失败;意图保持 active,不重试。",
        stats: { steps: steps.length, duration_ms: Date.now() - started },
      };
    }
  }

  return {
    schema: "FairyAuto/v1",
    status: "max_steps",
    steps,
    tick,
    note: `达到 max_steps=${maxSteps};继续调用可推进下一批。`,
    stats: { steps: steps.length, duration_ms: Date.now() - started },
  };
}
