// 从 chain_id + step_index + context 推断一个最小、只读的 work。
// 没有 context 就不猜;推断出来的 work 会标记 inferred=true,仍然走审批门。

function withParam(base, name, value) {
  const url = new URL(base);
  url.searchParams.set(name, value);
  return url.href;
}

const RULES = {
  "idor-bola": {
    2: (context) =>
      context.url && context.session_a && context.session_b && context.marker
        ? {
            action: "compare",
            args: {
              url: context.url,
              session_a: context.session_a,
              session_b: context.session_b,
              marker: context.marker,
            },
          }
        : null,
  },
  "reflected-xss": {
    1: (context) =>
      context.url
        ? {
            action: "browser",
            args: {
              url: context.url,
              ...(context.session_a ? { session: context.session_a } : {}),
            },
          }
        : null,
  },
  "git-source-leak": {
    1: (context) => {
      if (!context.base_url) return null;
      try {
        return { action: "probe", args: { url: new URL("/.git/config", context.base_url).href } };
      } catch {
        return null;
      }
    },
  },
  "sourcemap-leak": {
    1: (context) => (context.map_url ? { action: "probe", args: { url: context.map_url } } : null),
  },
  "api-docs-authz": {
    1: (context) => (context.doc_url ? { action: "probe", args: { url: context.doc_url } } : null),
  },
  "ssrf-canary": {
    1: (context) => {
      if (!context.url || !context.param || !context.canary_url) return null;
      try {
        return {
          action: "probe",
          args: { url: withParam(context.url, context.param, context.canary_url) },
        };
      } catch {
        return null;
      }
    },
  },
};

export function inferWork(chainId, stepIndex, context = {}) {
  const rule = RULES[chainId] && RULES[chainId][stepIndex];
  if (!rule) return null;
  const work = rule(context || {});
  if (!work) return null;
  return {
    action: work.action,
    args: work.args,
    inferred: true,
    note: `inferred from ${chainId} step ${stepIndex}`,
  };
}
