// Web 攻击链知识库:把"发现"翻译成"可证明的影响链"。
// 只产计划,不发请求。每一步都写清楚:做什么、拿到什么算证到、风险、是否需要人批准、在哪停。

const hasFinding = (ctx, kind, predicate = () => true) => ctx.findings.some((f) => f.kind === kind && predicate(f));
const hasFactTag = (ctx, tag) => ctx.facts.some((f) => (f.tags || []).includes(tag));
const hasAssetType = (ctx, type, predicate = () => true) => ctx.assets.some((a) => a.type === type && predicate(a));

export const PLAYBOOKS = [
  {
    id: "cors-credential-read",
    title: "CORS 任意源 + 凭证 → 跨站读取",
    attack_class: "CWE-942 / CORS misconfiguration",
    goal: "证明攻击者源能在受害者登录态下读到本应同源的敏感响应",
    requires: [
      { label: "CORS 反射任意源且允许凭证", test: (ctx) => hasFinding(ctx, "cors", (f) => f.severity === "high") },
      { label: "存在登录态(Cookie 或 Bearer)", test: (ctx) => hasFactTag(ctx, "session") || hasFinding(ctx, "cookie") },
    ],
    steps: [
      { action: "准备两个你自己拥有的测试账号 A/B,以及一个你控制的攻击者源(本地 127.0.0.1 页面即可)。", proof: "账号与源的就绪记录", risk: "low", approval: false, requests: 0 },
      { action: "用 A 登录目标,在 A 账号里预先放一条带唯一标记的数据;在同浏览器打开攻击者源页面,由页面 fetch 目标敏感接口。", proof: "攻击者源读到 A 的标记数据", risk: "medium", approval: true, requests: 2 },
      { action: "换一个敏感接口重复一次,确认不是单接口特例。", proof: "第二条接口同样可读", risk: "medium", approval: true, requests: 2 },
    ],
    stop: "读到一条你自己账号的标记数据即停。不遍历、不导出、不读取他人数据。",
    safety: ["只用你自己的两个账号", "标记数据由你预先写入", "跨站读取证明成立后立刻停"],
    budget: "≤4 请求",
    refs: ["CWE-942", "OWASP A05:2021"],
  },
  {
    id: "open-redirect-oauth",
    title: "开放重定向 + OAuth → 授权码/token 劫持",
    attack_class: "CWE-601 / OAuth redirect_uri",
    goal: "证明跳转参数可把 OAuth 授权码或 token 送到攻击者控制的外部源",
    requires: [
      { label: "存在可控跳转参数", test: (ctx) => hasFinding(ctx, "open-redirect") },
      { label: "观察到 OAuth/OIDC 授权端点", test: (ctx) => hasFactTag(ctx, "oauth") || hasFactTag(ctx, "oidc") },
    ],
    steps: [
      { action: "确认 redirect_uri 的校验粒度:精确匹配、前缀匹配,还是允许附加路径/子域。", proof: "不同 redirect_uri 变体的响应差异", risk: "low", approval: false, requests: 3 },
      { action: "用测试账号 A 走一遍授权流程,观察 code/token 是否被送到你的 canary 域名。", proof: "canary 收到一次 code", risk: "medium", approval: true, requests: 2 },
      { action: "确认 code 是否可被换 token(只验证一次,不读业务数据)。", proof: "一次 token 交换结果", risk: "high", approval: true, requests: 1 },
    ],
    stop: "拿到一次授权码即停;不换 token、不读数据、不复用。禁止对真实用户发起。",
    safety: ["只用测试账号", "canary 必须是你自己的域名", "证到 redirect 成立即可收手"],
    budget: "≤6 请求",
    refs: ["CWE-601", "RFC 6749 §3.1.2"],
  },
  {
    id: "reflected-xss",
    title: "反射点 + 弱 CSP/无 HttpOnly → 会话风险",
    attack_class: "CWE-79 / XSS",
    goal: "证明反射参数处于可执行上下文,并评估会话暴露面",
    requires: [
      { label: "参数值反射进响应", test: (ctx) => hasFinding(ctx, "reflection") },
      {
        label: "缺 CSP 或 Cookie 缺 HttpOnly",
        test: (ctx) => hasFinding(ctx, "security-header", (f) => /CSP/.test(f.title)) || hasFinding(ctx, "cookie"),
      },
    ],
    steps: [
      { action: "用 web_browser 打开反射 URL,看 DOM 里标记落在文本、属性还是脚本上下文(拿截图/文本)。", proof: "上下文截图/片段", risk: "low", approval: false, requests: 1 },
      { action: "若在可执行上下文,用 web_browser 的 eval 动作构造最小无害证明(仅改 document.title 为 fairy-proof),不读取 cookie。", proof: "标题变化", risk: "medium", approval: true, requests: 1 },
      { action: "评估会话 Cookie 是否可被脚本读取;只记录属性,不实际外传。", proof: "Cookie 属性对照", risk: "low", approval: false, requests: 0 },
    ],
    stop: "证明脚本可执行即停。不窃取 Cookie、不发起请求、不落地后门。",
    safety: ["最小证明只改标题", "只在测试账号会话里验证", "不构造窃取链"],
    budget: "≤3 请求",
    refs: ["CWE-79", "OWASP A03:2021"],
  },
  {
    id: "git-source-leak",
    title: "Git/备份暴露 → 源码 → 凭据",
    attack_class: "CWE-538 / source disclosure",
    goal: "确认源码泄露范围,并把源码交给静态分析找可利用凭据",
    requires: [{ label: "Git 或备份文件可访问", test: (ctx) => hasFinding(ctx, "exposure", (f) => /Git|备份|源码|\.env/i.test(f.title)) }],
    steps: [
      { action: "只读请求 /.git/config 与 /.git/HEAD,确认仓库类型与 remote;不 clone、不整库下载。", proof: "config 片段(脱敏)", risk: "low", approval: false, requests: 2 },
      { action: "由人决定最小恢复范围;恢复出的源码交给 Verdex scan / secrets 做静态审计。", proof: "secrets/scan 结果", risk: "medium", approval: true, requests: 0 },
      { action: "若发现硬编码凭据:只确认其归属与权限边界,不做登录尝试,按披露流程处理。", proof: "凭据类型与位置(脱敏)", risk: "high", approval: true, requests: 0 },
    ],
    stop: "拿到 config 即停;不 clone 全库,不尝试用泄露凭据登录。",
    safety: ["只读最小文件", "源码本地审计", "凭据只登记不使用"],
    budget: "≤2 请求",
    refs: ["CWE-538", "OWASP A01:2021"],
  },
  {
    id: "idor-bola",
    title: "对象级越权(BOLA/IDOR)",
    attack_class: "CWE-639 / broken object level auth",
    goal: "证明账号 B 能读取账号 A 的对象",
    requires: [
      { label: "存在带对象标识的参数/路径", test: (ctx) => hasAssetType(ctx, "param") || hasAssetType(ctx, "endpoint") },
      { label: "已登记两个测试账号", test: (ctx) => hasFactTag(ctx, "accounts") || hasAssetType(ctx, "account") },
    ],
    steps: [
      { action: "账号 A 创建一条带唯一标记的资源,记录对象 id。", proof: "A 的资源 id", risk: "low", approval: false, requests: 1 },
      { action: "用 web_compare(session_a=A 所有者, session_b=B 另一账号, marker=A 对象里的唯一串)请求同一接口,只读一次。", proof: "verdict=marker-in-both,且 B 侧命中 A 的标记", risk: "medium", approval: true, requests: 2 },
      { action: "换一个资源类型重复一次,确认不是单点。", proof: "第二类对象同样越权", risk: "medium", approval: true, requests: 1 },
    ],
    stop: "读到一条属于 A 的标记即停。不遍历 id、不批量导出、不修改/删除他人数据。",
    safety: ["只用自建测试账号", "只读不写", "单 id 证明即停"],
    budget: "≤3 请求",
    refs: ["CWE-639", "OWASP API1:2023"],
  },
  {
    id: "ssrf-canary",
    title: "SSRF → 带外回连证明",
    attack_class: "CWE-918 / SSRF",
    goal: "证明服务端会代替你请求外部地址,且不触碰内网",
    requires: [
      { label: "存在疑似 URL/回调参数", test: (ctx) => hasAssetType(ctx, "param") },
      { label: "已准备自己的 canary 监听", test: (ctx) => hasFactTag(ctx, "canary") },
    ],
    steps: [
      { action: "让参数指向你自己的 canary(如 https://<your-canary>/fairy-<random>),观察回连。", proof: "canary 收到一次请求", risk: "medium", approval: true, requests: 1 },
      { action: "如需证明可读回显,只请求你自己的公网页面,不碰内网/元数据。", proof: "响应中出现你的页面标记", risk: "medium", approval: true, requests: 1 },
    ],
    stop: "一次回连即停。禁止探测内网、云元数据、localhost 服务。",
    safety: ["只打自己的 canary", "不扫内网", "不读元数据"],
    budget: "≤2 请求",
    refs: ["CWE-918", "OWASP A10:2021"],
  },
  {
    id: "api-docs-authz",
    title: "API 文档暴露 → 鉴权矩阵 → BFLA",
    attack_class: "CWE-285 / broken function level auth",
    goal: "用公开的 API 文档找出未授权/越权端点",
    requires: [
      {
        label: "发现 Swagger/OpenAPI/Actuator 等文档",
        test: (ctx) =>
          hasFinding(ctx, "exposure", (f) => /Swagger|Actuator|API/i.test(f.title)) || hasFactTag(ctx, "api-docs"),
      },
    ],
    steps: [
      { action: "拉取 OpenAPI/Swagger JSON,列出端点与声明的鉴权方式。", proof: "端点清单", risk: "low", approval: false, requests: 1 },
      { action: "用普通测试账号访问标注为 admin 的只读端点,只读一次。", proof: "普通账号拿到 admin 响应", risk: "medium", approval: true, requests: 1 },
      { action: "对未见文档的端点做一次 401/403 基线对照。", proof: "鉴权矩阵", risk: "low", approval: false, requests: 2 },
    ],
    stop: "证明一个函数级越权即停。不调用写接口、不批量枚举。",
    safety: ["只读端点", "单次证明", "不触发写操作"],
    budget: "≤4 请求",
    refs: ["CWE-285", "OWASP API5:2023"],
  },
  {
    id: "sourcemap-leak",
    title: "Source Map 暴露 → 前端源码 → 隐藏接口",
    attack_class: "CWE-540 / information exposure",
    goal: "从 .map 还原前端路由与接口,扩大可测面",
    requires: [
      {
        label: "发现 .map 或前端源码暴露",
        test: (ctx) => hasFactTag(ctx, "sourcemap") || hasFinding(ctx, "exposure", (f) => /\.map|source ?map/i.test(f.title)),
      },
    ],
    steps: [
      { action: "只拉一个 .map 验证可访问,确认 sources 列表。", proof: "sources 片段", risk: "low", approval: false, requests: 1 },
      { action: "提取接口路径与参数,交给 Verdex js_deobfuscate / scan。", proof: "端点清单", risk: "low", approval: false, requests: 0 },
      { action: "对新发现的端点回到 web_scan 做只读基线。", proof: "新增攻击面", risk: "low", approval: false, requests: 3 },
    ],
    stop: "不批量下载全部 chunk;拿到端点清单即停。",
    safety: ["单文件验证", "不整站镜像", "源码本地分析"],
    budget: "≤4 请求",
    refs: ["CWE-540"],
  },
];

export function planChains(ledger) {
  const ctx = { findings: ledger.findings || [], facts: ledger.facts || [], assets: ledger.assets || [] };
  const results = [];
  for (const playbook of PLAYBOOKS) {
    const matched = [];
    const missing = [];
    for (const requirement of playbook.requires) {
      if (requirement.test(ctx)) matched.push(requirement.label);
      else missing.push(requirement.label);
    }
    if (!matched.length) continue;
    results.push({
      id: playbook.id,
      title: playbook.title,
      attack_class: playbook.attack_class,
      goal: playbook.goal,
      readiness: missing.length ? "blocked" : "ready",
      matched,
      missing,
      steps: playbook.steps,
      stop: playbook.stop,
      safety: playbook.safety,
      budget: playbook.budget,
      refs: playbook.refs || [],
    });
  }
  results.sort((a, b) => (a.readiness === b.readiness ? 0 : a.readiness === "ready" ? -1 : 1));
  return results;
}
