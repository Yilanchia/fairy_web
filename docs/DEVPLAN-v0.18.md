# Fairy / Web 精进开发文档 v0.18 — 自治闭环 + 账号编排

> 交付对象:实现者(DeepSeek 等)。本文档自包含,不依赖对话上下文。
> 读完就能动手:每个模块给出目标、涉及文件、精确接口/数据结构、实现要点、验收测试。
>
> **总原则(不可动摇):** 只补"规划自治 + 账号省力 + 证据深度",**不**加自动利用、
> 横向、凭据窃取、WAF 真载荷绕过。Fairy 的卖点是"授权 + 可复核 + 停在影响成立处",
> 任何让它变成攻击机器人的改动一律拒绝。现有的 scope 护照、逐请求审计、数据最小化、
> 审批门,全部保留,新能力必须套在这些闸门之内。

---

## 0. 现状诊断(为什么偏弱)

Fairy 的"手"很全(scan/crawl/browser/compare/param/waf/matrix),"脑"太浅:

1. **推断只认人喂的 context**:`src/work.js` 的 `inferWork(chainId, stepIndex, context)`
   是 6 条链的硬编码表,且只有调用方传了 `context` 才动。账本里其实已经有 base_url、
   参数、会话、marker,但推断不读账本。
2. **闭环断在"观察→下一步"**:`src/worker.js` 执行完把结果写回意图并结单,但**不把
   观察归一成 fact**;`src/auto.js` 跑完预声明的 work 就停在 `needs_action`。于是链无法
   自走,模型得一步一个 MCP 调用手推。
3. **账号全靠人**:BOLA/IDOR/BFLA(高价值发现)需要 ≥2 个已登录身份 + 已知归属,
   现在每次都要人注册账号、手递 cookie、手填 `--a/--b/--marker`。

本次要解决的就是这三点。模块 1、2 解决"脑浅",模块 3、4、5 解决"账号靠人"。

---

## 1. 模块一:账本驱动的 work 推断(P1,最大自治解锁)

**目标**:`inferWork` 在调用方没传 context 时,也能从账本 facts/assets + 会话清单派生
context,让 `fairy_auto_run` 不喂 context 也能自走几步。

**涉及文件**:`src/work.js`(改)、`src/planner.js`(改)、`src/session.js`(读)。

**新增函数(src/work.js):**

```js
// 从账本 + 会话清单派生 work 推断用的 context。显式 context 永远覆盖派生值。
export function deriveContext(ledger, extras = {}) {
  const derived = {};
  // base_url:取第一个 host 资产;私网/IP 用 http,否则 https(可被 extras 覆盖)
  const host = (ledger.assets || []).find((a) => a.type === "host");
  if (host) {
    const scheme = /^(?:\d+\.|localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(host.value)
      ? "http" : "https";
    derived.base_url = `${scheme}://${host.value}`;
  }
  // url/param:取第一个带查询串的 endpoint 资产
  const ep = (ledger.assets || []).find((a) => a.type === "endpoint" && a.value.includes("?"));
  if (ep && host) {
    try {
      const u = new URL(ep.value, derived.base_url);
      derived.url = u.href;
      const firstParam = [...u.searchParams.keys()][0];
      if (firstParam) derived.param = firstParam;
    } catch { /* ignore */ }
  }
  // sessions:调用方传入的已保存会话名(planner 从 listSessions 拿)
  const sessions = Array.isArray(extras.sessions) ? extras.sessions : [];
  if (sessions[0]) derived.session_a = sessions[0];
  if (sessions[1]) derived.session_b = sessions[1];
  return { ...derived, ...extras.context }; // 显式 context 优先
}
```

**改 src/planner.js 的 `materializeChain`**:落单前构造派生 context。

```js
import { inferWork, deriveContext } from "./work.js";
import { listSessions } from "./session.js";
// ...在 appendLedger 回调里,构造 ctx:
const ctx = deriveContext(ledger, {
  sessions: listSessions(projectDir).map((s) => s.name),
  context: options.context || {},
});
// 原来的 inferWork(chainId, index + 1, options.context || {}) 改为:
const planned = workPlan.get(index + 1) || inferWork(chainId, index + 1, ctx) || null;
```

**实现要点**
- `deriveContext` 是**纯函数**,不发请求、不读 session 明文(只读会话名)。
- `inferWork` 的 RULES 表不动签名,只是现在喂给它的 context 更全。
- base_url 的 scheme 是启发式,文档里注明可被 `options.context.base_url` 覆盖。

**验收测试(tests/work.test.mjs 新增)**
- 账本里有 host 资产 `127.0.0.1:8080` + 一个 `/item?id=1` endpoint,`deriveContext` 返回
  `base_url=http://127.0.0.1:8080`、`url=.../item?id=1`、`param=id`。
- 存了 `alice`/`bob` 两个会话,`deriveContext` 带出 `session_a=alice`、`session_b=bob`。
- 显式传 `context.base_url` 时覆盖派生值。
- `materializeChain` 对 `git-source-leak` 链:不传 context 也能从账本派生出 step1 的
  probe work(`/.git/config`),`intent.work.inferred === true`。

---

## 2. 模块二:事件驱动闭环 — worker 观察回灌成 fact(P1)

**目标**:worker 执行完把**可判定的观察**归一成账本 fact,下一轮 `plannerTick` /
`deriveContext` 据此选下一步,形成 ARTEX 式"图一变就推进"的闭环。

**涉及文件**:`src/worker.js`(改)、`src/ledger.js`(用现成 `addFact`)。

**新增函数(src/worker.js):**

```js
// 把 worker 动作的输出归一成 0..N 条 fact。只记可判定的观察,不编造漏洞。
function factsFromResult(action, output) {
  const facts = [];
  const ev = (url, note) => [{ kind: "http", request_id: output.request_id || null, url, note }];
  if (action === "probe" && output.status === 200 && /\/\.git\/config$/.test(output.url || "")) {
    facts.push({ statement: `git 配置可读:${output.url}`, confidence: "observed",
      tags: ["git", "exposed"], evidence: ev(output.url, "worker probe 200") });
  }
  if (action === "compare" && output.verdict === "marker-in-both") {
    facts.push({ statement: `越权候选:${output.url} 标记在两账号均可见`, confidence: "observed",
      tags: ["bola", "idor"], evidence: ev(output.url, `verdict=${output.verdict}`) });
  }
  if ((action === "param" || action === "param_adaptive") && (output.findings || []).length) {
    for (const f of output.findings) {
      facts.push({ statement: `参数探针命中 ${f.kind}:${f.where || output.targets?.[0] || ""}`,
        confidence: "observed", tags: ["param", f.kind], evidence: ev(f.where, "存在性探针") });
    }
  }
  return facts;
}
```

**改 src/worker.js 的结单逻辑**:在 `completeIntent` 的同一个 `appendLedger` 事务里写 fact。

```js
const derivedFacts = factsFromResult(action, output);
const saved = appendLedger(projectDir, (current) => {
  const target = current.intents.find((item) => item.id === intentId);
  if (!target) throw new Error(`intent 不存在:${intentId}`);
  for (const f of derivedFacts) addFact(current, f);   // 新增:观察回灌
  if (options.complete === false) return target;
  return completeIntent(current, intentId, { status: "done", note });
});
```
(需在 worker.js 顶部 `import { ..., addFact } from "./ledger.js"`。)

**实现要点**
- `addFact` 已自带去重(statement 相同不重复),重复执行幂等。
- 只记"观察到的事实",confidence 一律 `observed`;**不**在这里造 finding(finding 仍走
  `fairy_ingest`,保持候选→人工 verified 的纪律)。
- 不改 `auto.js` 的停止语义:仍然遇审批门停、无 work 停、失败不重试。推进力来自"新 fact
  让下一条链 ready / 让 deriveContext 能派生下一步",不是自动批准。

**验收测试(tests/tick.test.mjs 扩展)**
- worker probe 命中 `/.git/config` 200 后,账本出现 `git 配置可读` fact。
- worker compare 得 `marker-in-both` 后,账本出现 `越权候选` fact。
- 同一动作执行两次,fact 不重复(幂等)。

---

## 3. 模块三:账号编排层 — accounts manifest(解决测试账号痛点,P1)

**目标**:把人的介入从"每次会话手递 cookie"压到"一次放一份清单"。授权人一次性写
`.fairy/accounts.json`,Fairy 批量登录成命名会话、记录角色与对象归属,之后 compare /
role_matrix 自动配对。

**涉及文件**:新增 `src/accounts.js`;`src/mcp.js`(加 2 个工具);`src/cli.js`(加命令);
复用 `src/auth.js:login`、`src/session.js:saveSession`、`src/ledger.js:addAsset`(已有
`account` 类型)+ `addFact`;`.gitignore` 加 `accounts.json`。

**清单格式 `.fairy/accounts.json`(FairyAccounts/v1):**

```json
{
  "schema": "FairyAccounts/v1",
  "accounts": [
    {
      "name": "alice", "role": "user",
      "login": {
        "url": "http://127.0.0.1:8080/login", "method": "POST",
        "fields": { "username": "alice" },
        "password_env": "FAIRY_ACCT_ALICE",
        "token_field": null
      },
      "owns": [ { "marker": "ALICE-ORDER-7001", "url": "/api/orders/7001", "note": "alice 的订单" } ]
    },
    { "name": "bob", "role": "user",
      "login": { "url": "...", "fields": { "username": "bob" }, "password_env": "FAIRY_ACCT_BOB" }, "owns": [] },
    { "name": "admin", "role": "admin",
      "login": { "url": "...", "fields": { "username": "admin" }, "password_env": "FAIRY_ACCT_ADMIN" } }
  ]
}
```

**关键安全约束(写死)**
- 密码**不写进 clear**:清单里用 `password_env` 指向环境变量名,登录时 `process.env` 现取;
  也允许 `password`(明文)但加载时告警。`accounts.json` 强制 0600 + 进 `.gitignore`。
- 清单、会话值**永不回显**:`fairy_accounts_show` 只输出 name/role/owns.marker/会话是否就绪,
  绝不输出密码、cookie、token。
- 登录是**写操作**:`provisionAccounts` 前检查 scope `limits.methods` 含 POST,否则直接拒绝
  (复用 `auth.js:login` 里现成的方法校验)。
- 每个账号只登录一次(`auth.js:login` 本就不重试、不爆破)。

**新增函数(src/accounts.js):**

```js
export const ACCOUNTS_SCHEMA = "FairyAccounts/v1";
export function loadAccounts(projectDir) { /* 读 .fairy/accounts.json,校验 schema,返回 accounts[] */ }

// 按清单批量登录:对每个账号跑 auth.login → 存成同名会话;把账号与归属写进账本。
export async function provisionAccounts(projectDir, options = {}) {
  // options.only: 只登录指定 name 子集
  // 对每个 account:
  //   1) 取密码:account.login.password_env ? process.env[...] : account.login.password
  //   2) new Guard(projectDir),调 login(guard, {url, session: name, method, fields:{...fields, password}, token_field})
  //   3) appendLedger: addAsset({type:"account", value:name, tags:[role]});
  //      对 owns[] 每条 addFact({statement:`${name} 拥有对象 ${marker} (${url})`, confidence:"observed", tags:["ownership", role]})
  //   4) 汇总 {name, role, session_ready:true/false, error} —— 不含任何凭据
  // 返回 { provisioned: [...], failed: [...] }  仅元数据
}

// 从归属关系生成 BOLA 对照 work(喂给 worker 'compare'),无需人手填 --a/--b/--marker。
export function bolaPairs(accounts) {
  // 对每个有 owns 的 owner A,对每个其他账号 B:
  //   { action:"compare", args:{ url: owner.base+own.url, session_a: A, session_b: B, marker: own.marker } }
}
```

**MCP 工具(src/mcp.js,照现有 `{name, description, inputSchema, run}` 模式加):**
- `fairy_accounts_provision`:`{project, only?:string[]}` → 调 `provisionAccounts`。发包(登录)。
- `fairy_accounts_show`:`{project}` → 调 `loadAccounts` + `listSessions`,只回元数据。不发包。

**CLI(src/cli.js):** `node src/cli.js accounts <project> [--only alice,bob]`。

**验收测试(tests/accounts.test.mjs,用 tests/fixture-server.mjs):**
- 清单含 alice/bob/admin,`provisionAccounts` 后三个命名会话就绪,账本出现 3 条 account 资产。
- scope `methods` 不含 POST 时 `provisionAccounts` 抛错拒绝。
- `fairy_accounts_show` 输出不含密码/cookie(断言 header 值、password 不出现)。
- `bolaPairs` 对 alice(owns ORDER-7001)/bob 生成 compare work,marker 正确。

---

## 4. 模块四:自建对象做归属真值(BOLA 更安全,P2)

**目标**:不去读真实用户的对象来证 BOLA,而是让账号**自己创建**对象,拿到自己的 ID 作
marker,再测别人能否读。归属是自造的 ground truth,证据更硬,也不碰真实数据。

**涉及文件**:`src/accounts.js`(扩展 seed)、新增 scope 开关 `allow_object_seeding`
(`src/scope.js:DEFAULT_LIMITS` 加 `allow_object_seeding: false`)。

**清单扩展**:每个 account 可选 `seed`:

```json
"seed": {
  "create": { "url": "/api/orders", "method": "POST", "fields": { "item": "fairy-probe" } },
  "extract": { "from": "json", "path": "id" }   // 或 { "from":"regex", "pattern":"order/(\\d+)" }
}
```

**实现要点**
- 创建对象是**写操作**:要 scope `methods` 含 POST **且** `limits.allow_object_seeding === true`
  **且** 调用 `confirm: true`,三者缺一拒绝。
- 创建成功后把 `extract` 出来的 id 作为该账号 `owns` 的 marker 写进账本(confidence observed),
  再交给 `bolaPairs` 生成对照。
- 只创建**最小探针对象**(如一条带唯一标记的备注/订单),不批量、不删别人数据。
- 停止点:证到"B 能读 A 自建对象"即停,不 dump、不改、不横向。

**验收**:靶场 alice 自建订单拿到 id,bob compare 得 `marker-in-both` → 自造 ground truth 的
BOLA 候选;关闭 `allow_object_seeding` 时 seed 被拒。

---

## 5. 模块五:自助注册(opt-in,重门禁,P3 — 最后做、可选)

**目标**:目标站开放注册时,让 agent 自己注册测试账号,进一步减少人工。**但这是最危险的
一块,必须重门禁,且遇到反自动化控制就停下问人。**

**涉及文件**:新增 `src/register.js`;`src/scope.js` 加开关 `allow_account_provisioning: false`;
复用 `src/browser.js`(填表)、`src/auth.js:login`、`src/accounts.js`(写回清单)。

**硬约束(不可绕过)**
- 要 scope `allow_account_provisioning === true` **且** `methods` 含 POST **且** `confirm: true`。
- **只处理邮箱验证链**:邮箱必须是授权人自己控制的收件箱(IMAP 配置走 env:`FAIRY_MAIL_*`),
  Fairy 轮询收件箱取验证链接。
- **遇到 CAPTCHA / 短信 / 手机验证一律停下返回 `needs_human`**,绝不自动识别验证码、绝不
  对接打码平台、绝不处理 SMS。自动绕过反自动化控制既破坏控制、多半违反 ToS,**不做**。
- 注册成功后把账号写进 `.fairy/accounts.json`(password_env 指向新生成的随机密码,存 env/vault,
  不落明文到报告)。

**流程**:`register(projectDir, {signup_url, email, ...})` → 浏览器填注册表单提交 →
轮询邮箱取验证链 → probe 验证链 → 若中途出现 CAPTCHA/phone 字段,返回 `{status:"needs_human", reason}`。

**验收**:靶场纯邮箱注册流程可自动完成并写回清单;带 CAPTCHA 的注册页返回 `needs_human`、
不提交。关闭 `allow_account_provisioning` 时整个工具拒绝。

---

## 6. 模块六:证据深度到"影响边界"(P2,差异化)

**目标**:在不发真实载荷的前提下,把链多走一格到**可定级**,拉高 verified/candidate 比率
(这是 STRATEGY.md 定的质量指标),让"已证"比别人的"疑似"值钱。

**涉及文件**:新增 `src/proof.js`;`src/playbooks.js`(reflected-xss 链补一步)、
`src/work.js`(reflected-xss 的推断链到 dom_context)。

**规则(只升置信,不造载荷):**
- **反射 XSS**:reflection 候选 → 自动接 `web_dom_context` 判上下文 + 读 CSP。
  落在 `<script>` 上下文 **且** 无 CSP → 写 fact`反射落在 script 上下文且无 CSP → XSS 可证`,
  并把对应 finding 的 `confidence` 升到 high(仍是 candidate,仍不生成 payload)。
- **SQLi**:存在性探针命中后,只做一次**有界布尔确认**即停,不 UNION/堆叠/时间盲注/取数。

**实现要点**:`src/proof.js` 导出 `classifyProof(ledger)`,读 facts 给出"可证/需人工复核"
标签 + 原因,供 `fairy_report_bundle` 展示。**绝不**自动把 candidate 直接改成 verified
——verified 永远是人工动作(保留 `fairy_ledger_advance`)。

**验收**:靶场反射参数落在 script 上下文且无 CSP → finding 置信升 high + `XSS 可证` fact;
有 CSP 或落在文本上下文时不升级。

---

## 7. 模块七:跨 engagement 记忆(P3,路线图已列)

**目标**:"这个站用 Cloudflare、登录在 /auth、x/y/z 参数会反射"——跨 engagement 记下来,
重复目标直接跳过重探。

**涉及文件**:新增 `src/memory.js`;存储在用户级目录 `FAIRY_MEMORY_DIR`(默认
`~/.fairy/memory.json`),**不**放进 engagement 目录、**不**进仓库。

**数据(按 host 归档,只存非敏感元数据):**

```json
{ "schema": "FairyMemory/v1",
  "hosts": { "example.com": {
    "tech": ["nginx", "php"], "waf": "cloudflare",
    "login_paths": ["/auth/login"], "reflecting_params": ["q", "redirect"],
    "prior_finding_kinds": ["cors", "open-redirect"], "updated_at": "..." } } }
```

**硬约束**:只存技术栈/WAF/路径/参数名/发现类型等元数据;**绝不**存 cookie、凭据、
对象数据、响应正文、marker 值。

**接口**:`recallHost(host)` / `rememberHost(host, patch)`;`mission`/`ingest` 完成后自动
`rememberHost`;MCP 加只读 `fairy_memory_show {host}`。

**验收**:一次 engagement 后 `fairy_memory_show` 能召回该 host 的 tech/waf/反射参数;
断言记忆文件不含任何 cookie/密码字段。

---

## 8. 实施顺序与里程碑

1. **v0.18.0 自治闭环(先做,风险最低)**:模块一 + 模块二。做完 `fairy_auto_run` 不喂
   context 也能自走只读链。
2. **v0.18.1 账号编排**:模块三。做完 BOLA/矩阵"一次清单、之后自服务"。
3. **v0.18.2 证据深度 + 记忆**:模块六 + 模块七。
4. **v0.19 可选高风险**:模块四(自建对象)、模块五(自助注册),各自独立开关,默认关。

## 9. 全局不做清单(任何模块都不得触碰)

- 不自动利用:不 UNION 取数、不堆叠注入、不时间盲注、不 RCE、不横向、不持久化、不隧道。
- 不自动绕过控制:不解验证码、不对接打码、不处理 SMS、不把真实攻击载荷套进 WAF 变体。
- 不碰凭据与数据:密码/cookie/token 永不回显、永不入报告;发现敏感数据即停,不 dump。
- 不自动升级结论:candidate→verified 永远是人工;自动循环遇审批门必停,不自动 approve。
- 不越权越界:所有新发包工具一律走 scope 护照 + Guard 审计 + 限速;登录/创建对象需 scope
  显式授权写方法。

## 10. 文档与测试收尾

- 每个模块都要有 `tests/*.test.mjs`,复用 `tests/fixture-server.mjs`(只听 127.0.0.1)。
- 更新 `README.md` 工具表、`docs/STRATEGY.md` 对标表、`CHANGELOG.md`。
- `bench/` 基准跑通,确认已知类别不退化(recall/precision 不下降)。
