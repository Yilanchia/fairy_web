# Fairy / Web

> Verdex 够不到的那一段,由这只手来接:**真的发 HTTP,但每一发都带着授权护照和审计。**

Verdex 是证据优先的静态分析内核——源码、逆向、pwn、固件、HAR,全都只读、只产文本、从不联网。这是它的原则,也是它的边界:web 渗透真正需要的那一步,是**和有血有肉的目标交互**。

Fairy / Web 补的就是这一步。它不是一个"更快的扫描器",而是一层**受控的请求层**:

- 没有 `fairy.scope.json` → 一个包都不发。
- 每一次请求 → 过 scope 校验、过限速、写审计、可回查 `request_id`。
- 只证明存在 → 不注入载荷、不爆破、不 dump 数据、不改状态。

三者的组合,才是能让 Fairy 真正"伸手"而不脱手的东西。

```
        ┌──────────────────────────────┐
        │  Fairy(模型)               │
        └──────────┬───────────────────┘
                   │ MCP
     ┌─────────────┴──────────────┐
     │                            │
┌────▼─────────┐          ┌───────▼──────────┐
│ fairy (本仓) │          │ verdex           │
│ 发包 / 取证  │──HAR────▶│ 静态复核 / 源码   │
│ 授权+审计    │          │ 逆向 / pwn / 固件 │
└──────────────┘          └──────────────────┘
```

Fairy 采集到的流量会脱敏导出成 `traffic.har`,直接喂给 Verdex 的 `har_analyze` 做第二遍静态复核——两只手互相校验,而不是各自为战。

---

## 快速开始(CLI)

```powershell
node src/cli.js init  D:\work\engagements\lab --include "127.0.0.1" --basis "自建靶场" --operator fairy
node src/cli.js show  D:\work\engagements\lab
node src/cli.js probe D:\work\engagements\lab "http://127.0.0.1:8080/login"
node src/cli.js crawl D:\work\engagements\lab "http://127.0.0.1:8080/" --pages 30 --depth 2
node src/cli.js scan  D:\work\engagements\lab "http://127.0.0.1:8080/" --crawl
node src/cli.js report D:\work\engagements\lab "http://127.0.0.1:8080/" --crawl
node src/cli.js har   D:\work\engagements\lab capture.har
node src/cli.js mcp   --project D:\work\engagements\lab
```

`init` 是唯一会写授权护照的命令;后面所有命令都读它。`report` 会在
`.fairy/runs/<run_id>/` 下落 `report.json` / `report.md` / `report.html` /
`scope.json` / `traffic.har`。

## MCP(让模型直接调用)

挂到 dsh 的 profile 里,模型就会看到 `mcp__fairy__*`:

```powershell
node scripts/mount-dsh.mjs            # 默认 desktop profile,自动备份
# 或者手动在 profile 的 cordis.patch.yml 里加 insert(见 scripts/mount-dsh.mjs)
```

| 工具 | 作用 | 是否发包 |
|---|---|---|
| `fairy_scope_init` | 建授权护照(include/basis/limits) | 否 |
| `fairy_scope_show` | 查看当前 scope | 否 |
| `web_probe` | 单请求取证:状态/头/正文片段/重定向/TLS/`request_id` | 是 |
| `web_crawl` | 同源爬取:标题/链接/表单/JS 端点/外链主机 | 是 |
| `web_scan` | 一轮被动+轻主动检测,按严重度出候选 | 是 |
| `web_report` | `web_scan` + 不可变快照 + 脱敏 HAR | 是 |
| `har_ingest` | 静态分析你导出的 HAR,顺带列主机清单 | 否 |
| `fairy_ledger_init` / `fairy_ledger_show` | 建/看作战账本(资产/事实/发现/意图/覆盖) | 否 |
| `fairy_ledger_add` | 追加资产/事实/发现/意图,自动去重编号 | 否 |
| `fairy_ledger_advance` | 领取/结单意图,改发现状态 | 否 |
| `fairy_ledger_ingest` | 把最近一次扫描报告导入账本 | 否 |
| `fairy_chain_plan` | 按账本匹配攻击链,给最小证明与停止点 | 否 |
| `web_login` | 单次登录并把会话存成命名 profile(不重试/不爆破) | 是 |
| `web_session` | 会话管理:list/show/create/delete,不回显值 | 否 |
| `web_compare` | 双会话差分:BOLA/IDOR/BFLA 证据骨架 | 是 |

所有网络工具都要求 `project`(作业目录),scope 与产物都落在那里,天然按 engagement 隔离。

## 作战账本与攻击链

一次 engagement 不只是"扫了一次",而是一条有状态的推进链。账本落在
`.fairy/ledger.json`(不提交、不联网):

```powershell
# CLI 也可以直接看
node -e "import('./src/ledger.js').then(m=>console.log(JSON.stringify(m.summary(m.loadLedger('D:/work/lab')),null,2)))"
```

MCP 里的典型节奏:

```
fairy_ledger_init(project)
web_report(project, urls, crawl=true)
fairy_ledger_ingest(project)            # 资产/技术栈/候选发现入账
fairy_chain_plan(project)               # ready 的链 + 每步证明 + 停止点
fairy_ledger_add(kind="fact", data={statement:"已准备测试账号 A/B", tags:["accounts"]})
fairy_ledger_advance(action="claim")    # 领取下一步意图
fairy_ledger_advance(action="done", intent_id="I-001", note="...")
```

攻击链知识库在 [`src/playbooks.js`](src/playbooks.js):CORS+凭证、开放重定向+OAuth、
反射 XSS、Git 源码泄露、BOLA、SSRF、API 文档、SourceMap。每条链都写清楚
**最小证明、风险、是否需要人批准、在哪停**,只产计划不发请求。

战略与 ARTEX 对标见 [`docs/STRATEGY.md`](docs/STRATEGY.md)。

## 认证态与 BOLA

登录是写操作,必须先在 scope 里显式授权 POST:

```powershell
node src/cli.js init D:\work\lab --include "127.0.0.1" --basis "自建靶场" --methods GET,POST
node src/cli.js login D:\work\lab http://127.0.0.1:8080/login --session alice --data "username=alice&password=..."
node src/cli.js login D:\work\lab http://127.0.0.1:8080/login --session bob   --data "username=bob&password=..."
node src/cli.js compare D:\work\lab http://127.0.0.1:8080/api/orders/2 --a bob --b alice --marker "BOB-ORDER-2"
```

结果给 `verdict`:`marker-in-both` 且 A 是资源所有者时,说明 B 能读到 A 的对象,
这就是 BOLA 候选。`compare` 默认只回状态/长度/正文哈希/相似度/标记,不回传正文。

安全约束是硬的:

- **只尝试一次**:没有重试、没有字典、没有爆破。
- **会话不裸奔**:设 `FAIRY_SESSION_KEY`(≥8 字符)则 AES-256-GCM;否则 0600 落盘并在返回里带警告。`list`/`show` 只给头名,绝不回显 Cookie/Authorization。
- **登录即写操作**:scope 的 `limits.methods` 不含 POST 时直接拒绝。
- **差分不带数据**:正文只留 sha256 与长度,证据按 `request_id` 回审计日志。

`web_scan` / `web_crawl` / `web_probe` / `web_report` 都接受 `--session`(MCP 里是 `session`),
可以直接对登录后的页面/接口做只读检测。

## 授权护照

```json
{
  "schema": "FairyScope/v1",
  "authorization": {
    "basis": "自建靶场 / 某 SRC 项目 #123 / 书面授权",
    "operator": "fairy",
    "expires_at": "2026-12-31T23:59:59+08:00"
  },
  "include": ["127.0.0.1", "*.lab.example.com", "10.10.0.0/24"],
  "exclude": ["pay.lab.example.com"],
  "limits": {
    "rps": 5,
    "max_requests": 2000,
    "max_pages": 40,
    "max_active_pages": 15,
    "timeout_ms": 10000,
    "allow_private": true,
    "verify_tls": true,
    "methods": ["GET", "HEAD", "OPTIONS"]
  }
}
```

规则是硬的:

- `basis` 少于 8 字 → 拒绝。写清楚"凭什么"。
- `*`、`*.com` 这类过宽声明 → 拒绝。
- `exclude` 永远压过 `include`。
- 目标解析到 `169.254.169.254` / `100.100.100.200` 等云元数据地址 → 无条件拒绝。
- 解析到内网地址但 `allow_private` 未开 → 拒绝(自建靶场请显式打开)。
- `expires_at` 过期 → 拒绝启动。
- 重定向每一跳都重新过 scope;跳出授权范围就停在原地,把跳转记录成证据。
- 默认只读方法;要 POST/PUT 必须在 `methods` 里显式加。

## 检测项

| 类型 | 说明 | 默认严重度 |
|---|---|---|
| `security-header` | CSP / XFO / XCTO / HSTS / Referrer-Policy 缺失 | low |
| `cookie` | Set-Cookie 缺 HttpOnly / Secure / SameSite | medium/low |
| `cors` | ACAO 反射任意 Origin,或 `*` + credentials | high/medium |
| `reflection` | 参数值原样反射进 HTML(仅标记,不是载荷) | medium(low confidence) |
| `open-redirect` | 常见跳转参数被外部 canary 控制 | medium |
| `exposure` | `.git/HEAD`、`.env`、Actuator、`server-status`、`.DS_Store` 等 | high/medium/info |
| `directory-listing` | `Index of /` | medium |
| `tls` | 过期/将过期/旧协议 | high/medium |
| `info-disclosure` | Server / X-Powered-By 版本泄露 | info |

所有结果都是**待复核候选**,带证据片段和 `request_id`;`request_id` 可以在
`.fairy/audit/<run_id>.jsonl` 里翻到对应请求。Fairy 不会把"静态推断"写成"已验证"。

## 安全边界(写死在代码里,不是口号)

- **不发载荷**:反射检测只放 `fairy<hex>` 这种无特殊字符标记,由人判断上下文。
- **不爆破**:没有字典、没有并发轰炸;`rps` 与 `max_requests` 双重上限,超了直接停。
- **不 dump**:发现敏感数据只截 240 字证据,不批量拉取、不横向。
- **不改状态**:默认 GET/HEAD/OPTIONS;POST 等需 scope 显式授权。
- **不越界**:DNS 归属检查 + 逐跳重定向校验 + 元数据地址黑名单。
- **不裸奔**:Cookie/Authorization/Set-Cookie 在报告与 HAR 里一律脱敏;URL 里的
  token/secret/session 类参数打码。
- **可回滚**:每次 `web_report` 都把当次 `scope.json` 快照进 run 目录,授权记录与
  证据绑在一起。

## 和 Verdex 的桥

```powershell
node scripts/verdex-bridge.mjs "D:\...\.fairy\runs\<run_id>\traffic.har"
```

它调用 Verdex 的 `analyzeHar`,对 Fairy 采集的流量做第二遍静态判断(缺失头、
Cookie 标志、CORS、URL 令牌、反射)。同样的 HAR 也可以直接丢给
`mcp__verdex__har_analyze`。

分工建议:**Fairy 负责"外面长什么样",Verdex 负责"里面是什么逻辑"**。
拿到 JS/源码后用 `scan` / `js_deobfuscate` / `secrets`,拿到二进制后走 `bin_*` 链。

## 测试

```powershell
npm test
```

内置一个只监听 `127.0.0.1` 的靶场(`tests/fixture-server.mjs`),覆盖:

- scope 过宽/缺依据/过期拒绝
- 云元数据与未放行内网地址拒绝
- 靶场扫描命中 CORS/Git 暴露/开放重定向/反射/Cookie/安全头
- `max_requests` 熔断
- HAR 导入、报告落盘、HAR 脱敏
- MCP `initialize` / `tools/list` / `scope_init` / `web_scan` 端到端

## 目录

```
src/
  scope.js       授权护照:解析、校验、主机匹配、私网/元数据判定
  http.js        低层 HTTP(手动重定向、CookieJar、TLS 信息、解压)
  guard.js       唯一出口:校验 → 限速 → 审计 → 采集
  crawl.js       同源爬取 + HTML 解析
  fingerprint.js 技术栈指纹
  checks.js      被动/主动检测与暴露面
  scan.js        编排、去重、统计
  har.js         HAR 导入 / 脱敏导出
  auth.js        单次登录 + 双会话差分
  session.js     会话保管(加密/0600/不回显)
  ledger.js      作战账本:资产/事实/发现/意图/覆盖
  playbooks.js   web 攻击链知识库与匹配
  report.js      JSON / Markdown / 自包含 HTML
  mcp.js         MCP(stdio)
  cli.js         CLI
docs/            战略与对标
tests/           靶场 + 测试
scripts/         demo 靶场、Verdex 桥、dsh 挂载
```

## 路线图

- [x] v0.2 作战账本(资产/事实/发现/意图/覆盖)+ 8 条攻击链知识库
- [x] v0.3 认证态:单次登录 + 加密会话 + 双账号 BOLA 证据差分
- [ ] v0.3 角色/权限矩阵:普通用户 vs 管理员端点
- [ ] v0.4 浏览器运行时(Playwright):SPA/XHR/DOM/控制台
- [ ] v0.4 HAR 重放:把 Burp 请求按 scope 重放并做差分
- [ ] v0.5 参数级差分:SQLi/NoSQLi/SSTI/路径穿越,只判存在
- [ ] v0.5 报告 v2:CVSS/OWASP/复现步骤/修复建议/披露信
- [ ] 交互审批门:高风险步骤暂停等确认
- [ ] Fairy 记忆:跨 engagement 记录"这个站踩过什么坑"

## 已知限制

- 单次请求 + 启发式规则,不构成完整攻击面;`max_pages` / `max_active_pages` 之外的路径不会被测。
- 反射/CORS/跳转都是候选,必须在浏览器或双账号环境人工复核后才能定级。
- 不做 JS 渲染,SPA 的路由与接口只能拿到静态 HTML 里出现的那部分。
- 主动检测会向目标发包,仅限授权范围,并遵守项目规则(限速/禁爆破/测试时段)。

---

只对授权目标动手。发现敏感数据即停,不 dump、不横向、不 hack-back。赢,还要全身而退。
