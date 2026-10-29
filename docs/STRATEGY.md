# Fairy / Web 战略:追平 ARTEX 的推进力,赢在证据纪律

> 目标不是做一个更能打的攻击机器人,而是做一个**能把影响证到、且只证到该证的地方**的 web 操作员。

## 1. ARTEX 到底强在哪

ARTEX 是 LLM 多 agent 驱动的自主渗透系统(Go + Next.js + PostgreSQL),核心不是某个漏洞检测器,而是**把多步利用链稳定推下去**的工程:

- **双图**:资产图(全局资产真值)+ 探索图(goal / intent / fact / finding / hint 的血缘链),两图用 anchor 相连,支撑覆盖度。
- **planner / worker 分离**:planner 只产意图,worker 领一条意图执行并写回;图一变就唤醒 planner,形成事件驱动闭环。
- **共享 todolist**:planner 跨轮保留攻击链待办,只在前置 fact 出现后才派下一步,解决"无状态会话里链会断"的问题。
- **过程级信息交换**:worker 之间可按关键字检索彼此的执行过程,复用观察,减少重复劳动。
- **平台配套**:MITM 流量记录、工具审批门、skills / memory / MCP、资产同步。

参考:[RuoJi6/ARTEX](https://github.com/RuoJi6/ARTEX)、[AhnLab 的跟踪分析](https://www.ahnlab.com/ko/contents/content-center/36300)、[Security Affairs 报道](https://securityaffairs.com/200661/hacking/ai-driven-tool-artex-used-in-attacks-against-south-korean-banks.html)。ARTEX 被滥用打真实银行这件事本身,就是 Fairy 必须把"授权 + 非破坏 + 数据最小化"写进代码的原因。

## 2. Fairy 现状 vs ARTEX

| 维度 | ARTEX | Fairy 现在 | 判断 |
|---|---|---|---|
| 资产/事实/发现状态 | Postgres 双图 | 无状态,一次扫描一份 JSON | **最大差距**,账本已起步 |
| 多步链推进 | planner + 共享 todolist | 单轮检测,无链 | 已有 8 条链知识库,缺执行闭环 |
| 过程复用 | worker trace 检索 | 无 | 账本 + 报告可部分替代 |
| 浏览器/SPA/DOM | MITM + 真实工具 | 只有原始 HTTP | 下一阶段 |
| 认证态 / BOLA | 凭据管理 + 复测 | 只有 Cookie 属性检查 | 下一阶段 |
| 注入类深度 | Kali/Bash 全工具 | 只做无载荷标记 | 有意为之,需"证明级"方案 |
| 审批与人环 | 工具审批门 | scope + 限速,无交互审批 | 需补 |
| 报告与披露 | UI + 统一报告 | HTML/MD + 审计 | 已不弱,需 CVSS/OWASP/复现 |
| 安全与合规 | 取决于使用者 | 授权护照 + 逐请求审计 + 数据最小化 | **已领先** |
| 可复现性 | 平台内 | `request_id` + HAR + scope 快照 | **已领先** |

结论:能力面差在"状态、浏览器、认证态、注入深度";纪律面 Fairy 已经领先,不能为了追平把领先项丢掉。

## 3. 差异化:Proof-Carrying Pentest(可证明渗透)

每一条结论都必须携带四样东西,否则不进报告:

1. **证据**:请求/响应片段 + `request_id` + 审计日志位置。
2. **最小影响**:只在测试账号、只读一次、只拿标记数据;越权只用双账号;带外只打自己的 canary。
3. **停止点**:证到影响成立即停,不 dump、不横向、不落地。
4. **反证说明**:这条为什么可能是误报、还需要什么才能定级。

这套约束不是枷锁,是让 Fairy 的"已证"比别人的"疑似"更值钱。

## 4. 架构:四层

```
Hands   现有:scope / guard / http / crawl / checks / har / report
Brain   账本(assets/facts/findings/intents/coverage)+ 攻击链知识库 + 计划推进
Senses  浏览器(Playwright)/ 流量录制 / JS 与 SourceMap 分析
Discipline  ROE / 证据分级 / 审批门 / 数据分级 / 披露包
```

- **Brain 先做**:没有状态,多步链永远是一次性的。账本已落地(`.fairy/ledger.json`),攻击链已落地(`src/playbooks.js`)。
- **Senses 决定上限**:SPA、DOM XSS、OAuth 流程、WebSocket 都绕不开浏览器。
- **Discipline 决定能不能长期用**:审批门、数据分级、披露模板。

## 5. 路线图与验收标准

### v0.2 作战账本 + 链规划(本轮)
- [x] `fairy_ledger_init/show/add/advance/ingest`
- [x] 8 条 web 攻击链知识库(CORS、OAuth 重定向、XSS、Git 泄露、BOLA、SSRF、API 文档、SourceMap)
- [x] 扫描报告一键入账,链规划区分 ready / blocked
- [x] 16 项测试
- 验收:扫描 → 入账 → `fairy_chain_plan` 能给出带停止点的下一步。

### v0.3 认证态与 BOLA(本轮完成前两项)
- [x] 登录流程录制(单次,不爆破),会话按需加密保存(AES-256-GCM 或 0600 + 警告)
- [x] 双账号请求差分(`web_compare`),输出 `marker-in-both` / `status-diff` 证据
- [ ] 角色/权限矩阵(普通用户 vs 管理员端点的自动化对照)
- 验收:靶场已复现 `marker-in-both` + `marker-only-in-a` 两种判读,证据带双侧 `request_id`。

### v0.4 浏览器运行时(本轮完成)
- [x] CDP 无头浏览器(零依赖):渲染、XHR 录制、DOM 快照、控制台错误、截图
- [x] SPA 动态链接与 XHR 接口发现
- [x] 登录态注入 + 浏览器网络层 scope 闸门(越界 fetch 直接阻断)
- [x] 页面动作 `fill/click/eval/wait`,可跑登录流与最小证明
- [x] HAR 按 scope 重放与状态/长度差分(写方法需显式授权)
- [ ] DOM XSS 的专用判定(目前靠 `actions` + 人工确认)
- 验收:纯前端页面拿到 `SPA Ready` 标题、动态链接、XHR 与截图;越界 fetch 被阻断并记审计;HAR 重放能区分"仍是 200"与"已变 403"。

### v0.5 深度检测与披露(本轮完成交付部分)
- [x] 报告 v2:OWASP / CWE / CVSS 估计 / 复现步骤 / 修复建议
- [x] HAR 按 scope 重放(只读默认、写方法显式授权、越界跳过)
- [ ] 参数级差分(SQLi/NoSQLi/SSTI/路径穿越)只判存在、不取数据
- [ ] JWT/OAuth 配置审计
- [ ] 披露信模板
- [ ] 交互审批门(高风险步骤暂停等确认)
- 验收:每条 verified 发现都带分类、复现步骤、修复建议与 `request_id`,第三方可按报告复核。

### v0.6 web ↔ binary 交接(本轮)
- [x] 扫描时发现样本链接(APK/固件/ELF/PE/归档)
- [x] 本地样本/URL 样本登记:sha256、隔离目录、不执行、需显式确认才下载
- [x] 输出 Verdex 工具链 + 本机后端预检(`file`/`objdump`/`jadx`/IDA/Ghidra…)
- [x] `binary-artifact` 链并入作战账本,下一步进 `fairy_chain_plan`
- 验收:真实 PE → `pe` 链;实调 `mcp__verdex__analyze_target` 得 `pe`;`pwn_checksec`/`bin_strings` 可用;`bin_info` 缺 `file` 被预检标红并给出警告。

### v0.7 参数级与 DOM(本轮)
- [x] SQLi 错误签名 / 布尔差分、SSTI `{{7*7}}`,只判存在
- [x] 双重授权:scope `allow_active_probes=true` + 调用 `confirm=true`
- [x] DOM 上下文判定(script/事件属性/普通属性/文本/注释)+ CSP 读取
- [x] 披露文档:只取 verified、不带证据正文
- [ ] 交互审批门(高风险步骤暂停等确认)
- 验收:靶场命中错误型 SQLi、布尔差分、SSTI 各一条;正常反射参数零误报;DOM 命中 script 与 text 两种上下文。

### v0.8 WAF 行为分析
- [x] 常见 WAF 指纹(响应头 / Cookie / 拦截页)
- [x] 四种语法形状 × 四种编码变体的拦截矩阵
- [x] 双重授权:scope `allow_waf_probe=true` + 调用 `confirm=true`
- [x] 只测量规范化差异,不自动绕过、不套真实攻击载荷
- [x] 把通过验证的编码接入参数探测(仅检测探针,三重授权)
- 验收:靶场识别 `normalization-gap`,单次编码被拦截、双重编码/HTML 实体/Unicode 通过;`web_param_adaptive` 用 double 画像命中只读 SQLi 探针,输出 `request_id` 与停止点。

### v0.9 mission + 基准
- [x] `fairy_mission`:扫描 → 报告 → 入账 → 链规划,有边界、有停止条件
- [x] `bench/`:本地类别级基准(recall / precision / 请求成本)
- [x] 默认不自动登录、不自动参数探测、不自动 WAF 画像
- [ ] 把 mission 接到 planner/worker 循环(多步、跨工具、可暂停)
- 验收:本机靶场 recall 100% / precision 100% / 3.5 请求一条;mission 产出报告、账本、next 链。

### v0.10 planner / worker
- [x] `fairy_chain_materialize`:ready 链 → 有依赖的意图序列,幂等
- [x] `claim` 只领取依赖已满足的下一步
- [x] `requires_approval` 审批门:不批准不会被领取
- [x] `approve` / `done` / `blocked` 状态机
- [ ] 自动 worker(执行步骤)与跨轮 planner
- 验收:落单 3 步链,claim 第一步;完成后第二步因审批门不可领取,approve 后可领取。

### v0.11 worker
- [x] `fairy_worker_run`:执行 active 且已审批的意图
- [x] 动作白名单:`probe / compare / browser / param / param_adaptive`
- [x] 结果写回意图并结单;没有隐式重试、没有自选目标
- [x] 未审批 / 未 claim / 非白名单动作直接拒绝
- [ ] worker 自动选择动作(仍需 LLM 规划)
- 验收:claim 第一步后执行 probe,结果写回;requires_approval 的意图在 approve 前被拒。

### v0.12 planner tick
- [x] `fairy_planner_tick`:读账本/链 → 落单 ready 链 → 选下一步
- [x] 没有下一步时提示 `materialize` / `approve` / `wait_active`
- [x] 只读与落单,不发请求;执行仍归 worker
- [ ] 跨轮自动循环(完成一步后自动 tick)
- 验收:空账本先提示 materialize;落单后给 claim_next;审批未过时给 approve。

### v0.13 auto loop
- [x] `fairy_auto_run`:tick → claim → 执行已声明 work → 再 tick
- [x] 没有 work 停在 `needs_action`;需要审批停在 `approve`
- [x] 不自动批准、不自动推断动作、失败不重试
- [ ] 跨轮续跑(外部调度器按状态继续)
- 验收:声明 step1 probe,自动执行并结单;第二步审批未过时不执行。

### v0.14 work inference
- [x] 从 chain_id + step_index + context 推断只读 work
- [x] 支持 git/泄露、IDOR、反射 XSS、SourceMap、API 文档、SSRF 六类
- [x] 没有 context 不推断,停在 `needs_action`
- [x] 推断结果标记 `inferred=true`,仍走审批门
- [ ] 更多链的动作映射与参数模板
- 验收:给 `base_url` 自动推断 git 链 step1 probe 并执行;不给 context 停在 needs_action。

### v0.15 权限矩阵
- [x] `web_role_matrix`:多账号 × 多端点只读 GET
- [x] 角色差异(BFLA)与登录态正文差异(IDOR/BOLA)候选
- [x] 只回状态/长度/哈希,不读对象内容
- [x] 明确不做横向执行、凭据窃取、提权
- [ ] 角色/租户矩阵自动发现与 API schema 驱动
- 验收:admin 200 / alice 403 被标 role-restricted;多账号正文哈希不同被标 data-diff。

### v0.16 最高授权闸
- [x] `high-auth`:HMAC 签名授权文件(basis/approver/assets/expiry/actions)
- [x] `fairy_reachability`:最高授权后的只读身份/权限/资产图
- [x] 动作白名单只有 `read-only`;横向/凭据/持久化/隧道直接拒绝
- [x] agent 不能自签,只能验证;密钥在授权人手里
- [ ] 多资产图的可视化与导出
- 验收:无授权文件拒绝;资产不在清单拒绝;签名/动作/过期校验通过后只读出图。

### v0.17 证据闭环
- [x] `fairy_ingest`:scan/param/WAF/矩阵/可达性/Verdex 统一入账
- [x] `source_run_id` / `source_id` / `source`,重复导入幂等
- [x] `fairy_report_bundle`:以账本为准的跨工具 JSON/MD/HTML 报告
- [x] Verdex `file:line` findings 回流,不再只停在交接
- [ ] 报告与披露模板合一、状态流转可视化
- 验收:param + Verdex 入同一账本;bundle 报告同时出现两种来源;重复导入 skipped。

## 6. 质量指标(比"扫了多少"更重要)

| 指标 | 目标 |
|---|---|
| 越界请求 | 0 |
| 未脱敏凭据落入报告 | 0 |
| 发现带证据比例 | 100% |
| verified / candidate | 逐轮上升,不虚报 |
| 每发现平均请求数 | 越低越专业 |
| 覆盖声明 | 只报实际测过的资产,不写"全站" |

## 7. 许可与边界

ARTEX 是 AGPL-3.0。本仓库**不复制其代码**,只借鉴其公开架构思想(双图、planner/worker、共享 todolist),实现独立。Fairy 不提供 RCE/横向/持久化能力,不自动利用,不碰未授权目标。

---

一句话:ARTEX 证明"AI 能自己走完攻击链";Fairy 要证明的是"AI 走完链之后,留下的是一份能复核、能修复、能披露的证据"。
