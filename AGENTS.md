# Fairy / Web 工作区约定

这是 Fairy 的 web 手。默认用 Fairy 的 MCP 工具做 web;遇到二进制/固件/样本,
交给 Verdex,不要自己硬啃。

## 路由

- **web 目标(域名/URL/登录态/API)**:`fairy_scope_init` → `web_scan` / `web_browser` /
  `web_login` / `web_compare` / `web_report`。
- **本地二进制 / APK / 固件 / 样本**:先 `fairy_handoff` 登记并拿链,再调
  `mcp__verdex__analyze_target`,按 `preflight` 跳过缺失后端的步骤。
- **web 上发现的样本链接**:`web_scan` 会列进 `attack_surface.artifacts`;
  下载走 `fairy_handoff(url, confirm=true)`,不要用普通爬虫硬拉。
- **参数级探测**:`web_param`(SQLi/SSTI),必须 scope `allow_active_probes=true` 且
  `confirm=true`;只判存在,不取数据。DOM 上下文用 `web_dom_context`。
- **WAF 行为**:`web_waf`,必须 scope `allow_waf_probe=true` 且 `confirm=true`;
  只测指纹与编码规范化差异,不自动绕过、不套真实载荷。
- **披露**:`fairy_disclose` 只收 verified 发现;先 `fairy_ledger_advance(finding-status)`。
- **HAR / 抓包**:`har_ingest` 静态看;需要"现在还是不是这样"用 `web_replay`。
- **采集 → 静态复核**:`web_report` 产出的 `traffic.har` 交给
  `mcp__verdex__har_analyze`。

## 边界

- 只对授权护照(scope)内的目标动手;没有 scope 不发请求。
- 样本只登记、只静态分析,**不执行**、不联网回连、不上传第三方。
- 默认只读方法;登录/重放写方法必须 scope 显式授权。
- 发现敏感数据即停,不 dump、不横向、不 hack-back。
- 报告里 CVSS 是估计值,候选不等于已验证。
