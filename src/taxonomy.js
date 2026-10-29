// 发现归类:给每条候选补 OWASP / CWE / CVSS 估计 / 修复建议 / 复现步骤。
// CVSS 是"估计",用于排序与沟通,不是权威打分;报告里必须带这句话。

const TAXONOMY = {
  cors: {
    owasp: "A05:2021 Security Misconfiguration",
    cwe: "CWE-942",
    base: 8.1,
    remediation: "按白名单返回 Access-Control-Allow-Origin,禁止反射任意 Origin;需要携带凭证时不要使用 *;在网关层统一处理。",
  },
  "open-redirect": {
    owasp: "A01:2021 Broken Access Control",
    cwe: "CWE-601",
    base: 6.1,
    remediation: "跳转目标使用相对路径或服务端白名单;不要把外部 URL 直接传给 Location。",
  },
  reflection: {
    owasp: "A03:2021 Injection",
    cwe: "CWE-79",
    base: 6.1,
    remediation: "按输出上下文做 HTML/属性/JS 转义;启用 CSP;会话 Cookie 加 HttpOnly。",
  },
  xss: {
    owasp: "A03:2021 Injection",
    cwe: "CWE-79",
    base: 6.1,
    remediation: "按输出上下文转义;启用 CSP;避免 innerHTML 拼接。",
  },
  sqli: {
    owasp: "A03:2021 Injection",
    cwe: "CWE-89",
    base: 8.1,
    remediation: "使用参数化查询/预编译语句;统一数据库错误页;数据库账号最小权限。",
  },
  ssti: {
    owasp: "A03:2021 Injection",
    cwe: "CWE-94",
    base: 8.1,
    remediation: "不要把用户输入拼进模板;使用沙箱/白名单;升级模板引擎并关闭危险函数。",
  },
  cookie: {
    owasp: "A05:2021 Security Misconfiguration",
    cwe: "CWE-1004 / CWE-614",
    base: 4.3,
    remediation: "会话 Cookie 设置 HttpOnly、Secure、SameSite=Lax/Strict;按前缀规则使用 __Host-。",
  },
  "security-header": {
    owasp: "A05:2021 Security Misconfiguration",
    cwe: "CWE-693",
    base: 3.1,
    remediation: "补齐 CSP、X-Frame-Options、X-Content-Type-Options、HSTS、Referrer-Policy。",
  },
  exposure: {
    owasp: "A01:2021 Broken Access Control",
    cwe: "CWE-538",
    base: 7.5,
    remediation: "移除对外暴露的 .git/.env/备份/Actuator;检查历史泄露并轮换相关密钥。",
  },
  "info-exposure": {
    owasp: "A01:2021 Broken Access Control",
    cwe: "CWE-200",
    base: 5.3,
    remediation: "不要把令牌放在 URL;改用 Authorization 头或安全 Cookie。",
  },
  "directory-listing": {
    owasp: "A01:2021 Broken Access Control",
    cwe: "CWE-548",
    base: 5.3,
    remediation: "关闭 Web 服务器目录浏览;敏感目录加鉴权。",
  },
  tls: {
    owasp: "A02:2021 Cryptographic Failures",
    cwe: "CWE-295",
    base: 5.9,
    remediation: "续期证书;只允许 TLS 1.2+;开启 HSTS。",
  },
  transport: {
    owasp: "A02:2021 Cryptographic Failures",
    cwe: "CWE-319",
    base: 5.9,
    remediation: "全站 HTTPS 并 301 跳转;开启 HSTS;Cookie 加 Secure。",
  },
  "info-disclosure": {
    owasp: "A05:2021 Security Misconfiguration",
    cwe: "CWE-200",
    base: 3.7,
    remediation: "隐藏 Server/X-Powered-By 版本号;减少指纹面。",
  },
  idor: {
    owasp: "A01:2021 Broken Access Control",
    cwe: "CWE-639",
    base: 8.1,
    remediation: "对象级鉴权:每次访问都校验资源归属;不要只依赖前端隐藏 id。",
  },
  authz: {
    owasp: "A01:2021 Broken Access Control",
    cwe: "CWE-862 / CWE-863",
    base: 8.1,
    remediation: "服务端按角色/租户强制鉴权;默认拒绝;为每个端点补权限矩阵测试。",
  },
  "data-diff": {
    owasp: "A01:2021 Broken Access Control",
    cwe: "CWE-639",
    base: 7.5,
    remediation: "确认响应差异来自对象归属;对象级鉴权必须在服务端完成。",
  },
  ssrf: {
    owasp: "A10:2021 Server-Side Request Forgery",
    cwe: "CWE-918",
    base: 7.5,
    remediation: "目标地址白名单;禁止访问内网/元数据;出站代理统一管控。",
  },
};

function cvssFor(base, severity) {
  if (severity === "critical") return 9.1;
  if (severity === "high") return Math.max(7.5, base);
  if (severity === "medium") return Math.min(base, 6.5);
  if (severity === "low") return Math.min(base, 4.3);
  return 0;
}

function reproFor(finding) {
  const steps = [`在授权环境重放 ${finding.where || "该请求"}`];
  if (finding.evidence?.request_id) {
    steps.push(`从审计日志回查 request_id=${finding.evidence.request_id} 的原始请求/响应`);
  }
  if (finding.evidence?.snippet) steps.push("核对报告中的证据片段");
  steps.push(finding.verify || "人工复核上下文后定级");
  return steps;
}

export function classifyFinding(finding) {
  const entry = TAXONOMY[finding.kind] || TAXONOMY["info-disclosure"];
  return {
    owasp: entry.owasp,
    cwe: entry.cwe,
    cvss: cvssFor(entry.base, finding.severity),
    remediation: finding.remediation || entry.remediation,
    repro: reproFor(finding),
    cvss_note: "CVSS 为估计值,用于排序与沟通,定级前需人工校准。",
  };
}

export function enrichFindings(findings) {
  for (const finding of findings || []) {
    if (finding.owasp && finding.cwe && Number.isFinite(finding.cvss) && finding.remediation) continue;
    const meta = classifyFinding(finding);
    finding.owasp = finding.owasp || meta.owasp;
    finding.cwe = finding.cwe || meta.cwe;
    finding.cvss = Number.isFinite(finding.cvss) ? finding.cvss : meta.cvss;
    finding.remediation = finding.remediation || meta.remediation;
    finding.repro = finding.repro || meta.repro;
    finding.cvss_note = meta.cvss_note;
  }
  return findings;
}
