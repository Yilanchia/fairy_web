import fs from "node:fs";
import path from "node:path";
import { loadLedger } from "./ledger.js";
import { severityRank } from "./util.js";

// 披露文档:只从账本里取已复核(verified)的发现;默认不带证据正文,避免把数据写进对外文档。

const SEVERITY_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };

function line(value) {
  return String(value ?? "").replace(/\r?\n/g, " ").trim();
}

export function buildDisclosure(ledger, options = {}) {
  const includeCandidates = options.includeCandidates === true;
  const findings = (ledger.findings || [])
    .filter((finding) => finding.status === "verified" || (includeCandidates && finding.status === "candidate"))
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));

  if (!findings.length) {
    throw new Error(
      "没有可披露的发现:先用 fairy_ledger_advance(finding-status, verified) 复核,或传 include_candidates=true。",
    );
  }

  const engagement = ledger.engagement || {};
  const scope = engagement.scope || {};
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of findings) counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  const top = findings[0];

  const lines = [];
  lines.push("# 安全测试发现披露", "");
  lines.push(`- 项目: ${line(engagement.name || "未命名")}`);
  lines.push(`- 测试方/操作者: ${line(scope.operator || "未填写")}`);
  lines.push(`- 授权依据: ${line(scope.basis || "未填写")}`);
  lines.push(`- 授权范围: ${line((scope.include || []).join(", "))}`);
  lines.push(`- 生成时间: ${new Date().toISOString()}`);
  lines.push(`- 发现数量: ${findings.length}(严重 ${counts.critical} / 高危 ${counts.high} / 中危 ${counts.medium} / 低危 ${counts.low} / 信息 ${counts.info})`);
  lines.push("");

  lines.push("## 摘要", "");
  lines.push(
    `本轮共复核 ${findings.length} 条发现。最高风险为 **${line(top.title)}**(${SEVERITY_LABEL[top.severity] || top.severity},CVSS 估计 ${top.cvss ?? "N/A"})。`,
  );
  lines.push("");

  lines.push("## 发现详情", "");
  for (const finding of findings) {
    lines.push(`### [${SEVERITY_LABEL[finding.severity] || finding.severity}] ${line(finding.title)}`, "");
    lines.push(`- 位置: \`${line(finding.where)}\``);
    lines.push(`- 分类: ${line(finding.owasp || "-")} / ${line(finding.cwe || "-")} / CVSS 估计 ${finding.cvss ?? "N/A"}`);
    if (finding.impact) lines.push(`- 影响: ${line(finding.impact)}`);
    if (finding.repro?.length) {
      lines.push("- 复现步骤:");
      for (const step of finding.repro) lines.push(`  ${line(step)}`);
    }
    if (finding.evidence?.request_id) lines.push(`- 证据(request_id): ${line(finding.evidence.request_id)}`);
    if (finding.remediation) lines.push(`- 修复建议: ${line(finding.remediation)}`);
    lines.push("");
  }

  lines.push("## 时间线", "");
  lines.push(`- ${new Date().toISOString().slice(0, 10)} 发现并复核`);
  lines.push("- 待补充:报告发送、修复、复测");
  lines.push("");

  lines.push("## 联系与披露", "");
  lines.push("- 安全问题联系人: <待填写>");
  lines.push("- 建议在修复上线后复测,并保留本报告与审计日志作为证据。");
  lines.push("");
  lines.push(`> 本报告仅覆盖授权范围(${line((scope.include || []).join(", "))})。`); 
  lines.push("> 文中 CVSS 为估计值;未附带请求/响应正文,证据可在授权环境按 request_id 复核。");
  lines.push("");

  return {
    markdown: lines.join("\n"),
    stats: {
      findings: findings.length,
      by_severity: counts,
      verified_only: !includeCandidates,
      top: { id: top.id, title: top.title, severity: top.severity, cvss: top.cvss ?? null },
    },
  };
}

export function writeDisclosure(projectDir, options = {}) {
  const ledger = loadLedger(projectDir);
  const result = buildDisclosure(ledger, options);
  const file = path.join(path.resolve(projectDir), ".fairy", "disclosure.md");
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${result.markdown}\n`, "utf8");
  return { file, ...result };
}
