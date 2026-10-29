import fs from "node:fs";
import path from "node:path";
import { loadLedger, summary } from "./ledger.js";
import { escapeHtml, nowIso, severityRank } from "./util.js";

// 跨工具证据报告:以账本为准,而不是以某一次 scan 为准。
// scan / param / WAF / matrix / reachability / Verdex 的发现都在这张总账里。

const SEVERITY_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };
const SEVERITY_COLOR = {
  critical: "#ff4d6d",
  high: "#ff7a45",
  medium: "#f5c542",
  low: "#5bc0eb",
  info: "#8b93a7",
};

function findingRequestIds(finding) {
  return [...new Set((finding.evidence || []).map((item) => item.request_id).filter(Boolean))];
}

function sortedFindings(ledger) {
  return [...ledger.findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

function renderMarkdown(ledger, report, title) {
  const lines = [];
  lines.push(`# ${title}`, "");
  lines.push(`- engagement: ${ledger.engagement?.name || "-"}`);
  lines.push(`- 生成时间: ${report.generated_at}`);
  lines.push(`- 授权依据: ${ledger.engagement?.scope?.basis || "-"}`);
  lines.push(`- 操作者: ${ledger.engagement?.scope?.operator || "-"}`);
  lines.push(`- include: ${(ledger.engagement?.scope?.include || []).join(", ")}`);
  lines.push("");

  lines.push("## 总览", "");
  lines.push("| 严重度 | 数量 |");
  lines.push("|---|---:|");
  for (const severity of ["critical", "high", "medium", "low", "info"]) {
    lines.push(`| ${SEVERITY_LABEL[severity]} | ${report.summary.findings.by_severity[severity] || 0} |`);
  }
  lines.push("");
  lines.push("| 状态 | 数量 |");
  lines.push("|---|---:|");
  for (const status of ["candidate", "verified", "false-positive", "remediated", "accepted-risk"]) {
    lines.push(`| ${status} | ${report.summary.findings.by_status[status] || 0} |`);
  }
  lines.push("");
  lines.push(
    `- 请求覆盖: ${report.summary.assets.total} 个资产 / ${report.summary.assets.tested} 个已测(${report.summary.assets.percent}%)`,
  );
  lines.push(`- 覆盖 runs: ${ledger.coverage?.runs?.length || 0}`);
  lines.push("");

  lines.push("## 发现", "");
  const findings = sortedFindings(ledger);
  if (!findings.length) lines.push("账本里还没有发现。", "");
  for (const finding of findings) {
    lines.push(`### ${finding.id} [${SEVERITY_LABEL[finding.severity] || finding.severity}] ${finding.title}`, "");
    lines.push(`- 位置: \`${finding.where || "-"}\``);
    lines.push(`- 类型: ${finding.kind} / 状态: ${finding.status} / 置信度: ${finding.confidence || "medium"}`);
    if (finding.source) lines.push(`- 来源: ${finding.source}`);
    if (finding.owasp || finding.cwe) {
      lines.push(`- 分类: ${finding.owasp || "-"}${finding.cwe ? ` / ${finding.cwe}` : ""}`);
    }
    if (finding.cvss !== undefined && finding.cvss !== null) {
      lines.push(`- CVSS 估计: ${finding.cvss}(${finding.cvss_note || "待人工校准"})`);
    }
    if (finding.detail) lines.push(`- 说明: ${finding.detail}`);
    if (finding.remediation) lines.push(`- 修复: ${finding.remediation}`);
    const requestIds = findingRequestIds(finding);
    if (requestIds.length) lines.push(`- 请求: ${requestIds.join(", ")}`);
    if (finding.source_run_id) lines.push(`- source_run: ${finding.source_run_id}${finding.source_id ? ` / ${finding.source_id}` : ""}`);
    if (finding.repro?.length) lines.push(`- 复现: ${finding.repro.join(" → ")}`);
    lines.push("");
  }

  lines.push("## 资产", "");
  const byType = new Map();
  for (const asset of ledger.assets) {
    if (!byType.has(asset.type)) byType.set(asset.type, []);
    byType.get(asset.type).push(asset);
  }
  for (const [type, assets] of byType) {
    lines.push(`### ${type}(${assets.length})`, "");
    for (const asset of assets.slice(0, 100)) lines.push(`- \`${asset.value}\`${asset.tested ? " ✅" : ""}`);
    lines.push("");
  }

  lines.push("## 覆盖 runs", "");
  lines.push("| run_id | source | findings | 导入时间 |");
  lines.push("|---|---|---:|---|");
  for (const run of ledger.coverage?.runs || []) {
    lines.push(`| ${run.run_id} | ${run.source || "-"} | ${run.findings ?? "-"} | ${run.imported_at} |`);
  }
  lines.push("");

  if (ledger.facts.length) {
    lines.push("## 事实", "");
    for (const fact of ledger.facts.slice(0, 50)) lines.push(`- ${fact.id} [${fact.confidence}] ${fact.statement}`);
    lines.push("");
  }

  lines.push("> 候选不等于已验证;CVSS 是估计值。发现敏感数据即停,不 dump、不横向。", "");
  return lines.join("\n");
}

function renderHtml(ledger, report, title) {
  const findings = sortedFindings(ledger);
  const cards = ["critical", "high", "medium", "low", "info"]
    .map(
      (severity) =>
        `<div class="card"><div class="num" style="color:${SEVERITY_COLOR[severity]}">${report.summary.findings.by_severity[severity] || 0}</div><div class="label">${SEVERITY_LABEL[severity]}</div></div>`,
    )
    .join("");

  const findingHtml = findings.length
    ? findings
        .map((finding) => {
          const requestIds = findingRequestIds(finding);
          return `<article class="finding" id="${escapeHtml(finding.id)}">
  <div class="fhead"><span class="sev" style="background:${SEVERITY_COLOR[finding.severity] || "#8b93a7"}">${SEVERITY_LABEL[finding.severity] || escapeHtml(finding.severity)}</span>
  <span class="fid">${escapeHtml(finding.id)}</span><h3>${escapeHtml(finding.title)}</h3></div>
  <div class="where">${escapeHtml(finding.where || "-")}</div>
  <p>${escapeHtml(finding.detail || "")}</p>
  <div class="meta">${escapeHtml(finding.kind)} · ${escapeHtml(finding.status)} · 置信度 ${escapeHtml(finding.confidence || "medium")}${finding.source ? ` · 来源 ${escapeHtml(finding.source)}` : ""}${finding.cvss ? ` · CVSS ${finding.cvss}` : ""}${requestIds.length ? ` · 请求 ${escapeHtml(requestIds.join(", "))}` : ""}</div>
  ${finding.remediation ? `<div class="fix"><b>修复</b>${escapeHtml(finding.remediation)}</div>` : ""}
</article>`;
        })
        .join("")
    : '<p class="empty">账本里还没有发现。</p>';

  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
body{font-family:ui-sans-serif,system-ui,"Segoe UI",sans-serif;background:#0f1218;color:#dbe2ef;margin:0;padding:32px}
h1,h2,h3{color:#fff}h1{font-size:28px;margin:0 0 8px}h2{margin-top:32px;border-bottom:1px solid #263041;padding-bottom:8px}
.wrap{max-width:1100px;margin:0 auto}.muted{color:#8b93a7}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:20px 0}
.card{background:#171d28;border:1px solid #263041;border-radius:10px;padding:14px 20px;min-width:96px}
.num{font-size:26px;font-weight:700}.label{font-size:12px;color:#8b93a7;margin-top:4px}
.finding{background:#151b25;border:1px solid #263041;border-radius:10px;padding:16px;margin:14px 0}
.fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.fhead h3{margin:0;font-size:17px}
.sev{color:#0f1218;font-weight:700;font-size:12px;padding:3px 8px;border-radius:999px}
.fid{font-family:ui-monospace,Consolas,monospace;color:#8b93a7;font-size:12px}
.where{font-family:ui-monospace,Consolas,monospace;color:#9ecbff;font-size:12px;margin:8px 0;word-break:break-all}
.meta{font-size:12px;color:#8b93a7}.fix{margin-top:10px;color:#c9d4e6;font-size:13px}.fix b{color:#fff;margin-right:8px}
.empty{color:#8b93a7}
</style></head><body><div class="wrap">
<h1>${escapeHtml(title)}</h1>
<div class="muted">${escapeHtml(ledger.engagement?.name || "")} · ${escapeHtml(report.generated_at)} · 授权依据:${escapeHtml(ledger.engagement?.scope?.basis || "-")}</div>
<div class="cards">${cards}</div>
<h2>发现</h2>${findingHtml}
<h2>覆盖</h2><p class="muted">${report.summary.assets.total} 个资产 / ${ledger.coverage?.runs?.length || 0} 个导入 run</p>
</div></body></html>`;
}

export function writeLedgerReport(projectDir, options = {}) {
  const ledger = loadLedger(projectDir);
  const title = String(options.title || "Fairy 证据总账");
  const report = {
    schema: "FairyBundleReport/v1",
    generated_at: nowIso(),
    engagement: ledger.engagement,
    summary: summary(ledger),
    findings: sortedFindings(ledger),
    assets: ledger.assets,
    facts: ledger.facts,
    coverage: ledger.coverage,
  };

  const stamp = report.generated_at.replace(/[:.]/g, "-");
  const dir = path.join(path.resolve(projectDir), ".fairy", "reports", stamp);
  fs.mkdirSync(dir, { recursive: true });
  const jsonPath = path.join(dir, "report.json");
  const mdPath = path.join(dir, "report.md");
  const htmlPath = path.join(dir, "report.html");
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  fs.writeFileSync(mdPath, renderMarkdown(ledger, report, title), "utf8");
  fs.writeFileSync(htmlPath, renderHtml(ledger, report, title), "utf8");

  return { dir, json: jsonPath, markdown: mdPath, html: htmlPath, summary: report.summary };
}
