import fs from "node:fs";
import path from "node:path";
import { buildHar } from "./har.js";
import { escapeHtml, severityRank, truncate } from "./util.js";

const SEVERITY_LABEL = { critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息" };
const SEVERITY_COLOR = {
  critical: "#ff4d6d",
  high: "#ff7a45",
  medium: "#f5c542",
  low: "#5bc0eb",
  info: "#8b93a7",
};

export function writeReport(projectDir, { result, traffic }) {
  if (!result || result.schema !== "FairyScan/v1") throw new Error("writeReport 需要一次 FairyScan/v1 扫描结果");
  const dir = path.join(path.resolve(projectDir), ".fairy", "runs", result.run_id);
  fs.mkdirSync(dir, { recursive: true });

  const jsonPath = path.join(dir, "report.json");
  fs.writeFileSync(jsonPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");

  const scopePath = path.join(dir, "scope.json");
  fs.writeFileSync(scopePath, `${JSON.stringify(result.scope, null, 2)}\n`, "utf8");

  const mdPath = path.join(dir, "report.md");
  fs.writeFileSync(mdPath, renderMarkdown(result), "utf8");

  const htmlPath = path.join(dir, "report.html");
  fs.writeFileSync(htmlPath, renderHtml(result), "utf8");

  let harPath = null;
  if (traffic && traffic.length) {
    harPath = path.join(dir, "traffic.har");
    fs.writeFileSync(harPath, `${JSON.stringify(buildHar(traffic, { run_id: result.run_id }), null, 2)}\n`, "utf8");
  }

  return { dir, json: jsonPath, scope: scopePath, markdown: mdPath, html: htmlPath, har: harPath };
}

function renderMarkdown(result) {
  const lines = [];
  const s = result.stats;
  lines.push("# Fairy Web 证据报告", "");
  lines.push(`- run_id: \`${result.run_id}\``);
  lines.push(`- 生成时间: ${result.generated_at}`);
  lines.push(`- 模式: ${result.mode}`);
  lines.push(`- 目标: ${result.targets.join(", ")}`);
  lines.push(`- 请求数: ${s.requests} / 页面: ${s.pages} / 发现: ${result.findings.length}`);
  lines.push("");

  lines.push("## 授权记录", "");
  lines.push(`- 依据: ${result.scope.authorization.basis}`);
  if (result.scope.authorization.operator) lines.push(`- 操作者: ${result.scope.authorization.operator}`);
  if (result.scope.authorization.expires_at) lines.push(`- 有效期至: ${result.scope.authorization.expires_at}`);
  lines.push(`- include: ${result.scope.include.join(", ")}`);
  if (result.scope.exclude.length) lines.push(`- exclude: ${result.scope.exclude.join(", ")}`);
  lines.push(
    `- 限制: rps=${result.scope.limits.rps}, max_requests=${result.scope.limits.max_requests}, methods=${result.scope.limits.methods.join("/")}, allow_private=${result.scope.limits.allow_private}`,
  );
  lines.push("");

  lines.push("## 发现", "");
  if (!result.findings.length) {
    lines.push("本轮没有命中规则。覆盖有限,不等于目标安全。", "");
  }
  for (const finding of result.findings) {
    lines.push(`### ${finding.id} [${SEVERITY_LABEL[finding.severity] || finding.severity}] ${finding.title}`, "");
    lines.push(`- 位置: \`${finding.where}\``);
    lines.push(`- 类型: ${finding.kind} / 置信度: ${finding.confidence}`);
    if (finding.detail) lines.push(`- 说明: ${finding.detail}`);
    if (finding.evidence?.request_id) lines.push(`- 请求: ${finding.evidence.request_id}`);
    if (finding.evidence?.snippet) {
      lines.push("", "```text", truncate(String(finding.evidence.snippet), 400), "```");
    }
    if (finding.verify) lines.push(`- 复核: ${finding.verify}`);
    lines.push("");
  }

  lines.push("## 页面与技术栈", "");
  for (const page of result.pages.slice(0, 50)) {
    const tech = page.tech && page.tech.length ? ` · ${page.tech.map((t) => t.tech).join("/")}` : "";
    const shown = page.requested_url || page.url;
    const final = shown !== page.url ? ` → ${page.url}` : "";
    lines.push(`- [${page.status}] ${shown} — ${page.title || "(无标题)"}${tech}${final}`);
  }
  lines.push("");

  if (result.attack_surface.endpoints.length || result.attack_surface.forms.length) {
    lines.push("## 攻击面草图", "");
    for (const endpoint of result.attack_surface.endpoints.slice(0, 60)) lines.push(`- \`${endpoint}\``);
    for (const form of result.attack_surface.forms.slice(0, 30)) {
      lines.push(
        `- 表单 ${form.method} ${form.action} (${form.inputs.map((i) => i.name).join(", ") || "无字段"})`,
      );
    }
    lines.push("");
  }

  lines.push("## 覆盖与限制", "");
  for (const item of result.limitations) lines.push(`- ${item}`);
  lines.push("");
  lines.push(`> 审计日志: \`${result.audit_path}\`;每条发现可用 request_id 回查。`);
  lines.push("> Fairy 只在授权范围内发包;发现敏感数据即停,不 dump、不横向。", "");
  return lines.join("\n");
}

function renderHtml(result) {
  const s = result.stats;
  const findings = [...result.findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  const cards = ["critical", "high", "medium", "low", "info"]
    .map(
      (sev) => `<div class="card"><div class="num" style="color:${SEVERITY_COLOR[sev]}">${s.findings[sev] || 0}</div><div class="label">${SEVERITY_LABEL[sev]}</div></div>`,
    )
    .join("");

  const findingHtml = findings.length
    ? findings
        .map((f) => {
          const evidence = f.evidence?.snippet
            ? `<pre>${escapeHtml(truncate(String(f.evidence.snippet), 500))}</pre>`
            : f.evidence?.location
              ? `<pre>${escapeHtml(truncate(String(f.evidence.location), 300))}</pre>`
              : "";
          return `<article class="finding" id="${escapeHtml(f.id)}">
  <div class="fhead"><span class="sev" style="background:${SEVERITY_COLOR[f.severity] || "#8b93a7"}">${SEVERITY_LABEL[f.severity] || f.severity}</span>
  <span class="fid">${escapeHtml(f.id)}</span><h3>${escapeHtml(f.title)}</h3></div>
  <div class="where">${escapeHtml(f.where)}</div>
  <p>${escapeHtml(f.detail || "")}</p>
  <div class="meta">类型 ${escapeHtml(f.kind)} · 置信度 ${escapeHtml(f.confidence)}${f.evidence?.request_id ? ` · 请求 ${escapeHtml(f.evidence.request_id)}` : ""}</div>
  ${evidence}
  ${f.verify ? `<div class="verify"><b>复核</b>${escapeHtml(f.verify)}</div>` : ""}
</article>`;
        })
        .join("")
    : '<p class="empty">本轮没有命中规则。覆盖有限,不等于目标安全。</p>';

  const pages = result.pages
    .slice(0, 100)
    .map((p) => {
      const shown = p.requested_url || p.url;
      const final = shown !== p.url ? `<br><span class="muted">→ ${escapeHtml(p.url)}</span>` : "";
      return `<tr><td>${p.status}</td><td>${escapeHtml(shown)}${final}</td><td>${escapeHtml(p.title || "")}</td><td>${escapeHtml((p.tech || []).map((t) => t.tech).join(", "))}</td></tr>`;
    })
    .join("");

  const endpoints = result.attack_surface.endpoints
    .slice(0, 120)
    .map((e) => `<li><code>${escapeHtml(e)}</code></li>`)
    .join("");

  const forms = result.attack_surface.forms
    .slice(0, 40)
    .map(
      (f) =>
        `<li><code>${escapeHtml(f.method)} ${escapeHtml(f.action)}</code> — ${escapeHtml(f.inputs.map((i) => i.name).join(", ") || "无字段")}</li>`,
    )
    .join("");

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fairy Web 报告 ${escapeHtml(result.run_id)}</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0d12;color:#e6e9f0;font:14px/1.65 "Segoe UI",system-ui,"Microsoft YaHei",sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:40px 24px 80px}
.brand{font-weight:800;letter-spacing:.18em;font-size:13px;color:#6ee7ff}
.brand span{color:#ff77c8}
h1{font-size:26px;margin:10px 0 6px;letter-spacing:.02em}
.sub{color:#8b93a7;font-size:13px;margin-bottom:28px}
.panel{border:1px solid #1e2430;background:#10141b;border-radius:14px;padding:18px 20px;margin:16px 0}
.panel h2{font-size:13px;text-transform:uppercase;letter-spacing:.14em;color:#8b93a7;margin:0 0 12px}
.kv{display:grid;grid-template-columns:120px 1fr;gap:6px 14px;font-size:13px}
.kv b{color:#8b93a7;font-weight:500}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
.card{flex:1 1 120px;border:1px solid #1e2430;background:#10141b;border-radius:12px;padding:14px 16px}
.card .num{font-size:26px;font-weight:700;line-height:1.1}
.card .label{color:#8b93a7;font-size:12px;margin-top:4px}
.finding{border:1px solid #1e2430;border-left:4px solid #2a3140;background:#10141b;border-radius:12px;padding:16px 18px;margin:12px 0}
.fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.fhead h3{font-size:15px;margin:0;font-weight:650}
.sev{font-size:11px;font-weight:700;color:#0b0d12;border-radius:999px;padding:2px 9px}
.fid{font-family:ui-monospace,Consolas,monospace;color:#6b7488;font-size:12px}
.where{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#6ee7ff;margin:8px 0;word-break:break-all}
.meta{color:#8b93a7;font-size:12px;margin-top:6px}
pre{background:#0a0c11;border:1px solid #1e2430;border-radius:8px;padding:10px 12px;overflow:auto;font-size:12px;color:#c9d1e0}
.verify{margin-top:10px;font-size:13px;color:#a7b0c0;border-top:1px dashed #1e2430;padding-top:10px}
.verify b{color:#6ee7ff;margin-right:8px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #1a202b;vertical-align:top}
th{color:#8b93a7;font-weight:500}
td:nth-child(2){word-break:break-all;color:#b9c2d4}
details{margin-top:12px}
summary{cursor:pointer;color:#6ee7ff;font-size:13px}
ul.e{list-style:none;padding:0;margin:10px 0 0;font-size:12px;color:#a7b0c0}
ul.e li{padding:4px 0;border-bottom:1px solid #161b24;word-break:break-all}
.empty{color:#8b93a7}
.limits li{margin:4px 0;color:#a7b0c0}
footer{margin-top:36px;color:#5f687a;font-size:12px;text-align:center}
code{font-family:ui-monospace,Consolas,monospace;color:#c9d1e0}
.muted{color:#6b7488;font-size:11.5px}
</style>
</head>
<body><div class="wrap">
<div class="brand">FAIRY<span>/WEB</span> · EVIDENCE REPORT</div>
<h1>${escapeHtml(result.targets[0] || "")}</h1>
<div class="sub">run ${escapeHtml(result.run_id)} · ${escapeHtml(result.generated_at)} · ${escapeHtml(result.mode)} · ${s.requests} requests / ${s.pages} pages</div>

<div class="panel">
<h2>授权记录</h2>
<div class="kv">
<b>依据</b><span>${escapeHtml(result.scope.authorization.basis)}</span>
<b>操作者</b><span>${escapeHtml(result.scope.authorization.operator || "-")}</span>
<b>include</b><span>${escapeHtml(result.scope.include.join(", "))}</span>
<b>exclude</b><span>${escapeHtml(result.scope.exclude.join(", ") || "-")}</span>
<b>限制</b><span>rps ${result.scope.limits.rps} · max ${result.scope.limits.max_requests} · ${escapeHtml(result.scope.limits.methods.join("/"))} · private ${result.scope.limits.allow_private}</span>
</div>
</div>

<div class="cards">${cards}</div>

<div class="panel">
<h2>发现 (${findings.length})</h2>
${findingHtml}
</div>

<div class="panel">
<h2>页面与技术栈</h2>
<table><thead><tr><th>状态</th><th>URL</th><th>标题</th><th>技术栈</th></tr></thead><tbody>${pages}</tbody></table>
</div>

<div class="panel">
<h2>攻击面草图</h2>
<details open><summary>端点 (${result.attack_surface.endpoints.length})</summary><ul class="e">${endpoints || "<li>无</li>"}</ul></details>
<details><summary>表单 (${result.attack_surface.forms.length})</summary><ul class="e">${forms || "<li>无</li>"}</ul></details>
</div>

<div class="panel">
<h2>覆盖与限制</h2>
<ul class="limits">${result.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
<div class="meta">审计日志: ${escapeHtml(result.audit_path)}(每条发现可用 request_id 回查)</div>
</div>

<footer>Generated by fairy-web 0.1 · 仅限授权目标 · 证据优先,不 dump 数据</footer>
</div></body></html>`;
}
