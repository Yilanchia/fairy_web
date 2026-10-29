import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { startLab } from "../tests/fixture-server.mjs";
import { saveScope } from "../src/scope.js";
import { executeScan } from "../src/scan.js";
import { Guard } from "../src/guard.js";
import { runParamProbes } from "../src/probe.js";

// 本地基准:只跑本机靶场,不访问外网。
// 指标:按类别的召回率、非预期类别误报、请求数、耗时。

const EXPECTED = [
  { kind: "security-header", min: 3 },
  { kind: "cookie", min: 1 },
  { kind: "cors", min: 1 },
  { kind: "exposure", min: 1 },
  { kind: "reflection", min: 1 },
  { kind: "open-redirect", min: 1 },
  { kind: "info-disclosure", min: 1 },
  { kind: "sqli", min: 2 },
  { kind: "ssti", min: 1 },
];

const lab = await startLab();
const project = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-bench-"));
saveScope(project, {
  authorization: { basis: "Fairy local benchmark", operator: "bench" },
  include: ["127.0.0.1"],
  limits: { rps: 200, allow_active_probes: true },
});

const started = Date.now();
let safety = null;

try {
  const scanUrls = [
    `${lab.url}/`,
    `${lab.url}/search?q=hello`,
    `${lab.url}/redirect?next=/home`,
    `${lab.url}/login`,
    `${lab.url}/cors`,
    `${lab.url}/api/data`,
    `${lab.url}/admin`,
  ];
  const { result } = await executeScan(project, { urls: scanUrls });

  const guard = new Guard(project);
  let param;
  try {
    param = await runParamProbes(guard, {
      urls: [
        `${lab.url}/sqli?q=1`,
        `${lab.url}/boolean?q=1`,
        `${lab.url}/ssti?q=hello`,
        `${lab.url}/safe?q=hello`,
      ],
      confirm: true,
      classes: ["sqli", "ssti"],
    });
  } finally {
    safety = guard.summary();
    guard.close();
  }

  const seen = new Set();
  const findings = [...result.findings, ...param.findings].filter((finding) => {
    const key = `${finding.kind}|${finding.where}|${finding.title}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const actualByKind = {};
  for (const finding of findings) actualByKind[finding.kind] = (actualByKind[finding.kind] || 0) + 1;

  const expectedTotal = EXPECTED.reduce((sum, item) => sum + item.min, 0);
  let matched = 0;
  const byKind = EXPECTED.map((item) => {
    const actual = actualByKind[item.kind] || 0;
    const hit = Math.min(actual, item.min);
    matched += hit;
    return { kind: item.kind, expected: item.min, actual, hit, missed: Math.max(0, item.min - actual) };
  });

  const expectedKinds = new Set(EXPECTED.map((item) => item.kind));
  const unexpected = findings.filter((finding) => !expectedKinds.has(finding.kind));
  const requests = result.stats.requests + param.stats.requests;
  const duration = Date.now() - started;

  const metrics = {
    expected_total: expectedTotal,
    matched,
    recall: expectedTotal ? matched / expectedTotal : 0,
    precision: findings.length ? (findings.length - unexpected.length) / findings.length : 1,
    findings: findings.length,
    unexpected_kinds: unexpected.length,
    requests,
    duration_ms: duration,
    cost_per_finding: findings.length ? requests / findings.length : null,
    out_of_scope_requests: safety ? safety.blocked : null,
  };

  const output = {
    schema: "FairyBench/v1",
    generated_at: new Date().toISOString(),
    target: lab.url,
    metrics,
    by_kind: byKind,
    findings: findings.map((finding) => ({
      id: finding.id,
      kind: finding.kind,
      severity: finding.severity,
      title: finding.title,
      where: finding.where,
    })),
  };

  const resultsDir = path.resolve("bench", "results");
  fs.mkdirSync(resultsDir, { recursive: true });
  fs.writeFileSync(path.join(resultsDir, "latest.json"), `${JSON.stringify(output, null, 2)}\n`, "utf8");

  const lines = [
    "# Fairy Bench",
    "",
    `- 时间: ${output.generated_at}`,
    `- 指标: recall **${(metrics.recall * 100).toFixed(1)}%** / precision **${(metrics.precision * 100).toFixed(1)}%**`,
    `- 请求: ${metrics.requests} / 发现: ${metrics.findings} / 单条发现成本: ${metrics.cost_per_finding?.toFixed(1)} 请求`,
    `- 耗时: ${metrics.duration_ms} ms`,
    "",
    "| 类别 | 期望 | 实际 | 命中 | 缺失 |",
    "|---|---:|---:|---:|---:|",
    ...byKind.map((row) => `| ${row.kind} | ${row.expected} | ${row.actual} | ${row.hit} | ${row.missed} |`),
    "",
    "> 这是本机靶场的类别级基准,不是完整产品评测。读数为候选发现,不是已验证漏洞。",
  ];
  fs.writeFileSync(path.join(resultsDir, "latest.md"), `${lines.join("\n")}\n`, "utf8");

  console.log(
    `recall=${(metrics.recall * 100).toFixed(1)}% precision=${(metrics.precision * 100).toFixed(1)}% ` +
      `requests=${metrics.requests} findings=${metrics.findings} cost=${metrics.cost_per_finding?.toFixed(1)}`,
  );
  console.log(`results: ${path.join(resultsDir, "latest.json")}`);
} finally {
  await lab.close();
}
