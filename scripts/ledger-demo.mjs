import fs from "node:fs";
import path from "node:path";
import { initLedger, loadLedger, ingestScanReport, summary } from "../src/ledger.js";
import { planChains } from "../src/playbooks.js";

// 演示:扫描报告 → 账本 → 攻击链规划。
const project = path.resolve(process.argv[2] || ".");
initLedger(project);

const runsDir = path.join(project, ".fairy", "runs");
const runs = fs
  .readdirSync(runsDir)
  .filter((name) => fs.existsSync(path.join(runsDir, name, "report.json")))
  .sort();
if (!runs.length) throw new Error("没有 report.json:先跑 web_report");
const report = JSON.parse(fs.readFileSync(path.join(runsDir, runs[runs.length - 1], "report.json"), "utf8"));

console.log("== ingest ==");
console.log(JSON.stringify(ingestScanReport(project, report).added, null, 2));
console.log("== summary ==");
console.log(JSON.stringify(summary(loadLedger(project)), null, 2));
console.log("== chains ==");
for (const chain of planChains(loadLedger(project))) {
  console.log(`- [${chain.readiness}] ${chain.id} :: ${chain.title}`);
  if (chain.missing.length) console.log(`    missing: ${chain.missing.join(" / ")}`);
  console.log(`    stop: ${chain.stop}`);
}
