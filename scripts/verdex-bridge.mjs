import path from "node:path";
import { pathToFileURL } from "node:url";

// Fairy 采集 → Verdex 静态复核:把 fairy 产出的 traffic.har 直接喂给 Verdex 的 har_analyze。
const har = process.argv[2];
if (!har) {
  console.error("用法: node scripts/verdex-bridge.mjs <file.har> [verdex 根目录]");
  process.exit(1);
}
const root = process.argv[3] || "D:\\漏洞挖掘工作台";
const mod = await import(pathToFileURL(path.join(root, "src", "web.js")).href);
const result = mod.analyzeHar(path.resolve(har));
console.log(
  JSON.stringify(
    {
      entry_count: result.entry_count,
      finding_count: result.finding_count,
      by_kind: result.by_kind,
      top_findings: result.findings.slice(0, 5),
    },
    null,
    2,
  ),
);
