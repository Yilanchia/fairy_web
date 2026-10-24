import path from "node:path";
import { pathToFileURL } from "node:url";

// Feed a Fairy traffic.har into Verdex's static HAR analyzer.
// Usage: node scripts/verdex-bridge.mjs <file.har> [verdex-root]
// Or set VERDEX_ROOT.
const har = process.argv[2];
if (!har) {
  console.error("Usage: node scripts/verdex-bridge.mjs <file.har> [verdex-root]");
  console.error("       (or set VERDEX_ROOT)");
  process.exit(1);
}

const root = process.argv[3] || process.env.VERDEX_ROOT;
if (!root) {
  console.error("Verdex root not provided. Pass it as the 3rd argument or set VERDEX_ROOT.");
  process.exit(1);
}

const webModule = path.join(root, "src", "web.js");
const mod = await import(pathToFileURL(webModule).href);
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
