import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import path from "node:path";

// Cross-version test runner: Node 20's `node --test` does not accept glob
// patterns, and running browser tests in parallel can exhaust headless
// browsers. Run each test file in its own process, one after another.

const dir = path.resolve("tests");
const files = readdirSync(dir)
  .filter((name) => name.endsWith(".test.mjs"))
  .sort()
  .map((name) => path.join(dir, name));

let failed = 0;
for (const file of files) {
  process.stdout.write(`\n# ${path.basename(file)}\n`);
  const result = spawnSync(process.execPath, ["--test", file], { stdio: "inherit" });
  if (result.status !== 0) failed = result.status || 1;
}

process.exit(failed);
