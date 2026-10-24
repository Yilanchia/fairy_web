import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// Mount Fairy (and optionally Verdex) as MCP servers in a dsh profile.
// Usage: node scripts/mount-dsh.mjs [profile]
// Env: DSH_HOME (default ~/.dsh), FAIRY_ROOT (default cwd), VERDEX_ROOT (optional)

const profile = process.argv[2] || "desktop";
const dshHome = process.env.DSH_HOME || path.join(os.homedir(), ".dsh");
const file = path.join(dshHome, "profiles", profile, "cordis.patch.yml");
if (!fs.existsSync(file)) throw new Error(`profile config not found: ${file}`);

const fairyRoot = path.resolve(process.env.FAIRY_ROOT || process.cwd());
const fairyCli = path.join(fairyRoot, "src", "cli.js");
if (!fs.existsSync(fairyCli)) {
  throw new Error(`cannot find ${fairyCli}; run from the fairy_web repo or set FAIRY_ROOT`);
}

const verdexRoot = process.env.VERDEX_ROOT ? path.resolve(process.env.VERDEX_ROOT) : null;
const verdexCli =
  verdexRoot && fs.existsSync(path.join(verdexRoot, "src", "cli.js"))
    ? path.join(verdexRoot, "src", "cli.js")
    : null;

const text = fs.readFileSync(file, "utf8");
if (text.includes("id: mcp-fairy")) {
  console.log("mcp-fairy is already mounted; nothing to do.");
  process.exit(0);
}

const quote = (value) => `'${String(value).replace(/'/g, "''")}'`;
const stamp = Date.now();
fs.copyFileSync(file, `${file}.bak-fairy-${stamp}`);

const lines = [
  "",
  "# --- Fairy Web MCP (added by scripts/mount-dsh.mjs) ---",
  "- insert:",
  "    - id: mcp-fairy",
  "      name: '@deepseek-ai/dsh-mcp-client'",
  "      config:",
  "        serverName: fairy",
  "        transport: stdio",
  "        command: node",
  "        args:",
  `          - ${quote(fairyCli)}`,
  "          - mcp",
  "        env:",
  `          FAIRY_PROJECT: ${quote(fairyRoot)}`,
  `        cwd: ${quote(fairyRoot)}`,
  "        toolCallTimeoutMs: 600000",
];

if (verdexCli) {
  lines.push(
    "    - id: mcp-verdex",
    "      name: '@deepseek-ai/dsh-mcp-client'",
    "      config:",
    "        serverName: verdex",
    "        transport: stdio",
    "        command: node",
    "        args:",
    `          - ${quote(verdexCli)}`,
    "          - mcp",
    `        cwd: ${quote(verdexRoot)}`,
    "        toolCallTimeoutMs: 300000",
  );
}

fs.appendFileSync(file, `${lines.join("\n")}\n`, "utf8");
console.log(`backup: ${file}.bak-fairy-${stamp}`);
console.log(verdexCli ? "mounted: fairy + verdex" : "mounted: fairy (set VERDEX_ROOT to mount verdex too)");
console.log("Restart dsh (or let the MCP client reload) to pick up the new tools.");
