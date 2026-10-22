import fs from "node:fs";

// 把 Fairy / Verdex 两个 MCP server 挂进当前 dsh profile 的 patch 层。
// 默认 desktop profile;可用第一个参数指定 profile 名。
const profile = process.argv[2] || "desktop";
const file = `C:/Users/asus/.dsh/profiles/${profile}/cordis.patch.yml`;
if (!fs.existsSync(file)) throw new Error(`找不到 profile 配置:${file}`);
const text = fs.readFileSync(file, "utf8");
if (text.includes("id: mcp-fairy")) {
  console.log("已经挂载过 mcp-fairy,跳过。");
  process.exit(0);
}
const stamp = Date.now();
fs.copyFileSync(file, `${file}.bak-fairy-${stamp}`);

const block = String.raw`
# --- Fairy Web MCP: node D:\fairy_fairy\src\cli.js mcp ---
- insert:
    - id: mcp-fairy
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: fairy
        transport: stdio
        command: node
        args:
          - 'D:\fairy_fairy\src\cli.js'
          - mcp
        env:
          FAIRY_PROJECT: 'D:\fairy_fairy'
        cwd: 'D:\fairy_fairy'
        toolCallTimeoutMs: 600000
    - id: mcp-verdex
      name: '@deepseek-ai/dsh-mcp-client'
      config:
        serverName: verdex
        transport: stdio
        command: node
        args:
          - 'C:\verdex\src\cli.js'
          - mcp
        cwd: 'C:\verdex'
        toolCallTimeoutMs: 300000
`;
fs.appendFileSync(file, block, "utf8");
console.log(`backup: ${file}.bak-fairy-${stamp}`);
console.log(fs.readFileSync(file, "utf8"));
