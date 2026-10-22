import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// 样本分诊:判断 web 上捞到/本地拿到的东西该走 Verdex 的哪条链。
// Fairy 只做识别与登记,不执行样本;真正的逆向/解包交给 Verdex。

const EXT_KIND = {
  apk: "android-apk",
  aab: "android-apk",
  xapk: "android-apk",
  ipa: "ios-ipa",
  jar: "java-jar",
  dex: "dex",
  so: "elf",
  dylib: "macho",
  elf: "elf",
  exe: "pe",
  dll: "pe",
  sys: "pe",
  asar: "electron-asar",
  wxapkg: "wechat-miniprogram",
  har: "har",
  img: "firmware-unknown",
  trx: "firmware-unknown",
  bin: "firmware-unknown",
  zip: "zip",
  tar: "archive",
  gz: "archive",
  tgz: "archive",
  "7z": "archive",
  rar: "archive",
  cab: "archive",
  iso: "archive",
};

const MACHO_HEX = new Set(["feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe", "bebafeca"]);

export function kindFromUrl(value) {
  try {
    const pathname = new URL(String(value)).pathname.toLowerCase();
    const ext = path.extname(pathname).slice(1);
    return EXT_KIND[ext] || null;
  } catch {
    return null;
  }
}

function magic(file) {
  try {
    const fd = fs.openSync(file, "r");
    try {
      const buffer = Buffer.alloc(8);
      fs.readSync(fd, buffer, 0, 8, 0);
      return buffer;
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    return Buffer.alloc(0);
  }
}

export function detectArtifact(file) {
  const target = path.resolve(String(file));
  const buffer = magic(target);
  const hex2 = buffer.subarray(0, 2).toString("hex");
  const hex4 = buffer.subarray(0, 4).toString("hex");
  const ext = path.extname(target).slice(1).toLowerCase();

  if (hex4 === "7f454c46") return "elf";
  if (hex2 === "4d5a") return "pe";
  if (hex2 === "504b") {
    if (ext === "apk" || ext === "aab" || ext === "xapk") return "android-apk";
    if (ext === "ipa") return "ios-ipa";
    if (ext === "jar") return "java-jar";
    return "zip";
  }
  if (MACHO_HEX.has(hex4)) return "macho";
  if (hex4 === "6465780a" || buffer.subarray(0, 3).toString() === "dex") return "dex";
  if (hex4 === "68737173" || hex4 === "73717368") return "firmware-squashfs";
  if (hex4 === "55424923") return "firmware-ubifs";
  if (hex2 === "8519" || hex2 === "1985") return "firmware-jffs2";
  if (ext === "asar") return "electron-asar";
  if (ext === "wxapkg") return "wechat-miniprogram";
  if (ext === "har") return "har";
  return EXT_KIND[ext] || "unknown-file";
}

const CHAINS = {
  elf: [
    ["bin_info", "文件类型/架构/段"],
    ["pwn_checksec", "缓解措施(若做 pwn)"],
    ["bin_decompile", "反编译伪 C(IDA/Ghidra)"],
    ["reconstruct", "需要时由模型重建可读源码"],
  ],
  pe: [
    ["bin_info", "PE 头/架构/段"],
    ["pwn_checksec", "DEP/ASLR/CFG"],
    ["bin_decompile", "反编译伪 C"],
  ],
  macho: [
    ["bin_info", "Mach-O 头/架构"],
    ["bin_decompile", "反编译伪 C(iOS/macOS)"],
  ],
  dotnet: [
    ["dotnet_decompile", "ILSpy 反编译成 C#"],
    ["secrets", "对反编译结果扫硬编码密钥"],
  ],
  "android-apk": [
    ["mobile_unpack", "解包清点(原生库/DEX/资源/manifest)"],
    ["dex_decompile", "DEX → Java(jadx)"],
    ["bin_decompile", "对 lib/*.so 原生库反编译"],
    ["secrets", "对解包目录扫密钥"],
  ],
  "ios-ipa": [
    ["mobile_unpack", "解包清点 Payload"],
    ["bin_decompile", "对 Mach-O 反编译"],
  ],
  "java-jar": [
    ["mobile_unpack", "解包清点"],
    ["dex_decompile", "若含 dex;否则看 .class"],
  ],
  dex: [["dex_decompile", "DEX → Java"]],
  "firmware-squashfs": [
    ["fw_scan", "分流:文件系统/压缩/引导头 + 熵图"],
    ["fw_extract", "解包 SquashFS → rootfs"],
    ["bin_decompile", "对 rootfs 的 ELF 反编译"],
    ["secrets", "对 rootfs 扫凭据"],
  ],
  "firmware-jffs2": [
    ["fw_scan", "分流"],
    ["fw_extract", "解包 JFFS2(jefferson)→ rootfs"],
    ["secrets", "扫凭据"],
  ],
  "firmware-ubifs": [
    ["fw_scan", "分流"],
    ["fw_extract", "解包 UBIFS(ubireader)→ rootfs"],
    ["secrets", "扫凭据"],
  ],
  "firmware-unknown": [
    ["fw_scan", "分流:识别内嵌文件系统/压缩/引导头 + 熵图"],
    ["fw_extract", "识别出 SquashFS/JFFS2/UBI 后解包"],
  ],
  zip: [["mobile_unpack", "按 ZIP 清点(若是 app 包走对应链)"]],
  archive: [["mobile_unpack", "先清点归档内容"]],
  "electron-asar": [
    ["asar_unpack", "解包 Electron 归档"],
    ["js_deobfuscate", "对主/渲染进程 JS 反混淆"],
    ["scan", "对解包目录静态分析"],
  ],
  "wechat-miniprogram": [
    ["wxapkg_unpack", "解包 js/wxml/wxss/json"],
    ["js_deobfuscate", "对 JS 反转义/美化"],
    ["scan", "对解包目录静态分析"],
  ],
  har: [["har_analyze", "抓包流量静态分析"]],
  "unknown-file": [
    ["bin_info", "先看文件类型"],
    ["fw_scan", "疑似固件时做特征+熵分流"],
  ],
};

export function verdexChain(kind) {
  return (CHAINS[kind] || CHAINS["unknown-file"]).map(([tool, why], index) => ({
    step: index + 1,
    tool: `mcp__verdex__${tool}`,
    why,
  }));
}

// Verdex 后端预检:交接前告诉智能体"这条链在本机能不能跑",别让它一头撞到缺 file/objdump。
const COMMAND_CACHE = new Map();
const TOOL_REQUIREMENTS = {
  bin_info: { commands: ["file"] },
  bin_strings: { commands: ["strings"] },
  bin_symbols: { commands: ["nm", "objdump"] },
  bin_disasm: { commands: ["objdump"] },
  pwn_checksec: { commands: ["objdump"] },
  bin_decompile: { env: ["VERDEX_IDA", "VERDEX_GHIDRA"] },
  dotnet_decompile: { env: ["VERDEX_ILSPY"], commands: ["ilspycmd"] },
  dex_decompile: { env: ["VERDEX_JADX"], commands: ["jadx"] },
  fw_extract: { commands: [process.platform === "win32" ? "wsl" : "unsquashfs"] },
};
const PURE_TOOLS = new Set([
  "fw_scan",
  "mobile_unpack",
  "wxapkg_unpack",
  "asar_unpack",
  "js_deobfuscate",
  "scan",
  "secrets",
  "reconstruct",
  "har_analyze",
  "pwn_gadgets",
  "pwn_cyclic",
  "pwn_libc",
  "pwn_template",
  "pwn_gdbscript",
  "impact_proof",
]);

function hasCommand(command) {
  if (COMMAND_CACHE.has(command)) return COMMAND_CACHE.get(command);
  const probe =
    process.platform === "win32"
      ? spawnSync("where.exe", [command], { stdio: "ignore", windowsHide: true })
      : spawnSync("which", [command], { stdio: "ignore" });
  const ok = probe.status === 0;
  COMMAND_CACHE.set(command, ok);
  return ok;
}

function hasEnvPath(key) {
  const value = process.env[key];
  return Boolean(value && fs.existsSync(value));
}

export function preflightTool(tool) {
  const name = String(tool || "").replace(/^mcp__verdex__/, "");
  if (PURE_TOOLS.has(name)) {
    return { tool: `mcp__verdex__${name}`, available: true, missing: [], note: "纯 Node,无外部后端" };
  }
  const requirement = TOOL_REQUIREMENTS[name];
  if (!requirement) {
    return { tool: `mcp__verdex__${name}`, available: null, missing: [], note: "未登记依赖,以 Verdex 实际行为为准" };
  }
  const missing = [];
  for (const command of requirement.commands || []) {
    if (!hasCommand(command)) missing.push(command);
  }
  const envKeys = requirement.env || [];
  const envOk = envKeys.length ? envKeys.some(hasEnvPath) : true;
  const available = missing.length === 0 && (envKeys.length === 0 || envOk);
  return {
    tool: `mcp__verdex__${name}`,
    available: envKeys.length && !envOk && missing.length === 0 ? null : available,
    missing: [...missing, ...(envKeys.length && !envOk ? envKeys : [])],
    note: available
      ? "后端就绪"
      : envKeys.length && !envOk && missing.length === 0
        ? "未检测到 VERDEX_* 环境变量;Verdex 可能自动发现后端"
        : "缺少后端,该步可能失败",
  };
}

export function preflightChain(kind) {
  return verdexChain(kind).map((step) => preflightTool(step.tool));
}

export function describeArtifact(file) {
  const target = path.resolve(String(file));
  const stat = fs.statSync(target);
  const kind = detectArtifact(target);
  return {
    path: target,
    name: path.basename(target),
    bytes: stat.size,
    kind,
    chain: verdexChain(kind),
  };
}
