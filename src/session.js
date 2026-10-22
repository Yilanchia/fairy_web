import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// 会话保管:登录态是渗透里最敏感的东西,默认不落明文。
// 设了 FAIRY_SESSION_KEY 就 AES-256-GCM;没设就 base64 存并把风险写在文件里。
// 所有 list/show 输出只给名字与元数据,绝不回显 Cookie/Authorization 的值。

export const SESSION_SCHEMA = "FairySession/v1";
const FILE_MODE = 0o600;

export function sessionsDir(projectDir) {
  return path.join(path.resolve(projectDir), ".fairy", "sessions");
}

export function sessionPath(projectDir, name) {
  const safe = String(name || "").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
  if (!safe) throw new Error("session 名不能为空(只允许字母/数字/下划线/短横线)");
  return path.join(sessionsDir(projectDir), `${safe}.json`);
}

function passphrase() {
  const value = process.env.FAIRY_SESSION_KEY;
  return value && value.length >= 8 ? value : null;
}

function keyFrom(pass, salt) {
  return crypto.scryptSync(pass, salt, 32);
}

export function saveSession(projectDir, name, payload = {}) {
  const dir = sessionsDir(projectDir);
  fs.mkdirSync(dir, { recursive: true });
  const file = sessionPath(projectDir, name);
  const body = JSON.stringify({
    headers: payload.headers || {},
    note: String(payload.note || "").slice(0, 300),
    created_at: new Date().toISOString(),
  });

  let record;
  const pass = passphrase();
  if (pass) {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", keyFrom(pass, salt), iv);
    const encrypted = Buffer.concat([cipher.update(body, "utf8"), cipher.final()]);
    record = {
      schema: SESSION_SCHEMA,
      name: String(name),
      enc: "aes-256-gcm",
      salt: salt.toString("base64"),
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      data: encrypted.toString("base64"),
      updated_at: new Date().toISOString(),
    };
  } else {
    record = {
      schema: SESSION_SCHEMA,
      name: String(name),
      enc: "none",
      data: Buffer.from(body, "utf8").toString("base64"),
      updated_at: new Date().toISOString(),
      warning: "未设置 FAIRY_SESSION_KEY:会话仅 base64 存放(等同明文)。生产/真实目标请设置密钥。",
    };
  }

  fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", mode: FILE_MODE });
  try {
    fs.chmodSync(file, FILE_MODE);
  } catch {
    // Windows 上 chmod 可能不生效;目录隔离 + 不进报告是第二道防线。
  }
  return { name: record.name, path: file, enc: record.enc, warning: record.warning || null };
}

export function loadSession(projectDir, name) {
  const file = sessionPath(projectDir, name);
  if (!fs.existsSync(file)) throw new Error(`session 不存在:${name}(先 web_login 或 web_session create)`);
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  if (record.schema !== SESSION_SCHEMA) throw new Error(`session schema 不匹配:${record.schema}`);

  let body;
  if (record.enc === "aes-256-gcm") {
    const pass = passphrase();
    if (!pass) throw new Error(`session ${name} 已加密,请先设置 FAIRY_SESSION_KEY(≥8 字符)`);
    try {
      const decipher = crypto.createDecipheriv(
        "aes-256-gcm",
        keyFrom(pass, Buffer.from(record.salt, "base64")),
        Buffer.from(record.iv, "base64"),
      );
      decipher.setAuthTag(Buffer.from(record.tag, "base64"));
      body = Buffer.concat([decipher.update(Buffer.from(record.data, "base64")), decipher.final()]).toString("utf8");
    } catch {
      throw new Error(`session ${name} 解密失败:密钥不对或文件被改动`);
    }
  } else {
    body = Buffer.from(record.data, "base64").toString("utf8");
  }

  const parsed = JSON.parse(body);
  return {
    name: record.name,
    headers: parsed.headers || {},
    note: parsed.note || "",
    created_at: parsed.created_at,
    enc: record.enc,
  };
}

export function listSessions(projectDir) {
  const dir = sessionsDir(projectDir);
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => {
      try {
        const record = JSON.parse(fs.readFileSync(path.join(dir, file), "utf8"));
        return { name: record.name, enc: record.enc, updated_at: record.updated_at };
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => String(a.name).localeCompare(String(b.name)));
}

export function describeSession(projectDir, name) {
  const session = loadSession(projectDir, name);
  return {
    name: session.name,
    enc: session.enc,
    created_at: session.created_at,
    note: session.note,
    header_names: Object.keys(session.headers),
  };
}

export function deleteSession(projectDir, name) {
  const file = sessionPath(projectDir, name);
  if (!fs.existsSync(file)) throw new Error(`session 不存在:${name}`);
  fs.rmSync(file);
  return { deleted: true, name };
}
