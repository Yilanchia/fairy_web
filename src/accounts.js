import fs from "node:fs";
import path from "node:path";
import { login } from "./auth.js";
import { Guard } from "./guard.js";
import {
  initLedger,
  loadLedger,
  appendLedger,
  addAsset,
  addFact,
} from "./ledger.js";
import { listSessions, loadSession } from "./session.js";

// 账号编排:授权人写一份 .fairy/accounts.json,Fairy 只登录一次、只存会话,
// 密码从环境变量取;清单/会话值永不回显,不重试、不爆破。
// 归属关系由授权人显式提供,用于 BOLA 对照;不猜、不读真实用户数据。

export const ACCOUNTS_SCHEMA = "FairyAccounts/v1";

export function accountsPath(projectDir) {
  return path.join(path.resolve(projectDir), ".fairy", "accounts.json");
}

function ensureLedger(projectDir) {
  try {
    return loadLedger(projectDir);
  } catch {
    return initLedger(projectDir).ledger;
  }
}

function cleanOwns(owns) {
  return (Array.isArray(owns) ? owns : [])
    .map((own) => ({
      marker: String(own?.marker || "").trim(),
      url: String(own?.url || "").trim(),
      note: String(own?.note || "").slice(0, 200),
    }))
    .filter((own) => own.marker && own.url);
}

export function loadAccounts(projectDir) {
  const file = accountsPath(projectDir);
  if (!fs.existsSync(file)) {
    throw new Error(`没有账号清单:${file};先由授权人写 .fairy/accounts.json(FairyAccounts/v1)`);
  }
  const record = JSON.parse(fs.readFileSync(file, "utf8"));
  if (record.schema !== ACCOUNTS_SCHEMA) throw new Error(`账号清单 schema 不匹配:${record.schema}`);
  if (!Array.isArray(record.accounts) || !record.accounts.length) throw new Error("账号清单至少一个 accounts");

  const names = new Set();
  const warnings = [];
  const accounts = record.accounts.map((account) => {
    const name = String(account?.name || "").trim();
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) throw new Error(`account.name 不合法:${name}`);
    if (names.has(name)) throw new Error(`account.name 重复:${name}`);
    names.add(name);
    const loginSpec = account.login && typeof account.login === "object" ? account.login : {};
    if (!loginSpec.url) throw new Error(`账号 ${name} 缺少 login.url`);
    if (!loginSpec.password_env && !loginSpec.password) {
      throw new Error(`账号 ${name} 缺少 password_env(推荐)或 password(不推荐)`);
    }
    if (loginSpec.password && !loginSpec.password_env) {
      warnings.push(`账号 ${name} 使用明文 password;建议改用 password_env`);
    }
    return {
      name,
      role: String(account.role || "user").slice(0, 40),
      login: {
        url: String(loginSpec.url),
        method: loginSpec.method ? String(loginSpec.method).toUpperCase() : undefined,
        fields: loginSpec.fields && typeof loginSpec.fields === "object" ? loginSpec.fields : {},
        password_env: loginSpec.password_env ? String(loginSpec.password_env) : null,
        password: loginSpec.password ? String(loginSpec.password) : null,
        token_field: loginSpec.token_field ? String(loginSpec.token_field) : null,
        json: loginSpec.json === true,
      },
      owns: cleanOwns(account.owns),
      seed: account.seed && typeof account.seed === "object" ? account.seed : null,
    };
  });

  try {
    const mode = fs.statSync(file).mode & 0o777;
    if (process.platform !== "win32" && mode & 0o077) {
      warnings.push("accounts.json 权限过宽;建议 chmod 600");
    }
  } catch {
    // 权限检查失败不阻断加载。
  }

  return {
    schema: ACCOUNTS_SCHEMA,
    path: file,
    base_url: record.base_url ? String(record.base_url) : null,
    accounts,
    warnings,
  };
}

function resolvePassword(account) {
  if (account.login.password_env) {
    const value = process.env[account.login.password_env];
    if (!value) throw new Error(`缺少环境变量 ${account.login.password_env}`);
    return value;
  }
  if (account.login.password) return account.login.password;
  throw new Error("缺少登录凭据");
}

export function appendAccount(projectDir, account = {}) {
  const file = accountsPath(projectDir);
  const name = String(account.name || "").trim();
  if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) throw new Error(`account.name 不合法:${name}`);
  if (!account.login?.url) throw new Error("新账号缺少 login.url");
  if (!account.login?.password_env) throw new Error("新账号必须使用 password_env,不能写入明文密码");

  let record;
  if (fs.existsSync(file)) {
    record = JSON.parse(fs.readFileSync(file, "utf8"));
    if (record.schema !== ACCOUNTS_SCHEMA) throw new Error(`账号清单 schema 不匹配:${record.schema}`);
  } else {
    record = { schema: ACCOUNTS_SCHEMA, base_url: null, accounts: [] };
  }
  if (!Array.isArray(record.accounts)) record.accounts = [];
  if (record.accounts.some((item) => item.name === name)) throw new Error(`账号已存在:${name}`);

  const login = {
    url: String(account.login.url),
    method: account.login.method ? String(account.login.method).toUpperCase() : "POST",
    fields: account.login.fields && typeof account.login.fields === "object" ? account.login.fields : {},
    password_env: String(account.login.password_env),
  };
  if (account.login.token_field) login.token_field = String(account.login.token_field);
  const entry = {
    name,
    role: String(account.role || "user").slice(0, 40),
    login,
    owns: cleanOwns(account.owns),
    ...(account.seed && typeof account.seed === "object" ? { seed: account.seed } : {}),
  };
  record.accounts.push(entry);
  if (!record.base_url && account.base_url) record.base_url = String(account.base_url);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  return { file, account: entry };
}

export async function provisionAccounts(projectDir, options = {}) {
  const loaded = loadAccounts(projectDir);
  const only = Array.isArray(options.only) && options.only.length ? new Set(options.only.map(String)) : null;
  const selected = only ? loaded.accounts.filter((account) => only.has(account.name)) : loaded.accounts;
  if (!selected.length) throw new Error("没有匹配的账号可登录");

  ensureLedger(projectDir);
  const provisioned = [];
  const failed = [];

  for (const account of selected) {
    let password;
    try {
      password = resolvePassword(account);
    } catch (error) {
      failed.push({ name: account.name, role: account.role, error: error.message });
      continue;
    }

    const guard = new Guard(projectDir);
    try {
      const result = await login(guard, {
        url: account.login.url,
        session: account.name,
        method: account.login.method,
        fields: { ...(account.login.fields || {}), password },
        token_field: account.login.token_field,
        json: account.login.json,
      });

      appendLedger(projectDir, (ledger) => {
        const asset = addAsset(ledger, {
          type: "account",
          value: account.name,
          tags: ["account", account.role],
        }).asset;
        addFact(ledger, {
          statement: `账号 ${account.name} 已登录 (${account.role})`,
          confidence: "observed",
          tags: ["account", account.role],
          asset_ids: [asset.id],
          evidence: [{ kind: "note", note: "accounts manifest provision" }],
        });
        for (const own of account.owns) {
          addFact(ledger, {
            statement: `${account.name} 拥有对象 ${own.marker} (${own.url})`,
            confidence: "observed",
            tags: ["ownership", account.role],
            asset_ids: [asset.id],
            evidence: [{ kind: "note", url: own.url, note: own.note || "accounts manifest owns" }],
          });
        }
      });

      provisioned.push({
        name: account.name,
        role: account.role,
        session_ready: true,
        status: result.status,
        request_id: result.request_id,
      });
    } catch (error) {
      failed.push({ name: account.name, role: account.role, error: error.message });
    } finally {
      guard.close();
    }
  }

  return {
    schema: "FairyAccountsProvision/v1",
    path: loaded.path,
    provisioned,
    failed,
    warnings: loaded.warnings,
    note: "只登录一次,不重试、不爆破;会话值不在此输出。",
  };
}

export function showAccounts(projectDir) {
  const loaded = loadAccounts(projectDir);
  const ready = new Set(listSessions(projectDir).map((session) => session.name));
  return {
    schema: "FairyAccountsShow/v1",
    path: loaded.path,
    accounts: loaded.accounts.map((account) => ({
      name: account.name,
      role: account.role,
      owns: account.owns.map((own) => own.marker),
      session_ready: ready.has(account.name),
    })),
    bola_pairs: bolaPairs(loaded),
    warnings: loaded.warnings,
  };
}

function extractValue(body, spec = {}) {
  if (spec.from === "regex") {
    if (!spec.pattern) return null;
    try {
      const match = new RegExp(String(spec.pattern)).exec(String(body || ""));
      return match ? match[1] || match[0] : null;
    } catch {
      return null;
    }
  }
  try {
    let value = JSON.parse(String(body || ""));
    for (const key of String(spec.path || "id").split(".")) value = value?.[key];
    return value === undefined || value === null ? null : value;
  } catch {
    return null;
  }
}

// 自建对象做归属真值:每个账号只创建一个最小对象,提取 id 作为 marker。
// 必须 allow_object_seeding + POST 授权 + confirm=true;不删、不改、不批量。
export async function seedAccounts(projectDir, options = {}) {
  const loaded = loadAccounts(projectDir);
  ensureLedger(projectDir);
  const check = new Guard(projectDir);
  const limits = check.limits;
  check.close();
  if (limits.allow_object_seeding !== true) {
    throw new Error("对象播种未授权:scope.limits.allow_object_seeding=true 后重试。");
  }
  if (!limits.methods.includes("POST")) {
    throw new Error("对象播种需要 scope.limits.methods 包含 POST。");
  }
  if (options.confirm !== true) {
    throw new Error("对象播种需要 confirm=true:它会创建最小测试对象,必须显式确认。");
  }

  const only = Array.isArray(options.only) && options.only.length ? new Set(options.only.map(String)) : null;
  const accounts = loaded.accounts.map((account) => ({ ...account, owns: [...(account.owns || [])] }));
  const selected = only ? accounts.filter((account) => only.has(account.name)) : accounts;
  const seeded = [];
  const failed = [];

  for (const account of selected) {
    if (!account.seed?.create) continue;
    try {
      const session = loadSession(projectDir, account.name);
      const base = loaded.base_url || new URL(account.login.url).origin;
      const createUrl = new URL(account.seed.create.url, base).href;
      const method = String(account.seed.create.method || "POST").toUpperCase();
      if (method !== "POST") throw new Error(`seed.create.method 必须是 POST(当前 ${method})`);
      const fields = account.seed.create.fields && typeof account.seed.create.fields === "object" ? account.seed.create.fields : {};
      const json = account.seed.create.json === true;
      const body = json ? JSON.stringify(fields) : new URLSearchParams(fields).toString();
      const headers = {
        ...session.headers,
        "content-type": json ? "application/json" : "application/x-www-form-urlencoded",
      };

      const guard = new Guard(projectDir);
      let response;
      try {
        response = await guard.request(createUrl, { method, headers, body });
      } finally {
        guard.close();
      }
      if (!(response.status >= 200 && response.status < 300)) {
        throw new Error(`创建对象返回 HTTP ${response.status}`);
      }

      const value = extractValue(response.body, account.seed.extract || {});
      if (value === null || value === "") throw new Error("无法从创建响应提取对象 id");
      const markerValue = account.seed.marker_path
        ? extractValue(response.body, { from: "json", path: account.seed.marker_path })
        : account.seed.marker;
      const marker = String(markerValue || value);
      const template = account.seed.item_url || `${createUrl.replace(/\/$/, "")}/{id}`;
      const itemUrl = new URL(String(template).replace("{id}", encodeURIComponent(String(value))), base).href;
      account.owns.push({ marker, url: itemUrl, note: account.seed.note || "seeded object" });

      appendLedger(projectDir, (ledger) => {
        addFact(ledger, {
          statement: `${account.name} 自建对象 ${marker} (${itemUrl})`,
          confidence: "observed",
          tags: ["ownership", "seeded", account.role],
          evidence: [{ kind: "http", request_id: response.request_id, url: createUrl, note: "object seeding" }],
        });
      });

      seeded.push({
        account: account.name,
        marker,
        url: itemUrl,
        request_id: response.request_id,
        status: response.status,
      });
    } catch (error) {
      failed.push({ account: account.name, error: error.message });
    }
  }

  return {
    schema: "FairySeed/v1",
    seeded,
    failed,
    bola_pairs: bolaPairs({ accounts, base_url: loaded.base_url }),
    note: "每个账号只创建一个最小对象;不写回 accounts.json,seeded owns 只在本次返回与账本事实中生效。",
  };
}

export function bolaPairs(loaded) {
  const accounts = Array.isArray(loaded) ? loaded : loaded?.accounts || [];
  const fallbackBase = loaded?.base_url || null;
  const pairs = [];
  const seen = new Set();

  for (const owner of accounts) {
    if (!owner.owns?.length) continue;
    let ownerBase = fallbackBase;
    if (!ownerBase && owner.login?.url) {
      try {
        ownerBase = new URL(owner.login.url).origin;
      } catch {
        ownerBase = null;
      }
    }
    if (!ownerBase) continue;

    for (const own of owner.owns) {
      let url;
      try {
        url = new URL(own.url, ownerBase).href;
      } catch {
        continue;
      }
      for (const viewer of accounts) {
        if (viewer.name === owner.name) continue;
        const key = `${owner.name}|${viewer.name}|${own.marker}|${url}`;
        if (seen.has(key)) continue;
        seen.add(key);
        pairs.push({
          owner: owner.name,
          viewer: viewer.name,
          action: "compare",
          args: {
            url,
            session_a: owner.name,
            session_b: viewer.name,
            marker: own.marker,
          },
          note: `BOLA: ${owner.name} 的对象 ${own.marker},换 ${viewer.name} 读取`,
        });
      }
    }
  }

  return pairs;
}
