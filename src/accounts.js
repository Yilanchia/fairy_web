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
import { listSessions } from "./session.js";

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
