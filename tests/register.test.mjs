import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { saveScope } from "../src/scope.js";
import { accountsPath, loadAccounts } from "../src/accounts.js";
import { registerAccount } from "../src/register.js";
import { dispatch } from "../src/mcp.js";
import { startLab } from "./fixture-server.mjs";

process.env.FAIRY_REG_PASSWORD = "secret";

function tmpProject(lab, limits = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fairy-register-"));
  saveScope(dir, {
    authorization: { basis: "自建靶场自助注册测试", operator: "fairy-test" },
    include: ["127.0.0.1"],
    limits: { rps: 100, methods: ["GET", "POST"], allow_account_provisioning: true, ...limits },
  });
  return dir;
}

test("自助注册:无 CAPTCHA/手机,单次邮箱注册并写回清单(不含密码)", async () => {
  const lab = await startLab();
  const dir = tmpProject(lab);
  try {
    const out = await registerAccount(dir, {
      signupUrl: `${lab.url}/signup`,
      email: "carol@example.test",
      passwordEnv: "FAIRY_REG_PASSWORD",
      name: "carol",
      loginUrl: `${lab.url}/login`,
      confirm: true,
    });
    assert.equal(out.status, "registered");
    assert.equal(out.account, "carol");
    assert.ok(fs.existsSync(accountsPath(dir)));
    const loaded = loadAccounts(dir);
    assert.ok(loaded.accounts.some((account) => account.name === "carol"));
    const text = fs.readFileSync(accountsPath(dir), "utf8");
    assert.doesNotMatch(text, /secret/);
    assert.doesNotMatch(text, /"password"\s*:/);
    assert.match(text, /FAIRY_REG_PASSWORD/);
  } finally {
    await lab.close();
  }
});

test("自助注册:CAPTCHA 页返回 needs_human,不写账号", async () => {
  const lab = await startLab();
  const dir = tmpProject(lab);
  try {
    const out = await registerAccount(dir, {
      signupUrl: `${lab.url}/signup-captcha`,
      email: "captcha@example.test",
      passwordEnv: "FAIRY_REG_PASSWORD",
      confirm: true,
    });
    assert.equal(out.status, "needs_human");
    assert.match(out.reason, /CAPTCHA|手机|短信|OTP/);
    assert.equal(fs.existsSync(accountsPath(dir)), false);
  } finally {
    await lab.close();
  }
});

test("自助注册:邮箱验证需要人工链接;提供后写回", async () => {
  const lab = await startLab();
  const dir = tmpProject(lab);
  try {
    const first = await registerAccount(dir, {
      signupUrl: `${lab.url}/signup-verify`,
      email: "verify@example.test",
      passwordEnv: "FAIRY_REG_PASSWORD",
      confirm: true,
    });
    assert.equal(first.status, "needs_human");
    assert.equal(first.verification_required, true);
    assert.equal(fs.existsSync(accountsPath(dir)), false);

    const second = await registerAccount(dir, {
      signupUrl: `${lab.url}/signup-verify`,
      email: "verify@example.test",
      passwordEnv: "FAIRY_REG_PASSWORD",
      name: "verified",
      verificationUrl: `${lab.url}/signup/verify`,
      confirm: true,
    });
    assert.equal(second.status, "registered");
    assert.equal(second.verification_used, true);
    assert.ok(loadAccounts(dir).accounts.some((account) => account.name === "verified"));
  } finally {
    await lab.close();
  }
});

test("自助注册:开关/confirm/POST 三重闸门", async () => {
  const lab = await startLab();
  try {
    const off = tmpProject(lab, { allow_account_provisioning: false });
    await assert.rejects(
      () =>
        registerAccount(off, {
          signupUrl: `${lab.url}/signup`,
          email: "off@example.test",
          passwordEnv: "FAIRY_REG_PASSWORD",
          confirm: true,
        }),
      /allow_account_provisioning/,
    );

    const noConfirm = tmpProject(lab);
    await assert.rejects(
      () =>
        registerAccount(noConfirm, {
          signupUrl: `${lab.url}/signup`,
          email: "noconfirm@example.test",
          passwordEnv: "FAIRY_REG_PASSWORD",
        }),
      /confirm=true/,
    );

    const noPost = tmpProject(lab, { methods: ["GET"] });
    await assert.rejects(
      () =>
        registerAccount(noPost, {
          signupUrl: `${lab.url}/signup`,
          email: "nopost@example.test",
          passwordEnv: "FAIRY_REG_PASSWORD",
          confirm: true,
        }),
      /包含 POST/,
    );
  } finally {
    await lab.close();
  }
});

test("MCP:fairy_accounts_register 已注册", async () => {
  const list = await dispatch({ id: 1, method: "tools/list" });
  assert.ok(list.result.tools.some((tool) => tool.name === "fairy_accounts_register"));
});
