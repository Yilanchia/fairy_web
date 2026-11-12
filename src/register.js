import { Guard } from "./guard.js";
import { parseForms } from "./auth.js";
import { appendAccount } from "./accounts.js";

// 自助注册(最危险的一块):只处理授权人控制的单次邮箱注册。
// 遇到 CAPTCHA/手机/SMS/OTP 一律 needs_human,不绕过、不识别、不重试。
// 邮箱验证只接受授权人手动提供的 verification_url;不轮询收件箱。
// 密码只从 password_env 取,写回清单时也只写 env 名。

const RISK_RE = /captcha|recaptcha|hcaptcha|phone|mobile|sms|otp|mfa|verification_code/i;
const VERIFY_RE = /verify|verification|confirm your (e-?mail|account)|check your (e-?mail|inbox)/i;

function human(reason, extra = {}) {
  return { status: "needs_human", reason, ...extra, note: "未绕过反自动化控制;请人工完成这一步。" };
}

export async function registerAccount(projectDir, options = {}) {
  const signupUrl = String(options.signupUrl || options.signup_url || "");
  const email = String(options.email || "").trim();
  const passwordEnv = String(options.passwordEnv || options.password_env || "").trim();
  if (!signupUrl) throw new Error("需要 signup_url");
  if (!email) throw new Error("需要 email");
  if (!passwordEnv) throw new Error("需要 password_env(不接受明文密码入库)");
  if (!process.env[passwordEnv]) throw new Error(`缺少环境变量 ${passwordEnv}`);

  const guard = new Guard(projectDir);
  try {
    if (guard.limits.allow_account_provisioning !== true) {
      throw new Error("自助注册未授权:scope.limits.allow_account_provisioning=true 后重试。");
    }
    if (!guard.limits.methods.includes("POST")) {
      throw new Error("自助注册需要 scope.limits.methods 包含 POST。");
    }
    if (options.confirm !== true) {
      throw new Error("自助注册需要 confirm=true:它会提交一次注册表单。");
    }

    const page = await guard.request(signupUrl);
    const forms = parseForms(page.body);
    const form = forms.find((item) => item.has_password) || forms.find((item) => item.inputs.length) || null;
    if (!form) return human("注册页没有可解析表单(可能是 SPA/JSON 注册)", { request_id: page.request_id });

    const risky = form.inputs.filter((input) => RISK_RE.test(input.name));
    if (risky.length || RISK_RE.test(page.body)) {
      return human("检测到 CAPTCHA/手机/短信/OTP;不提交、不绕过", {
        request_id: page.request_id,
        signals: risky.map((input) => input.name).slice(0, 5),
      });
    }

    const method = String(form.method || "POST").toUpperCase();
    if (method !== "POST") return human(`注册表单方法是 ${method},不是 POST`, { request_id: page.request_id });

    const data = {};
    for (const input of form.inputs) {
      if (["submit", "button", "reset", "file"].includes(input.type)) continue;
      if (input.type === "password") continue;
      if (input.value) data[input.name] = input.value;
    }
    Object.assign(data, options.fields || {}, { email });
    data.password = process.env[passwordEnv];
    if (options.username) data.username = String(options.username);

    const action = new URL(form.action || page.url, page.url).href;
    const response = await guard.request(action, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(data).toString(),
    });

    if (response.status < 200 || response.status >= 400) {
      return human(`注册请求返回 HTTP ${response.status}`, { request_id: response.request_id });
    }

    const needsVerification = VERIFY_RE.test(response.body || "");
    if (needsVerification && !options.verificationUrl) {
      return human("注册需要邮箱验证;把验证链接作为 verification_url 传入后再确认", {
        request_id: response.request_id,
        verification_required: true,
      });
    }
    if (needsVerification && options.verificationUrl) {
      const verifyUrl = new URL(String(options.verificationUrl), response.url).href;
      const verified = await guard.request(verifyUrl);
      if (verified.status < 200 || verified.status >= 400) {
        return human(`验证链接返回 HTTP ${verified.status}`, { request_id: verified.request_id });
      }
    }

    const name = String(options.name || email.split("@")[0]).replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
    const loginUrl = String(options.loginUrl || options.login_url || signupUrl);
    const added = appendAccount(projectDir, {
      name,
      role: options.role || "user",
      base_url: new URL(signupUrl).origin,
      login: {
        url: loginUrl,
        method: "POST",
        fields: options.loginFields || { email },
        password_env: passwordEnv,
      },
      owns: [],
    });

    return {
      schema: "FairyRegister/v1",
      status: "registered",
      account: added.account.name,
      password_env: passwordEnv,
      file: added.file,
      request_id: response.request_id,
      verification_used: Boolean(needsVerification && options.verificationUrl),
      note: "未回显密码;新账号使用 password_env。若目标需要邮箱验证,只接受人工提供的链接。",
    };
  } finally {
    guard.close();
  }
}
