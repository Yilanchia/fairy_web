import { browse } from "./browser.js";
import { shortHash, truncate } from "./util.js";

// DOM 反射上下文判定:只回答"标记落在哪",不生成利用载荷。
// script 文本 / 事件处理属性 / 普通属性 / HTML 文本 / 注释,五种上下文。

function expressionFor(marker) {
  return `(() => {
    const marker = ${JSON.stringify(marker)};
    const result = { found: false, context: null, tag: null, attr: null, snippet: null };
    for (const el of document.querySelectorAll('*')) {
      for (const attr of el.attributes) {
        if (attr.value.includes(marker)) {
          result.found = true;
          result.context = 'attribute';
          result.tag = el.tagName.toLowerCase();
          result.attr = attr.name;
          result.snippet = attr.value.slice(0, 160);
          return result;
        }
      }
    }
    const textWalker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_TEXT);
    while (textWalker.nextNode()) {
      const node = textWalker.currentNode;
      if (node.nodeValue.includes(marker)) {
        const parent = node.parentElement;
        const tag = parent ? parent.tagName.toLowerCase() : null;
        result.found = true;
        result.context = tag === 'script' ? 'script' : tag === 'style' ? 'style' : 'text';
        result.tag = tag;
        result.snippet = node.nodeValue.slice(0, 160);
        return result;
      }
    }
    const commentWalker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    while (commentWalker.nextNode()) {
      const node = commentWalker.currentNode;
      if (node.nodeValue.includes(marker)) {
        result.found = true;
        result.context = 'comment';
        result.snippet = node.nodeValue.slice(0, 160);
        return result;
      }
    }
    return result;
  })()`;
}

function headerValue(headers, name) {
  for (const key of Object.keys(headers || {})) {
    if (key.toLowerCase() === name) return headers[key];
  }
  return null;
}

export async function inspectDomContext(guard, options = {}) {
  const url = String(options.url || "");
  const param = String(options.param || "");
  if (!url) throw new Error("需要 URL");
  if (!param) throw new Error("需要 param(要判定上下文的查询参数名)");

  const marker = `fairy${shortHash(`${url}:${param}:${Date.now()}`, 8)}`;
  const target = new URL(url);
  target.searchParams.set(param, marker);

  const out = await browse(guard, {
    url: target.href,
    session: options.session || null,
    sessionHeaders: options.sessionHeaders || null,
    waitMs: Number.isFinite(Number(options.waitMs)) ? Number(options.waitMs) : 500,
    screenshot: options.screenshot === true,
    captureExpression: expressionFor(marker),
  });

  const context = out.capture || { found: false, context: null, tag: null, attr: null, snippet: null };
  const csp = headerValue(out.response_headers, "content-security-policy");
  const cspText = csp ? truncate(csp, 200) : null;

  let verdict = "not-reflected";
  let risk = "low";
  let interpretation = "页面 DOM 里没有找到标记;可能未反射,或只出现在响应源码/被脚本消费掉。";

  if (context.found) {
    if (context.context === "script") {
      verdict = "candidate-script-context";
      risk = cspText && !/unsafe-inline/i.test(cspText) ? "medium" : "high";
      interpretation = "标记落在 <script> 文本里,处于可执行上下文;需人工确认能否闭合字符串/语句。";
    } else if (context.context === "attribute" && /^on/i.test(context.attr || "")) {
      verdict = "candidate-event-handler";
      risk = cspText && !/unsafe-inline/i.test(cspText) ? "medium" : "high";
      interpretation = `标记落在事件处理属性 ${context.attr};浏览器会把它当 JS 执行。`;
    } else if (context.context === "attribute") {
      verdict = "attribute-context";
      risk = "low";
      interpretation = `标记落在属性 ${context.attr};只有 javascript:/data: 等协议或特定 sink 才可执行。`;
    } else if (context.context === "text") {
      verdict = "html-text";
      risk = "low";
      interpretation = "标记落在 HTML 文本节点;如果编码正确,通常不可执行。";
    } else if (context.context === "comment") {
      verdict = "html-comment";
      risk = "low";
      interpretation = "标记落在 HTML 注释;通常不可执行。";
    } else if (context.context === "style") {
      verdict = "style-context";
      risk = "low";
      interpretation = "标记落在 <style>;CSS 注入通常影响有限,除非结合旧浏览器特性。";
    }
  }

  return {
    ok: true,
    url: target.href,
    marker,
    reflected: context.found,
    context,
    csp: cspText,
    csp_present: Boolean(cspText),
    verdict,
    risk,
    interpretation,
    note: "只判定上下文,不生成 XSS 载荷;真正的执行证明由人在浏览器里完成。",
    limitations: [
      "标记是无特殊字符的 fairy<hex>,只能看落点,不能判断转义是否完整。",
      "CSP 判断只看响应头里有没有 unsafe-inline,未解析 nonce/hash 细节。",
      "不执行任何脚本证明;需要执行证明时由人工在测试账号里做。",
    ],
  };
}
