import fs from "node:fs";
import path from "node:path";
import { loadScope } from "./scope.js";
import { nowIso, severityRank } from "./util.js";

// 作战账本:一次 engagement 的"资产 / 事实 / 发现 / 意图 / 覆盖"。
// 对标 ARTEX 的双图,但刻意做小:JSON 落盘、可读、可 diff、可进报告。

export const LEDGER_SCHEMA = "FairyLedger/v1";
export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const ASSET_TYPES = new Set(["host", "endpoint", "param", "account", "tech", "artifact", "note"]);
const RISKS = new Set(["low", "medium", "high"]);
const FINDING_STATUS = new Set(["candidate", "verified", "false-positive", "remediated", "accepted-risk"]);
const INTENT_STATUS = new Set(["todo", "active", "done", "blocked", "skipped"]);

export function ledgerPath(projectDir) {
  return path.join(path.resolve(projectDir), ".fairy", "ledger.json");
}

export function loadLedger(projectDir) {
  const file = ledgerPath(projectDir);
  if (!fs.existsSync(file)) {
    throw new Error(`尚未建立作战账本:${file}。先运行 fairy_ledger_init(需要已有授权护照)。`);
  }
  const ledger = JSON.parse(fs.readFileSync(file, "utf8"));
  if (ledger.schema !== LEDGER_SCHEMA) throw new Error(`账本 schema 不匹配:${ledger.schema}`);
  return ledger;
}

export function saveLedger(projectDir, ledger) {
  const file = ledgerPath(projectDir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  ledger.updated_at = nowIso();
  const tmp = `${file}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(ledger, null, 2)}\n`, "utf8");
  fs.renameSync(tmp, file);
  return ledger;
}

export function initLedger(projectDir, options = {}) {
  const dir = path.resolve(projectDir);
  const file = ledgerPath(dir);
  if (fs.existsSync(file)) return { created: false, ledger: loadLedger(dir) };
  const scope = loadScope(dir);
  const ledger = {
    schema: LEDGER_SCHEMA,
    engagement: {
      name: options.name || path.basename(dir) || "engagement",
      created_at: nowIso(),
      updated_at: nowIso(),
      scope: {
        basis: scope.authorization.basis,
        operator: scope.authorization.operator,
        include: scope.include,
        exclude: scope.exclude,
      },
    },
    assets: [],
    facts: [],
    findings: [],
    intents: [],
    coverage: { notes: [], runs: [] },
    log: [],
  };
  saveLedger(dir, ledger);
  return { created: true, ledger };
}

export function appendLedger(projectDir, mutate) {
  const ledger = loadLedger(projectDir);
  const result = mutate(ledger);
  saveLedger(projectDir, ledger);
  return result;
}

function nextId(items, prefix) {
  let max = 0;
  const rx = new RegExp(`^${prefix}-(\\d+)$`);
  for (const item of items) {
    const match = rx.exec(item.id || "");
    if (match) max = Math.max(max, Number(match[1]));
  }
  return `${prefix}-${String(max + 1).padStart(3, "0")}`;
}

function cleanTags(tags) {
  return [...new Set((Array.isArray(tags) ? tags : []).map((t) => String(t).trim()).filter(Boolean))].slice(0, 12);
}

function normalizeEvidence(list) {
  return (Array.isArray(list) ? list : []).slice(0, 20).map((e) => ({
    kind: String(e?.kind || "http"),
    request_id: e?.request_id ? String(e.request_id) : null,
    url: e?.url ? String(e.url).slice(0, 500) : null,
    snippet: e?.snippet ? String(e.snippet).slice(0, 400) : null,
    note: e?.note ? String(e.note).slice(0, 200) : null,
  }));
}

export function addAsset(ledger, input = {}) {
  const type = String(input.type || "").toLowerCase();
  if (!ASSET_TYPES.has(type)) throw new Error(`asset.type 必须是:${[...ASSET_TYPES].join("/")}`);
  const value = String(input.value || "").trim();
  if (!value) throw new Error("asset.value 必填");
  const parentId = input.parent_id ? String(input.parent_id) : null;
  if (parentId && !ledger.assets.some((a) => a.id === parentId)) throw new Error(`asset.parent_id 不存在:${parentId}`);
  const existing = ledger.assets.find((a) => a.type === type && a.value === value && (a.parent_id || null) === parentId);
  if (existing) return { asset: existing, added: false };
  const asset = {
    id: nextId(ledger.assets, "AS"),
    type,
    value: value.slice(0, 500),
    parent_id: parentId,
    tags: cleanTags(input.tags),
    tested: false,
    tested_at: null,
    created_at: nowIso(),
  };
  ledger.assets.push(asset);
  ledger.log.push({ ts: nowIso(), action: "asset.add", id: asset.id, value: asset.value });
  return { asset, added: true };
}

export function addFact(ledger, input = {}) {
  const statement = String(input.statement || "").trim();
  if (statement.length < 4) throw new Error("fact.statement 至少 4 个字");
  const existing = ledger.facts.find((f) => f.statement === statement);
  if (existing) return { fact: existing, added: false };
  const assetIds = (Array.isArray(input.asset_ids) ? input.asset_ids : []).filter((id) =>
    ledger.assets.some((a) => a.id === id),
  );
  const fact = {
    id: nextId(ledger.facts, "FT"),
    statement: statement.slice(0, 500),
    confidence: ["observed", "inferred", "verified"].includes(input.confidence) ? input.confidence : "inferred",
    tags: cleanTags(input.tags),
    asset_ids: assetIds,
    evidence: normalizeEvidence(input.evidence),
    created_at: nowIso(),
  };
  ledger.facts.push(fact);
  ledger.log.push({ ts: nowIso(), action: "fact.add", id: fact.id, statement: fact.statement });
  return { fact, added: true };
}

export function addFinding(ledger, input = {}) {
  const title = String(input.title || "").trim();
  if (!title) throw new Error("finding.title 必填");
  const severity = SEVERITIES.includes(input.severity) ? input.severity : "medium";
  const kind = String(input.kind || "unknown");
  const where = String(input.where || "").slice(0, 500);
  const existing = ledger.findings.find((f) => f.title === title && f.kind === kind && f.where === where);
  if (existing) return { finding: existing, added: false };
  const finding = {
    id: nextId(ledger.findings, "V"),
    title: title.slice(0, 200),
    kind,
    severity,
    status: FINDING_STATUS.has(input.status) ? input.status : "candidate",
    where,
    detail: input.detail ? String(input.detail).slice(0, 1000) : "",
    impact: input.impact ? String(input.impact).slice(0, 1000) : "",
    remediation: input.remediation ? String(input.remediation).slice(0, 1000) : "",
    owasp: input.owasp ? String(input.owasp).slice(0, 80) : null,
    cvss: Number.isFinite(Number(input.cvss)) ? Number(input.cvss) : null,
    evidence: normalizeEvidence(input.evidence),
    source_run_id: input.source_run_id || null,
    source_id: input.source_id || null,
    created_at: nowIso(),
    updated_at: nowIso(),
  };
  ledger.findings.push(finding);
  ledger.log.push({ ts: nowIso(), action: "finding.add", id: finding.id, title: finding.title });
  return { finding, added: true };
}

export function addIntent(ledger, input = {}) {
  const goal = String(input.goal || "").trim();
  if (goal.length < 4) throw new Error("intent.goal 至少 4 个字");
  const dependsOn = (Array.isArray(input.depends_on) ? input.depends_on : []).map(String);
  for (const id of dependsOn) {
    if (!ledger.intents.some((i) => i.id === id)) throw new Error(`intent.depends_on 不存在:${id}`);
  }
  const assetIds = (Array.isArray(input.asset_ids) ? input.asset_ids : []).filter((id) =>
    ledger.assets.some((a) => a.id === id),
  );
  const existing = ledger.intents.find(
    (item) => item.goal === goal && (item.status === "todo" || item.status === "active"),
  );
  if (existing) return existing;
  const intent = {
    id: nextId(ledger.intents, "I"),
    goal: goal.slice(0, 300),
    status: "todo",
    depends_on: dependsOn,
    asset_ids: assetIds,
    risk: RISKS.has(input.risk) ? input.risk : "low",
    requires_approval: input.requires_approval === true,
    approved: input.approved === true,
    stop_condition: input.stop_condition ? String(input.stop_condition).slice(0, 400) : "",
    chain_id: input.chain_id ? String(input.chain_id) : null,
    step_index:
      input.step_index === undefined
        ? null
        : Number.isInteger(Number(input.step_index))
          ? Number(input.step_index)
          : null,
    work: input.work && typeof input.work === "object" && !Array.isArray(input.work) ? input.work : null,
    result: "",
    created_at: nowIso(),
    started_at: null,
    completed_at: null,
  };
  ledger.intents.push(intent);
  ledger.log.push({ ts: nowIso(), action: "intent.add", id: intent.id, goal: intent.goal });
  return intent;
}

export function claimNextIntent(ledger) {
  const done = new Set(ledger.intents.filter((i) => i.status === "done" || i.status === "skipped").map((i) => i.id));
  const next = ledger.intents.find(
    (i) =>
      i.status === "todo" &&
      (i.depends_on || []).every((dep) => done.has(dep)) &&
      (!i.requires_approval || i.approved),
  );
  if (!next) return null;
  next.status = "active";
  next.started_at = nowIso();
  ledger.log.push({ ts: nowIso(), action: "intent.claim", id: next.id });
  return next;
}

export function approveIntent(ledger, intentId) {
  const intent = ledger.intents.find((item) => item.id === intentId);
  if (!intent) throw new Error(`intent 不存在:${intentId}`);
  if (!intent.requires_approval) throw new Error(`intent ${intentId} 不需要审批`);
  intent.approved = true;
  ledger.log.push({ ts: nowIso(), action: "intent.approve", id: intentId });
  return intent;
}

export function completeIntent(ledger, intentId, options = {}) {
  const intent = ledger.intents.find((i) => i.id === intentId);
  if (!intent) throw new Error(`intent 不存在:${intentId}`);
  const status = INTENT_STATUS.has(options.status) ? options.status : "done";
  if (status === "todo" || status === "active") throw new Error("completeIntent 只接受 done/blocked/skipped");
  intent.status = status;
  intent.result = String(options.note || "").slice(0, 1000);
  intent.completed_at = nowIso();
  if (status === "done") {
    for (const assetId of intent.asset_ids || []) {
      const asset = ledger.assets.find((a) => a.id === assetId);
      if (!asset) continue;
      asset.tested = true;
      asset.tested_at = nowIso();
    }
  }
  ledger.log.push({ ts: nowIso(), action: "intent.complete", id: intent.id, status });
  return intent;
}

export function updateFinding(ledger, findingId, patch = {}) {
  const finding = ledger.findings.find((f) => f.id === findingId);
  if (!finding) throw new Error(`finding 不存在:${findingId}`);
  if (patch.status !== undefined) {
    if (!FINDING_STATUS.has(patch.status)) throw new Error(`status 必须是:${[...FINDING_STATUS].join("/")}`);
    finding.status = patch.status;
  }
  for (const key of ["impact", "remediation", "owasp", "detail"]) {
    if (patch[key] !== undefined) finding[key] = String(patch[key]).slice(0, 1000);
  }
  if (patch.cvss !== undefined) finding.cvss = Number.isFinite(Number(patch.cvss)) ? Number(patch.cvss) : null;
  finding.updated_at = nowIso();
  ledger.log.push({ ts: nowIso(), action: "finding.update", id: findingId, status: finding.status });
  return finding;
}

export function summary(ledger) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byStatus = { candidate: 0, verified: 0, "false-positive": 0, remediated: 0, "accepted-risk": 0 };
  for (const finding of ledger.findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    byStatus[finding.status] = (byStatus[finding.status] || 0) + 1;
  }
  const assetsByType = {};
  for (const asset of ledger.assets) assetsByType[asset.type] = (assetsByType[asset.type] || 0) + 1;
  const tested = ledger.assets.filter((a) => a.tested).length;
  const intentsByStatus = {};
  for (const intent of ledger.intents) intentsByStatus[intent.status] = (intentsByStatus[intent.status] || 0) + 1;
  const doneIds = new Set(ledger.intents.filter((i) => i.status === "done" || i.status === "skipped").map((i) => i.id));
  const next = ledger.intents.find(
    (i) =>
      i.status === "todo" &&
      (i.depends_on || []).every((d) => doneIds.has(d)) &&
      (!i.requires_approval || i.approved),
  );

  return {
    schema: ledger.schema,
    engagement: ledger.engagement,
    counts: {
      assets: ledger.assets.length,
      facts: ledger.facts.length,
      findings: ledger.findings.length,
      intents: ledger.intents.length,
    },
    assets: { by_type: assetsByType, tested, total: ledger.assets.length, percent: ledger.assets.length ? Math.round((tested / ledger.assets.length) * 100) : 0 },
    findings: { by_severity: bySeverity, by_status: byStatus },
    intents: { by_status: intentsByStatus, next: next ? { id: next.id, goal: next.goal, risk: next.risk } : null },
    updated_at: ledger.updated_at,
  };
}

export function ingestScanReport(projectDir, report) {
  if (!report || report.schema !== "FairyScan/v1") throw new Error("ingest 需要 FairyScan/v1 报告");
  return appendLedger(projectDir, (ledger) => {
    if (ledger.coverage.runs.some((run) => run.run_id === report.run_id)) {
      return { run_id: report.run_id, skipped: true, reason: "该 run 已导入过", summary: summary(ledger) };
    }
    const before = { assets: ledger.assets.length, facts: ledger.facts.length, findings: ledger.findings.length };
    const hosts = new Map();

    for (const page of report.pages || []) {
      let url;
      try {
        url = new URL(page.requested_url || page.url);
      } catch {
        continue;
      }
      const hostKey = url.host;
      let host = hosts.get(hostKey);
      if (!host) {
        const result = addAsset(ledger, { type: "host", value: hostKey, tags: ["scan"] });
        host = result.asset;
        hosts.set(hostKey, host);
      }
      addAsset(ledger, {
        type: "endpoint",
        value: `${url.pathname}${url.search}`,
        parent_id: host.id,
        tags: ["scan", String(page.status)],
      });
      for (const tech of page.tech || []) {
        addFact(ledger, {
          statement: `${hostKey} 使用 ${tech.tech}${tech.version ? ` ${tech.version}` : ""}`,
          confidence: "observed",
          tags: ["tech", tech.tech],
          asset_ids: [host.id],
          evidence: [{ kind: "http", url: page.requested_url || page.url, note: "web_scan fingerprint" }],
        });
      }
    }

    for (const artifact of report.attack_surface?.artifacts || []) {
      const asset = addAsset(ledger, {
        type: "artifact",
        value: artifact.url,
        tags: ["url", artifact.kind || "unknown"],
      }).asset;
      addFact(ledger, {
        statement: `发现疑似 ${artifact.kind || "unknown"} 样本:${artifact.url}`,
        confidence: "observed",
        tags: ["artifact", artifact.kind || "unknown"],
        asset_ids: [asset.id],
        evidence: [{ kind: "http", url: artifact.url, note: "web_scan artifact discovery" }],
      });
    }

    for (const finding of report.findings || []) {
      addFinding(ledger, {
        title: finding.title,
        kind: finding.kind,
        severity: finding.severity,
        where: finding.where,
        detail: finding.detail,
        impact: finding.impact,
        remediation: finding.remediation,
        owasp: finding.owasp,
        cvss: finding.cvss,
        status: "candidate",
        evidence: [
          {
            kind: "http",
            request_id: finding.evidence?.request_id || null,
            url: finding.where,
            snippet: finding.evidence?.snippet || null,
          },
        ],
        source_run_id: report.run_id,
        source_id: finding.id,
      });
    }

    ledger.coverage.runs.push({
      run_id: report.run_id,
      imported_at: nowIso(),
      pages: (report.pages || []).length,
      requests: report.stats?.requests || 0,
      findings: (report.findings || []).length,
    });
    ledger.coverage.notes.push(
      `导入 ${report.run_id}:${(report.pages || []).length} 页 / ${(report.findings || []).length} 条候选(候选不等于已验证)`,
    );
    ledger.log.push({ ts: nowIso(), action: "ledger.ingest", run_id: report.run_id });

    return {
      run_id: report.run_id,
      added: {
        assets: ledger.assets.length - before.assets,
        facts: ledger.facts.length - before.facts,
        findings: ledger.findings.length - before.findings,
      },
      summary: summary(ledger),
    };
  });
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}
