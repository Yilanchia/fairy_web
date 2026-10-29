import fs from "node:fs";
import path from "node:path";
import { executeScan } from "./scan.js";
import { writeReport } from "./report.js";
import { initLedger, loadLedger, ingestScanReport } from "./ledger.js";
import { planChains } from "./playbooks.js";
import { nowIso } from "./util.js";

// 一次有边界的任务:扫描 → 报告 → 入账 → 链规划。
// 不是"全自动打穿":主动探测、登录、WAF 画像仍然需要单独授权。

export function missionPath(projectDir, missionId) {
  return path.join(path.resolve(projectDir), ".fairy", "missions", `${missionId}.json`);
}

function saveMission(projectDir, mission) {
  const file = missionPath(projectDir, mission.mission_id);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(mission, null, 2)}\n`, "utf8");
  return file;
}

export async function runMission(projectDir, options = {}) {
  const urls = (Array.isArray(options.urls) ? options.urls : []).map((value) => String(value).trim()).filter(Boolean);
  if (!urls.length) throw new Error("mission 至少需要一个目标 URL");

  const startedAt = nowIso();
  const started = Date.now();
  const phases = [];

  const scanStarted = Date.now();
  const { result, traffic } = await executeScan(projectDir, {
    urls,
    crawl: options.crawl === true,
    max_pages: options.max_pages,
    max_depth: options.max_depth,
    headers: options.headers || {},
    auth_label: options.session || null,
  });
  phases.push({
    name: "scan",
    status: "completed",
    requests: result.stats.requests,
    pages: result.stats.pages,
    findings: result.findings.length,
    duration_ms: Date.now() - scanStarted,
  });

  let files = null;
  if (options.report !== false) {
    const reportStarted = Date.now();
    files = writeReport(projectDir, { result, traffic });
    phases.push({
      name: "report",
      status: "completed",
      files,
      duration_ms: Date.now() - reportStarted,
    });
  }

  const ledgerStarted = Date.now();
  initLedger(projectDir);
  const ingest = ingestScanReport(projectDir, result);
  phases.push({
    name: "ledger",
    status: "completed",
    added: ingest.added || null,
    skipped: ingest.skipped === true,
    duration_ms: Date.now() - ledgerStarted,
  });

  const planStarted = Date.now();
  const ledger = loadLedger(projectDir);
  const chains = planChains(ledger);
  const ready = chains.filter((chain) => chain.readiness === "ready");
  const blocked = chains.filter((chain) => chain.readiness === "blocked");
  phases.push({
    name: "plan",
    status: "completed",
    ready: ready.length,
    blocked: blocked.length,
    duration_ms: Date.now() - planStarted,
  });

  const mission = {
    schema: "FairyMission/v1",
    mission_id: result.run_id,
    status: "completed",
    started_at: startedAt,
    finished_at: nowIso(),
    targets: urls,
    mode: options.crawl ? "crawl" : "probe",
    auth: options.session ? { session: options.session } : null,
    phases,
    stats: {
      requests: result.stats.requests,
      pages: result.stats.pages,
      findings: result.findings.length,
      duration_ms: Date.now() - started,
    },
    report: files,
    ledger: {
      added: ingest.added || null,
      skipped: ingest.skipped === true,
    },
    next: ready.slice(0, 5).map((chain) => ({
      id: chain.id,
      title: chain.title,
      goal: chain.goal,
      steps: chain.steps.length,
      stop: chain.stop,
      budget: chain.budget,
    })),
    blocked: blocked.slice(0, 5).map((chain) => ({
      id: chain.id,
      title: chain.title,
      missing: chain.missing,
    })),
    limitations: [
      "mission 默认只做扫描/报告/入账/链规划,不主动登录、不跑参数探测、不跑 WAF 画像。",
      "主动步骤仍需要 scope 显式授权与 confirm;mission 不会替你越过这些闸门。",
      "结果是候选,不是已验证;链规划只是下一步建议。",
    ],
  };

  mission.path = saveMission(projectDir, mission);
  return mission;
}
