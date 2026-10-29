# Changelog

All notable changes to Fairy / Web. The project follows semantic versioning for
the CLI/MCP surface; evidence schemas use `Fairy*/v1` and are additive.

## 0.17.0 — 2026-10-30

### Added

- `fairy_ingest`: one evidence entry point for `FairyScan/v1`,
  `FairyParam/v1`, `FairyWaf/v1`, `FairyMatrix/v1`,
  `FairyReachability/v1` and Verdex `findings`.
- `fairy_report_bundle`: ledger-first cross-tool report in JSON, Markdown and
  self-contained HTML.
- `source` / `source_run_id` / `source_id` on findings; idempotent replay via
  `coverage.runs`.
- Verdex `file:line` findings map into `where`; `fairy_handoff` now returns a
  `verdex.ingest` hint.
- Ledger findings carry `confidence`, `cwe` and `source`.

### Changed

- Reports can be generated from the whole engagement ledger, not only the last
  scan run.
- WAF results are ingested as facts, not inflated into vulnerabilities.

## 0.16.0 — 2026-10-29

### Added

- `high-auth`: HMAC-signed authorization file with basis, approver, asset list,
  expiry and `read-only`-only actions.
- `fairy_reachability`: read-only identity/permission/asset graph behind the
  high-authorization gate.
- `web_role_matrix`: multi-account × multi-endpoint access matrix (BFLA/IDOR
  candidates, status/body hash only, no bodies).

### Security

- High-auth gate is operator-issued via CLI; the agent cannot self-sign.
- Explicit boundary: no lateral movement, credential theft, persistence,
  tunneling or detection evasion.

## 0.14.0 — 2026-10-29

### Added

- Context-driven `work` inference for git-leak, IDOR, reflected XSS, sourcemap,
  API docs and SSRF chains.
- `fairy_auto_run`: planner tick → claim → execute predeclared/inferred work →
  tick, stopping at approval gates or missing work.

## 0.12.0 — 2026-10-29

### Added

- `fairy_planner_tick`: read ledger/chains, optionally materialize ready chains,
  then select the next claimable intent.

## 0.10.0 — 2026-10-29

### Added

- `fairy_chain_materialize`: ready chain → dependent intent sequence
  (idempotent).
- Approval gate: `requires_approval` intents cannot be claimed until
  `approve`; `claim` only returns dependency-satisfied work.

## 0.9.0 — 2026-10-29

### Added

- `fairy_mission`: bounded scan → report → ledger → chain-plan pipeline.
- `bench/`: local category-level benchmark (recall, precision, request cost).

## 0.8.0 — 2026-10-29

### Added

- `web_waf`: WAF fingerprint plus normalization matrix across URL encoding,
  double encoding, HTML entities and JS Unicode.
- WAF profile written to `.fairy/waf/profile.json`.
- `web_param_adaptive`: applies profile-approved encodings to SQLi/SSTI
  existence probes only.
- Double authorization for WAF probing: `allow_waf_probe` + `confirm`.

### Security

- WAF analysis is measurement, not an automatic bypass engine; no real attack
  payloads are carried by the encoding variants.

## 0.7.0 — 2026-10-29

### Added

- Parameter-level SQLi (error/boolean) and SSTI probes, existence only.
- DOM reflection context + CSP read.
- Disclosure draft limited to `verified` findings.
- Browser runtime (CDP), HAR replay, auth/BOLA diff and sample handoff to
  Verdex were already in place.
