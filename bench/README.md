# Bench

Local, reproducible category-level benchmark. It runs only against
`tests/fixture-server.mjs` on `127.0.0.1`; no external targets.

```bash
npm run bench
```

Outputs:

- `bench/results/latest.json` — metrics + per-kind table + findings
- `bench/results/latest.md` — human-readable summary

Metrics:

- **recall** — matched expected classes / expected total
- **precision** — findings whose kind is expected / all findings
- **cost per finding** — HTTP requests / finding
- **duration** and **out-of-scope requests** (hard invariant: 0)

Current expected classes: security headers, cookies, CORS, exposure,
reflection, open redirect, info disclosure, SQLi (error + boolean), SSTI.

This is not a product benchmark. It is a regression guard: if a change makes a
known class disappear, or introduces a new unexpected class, the numbers move.
Expand it with more local labs (API authz, WAF, SPA) before comparing anything
externally.
