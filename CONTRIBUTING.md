# Contributing

Thanks for helping Fairy / Web. This project is an authorized-testing tool, so
contributions must preserve its safety model.

## Ground rules

- **Scope first**: every network action goes through `Guard`; do not add code
  paths that bypass the scope passport, rate limit, or audit log.
- **Proof, not exploitation**: detection may prove existence, but must not add
  payloads that execute commands, exfiltrate data, or persist access.
- **Data minimization**: never log request bodies, credentials, or full response
  bodies into reports/artifacts.
- **No brute force**: no dictionaries, spraying, or retry loops for credentials.

## Development

```bash
git clone https://github.com/Yilanchia/fairy_web.git
cd fairy_web
npm test
```

Requirements: Node.js >= 20. A local Chrome/Edge is optional; browser tests are
skipped when none is found.

## Pull requests

- Keep changes focused; add tests for new behavior.
- Run `npm test` before opening a PR.
- Update README/STRATEGY when behavior or safety gates change.
- By contributing, you agree your contribution is licensed under the MIT License.
