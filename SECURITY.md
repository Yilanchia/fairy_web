# Security Policy

## Authorized use only

Fairy / Web is a security-testing tool. It must only be used against systems you
own or have explicit written permission to test, such as CTF environments,
self-hosted labs, or an authorized bug-bounty/SRC scope.

The tool refuses to send requests without a local scope file (`fairy.scope.json`)
that declares an authorization basis. That is a safety guard, not a permission
grant: **you** remain responsible for confirming authorization and for following
the target's rules (rate limits, forbidden actions, test windows).

Do not use Fairy to attack third parties, exfiltrate data, or "hack back".
Security testing without authorization may be illegal.

## Reporting a vulnerability in Fairy

Please report security issues in Fairy privately via
[GitHub Security Advisories](https://github.com/Yilanchia/fairy_web/security/advisories/new)
rather than opening a public issue.

Include:

- affected version/commit;
- a minimal reproduction (local fixture preferred);
- impact and any suggested fix.

Please do not test vulnerabilities against third-party systems while researching
Fairy itself.

## Supported versions

Fairy is pre-1.0. Security fixes land on `main`; use the latest commit.

## No warranty

The software is provided under the MIT License, without warranty of any kind.
