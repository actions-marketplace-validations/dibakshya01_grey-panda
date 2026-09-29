# Security Policy

Grey Panda is a security tool; we hold ourselves to the standard we advocate.

## Reporting a vulnerability
**Please do not open a public issue for security vulnerabilities.**

Report privately via [GitHub Security Advisories](https://github.com/dibakshya01/grey-panda/security/advisories/new).
If that is unavailable to you, open a minimal issue asking a maintainer to open a
private channel — without any exploit details.

We aim to:
- acknowledge your report within **3 business days**,
- provide an initial assessment within **10 business days**,
- credit you (if you wish) when a fix ships.

## Scope
In scope: the Grey Panda scanner, SDK, MCP server, CLI, and CI templates in this
repository.

Out of scope: the security of *your* application (that's what Grey Panda helps you
review), and false positives/negatives in scanner rules — please file those as
normal issues so we can tune the rule.

## Supported versions
The latest minor release on the `main` branch receives security fixes.

## Our own posture
- Zero runtime dependencies — a deliberately tiny supply chain.
- Grey Panda scans itself in CI (`self-scan` job) on every push and PR.
- Dependencies (dev-only) are monitored via Dependabot.
