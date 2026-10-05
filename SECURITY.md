# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Don't open a public issue.

Include what you found, how to reproduce it, and what an attacker gains. Areas of particular interest:
- tenant isolation (any cross-organization read or write)
- reading sealed PII without an approved `reveal`
- bypassing four-eyes approvals or reusing an approval
- MCP scope escalation
- automation guards (loop depth, guessing limit, author authority)

## What has and hasn't been reviewed

- An internal adversarial review is documented in [`docs/threat-model.md`](docs/threat-model.md). It is **not** an independent audit.
- An independent static evaluation and the fixes that followed are in [`docs/history/`](docs/history/README.md).
- There has been **no external security audit** and no public deployment.

## Supported versions

Only `main` is supported.
