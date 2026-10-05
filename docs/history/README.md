# History

How Tinker got from "built" to "hardened".

| Doc | What it is |
|---|---|
| [2026-09-30-evaluation.md](2026-09-30-evaluation.md) | An independent static review of the code as it stood after milestone M8, before any of the fixes below. It scored the project 6/10. Its headline finding was that the PII vault was not wired into either server. |
| [hardening-log.md](hardening-log.md) | The four rounds that answered it. Each fix ships with a regression test, and most were proven by removing the fix and watching the test fail. |

The four rounds:

1. **Round 1:** PostgreSQL 18 and the evaluation's bug and hardening findings.
2. **Round 2:** sealed fields, with the vault wired into every write path.
3. **Round 3:**
   - four-eyes approvals
   - ingest sealing and the field retrofit
   - MCP erasure
   - the OIDC code flow
   - real WebAuthn
4. **Round 4:**
   - PII by type
   - automation keys and the automation engine
   - second-person reveal
   - crypto-shred erasure

These are historical records. They mention the scripts by the names they had then: `bin/dev-db-mac.sh` and `bin/test-mac.sh` are now [`bin/dev-db.sh`](../../bin/dev-db.sh) and [`bin/test.sh`](../../bin/test.sh). The evaluation's file and line references point at the code as it was reviewed.
