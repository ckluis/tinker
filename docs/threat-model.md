# Tinker Threat Model

> **INTERNAL — adversarial review, NOT an external audit.** This document is
> the output of an internal red-team pass (R3 of the production-readiness
> campaign, 2026-09-28), written by the team that built the system. It is
> not an independent security audit, not a penetration-test report, and not
> a compliance attestation. Treat findings as engineering input, not as
> assurance.

## 1. System overview (what is being defended)

Tinker is a single-binary Rust workspace (`tinker-mcp serve`, `tinker-cli`)
backed by one PostgreSQL 18 database (core + PII vault) and Redis. The
security-relevant surfaces reviewed:

| Surface | Entry | Auth |
|---|---|---|
| MCP over HTTP (new, item 46) | `tinker-mcp serve` → `POST /mcp`, `DELETE /mcp` | `Authorization: Bearer tk_…` per request; `Mcp-Session-Id` after `initialize` |
| MCP over HTTP+SSE (legacy) | `tinker-cli mcp http` → `GET /sse`, `POST /messages?session_id=`, `POST /mcp` | same Bearer scheme; session bound to opening credential |
| MCP over stdio | `tinker-mcp` / `tinker-cli mcp serve` | OS process boundary (invoker's credentials) |
| Machine keys (C6) | `tinker-cli mcp key issue/rotate/revoke/list` | operator-run; secret printed once |
| Approval-gated writes | `submit_for_review`, `publish`, `transition`, governed `create/update_record` | caller presents `approval_request_id` |
| File/blob store (item 42) | `FileStore::store`, `assert_linkable` | tenant-scoped registry; content-addressed backend |

## 2. Assets

1. **Tenant data** — records, drafts, files, dashboards, PII (vaulted, envelope-encrypted).
2. **Machine credential secrets** — `tk_` Bearer keys; only the SHA-256 hash is stored.
3. **Approval integrity** — an approval must authorize exactly one action on exactly one object/draft.
4. **Session integrity** — an MCP session must be usable only by the credential that opened it.
5. **Availability** — the server must not be remotely crashable by malformed input.

## 3. Trust boundaries

- **Network → server**: everything past the Bearer check is authenticated; before it, only `initialize`/`ping` shape validation. The deployer owns TLS and ingress (`mcp http` binds 127.0.0.1; `tinker-mcp serve --bind` is the operator's choice).
- **Org boundary**: `organization_id` on every row + Postgres RLS (forced on key tables) + per-request tenant context. Cross-org access must be indistinguishable from "does not exist" (no oracles).
- **Credential → session**: a session is bound to the credential id that opened it; every request re-verifies the Bearer key, so revocation/expiry take effect on the next request.
- **Agent → governed write**: the agent (MCP client) is *untrusted input shaping* — it may request any tool/args, but authorization (scopes, roles, RLS, approvals) is enforced server-side.

## 4. Attacker profiles

- **A1 — network attacker, no credentials**: can open TCP, send malformed HTTP/JSON-RPC, guess session ids and key material.
- **A2 — legitimate key holder, wrong org or least privilege**: holds a valid key for org B (or a query-only / single-tool key for org A); tries to read/write org A's data, escalate scopes, replay approvals.
- **A3 — malicious/compromised agent inside an org**: same-org attacker; tries self-approval, approval replay across actions, hostile query filters, hostile file uploads.
- **A4 — malicious file uploader**: polyglot/traversal/oversized payloads via the file store.

## 5. Controls (verified this pass)

### C6 machine keys
- Secrets are 256-bit (`tk_` + base64url), stored as SHA-256 (fast hash is fine: 256 bits of entropy, no human passwords).
- `verify()` collapses every failure to `Forbidden("invalid API key")` — byte-identical 401s, no existence oracle (live-tested: unknown/malformed/wrong-hash keys).
- Key material is never echoed in error bodies (live-tested).
- Comparison is constant-time (`ct_eq`); prefix lookup is indexed.
- Rotation/revocation are atomic; revoked and rotated-out keys return 401 on the next request (live-tested).
- **Fixed R3**: `verify()` panicked on multibyte input whose byte 12 fell inside a char boundary (`&secret[..12]`). HTTP transports neutralized it (non-ASCII `Authorization` rejected before `verify`), but any direct caller (env-var config, future transports) could crash the process. Now fails closed via `get(..).filter(ascii)` + regression test `r3_verify_multibyte_prefix_fails_closed`.

### MCP HTTP sessions (both servers)
- Server mints the session id (`Uuid::now_v7`); client-supplied ids on `initialize` are ignored (live-tested).
- Every non-`initialize` request re-authenticates the Bearer key AND checks it matches the session's credential id: org-B key + org-A session → 401 (live-tested); unknown session → 404; deleted session → 404 (live-tested).
- Idle sessions reaped after 30 min (60 s sweep). **Live-measured R3 2026-09-28**: session opened 21:42:19Z and confirmed working (tools/list 200); re-probed after 31 min idle → 404 "unknown or expired session"; fresh session afterwards → 200 (evidence: `closeout/r3_idle_reap.json`).
- Legacy SSE server (`tinker-cli mcp http`) binds sessions the same way (credential id), sweeps idle after 30 min, and drops the session when the SSE stream closes.

### Tenant isolation (every MCP tool)
Adversarial battery `crates/tinker-mcp/tests/r3_adversarial.rs`
(`r3_tenant_isolation_every_mcp_tool`, 5/5 green) seeds real objects, records,
drafts, and a dashboard in org A and probes each tool from org B:
`describe`, `query`, `get_record`, `update_record`, `create_record`,
`transition`, `render_dashboard`, `resources/list`, `resources/read` —
all return `not_found`, never `forbidden`, never data. Catalog lookups are
per-org; record/draft/dashboard/file ids are unguessable v7 UUIDs scoped by
`organization_id` predicates, so foreign ids look missing.

### Scopes
- `scope_allows` gates `tools/call` per tool; `tools/list` is allowed to any
`mcp:tool:*` holder (design: discovery). A query-only key calling
`create_record` gets JSON-RPC `-32001` (live-tested). A key with no
membership gets 403 at initialization (live-tested).
- Scopes are immutable for a credential's lifetime, so the session's
snapshotted scopes cannot drift.

### Approvals
- `publish` enforces: draft in `in_review`, approval decided by a non-author,
action == `publish`, payload `draft_id` bound, unexpired, single-use
(consume-before-publish). Cross-org approval ids fail closed (org-scoped
lookup). Replay fails closed (tested: second `create` with the same approval → `Forbidden`).
- Wrong-action approvals are rejected AND not consumed (tested).
- `submit_for_review` enforces author-only submission + action/payload
binding, but does **not** reject an author-decided approval (F4 below).
- The generic direct-write path (`consume_approval`) enforces
approved/unexpired/single-use but **not** action/object binding (F5 below).
- `decide()` permits any same-org actor by design; the gates sit at
consumption (`submit`/`publish`), not at decision.

### Files
- Max-bytes enforced; storage keys are SHA-256 content-addressed (traversal
names are registry metadata only — verified no escape from backend root);
tenant-scoped registry rows; hash re-verified on link; cross-org link ids
look missing; tampered bytes fail closed on link.
- MIME is caller-declared, no magic-byte sniffing (accepted risk, §6 F6:
no HTTP file-serving path exists today — `file get` writes to disk).

### Secrets & logging
- No runtime logging of C6 secrets (`IssuedCredential`'s derived `Debug`
is never formatted in logs; S3 `Debug` redacts). Expected exception:
`key issue`/`rotate` prints the secret once to the operator's stdout.
- PII vault: separate PII database, envelope encryption, no core join;
plaintext never logged (per item-42 review).

### Dependencies
- `cargo audit` run R3 (see §6 F7 for result).

## 6. Findings

| ID | Severity | Finding | Disposition | Evidence |
|---|---|---|---|---|
| F1 | Medium | C6 `verify()` panicked on multibyte key material (byte-12 mid-char boundary) — local/startup DoS via any non-HTTP caller | **Fixed** — `get(..).filter(ascii)` fail-closed | `r3_verify_multibyte_prefix_fails_closed` (crashed pre-fix, green post-fix); targeted suites green; full 115-suite gate pending quiet window |
| F2 | Info | `tools/list` allowed to single-tool keys (any `mcp:tool:*` scope permits discovery) | Accepted design — tool names/descriptions are not secret; documented | code + live probe |
| F3 | — | Caller-controlled `require_approval` on `create/update_record` | **Not a vulnerability** — no server-side approval mandate exists; it is opt-in governance. Verified no bypass. | code review + `approval_args` |
| F4 | Low | `submit_for_review` accepts author-decided approvals (no non-author check; `publish` has it) | Known limitation — the security gate is `publish` (non-author enforced); self-submit only fast-forwards to `in_review`, grants no publish | code review; recommend: enforce non-author at submit or drop the submit-approval requirement |
| F5 | Low | Generic `consume_approval` (direct writes) doesn't bind action/object — only approved/unexpired/single-use | Hardening gap — unexploitable today (nothing mandates approvals on direct writes), but any future policy-enforcing deployment gets cross-action replay | code review; recommend binding action+object for parity with lifecycle path |
| F6 | Info | File MIME is caller-declared, no sniffing; polyglots accepted | Accepted — no HTTP file-serving path exists (`file get` writes to disk); if a download endpoint is ever added it must force `application/octet-stream` / `Content-Disposition: attachment` | code review + `r3_file_upload_hostility` |
| F7 | Medium* | `cargo audit` unavailable in this environment (cargo-audit 0.22.2 fails to compile: aws-lc-sys C toolchain failure); manual review instead | Manual: jsonwebtoken 9.3.1 vs CVE-2026-25537 **investigated — not reachable** (strict `IdTokenClaims` with mandatory `exp: i64`; string-typed `exp` fails closed at the required-claims gate / deserialization; C6 keys don't use JWT at all). rustls 0.23.45 already includes the RUSTSEC-2026-0285 fix. No clean-audit claim made. **Recommend**: bump jsonwebtoken to ≥10.3 as defense-in-depth (careful: 10.x needs an explicit crypto provider or it panics at runtime) and add `cargo audit` to CI |

### Residual risks (accepted, monitor)
- No rate limiting on MCP HTTP auth paths. Brute force is infeasible (256-bit keys; verify = one indexed SELECT + SHA-256), but unauthenticated 401 loops are cheap — consider a token-bucket if the endpoint is ever public without a WAF.
- `IssuedCredential` derives `Debug` over the plaintext secret — safe today (never logged), but a future `{:?}` would leak. Consider a redacting `Debug` impl.
- The legacy `tinker-cli mcp http` SSE surface duplicates the new server's session logic with a different protocol — two implementations to keep in sync. Consider converging or documenting the legacy path as deprecated.

## 7. Out of scope
- TLS/ingress (deployer-owned), Postgres/Redis hardening, operator workstation
security, the stdio transport's OS-level trust (invoker's user), model-provider
adapters (item 24), social engineering.

## 8. Reproducibility
- Adversarial battery: `cargo test -p tinker-mcp --test r3_adversarial`
(5 tests; serial-safe; fixtures use `secorg_` slugs, cleaned post-run).
- Live probes: battery scripts under `/tmp/r3` (deleted at closeout);
idle-reap evidence at `~/workspace/prodread/closeout/r3_idle_reap.json`
(measured 2026-09-28: 404 after 31 min idle, fresh session 200).
- Fix: `crates/tinker-auth/src/apikey.rs` (`verify`).
