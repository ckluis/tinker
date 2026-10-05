# Tinker — Evaluation

**Date:** 2026-09-30 · **Input:** `tinker-eval.zip` (421 files, ~83k lines Rust, 28 crates), `tinker-eval-overview.md`, `tinker-eval-plan.md`
**Method:** static read-only review. No Rust toolchain on the review machine and **no `.git` in the zip**, so nothing was built or run, and commit SHAs cited in STATUS.md could not be checked. Paths below are relative to the zip root.

Legend: **[V]** verified by reading the code path · **[T]** taken on trust from the project's own docs/ledger · **[S]** suspected, not traced end to end.

---

## Step 1 — Understanding

**(a) What it is.** A Rust platform where you declare data objects once (fields, validation, relations, row policies, lifecycles) and Tinker materializes real Postgres tables (`data.<slug>`, physical columns `f_<hex>`), enforces tenant isolation with Postgres RLS, and exposes the objects through an MCP server (7 tools: `describe`, `query`, `get_record`, `create_record`, `update_record`, `transition`, `render_dashboard`), an HTTP app server, and a CLI. The problem it targets: give LLM agents a governed, self-describing data plane they can use correctly without prior training on its API.

**(b) Request flow (MCP over HTTP, the production path per `deploy/systemd/tinker-mcp.service`)** [V]
1. `Authorization: Bearer tk_…` → `MachineCredentialStore::verify` (`crates/tinker-auth/src/apikey.rs:256-301`): 12-char prefix lookup on the **owner pool**, revoked/expired check, SHA-256 of the secret compared with `ct_eq`. All failures collapse to one 401.
2. On `initialize`, `TenantContext` is built from `machine_credentials.organization_id` — the DB row, never caller input (`crates/tinker-mcp/src/http.rs:356`). Role comes from `memberships` (`crates/tinker-mcp/src/lib.rs:131-149`); no membership → fail.
3. Session stored in an in-process `HashMap`; each later call re-verifies the key and must match the session's credential id (`http.rs:262`).
4. Tool call → scope check → e.g. `tool_query` (`lib.rs:437-525`): client supplies slug/select/filters/limit only; `from`, org predicate and row-policy params are server-bound.
5. `CoreDb::tenant_tx` → `SET LOCAL app.organization_id / app.actor_id / app.purpose` inside a transaction on the **app role** (`crates/tinker-core/src/lib.rs:61-73`). RLS policies read `current_setting('app.organization_id', true)`.
6. Query runs under `statement_timeout`, audit row written in the same tx, commit, JSON out. Result cache keyed by (org, hash of SQL+params) (`crates/tinker-live/src/exec.rs:41`).

The web server (`tinker`) is cookie-only: `tinker_session` → SHA-256 lookup on the owner pool → org/actor from the session row → `tenant_tx`. It has **no record create/update/transition endpoints**; writes go through MCP.

**(c) Terms.**
- *No existence oracle:* an object or row you're not allowed to see returns the same `not_found` as one that doesn't exist, so probing can't map another tenant's data. Mostly holds; see S-7 for small exceptions.
- *Fail closed:* a missing or misconfigured dependency (embedding provider, TIN extension, OIDC, KEK, S3 config) yields a loud typed error, never a silent downgrade to a weaker path. Held up in the cases checked (see §2.2).

**Unclear or contradicted by the code — flagged, not papered over:**
- **The PII vault is not wired into either server.** OVERVIEW step 4 says "PII fields are sealed into the vault". Neither `tinker-web` nor `tinker-mcp` depends on `tinker-vault`. No non-test code constructs a `Vault` or reads `TINKER_KEK`, and the ontology has no PII field kind that seals values. The only production reference is an `Option<PiiProjector>` in comms delivery, and the web layer passes none (`crates/tinker-web/src/comms.rs:168`). [V] As shipped, a PII-bearing field is plaintext in `data.*`.
- **"Separate encrypted store" vs "one database".** `migrations/pii/0001_vault.sql` describes a separate DB; `docs/threat-model.md §1` says "one PostgreSQL 16 database (core + PII vault)". The separation depends on configuration, not on code structure.
- **Where the kill-bar results are.** OVERVIEW says BACKLOG.md; BACKLOG.md holds only the bar's definition (`BACKLOG.md:1208-1210`). The results are in `STATUS.md:3099-3168`.
- **Milestone crates.** `tinker-m0…m8` are test/gate harnesses, not runtime layers. Exception: `tinker-m7` ships the production operator binary `tinker-cli` (key issue/rotate/revoke).

---

## Step 2 — Evaluation

### 2.1 Architecture

**Sound:** the core is cleanly layered: `core → db → ontology → query/live/auth`, with no core crate depending on a surface crate and no cycles [V]. Tenant context is set only via `SET LOCAL` inside transactions, so no GUC leaks across pooled connections [V]. SQL is parameterized; slugs are regex-validated (`^[a-z][a-z0-9_]{1,62}$`); physical column names are generated, not user-supplied [V].

**Would restructure:**
1. **Env-var names conflict between binaries.** `tinker` reads `TINKER_CORE_URL` as the **owner** URL (`crates/tinker-web/src/main.rs:42,50`). `tinker-mcp` reads `TINKER_CORE_URL` as the **app role** and `TINKER_CORE_OWNER_URL` as owner (`crates/tinker-mcp/src/main.rs:74-75`). With the shipped template, `tinker` fails to start (fine). But an operator who "fixes" it by pointing `TINKER_CORE_URL` at the owner silently runs MCP tenant traffic as a role that is not subject to FORCE RLS on most tables. Unify the names. [V]
2. **Two MCP HTTP servers.** `crates/tinker-mcp/src/http.rs` and `crates/tinker-m7/src/mcp_http.rs` each have their own session map and auth mapping. Role resolution is written at least three times (`tinker-mcp/src/lib.rs:131`, `tinker-query/src/dashboard.rs:158`, web `role_of`). These are drift risks on the security-critical path. [V]
3. **`tinker-mcp` depends on `tinker-web`** only for `meta::describe_cached` and friends, so the MCP binary links the whole web surface. Extract `describe` into a neutral crate. [V]
4. **Move `tinker-cli` out of `tinker-m7`** into a properly named crate. Its `vfile`/`file`/`mcp serve` commands take `--org <slug> --actor <name>` and act as that actor with no credential (`crates/tinker-m7/src/main.rs:154-170`). That is acceptable for an operator tool but should be labelled loudly. [V]
5. MCP sessions are in-process; multi-instance needs sticky routing. [S]

### 2.2 Security

No cross-org read path was found through MCP, HTTP, search, or `tinker://ontology/*` resources. `r3_adversarial.rs` already exercises all 7 tools plus resources cross-org. The findings are hardening gaps, latent bugs, and one large claim/reality gap.

| # | Sev | Finding | Where | Status |
|---|---|---|---|---|
| S-1 | **High** | **PII is not sealed at runtime.** The vault crate is correct (AES-256-GCM, OsRng nonces, per-org DEK, KEK rotation) but nothing in the server calls it. PII in records sits in core tables in plaintext and is indexable and embeddable like any other field. Comms PII classification is sender-asserted (`pii_class` defaults to `"none"` in `crates/tinker-comms/src/inbound.rs:533,569`), and even `pii.restricted` bodies are stored plaintext in `comm_message.body`. | see Step 1 | [V] |
| S-2 | Med | **Owner pool on the request path; RLS not FORCEd on most tables.** Only ~10 migrations use FORCE. `0011`/`0027` remove it from `sessions`, `auth_credentials`, `memberships`, `actors`…; every dynamic `data.<slug>` table is ENABLE-only (`crates/tinker-ontology/src/lib.rs:898-906`). Key verify, session load, OIDC binding, inbound routing and DDL run on the owner pool. No tenant-content read on the owner pool was found today, but RLS is not a backstop for any future one. | migrations; `apikey.rs:239` | [V] |
| S-3 | Med | **Approvals are not bound to content.** `check_approval_binding` checks status, action, `payload.draft_id` and expiry only (`crates/tinker-ontology/src/lifecycle.rs:324-366`). A draft returns to editable after `reject`, and reject does not invalidate outstanding approvals. Path: reviewer approves `publish` for v1 → rejects → author edits to v2 → resubmits → publishes with the old, unconsumed, unexpired approval. Fix: bind approvals to a content hash or draft version. `ApprovalEngine::decide` has no requester≠decider check (only `publish` enforces it), so `submit_for_review`/`archive` can be self-approved. | `lifecycle.rs`, `crates/tinker-agents/src/approval.rs` | binding gap [V]; full chain [S] |
| S-4 | Med | **Ontology RLS policies are USING-only for ALL commands.** `ontology_objects_visible` etc. (`migrations/core/0002_ontology.sql:63-78`) let the app role UPDATE platform rows (`scope_kind='platform'`); the app role has blanket DML (`0001_tenancy.sql`). `Ontology::rename_object` (`lib.rs:1238`) is an unscoped `UPDATE … WHERE id=$3` in a tenant tx: any tenant could rename a platform object for everyone. No non-test caller today, so latent, but the policy defect is real. Fix: SELECT-only policy for platform rows plus separate write policies. | | [V] |
| S-5 | Med | **Template parser panic (C6 sibling).** `rest[2..end]` with `end = rest.find("%}")`; the template `{%}` gives `end=1` → slice `[2..1]` panics (`crates/tinker-comms/src/templates.rs:504-505`). Reachable by anyone who can author an email template; kills the request, not the process. | | [V] |
| S-6 | Low-Med | **Auth weaknesses.** OIDC login accepts a bare `id_token` with no state, nonce, or replay cache, so a stolen valid token mints a session. Passkey is raw Ed25519 with no origin/rpId binding, yet it is stamped `MultiFactor`. Web sessions are not re-validated against membership (fixed 12h). MCP sessions freeze the role at `initialize`. `Secure` cookie flag is opt-in and defaults off (`crates/tinker-web/src/lib.rs:293-294`). No CSRF token or Origin check; relies on `SameSite=Lax` + JSON content-type. | `tinker-web`, `tinker-auth`, `tinker-identity` | [V] |
| S-7 | Low | **Small oracles.** `/login/passkey/start` is unauthenticated, accepts any org/actor, inserts a challenge row (no rate limit), and returns 500 (FK fail) vs 200, which reveals whether an org/actor pair exists. MCP `find_session` returns 404 vs 401 for foreign session ids. SSE `invalidate` events leak row ids hidden by row filters to same-org members. | | [V] |
| S-8 | Low | File `pii_class` can be downgraded on dedup re-upload (`ON CONFLICT … SET pii_class = EXCLUDED.pii_class`, `crates/tinker-agents/src/files.rs:~740`). Reveal approvals in support sessions are reusable for the session's life (`crates/tinker-transfer/src/host.rs:~420`). No AAD on vault ciphertext (rows swappable within an org). | | [V] |

**Held up** [V]: atomic single-use approval consumption (`UPDATE … WHERE status='approved' AND expiry` + `rows_affected()==1`, `crates/tinker-ontology/src/mutate.rs:765-805`, identical errors for every failure). Expiry enforced in SQL. No self-approval on publish. Cross-action approvals rejected. `tk_` keys: 256-bit OsRng, constant-time compare, per-request revocation. Inbound email HMAC + replay window. Storage keys sha256-derived with traversal rejection. Query limit clamped to 1000. `query_audit` stores hashes, not values. Fail-closed confirmed for embedding provider placement (`placement_policy_rejects_hosted_embedding_provider` proves no text leaves the process), semantic backend, TIN extension, S3 config.

**File uploads:** there is no HTTP upload or serve handler in the tree. Files enter via inbound email attachments and library callers only, so Content-Disposition, nosniff and MIME trust are not yet in play. MIME is stored as the uploader declared it; whichever handler eventually serves files must not trust it.

**Where I'd attack next:** owner-pool SQL (every hand-written `WHERE organization_id` there is the only isolation); approval lifecycle edge cases (S-3); anything that later wires PII into search or embeddings; the in-process MCP session map once it is scaled out.

### 2.3 Verification culture

Spot-checked load-bearing STATUS.md claims against their named tests:

| Claim | Test | Verdict |
|---|---|---|
| PII cannot be joined from core SQL (`STATUS.md:21`) | `core_sql_cannot_reach_pii` (`crates/tinker-m0/tests/m0_pii.rs:78-128`) | **Narrower than stated.** Asserts no `pii_values` table, no FDW/dblink in core. Pins the structure but never attempts a join. And per S-1, nothing writes to the vault at runtime anyway. |
| PII vault RLS cross-tenant, fail-closed | `pii_app_role_rls_is_cross_tenant_fail_closed` (`crates/tinker-vault/tests/pii_rls_adversarial.rs:32-110`) | **Strong.** Real app role, two orgs, virgin session, `''` GUC edge case. |
| Approvals not replayable | `approval_is_consumed_atomically_and_not_replayable` (`crates/tinker-ontology/tests/mutate_validation.rs:1527-1580`) | **Strong**, plus siblings for pending/denied/expired/cross-org. Does not cover content drift (S-3). |
| Embedding provider fails closed | `placement_policy_rejects_hosted_embedding_provider` (`crates/tinker-m7/tests/m7_expand_ranking.rs:305-345`) | **Strong.** Asserts the fake adapter saw zero texts. |

- **Name integrity:** about 200 test-like identifiers cited in STATUS.md, 0 missing from the source. 12 sampled by hand all exist.
- **Tests are real:** 629 tests, ~90% against a live Postgres; only 2 `#[ignore]` (a timing bench). One test is `--skip`ped in two gates (`seed_drorg_1`, non-idempotent fixture).
- **Gate logs, commit SHAs, soak metrics and DR drill evidence** all live in `~/workspace/…` outside the zip. [T]

**Verdict:** the ledger is unusually honest. Tests bind to claims and confounds are written down. But the ledger is accurate at the *component* level and overstates at the *system* level. The vault is tested and correct, yet unused, and the overview presents it as a running property. The ledger culture survives scrutiny; the overview's summary of it partly does not.

### 2.4 LLM-first thesis (kill bars)

**Not bought as stated.** The evidence supports: "on a simple discover → draft → publish fixture task, the skill doc gave no measurable advantage over MCP + repo docs at n=3/arm." It does not support "static docs add no measurable value" or "the MCP is self-documenting."

- **The pre-registered bar was swapped.** Adopted bar: skill+MCP vs **raw HTTP + human docs** (`BACKLOG.md:1208-1210`). That arm "proved impossible" because HTTP has no write endpoints, so the test became skill vs no-skill on top of the MCP (`STATUS.md:3099-3103`). The headline is worded as if that was the plan.
- **Only v1 tests docs vs no docs**, and its control isn't docs-free: Arm B still had repo docs, MCP schemas, and teaching errors. v2 and v3 compare two doc variants (1.4KB router vs 12.5KB skill) with no no-skill arm. "Three experiments" is really one docs-vs-none test plus two docs-vs-docs tests.
- **n=3 per cell.** In v1, within-arm variance (16–180s) exceeds the arm gap, and the median is driven by one outlier the author attributes to stdio tooling friction. A TIE at n=3 is absence of evidence. No CIs, no model named, metric is wall-clock (+ output tokens in v2/v3), correctness is just "published", and a mid-run rootfs roll changed fixtures. The author lists most of these confounds; the overview drops them.
- **The MCP is self-teaching because it carries docs in-band.** `describe` says "Always the first call — never guess a field name" (`crates/tinker-mcp/src/lib.rs:~997`), errors are teach-mapped (`lib.rs:423-816`), and the skill's Rule Zero is the same instruction. The study measured *docs-in-skill vs docs-in-tool-output*. That is a good design finding (put the docs in the tool surface), not evidence that docs don't matter.
- **To convince a skeptic:** pre-register; ship raw transcripts and the verifier; three arms (bare schemas / full in-band teaching / in-band + skill); 20+ runs per arm across ≥3 models including small and non-Anthropic; tasks written by someone other than the MCP author, including silent-wrong cases (row-policy hiding, cross-object joins); blind automated correctness scoring; effect sizes with CIs.

### 2.5 Production readiness

**Single riskiest gap before real traffic: S-1, PII protection isn't wired.** It is the only gap that is *invisible*: an adopter reading the overview would put regulated data in and believe it is sealed. Every other gap below is documented by the project itself.

Runners-up:
1. **No real backup story.** No WAL archiving, base-backup schedule, standby, or backup role (`docs/disaster-recovery.md §6`); file bytes are outside dumps. `TINKER_KEK` exists only in the env file with nothing enforcing an off-host copy, so losing it makes every vault value unrecoverable. (Moot until S-1 is fixed, then critical.) [V docs]
2. **Blast radius of the serve process.** The env file the server runs with holds owner URLs (which run migrations and verify keys at request time) next to the KEK (`deploy/env/tinker.env.template:14-20`). One process compromise yields owner roles (CREATEROLE) + KEK. [V]
3. **No observability or per-tenant limits.** `/healthz` + logs only. Rate limiting is nginx-only (20 r/s per IP on `/mcp`), with nothing per key or per tenant. nginx config marked syntax-unvalidated; systemd units verified but never booted. [V]
4. **Migrations run at startup** under leader election, with no separate migrate step or rollback (forward-fix only). Acceptable for one node. [V]

**R1 soak "VM-load noise" explanation: plausible, not proven.** p50 flat across buckets and spikes clustered at 08:00/20:00 UTC support it. Against it: no CPU-steal or co-tenant measurement is cited; describe p50 (6.7–8.1ms) is itself 2–3× the 2.9ms baseline; baseline was 1 org / 100 records vs 3 tenants / 350k+ records in the soak; a 308s stall occurred. "Target met" (`BACKLOG.md:1470`) overstates; re-measure on a quiet box, as the authors themselves suggest. [T for numbers, V for reasoning]

### 2.6 Verdict

**Strengths**
- Tenant isolation is real and layered: credential-derived org, `SET LOCAL` in tx, RLS on the app role, parameterized SQL, validated identifiers, composite tenant FKs. No cross-org read found.
- Careful, correct primitives: atomic approvals, constant-time key checks, fail-closed backends, sound vault crypto.
- A genuine test culture: ~600 DB-backed tests, ledger names that resolve, confounds written down instead of buried.
- The in-band teaching MCP surface is a good design idea, even if the experiments over-read it.

**Weaknesses**
- The overview overstates the system: PII sealing isn't wired, and the kill-bar conclusion outruns n=3 plus a swapped bar.
- Isolation rests on the owner pool never being misused, with RLS not forced on most tables. Plus a latent ontology write-policy defect and an env-var naming trap that can put tenant traffic on the owner role.
- Approvals aren't content-bound; auth is prototype-grade (bare id_token OIDC, non-WebAuthn "passkeys" labelled MFA, no session re-validation).
- Duplicated security-critical code (two MCP servers, three role resolvers); a production CLI living in a milestone test crate.
- Operationally pre-production: no backups, no monitoring, nothing ever deployed.

**Score: 6 / 10.**
- Engineering discipline on the data plane is 8-level work.
- Production readiness is ~4 (and the project says so).
- The evaluator-facing claims cost the most. The headline PII property is false for the running system, and the LLM-first thesis is argued from evidence that can't carry it.
- Wiring the vault into the field/mutation path (or removing the claim), binding approvals to content, forcing RLS and splitting the owner role off the request path, and re-running the kill bar properly would put it at 7.5–8.

### Verified vs. taken on trust

- **Verified by reading code:** everything marked [V], including request flow, RLS/GUC handling, approval consumption and binding, vault wiring (absence of callers), template panic, ontology policy, env-var conflict, test-claim bindings, MCP tool text.
- **Taken on trust:** all runtime numbers (gate counts, soak metrics, DR RPO/RTO, kill-bar timings), commit SHAs, and anything in `~/workspace/` (not in the zip). Nothing was compiled or executed.
- **Suspected, not traced end to end:** the full S-3 exploit chain, and multi-instance session behaviour.
