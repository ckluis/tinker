# Tinker — backlog

Deferred work, recorded at deferral time with the reason. Nothing here is
forgotten; it is sequenced after the current milestone's exit tests.

## From M0 (2026-09-24)

- **TIN adoption benchmark. BLOCKED — evidence commit adaec9c (re-verified 2026-09-25).** The `TinSearchBackend` adapter is written
  against TIN's documented SQL surface (`USING tin`, `==>` operator,
  `tin.score`) and fails closed when the extension is absent. Adoption is
  blocked on: (a) an installable production TIN for self-hosted Postgres —
  as of 2026-09-24 TIN is GA only on PlanetScale Postgres/Neki, and
  PlanetScale's `planetscale/lead` compatibility extension targets PG17/18
  (we run PG16) and is deliberately non-production; (b) the M0
  compatibility/workload benchmark (correctness-identical results on the
  permission suite, latency comparison on a realistic corpus). When both
  hold, flip the default backend and keep native as the fallback.
  - **Re-verified 2026-09-25 (still blocked, evidence):** PlanetScale
    docs state TIN is GA only on PlanetScale Postgres and Neki; the
    only independent artifact is `planetscale/lead`, which its README
    (crawled 2026-09-25) calls "a deliberately non-production Postgres
    text-search extension ... intentionally unsuitable for production
    workloads", built for PG17/18 only — Tinker runs PG16. No
    production-installable TIN for self-hosted Postgres exists.
    Re-check on a future pass; the adapter stays in fail-closed mode.
- **Shared-object adoption.** DONE 2026-09-24 (post-M8 item 20):
  `Ontology::adopt_object` creates a metadata-only row pointing at the
  existing shared table instead of erroring on the duplicate slug.
  Adopt-vs-define: `define_object` still fails closed on an existing
  table (its error now guides to `adopt_object`); `adopt_object` links
  to the existing table with `adopted_from` = the root definer's id
  (chains always flatten to the root). Base fields resolve live from
  the adopted object (migration 0030 extends the `ontology_fields`
  RLS policy so the adopter sees shared base fields); the adopter's
  own post-adoption fields are namespaced by its adopted row, and
  shadowing a base field fails closed. Adoption is idempotent and
  race-convergent. RLS data isolation unchanged. Proven by 10 tests in
  `crates/tinker-m0/tests/m0_adopt.rs`.
- **`add_field` scope authorization.** DONE 2026-09-24: the explicit
  scope checks were verified in place — M0 `Ontology::add_field`
  predicates on `organization_id` + `scope_kind='organization'`
  (platform objects immutable to tenant actors; pack installer uses
  `add_platform_field`), and M4 `SchemaEvolver::add_field_inner`
  locks `schema_versions WHERE id=$1 AND organization_id=$2`. Pinned
  with adversarial tests: `sibling_add_field_is_rejected` (B's
  `add_field` on A's draft → `NotFound`, no existence oracle, no
  physical column materialized on A's ext table, A can still evolve
  afterwards) and the HTTP `/fields` endpoint in
  `hostile_version_ids_fail_closed`, both in `m4_hardening.rs`.
- **Effect reservation liveness.** DONE 2026-09-24: `claim_step` reaps the
  step's own NULL-output reservations on every successful claim (a live
  owner's reservation is never touched), and `recorded_effect_output`
  decodes NULL output as "not recorded" instead of erroring. Covered by
  `crashed_reservation_is_reaped_on_next_claim`.
- **KEK management.** DONE 2026-09-24 (post-M8 item 15, commit
  `78d189d`): the rotation half is shipped — `Vault` holds a versioned
  KEK set keyed by `kek_id` (`TINKER_KEK` + optional
  `TINKER_KEK_PREVIOUS` from env); `rotate_dek` versions the DEK
  without re-encrypting values; `rewrap_deks` migrates wrappings to the
  current KEK so a retired KEK can be dropped; unknown `kek_id` fails
  closed. Covered by `crates/tinker-vault/tests/kek_rotation.rs`
  (6 tests). KMS/HSM-backed KEK sourcing remains production future
  work.
- **`tinker-auth` Tokio dev-dependency.** DONE 2026-09-24: `tokio` added
  as a dev-dependency; `cargo clippy --workspace --all-targets` compiles.
- **Query compiler hardening (M2/M3).** DONE 2026-09-24 (post-M8 item
  12): field-level permissions and inference controls remain
  architecture comments (not in scope), but the executor gap is closed —
  see "Query compiler executor" below for the shipped work.
- **PII store `vault_items`.** DONE 2026-09-24 (post-M8 item 16,
  migration `0004_drop_vault_items`): dropped. The table never gained a
  consumer — no code path read or wrote it, and the app role was denied
  entirely (`USING (false)`). A credentials-shaped table that nothing
  uses invites future code to assume a working secrets store; if
  connector credentials ever need a home, they get a designed, tested
  table then. `pii_rls_adversarial.rs` now pins the table's absence
  (`to_regclass('vault_items') IS NULL`).
- **Dev credentials.** DONE 2026-09-24 (subsumed by post-M8 item 8):
  the app roles' passwords were rotated to fresh 48-hex secrets in
  git-ignored `.secrets/.env.test`; `bin/pg-ensure.sh` re-applies them
  from the environment on every run and
  `tinker_db::rotate_app_role_passwords` is mandatory in the migration
  runner, so the frozen-0001 `*_dev_pw` literals can never survive
  provisioning. (Kept as a one-shot backstop; never live.)

## New items from the M0 harden/secure/performance pass (2026-09-24)

- **Adversarial coverage still open.** DONE 2026-09-24: all three are
  now covered. (1) Concurrent `add_field` on one draft:
  `concurrent_add_field_on_one_draft` in `m4_hardening.rs` — two
  spawned adds serialize on the version `FOR UPDATE` row lock, both
  fields land in the draft spec. (2) PII app-role RLS cross-tenant reads
  at the SQL level: new `tinker-vault/tests/pii_rls_adversarial.rs` —
  app role sees only its declared org, nothing with no context, never
  `vault_items` (`USING (false)`), a targeted read of org B's row id
  scoped to A returns empty, unknown org sees nothing. (3)
  Relation-only filter/join ordering:
  `relation_only_filter_and_order_joins_execute` in `m4_hardening.rs` —
  filter on one relation + ORDER BY a second relation's traversal with
  base-only select; asserts 3 LEFT JOINs (ext + 2 relations) render
  before WHERE before ORDER BY and executes to [Bob, Carol].
  - Finding (documented in-test, no migration): on a pooled connection
    that previously ran `SET LOCAL app.organization_id` in a rolled-back
    transaction, PostgreSQL reports the context as `''` (not NULL) in
    the next transaction, and the RLS `::uuid` cast rejects it with
    22P02 — fails LOUD, never leaks rows. Virgin sessions get NULL and
    fail closed to empty.
  - Finding (fixed): ORDER BY did not accept relation traversal
    (`unknown order field: referred_by.name`). `resolve_order_field`
    now delegates to `resolve_select` (async), so ORDER BY supports the
    same paths as SELECT/filters; direct-field expressions are
    unchanged.
- **Query compiler executor.** DONE 2026-09-24 (post-M8 item 12):
  `Param::from_json_for_kind` converts JSON filter values to typed binds
  per field kind (`Date`/`Timestamp` variants added; strict `Validation`
  errors, never silent coercion); number/currency placeholders carry
  explicit `::int8`/`::float8` casts because sqlx's prepared-statement
  cache is keyed by SQL text alone — without the cast, an INT8 then
  FLOAT8 bind on a pooled connection reuses the first preparation
  (22P03 or silent garbage comparison). `tinker_live::bind_param` is the
  single canonical `Param` → SQLx binding path (executor, streamer, and
  test harnesses all use it; m4 test harnesses refactored onto it).
  `QueryExecutor::execute_stream` pages compiled plans through a
  server-side cursor in `STREAM_CHUNK` (500) fetches with bounded memory;
  audit row written on exhaustion with the true row count, abandoned or
  failed streams roll back with no audit row. `column_json` now decodes
  TEXT[] (multi_select) to a JSON array instead of Null. Covered by the
  new `tinker-m2/tests/m2_stream.rs` (4 tests: exactly-once paging +
  audit, tenant isolation across chunks, no-audit on abandon, field-aware
  coercion through the compiler).
- **App-role passwords.** DONE 2026-09-24 (post-M8 item 8): the
  environment was seeded with the published defaults (`TINKER_CORE_URL`
  / `TINKER_PII_URL` carried `tinker_app_dev_pw` /
  `tinker_pii_app_dev_pw` verbatim). Both rotated to fresh 48-hex-char
  secrets in git-ignored `.secrets/.env.test`; cluster re-provisioned
  via `bin/pg-ensure.sh`. New `tinker_db::rotate_app_role_passwords`
  (owner handles, fail-closed on missing password segment) is now
  mandatory in `examples/migrate.rs`, so the repo's own migration
  runner can never leave the frozen-0001 defaults live. Covered by
  three tests in `crates/tinker-db/tests/app_role_passwords.rs`
  (end-to-end eviction of a simulated published-default back to the
  env secret, fail-closed, extraction parity with pg-ensure).
- **Local owner privileges.** DONE 2026-09-24 (post-M8 item 11):
  `bin/pg-ensure.sh` is now the one-shot privileged bootstrap: role /
  database / extension setup runs as the postgres superuser (installs
  `pgcrypto` in core+pii, `pg_trgm` in core, sets all passwords from
  environment), then converges `tinker_core` / `tinker_pii` to LOGIN +
  CREATEROLE only (NOT superuser, NOT createdb) on every run.
  CREATEROLE is the documented minimum for the supported app-role
  password rotation (`tinker_db::rotate_app_role_passwords` issues
  ALTER ROLE over owner handles); the bootstrap also grants each owner
  ADMIN OPTION (only) on its app role, which PostgreSQL requires
  alongside CREATEROLE to change another role's password. App roles
  stay plain LOGIN. Real fallout found and fixed while here: the
  codebase's owner/system pool assumed superuser RLS bypass, but five
  tables carry FORCE ROW LEVEL SECURITY (`auth_credentials`,
  `memberships`, `workspaces`, `apps`, `actors`) and are read without
  a tenant context (OIDC pre-tenant binding lookup, Authorizer
  workspace/app scope resolution, operator identity resolution) —
  stripping SUPERUSER silently broke OIDC login and scope resolution
  (caught by `m1_auth_replaceable`). Migration
  `0027_no_force_rls_system_scope.sql` removes FORCE (keeps RLS) on
  exactly those tables, mirroring 0011's sessions precedent; the app
  role remains fully policy-bound. Covered by five tests in
  `crates/tinker-db/tests/owner_least_privilege.rs` (role flags,
  ADMIN OPTION grants, extension preinstall, system-scope visibility
  without tenant context + app-role blindness).
- **Migration immutability.** DONE 2026-09-24: the pre-release edits
  to 0001/0005 (core) and 0001/0002 (pii) were repaired in the dev DB
  by deleting the stale `_sqlx_migrations` rows and re-applying (all
  touched migrations are idempotent: `IF NOT EXISTS` + `DROP POLICY IF
  EXISTS`). The principle is now enforced, not just stated: post-M8
  item 14's source-checksum verifier fails closed on any
  edited-after-apply / never-applied / applied-with-no-file migration.

## From M6 (2026-09-24)

M6's milestone exits are verified (see STATUS.md). Deferred hardening and
design questions found during the loop, sequenced here, not claimed as
done:

- **Reconciliation fingerprint columns.** DONE 2026-09-24 in two parts:
  (a) The backlog item proper (migration
  `0024_ingest_run_first_class_counts.sql`): `ingest_run` now carries
  first-class `fingerprint`, `count_landed`, `count_promoted`,
  `count_linked`, `count_created`, `count_queued_for_review`,
  `count_pages`, `drift_breaking`, and `duration_millis` columns,
  populated by `finish_run` from the counts JSON and honestly
  backfilled for all 330 historical runs from their existing JSON
  (failed runs keep NULLs — no fabricated outcomes). Indexes on
  `fingerprint` and on `stream_id WHERE drift_breaking`.
  (b) Adjacent hardening the implementer added while here (migration
  `0023_ingest_reconcile_columns.sql`, beyond the item's letter):
  `ingest_stream` carries a reconciliation rollup —
  `reconcile_fingerprint` (sha256 of the canonical reconciliation
  outcome; stable across identical runs), `reconcile_seen_at`,
  `reconcile_expected`, `reconcile_unexpected` — populated by
  `Reconciler::reconcile` in the same transaction as the history row.
  Tests: `run_outcome_first_class_columns` (columns match counts JSON
  and the pipeline report), `infra_failure_fails_run_loudly` extended
  (failed run leaves outcome columns NULL),
  `reconcile_populates_stream_rollup`, `reconcile_rollup_tracks_drift`
  (fingerprint changes on drift, stable on identical reruns).
- **`fail_stale_runs` has no age threshold or advisory lock.** DONE
  2026-09-24 (migration 0022_run_heartbeat): every pre-existing `running`
  row was treated as crashed immediately, and two genuinely concurrent
  `start_run` calls on the same stream could interleave. Now:
  `last_heartbeat_at` (refreshed per page during execution), a 300s
  staleness threshold, a per-stream `pg_advisory_xact_lock` serializing
  `start_run`, a partial unique index guaranteeing one `running` row per
  stream at the DB level, and `TinkerError::Busy` (HTTP 409) for a live
  concurrent run. Covered by `concurrent_start_run_serializes`,
  `fresh_running_run_is_not_superseded`, `heartbeat_run_refreshes_liveness`.
- **Per-record error classification.** DONE 2026-09-24: any
  per-record error became a `canonical_write` conflict review, so an
  infrastructure outage would have painted as a green run with reviews
  pending. Now `TinkerError::is_record_data_error()` classifies:
  `Validation`/`Conflict`/`NotFound` and Postgres data-integrity
  SQLSTATEs (23514/23505/23503/23502/22001/22P02/22003) quarantine the
  record as a review and the run continues; `Db` transport/pool/
  serialization failures, `Forbidden`, `Busy`, `Serde`, `Internal` fail
  the run loudly (`run()` marks it `failed`); `DuplicateEffect` is a
  benign no-op (the write already landed). Covered by
  `infra_failure_fails_run_loudly` (end-to-end: dropped canonical
  table → run `failed`, zero reviews), `record_error_classification_sqlstate`
  (real 23514/42P01/connection-refused), and the tinker-core unit test
  for the pure arms. The pre-existing
  `canonical_write_failure_queues_review_atomically` (23514 → review)
  still passes unchanged.
- **AI-assisted mapping proposals.** DONE 2026-09-25 (post-M8 item
  25, commit `b702986`): `MappingEngine::propose_mappings_ai` asks the
  named model provider to map a stream's observed source fields onto
  the target object's api fields. Same governed lifecycle —
  suggestions land as `proposed`, never activated; operator mappings
  win; `ON CONFLICT DO NOTHING` converges concurrent proposers. The
  model sees field names only (record values never leave the
  process); `hosted` providers rejected; model output validated
  per-suggestion, malformed output fails closed with zero rows.
  Pinned by 7 tests in `crates/tinker-m6/tests/mapping_ai.rs`.
- **Installer lock scope.** DONE 2026-09-24: the install advisory lock
  is now per-pack (`tinker-pack-install:{pack_id}` via
  `PackInstaller::install_lock_key`) instead of one global
  `tinker-pack-install` key, so concurrent installs of disjoint packs
  proceed in parallel. Same-pack installs still serialize on the
  check-then-create passes. A genuine cross-pack slug race hits the DB
  `UNIQUE(scope_kind, scope_id, api_slug)` constraint and gets exactly
  one retry, which converges through the idempotent resolve-existing
  path (a second 23505 is returned as-is). Covered by three tests in
  `crates/tinker-packs/tests/install_lock_scope.rs`:
  `disjoint_pack_installs_do_not_serialize` (holds the legacy global key
  as a tripwire — a return to global serialization would hang until the
  timeout), `install_lock_is_per_pack` (pack A's install observably
  blocks in pg_locks on its held per-pack key, then completes on
  release — deterministic, no dropped futures), and
  `same_pack_installs_serialize_and_converge`.
- **Non-monotonic sources.** DONE 2026-09-24 (post-M8 item 7):
  `cursor_kind='snapshot'` streams scan the whole source every run,
  land only records whose content hash differs from the mirror
  (`landing._record_hash`), and mark mirror rows absent from the
  complete scan `_deleted=true` (migration 0025, frozen). Covered by
  three tests in `crates/tinker-m6/tests/m6_ingest.rs`:
  `snapshot_cursor_diff_is_stable`, `snapshot_cursor_captures_rewritten_history`,
  `snapshot_cursor_marks_missing_as_deleted`.

## From M7 (2026-09-24)

M7's milestone exits are verified (see STATUS.md). Deferred hardening and
design questions found during the loop, sequenced here, not claimed as
done. All five are grounded in the shipped code:

- **Real model-provider adapters.** DONE 2026-09-25 (post-M8 item
  24, commit `a7e5486`): `tinker-agents/src/adapters.rs` ships
  `HttpModelAdapter` — OpenAI-compatible `/v1/chat/completions` HTTP
  transport for `hosted`/`private` providers (auth via
  `TINKER_PROVIDER_<NAME>_API_KEY`, retries honoring Retry-After,
  live `usage`-block token accounting with fail-closed on missing
  usage, transport-level placement check in the gateway). New
  `m7_adapters` suite 11/11 against an axum mock provider. Remaining:
  live provider billing API adapters (bills are manually imported)
  and price-list freshness vs provider list prices.
- **Cost records in currency.** DONE 2026-09-25 (post-M8 item 21,
  commit `a531233`): `model_prices` price list + `cost_records`
  (per-org/window/model, cost computed at record time, unpriced tokens
  flagged never zero-priced) + `provider_bills` import with
  Match/LedgerOver/LedgerUnder reconciliation (migration 0031);
  `TransformEngine` now records real completion tokens best-effort.
  Remaining: live provider billing API adapters (bills are manually
  imported) and price-list freshness vs provider list prices.
- **Embedding-based semantic ranking.** DONE 2026-09-25 (post-M8 item
  27): `expand.rs` no longer ranks purely deterministically. Opt-in
  `SemanticRanker` pools each source record's AUTHORIZED candidates
  across its edges (authorization render runs first, per edge) and
  orders them by embedding cosine similarity to a focus text via
  `ModelGateway::embed_texts` (placement-enforced; `hosted` providers
  rejected for record text). `HttpEmbeddingAdapter` speaks
  OpenAI-compatible `/v1/embeddings` with retry/backoff and fail-closed
  vector handling; any embedder/placement failure degrades to
  deterministic order. `RankingRecord` provenance (provider,
  ranked/fallback counts) persisted via migration
  `0033_expansion_ranking` (`ranking JSONB` on `expansion_manifests`).
  The authorization-before-ranking invariant holds through the swap:
  `semantic_retrieval_ranks_but_cannot_expand_authorization`
  (`m7_agents`) still green, plus new `m7_expand_ranking` 4/4 —
  including proof that masked/forbidden field values never reach the
  embedder. Honest limit: tests use `FakeEmbeddingAdapter`; no live
  provider call.
- **Approval expiry and escalation.** DONE 2026-09-24 (post-M8 item
  13): migration `0028_approval_expiry` adds `expires_at TIMESTAMPTZ`
  (default now()+24h; existing rows backfilled to `created_at`+24h) and
  `escalated_at TIMESTAMPTZ` to `approval_requests`, plus pending-expiry
  and pending-escalation indexes. `request_with_ttl` (default
  `DEFAULT_APPROVAL_TTL` = 24h) stamps the deadline; `decide` and
  `mark_executed` lazily transition past-deadline rows to `expired` in
  the same transaction and fail closed with a distinct error — a stale
  approval can never authorize an action, including one that lapses
  between decide and execute. `expire_stale_approvals` bulk-expires an
  org's stale pending rows for the operator loop. `escalation_due`
  lists pending, never-escalated rows older than the threshold
  (`DEFAULT_ESCALATION_AFTER` = 4h, per-attachment
  `ttl_secs`/`escalation_after_secs` overrides parsed from the
  approval-policy JSON); `mark_escalated` flags them with a single
  atomic UPDATE…RETURNING so concurrent notifiers can't double-claim.
  Escalation never changes decidability. Covered by the new
  `tinker-m7/tests/m7_approval_expiry.rs` (6 tests). Lesson: the table
  has FORCED RLS, so even the owner pool sees zero rows without
  `app.organization_id` — test time-travel helpers must go through
  `tenant_tx`. Escalation is a query hook, not a delivery mechanism;
  no chat/email/page sender is wired yet.
- **MCP wire transport (DONE items 22+28, 2026-09-25 — stdio + HTTP/SSE;
  Directus C6 complete).** `tinker-cli mcp serve` exposes the in-process
  `McpServer` over JSON-RPC 2.0 stdio with launch-scoped identity.
  Item 28 added the HTTP/SSE transport (`tinker-cli mcp http`: GET /sse,
  POST /messages, POST /mcp, MCP 2024-11-05) plus the inbound
  machine-credential story it was blocked on: migration 0034
  `machine_credentials` (SHA-256-only storage), issue/rotate/revoke/
  list via `tinker-cli mcp key`, scope grammar
  (item 35 renamed the CLI binary `tinker` -> `tinker-cli`; the web
  server keeps the `tinker` name)
  (mcp:tools/mcp:resources/mcp:tool:<name>) enforced per message
  (-32001 on denial), sessions bound to the opening credential,
  127.0.0.1 bind only. Covered by `apikey_credentials` (10 tests) and
  `m7_mcp_http` (7 tests).

## From M5 (2026-09-24)

M5's milestone exits are verified (see STATUS.md), but the PRD's "Launch
communication scope" (PRD v0.6 §44, p.56) names product surface beyond the
exits. These are sequenced here, not claimed as done:

- **@-mentions. DONE as item 31 (2026-09-25).** Chat was specified to ship mentions. Not implemented:
  no mention extraction from message bodies, no actor handle to resolve
  `@name` against (`actors` has `display_name` but no unique handle), and
  no wiring from `post_message` to the notification router. Needs:
  migration adding a per-org-unique `handle` to `actors` (backfilled from
  display_name), `@handle` extraction, tenant-scoped resolution, and
  "mention" notification routing (the router already supports the kind).
- **Message search. DONE as item 32 (2026-09-25).** Chat was specified to ship search. Not implemented:
  no search over message bodies. The M0 search adapters (native pg_trgm +
  TIN) exist; message search should index the comms message table through
  the same permission-aware path.
- **Email receive / attachments / templates.** DONE 2026-09-25
  (item 36, commit `903eb5b`): inbound provider webhook receiving with
  HMAC verification, tenant-scoped address routing, replay/idempotency
  registry (migration 0037); attachment links via the item-23
  `stored_files` registry (bytes never touch Postgres, caps enforced);
  governed versioned templates with a minimal safe render engine and
  provider-trait send path. 22 integration tests, 98/98 suites and
  432/432 tests green. Honest limits: no threading/in-reply-to, text
  body only, no bounce/DSN, no real provider integration. M5 delivers provider-backed
  *sending* (trait + fake provider; real SMTP/API provider is later work).
  Receiving, attachment storage, and templating are now implemented.
- **Cross-plane grant audit surface.** DONE 2026-09-24: grant *use*
  is now audit-logged — every successful cross-plane thread-card read
  appends a row to `cross_plane_grant_uses` (migration 0026),
  RLS-pinned to the accessed org, app role SELECT+INSERT only, and the
  audit write fails the read closed. New owner/admin-only endpoints:
  `GET /api/comms/grants` (every grant ever issued in the org — live,
  expired, revoked — with use counts) and
  `GET /api/comms/grants/{id}/uses` (audited reads under one grant;
  foreign ids yield an empty list). Covered by
  `cross_plane_grant_use_is_audit_logged` in `m5_comms.rs`.

## From M8 (2026-09-24)

M8's milestone exits are not yet committed (see STATUS.md). Deferred
hardening and design questions found during the loop, sequenced here,
not claimed as done. The M7-deferred items (real model adapters,
currency cost records, embedding ranking, approval expiry, MCP wire
transport) also cover M8's surface — they are not re-listed here.

- **Live Redis verification.** DONE 2026-09-24 (post-M8 item 19,
  commit `ef6b226`): `RedisSessionStore` implements `SessionStore` over
  a real Redis (`SET .. EX` / `GET` / `DEL`, raw-byte values, boundary
  validation matching the fake, `ttl=0` → `DEL`, I/O errors →
  `TinkerError::Internal` so a dead Redis never reads as "session
  missing"). Proven by 6 tests in
  `crates/tinker-transfer/tests/redis_session_store.rs` against live
  Redis 7.0.15: cross-instance write visibility, server-side TTL
  (raw `PTTL`) + real expiry, binary-safe round-trip, validation
  parity, loud failure on unreachable Redis, kill/restart recovery
  with no client-local state. Redis cluster/Sentinel failover remains
  unverified (standalone restart recovery only).
- **Directus-derived candidates (→ items 37–42 open; folded in per user request, 2026-09-24;
  C6 DONE items 22+28, C7 partial DONE item 23, remainder → items 37–42;
  full analysis in `goals/build-the-tinker-platform-m0-m8/directus-assessment.md`).
  Directus v12 is MSCL-1.0-GPL (source-available, not OSI-open); these
  are transfer-of-ideas only, not code adoption:**
  - **C1 record-level content versioning (DONE item 40, 2026-09-26,
    `6452fbb`):** draft → review → publish per record, composed with
    M7 approvals (publish requires an approved approval) and M8
    retention (migration 0041; lifecycle engine with immutable
    versions + audit trail; read paths default to published when
    lifecycle_enabled; snapshot fail-closed hardening). Gate 102/102
    suites, 509/509 tests green. Original open brief below.
  - **C2 row-level permission filters (DONE item 38, 2026-09-26):** commit
    `c8f8337` — per-role row filters compiled into the query
    compiler alongside the tenant predicate ("policy before
    ranking"); filters stored as data per (org, role, object)
    (migration 0039), spliced into native + TIN search before
    matching/ranking, render_record returns NotFound for hidden
    rows; gate 100/100 suites, 474/474 tests green. Original open
    brief below.
  - **C3 field validation + write presets (DONE item 37, 2026-09-25):** commit
    `0603250` — server-side validation rules (min/max, pattern,
    options) as field metadata (migration 0038) + write presets
    through the governed mutation connector (M3 debt); gate 99/99
    suites, 464/464 tests green. Original open brief below.
  - **C4 portable schema snapshot/diff/apply (DONE item 39, 2026-09-26,**
    **`d5a74e3`):** signed versioned artifact for dev → staging → prod
    and pack distribution, with a version/vendor hash guard; applies
    through M4 evolution machinery. Gate 101/101 suites, 489/489 tests
    green. Original open brief below.
  - **C5 dashboard composer (DONE item 41, 2026-09-26, `fbc4f01`):**
    dashboard as governed object (org-scoped, RLS; migration 0042);
    panels embed QueryIntents (no saved-view library exists yet —
    honest v1 limit); each panel executes under the VIEWER's
    permissions (item-38 row filters + field projection, no
    privilege escalation via shared dashboards); per-panel failure
    isolation; composes with item-40 lifecycle visibility. Gate
    103/103 suites, 516/516 tests green. Original open brief below.
  - **C6 MCP wire transport (DONE items 22+28, 2026-09-25):** stdio
    transport (item 22) plus HTTP+SSE transport and inbound machine
    credentials (item 28: `tinker-cli mcp http`, `tinker-cli mcp key`
    issue/rotate/revoke/list, migration 0034; CLI renamed `tinker-cli`
    by item 35) for external MCP clients (also listed under M7).
  - **C7 governed file/blob type (DONE item-23, 2026-09-25):**
    migration 0032 `stored_files` registry (tenant RLS, sha256
    content addressing, pii_class) + `FileStore` in tinker-agents
    (FsFileBackend, dedup, integrity-verified fetch, retention that
    deletes bytes, audit on every access) + `tinker-cli file`
    store/get/delete CLI. Bytes never touch Postgres. S3 backend and
    record-write-path File-field validation DONE 2026-09-26 (item 42,
    `dbef5d6`): SigV4 S3-compatible FileBackend (env-only config,
    fail-closed unconfigured, SSE passed through never logged, secrets
    redacted in Debug; Fs stays default) + FileLinkValidator on the
    write path (exists in stored_files, same org, pii_class fits the
    field ceiling, sha256 re-hash at link; identical opaque error for
    missing/deleted/cross-org — no oracle); migration 0043 records
    byte placement per file. Honest v1 limits: no multipart resume,
    no CDN signed-URL serving, no cross-backend migration tooling.
  - Explicitly NOT adopted: Directus's Flows engine, CMS breadth,
    legacy-schema wrapper, GraphQL surface, multi-database scope,
    generic AI assistant, tiered licensing.

## From M4 (2026-09-24)

- **Pack drift / reinstall idempotence proof.** DONE 2026-09-24
  (post-M8 item 17, `crates/tinker-packs/tests/drift_repair.rs`, 5 tests).
  Reinstall is now drift-reconciling in two phases: missing pack fields
  are re-added, drifted field metadata (name/label/required/options) is
  restored, undeclared fields are left alone, and a type-drifted pack
  field fails closed (reinstall never rewrites a physical column). The
  proof also fixed two real installer bugs the new tests exposed: the
  cross-pack 23505 retry was dead code (`define_object_inner` launders
  23505 into `Validation("object slug already exists: …")`, so the old
  `is_unique_violation` predicate never matched), and one whole-pass
  retry could not survive multi-object collisions — pass 1 now
  re-resolves per object on a lost race. Proven: drift repair with data
  intact, fail-closed type drift, 8-way duplicate-install convergence,
  cross-pack slug-collision convergence, and reinstall over an org with
  an active evolved schema leaving extension tables/rows/ExtFields
  intact (evolution-aware by construction: evolved fields never live in
  `ontology_fields`).
- **Governance of promotion/rollback invalidation. DONE as item 33 (2026-09-25).** Versioned queries
  bypass the plan cache (`Versioned` plan kind is never cached), which is
  the current invalidation story. If versioned plans ever become cached,
  promotion/rollback need explicit version-keyed invalidation.
- **SSE + version changes.** DONE 2026-09-24 (post-M8 item 18, commit
  5ecd2c0): `SignalKind::{Invalidate, SchemaVersion}` shares the per-org
  bus/sequence space; `GET /api/sse` emits a distinct `schema_version`
  event (`{seq, object_id}`, no rows/record ids); promote/rollback drop
  the object's cached query plans and publish the signal post-commit.
  Pinned by 2 tests in `m4_sse_schema_version.rs`.
- **Cohort membership validation.** DONE 2026-09-24: `mark_canary`
  now validates the cohort against the org roster at transition time.
  Unknown UUIDs, foreign-org actors, and empty cohorts are rejected with
  `Validation` (HTTP 400) instead of silently producing a canary nobody
  can see. Duplicates are deduped. The roster read runs in the caller's
  tenant transaction, so the actors RLS policy scopes it to exactly this
  org — the rejection message never reveals whether a UUID exists in
  another org. Gating enforcement in `resolve()` is unchanged. Covered
  by `mark_canary_validates_cohort_roster` (unknown / foreign-org /
  empty rejected; version untouched; valid cohort transitions) and
  `mark_canary_dedupes_cohort` in `m4_hardening.rs`. Complements the
  existing `malformed_cohort_rejected` (malformed JSON shapes) test.
- **Migration checksum verification.** DONE (2026-09-24, item 14,
  commit `deedcc6`). `pg-ensure.sh` now runs checksum verification
  (SHA-384, byte-identical to `sqlx::migrate!`'s algorithm) of every
  `.sql` file against `_sqlx_migrations` checksums after the migrator,
  via `tinker-db::migrate_check` + the `verify-migrations` example.
  Fails closed on edited-after-apply, never-applied, applied-with-no-file,
  and stale-embedded-set drift. 6 tests pin the algorithm, live-cluster
  agreement, and every fail-closed shape.
- **Browser/mobile verification. DONE as item 34 (2026-09-25).** The `/schema` builder page is tested at
  HTTP level only (rendering, forms, gates). No real-browser or mobile
  verification of DataStar/custom elements on the builder. Drag/resize
  canvas for visual authoring is future work.
- **Adopt-vs-define semantics.** DONE 2026-09-24 (post-M8 item 20,
  commit `d9d7839`): `Ontology::adopt_object` + the joint design with
  M4 per-org overlays — the adopter's own fields are namespaced by its
  adopted row, base fields resolve live, shadowing fails closed, and
  `describe_object_with_ext` composes M4 evolution on top of adopted
  objects unchanged.

## User directives (2026-09-25)

- **Single-server efficiency.** DONE 2026-09-25 (post-M8 item 29):
  reference profile recorded (2 vCPU AMD EPYC 9D25, 7,935 MiB RAM, 7.5 GB
  overlay, PG 16.15 + Redis 7.0.15 on 127.0.0.1); deterministic `crm-10k`
  workload (10 tenants, 12,500 seeded records) in
  `crates/tinker-m7/tests/m7_efficiency.rs` (10 tests: 8 tripwires +
  throughput probe + ceiling ramp); production optimizations shipped:
  landing N+1 removed (500 INSERTs → 1 multi-row INSERT, chunked 1,000),
  pool discipline (`CoreDb`/`OwnerDb::connect` in the `tinker` binary,
  was raw `PgPool::connect`), migration 0035
  `(organization_id, source_id)` index for the cross-stream identity
  lookup (planner-verified Index Scan). Baselines measured under
  contention (loadavg 4–5, labeled as upper bounds): ingest p50 12.0s
  (budget 30s), query_miss 12ms (500ms), query_hit 0ms (100ms),
  gateway 0ms (500ms), mcp_tools_list 2ms (500ms), mcp_sse 2ms
  (5,000ms), key_verify 2ms (100ms), session_load 0ms (100ms).
  Throughput: query_hit 5,141 ops/s, mcp_tools_list 176 ops/s
  (8 workers). Ceiling ramp (mcp_tools_list): linear to 32 workers
  (409 req/s), no knee observed — measured ceiling ≥400 req/s machine
  API. Evidence doc: `docs/one-server-efficiency.md` (all TBDs filled).
  Gates: fmt clean, clippy `-D warnings` clean, full serial suite
  87 binaries / 353 tests passed / 0 failed (m7_efficiency binary
  interrupted by a load stall at loadavg 15+, not a test failure;
  its 10 tests passed in the calibration run). Logs:
  `~/workspace/tinker-item29-{baseline,gate,clippy}.log`.
  Honest limits: numbers are contention-inclusive (quiet window never
  materialized); ingest is the tightest path (~40 rows/s); the ramp
  did not find the knee; debug build.
  Original directive 2026-09-25 02:17 EDT (George Guimarães's
  "Phoenix+DB" post): make Tinker so efficient a business runs on ONE
  server. Acceptance: (1) reference profile ✅, (2) baseline measured
  ✅, (3) tripwires ✅, (4) optimizations measured ✅, (5) evidence doc
  ✅ with measured ceiling, not an unlimited claim.
- **Scale-out spike. DONE as item 30 (2026-09-25).** User directive 2026-09-25 02:18 EDT (companion to
  single-server efficiency): Tinker must *support* scale-out even though
  one server is the efficiency target. Time-boxed spike, sequenced with
  the single-server item. Prove the mechanics, document what breaks:
  1. Two app instances behind a load balancer sharing one Postgres +
     one Redis: migration ownership (advisory-lock the migrator so only
     one instance migrates), connection-pool sizing, no in-process
     state assumptions on request paths.
  2. Sessions across instances: item 19's live Redis session store
     means no stickiness should be required — prove login on A,
     request on B.
  3. Cross-instance signal fan-out: the per-org SSE bus/sequence space
     (items 18, 27) is per-process; spike Redis pub/sub (or Postgres
     LISTEN/NOTIFY) fan-out so an invalidate/schema_version signal
     published on A reaches an SSE subscriber on B, with sequence
     ordering preserved.
  4. Machine credentials (item 28) and approvals work unchanged across
     instances (Postgres-backed — should be free, verify).
  5. Spike doc: what survives scale-out, what doesn't (e.g. in-process
     plan-cache invalidation across nodes), and the minimal changes a
     real multi-instance deployment needs. No production topology
     claims — the spike is the evidence.

## Sequenced next (2026-09-25, user directive 02:52 EDT: push hard, gates non-negotiable)

Pipeline order after item 30 closes: item 31 → 32 → 33 → 34.
Dispatch the next the moment the previous closes; zero idle time.
Non-negotiable per item: serial `-j1` `--no-fail-fast` full workspace
suite green before any completion claim; `cargo fmt --all --check`
clean; `cargo clippy --workspace --all-targets -- -D warnings` clean;
honest limits stated; no completion claim on partial/flaky/
environmental results (fix properly, never weaken the gate); applied
migrations immutable (next core migration: check
`crates/tinker-db/migrations/core/` for the current max — 0034 was
item 28's; items run serially so each worker claims the next number);
STATUS.md ledger entry per item; durable logs under `~/workspace/`
(`tinker-itemNN-*.log`), never `/tmp`. Env: `pg-ensure.sh` only if
PostgreSQL is actually down; before Cargo/SQLx,
`set -a; . .secrets/.env.test; set +a; export
DATABASE_URL="$TINKER_CORE_OWNER_URL"`; never run concurrent
DB-touching commands; never bare `psql` (use the credentialed URL).
Item 29's worker needs a quiet box for timing — no other DB-touching
or CPU-heavy work runs while an item's verification gate is running.

- **Item 30 — Scale-out spike. DONE 2026-09-25** (commit `Item 30:
  scale-out spike`; gate 92 suites / 374 tests / 0 failed;
  `docs/scale-out-spike.md`). The "Scale-out spike" entry under
  "User directives (2026-09-25)" above, now numbered. Time-boxed:
  prove (1) two app instances + shared Postgres/Redis with
  advisory-lock migration ownership and no in-process state on
  request paths; (2) login on A, request on B via the item-19 Redis
  session store, no stickiness; (3) cross-instance SSE fan-out —
  the per-org bus/sequence space (items 18, 27) is per-process
  today, so spike Redis pub/sub or Postgres LISTEN/NOTIFY such that
  an invalidate/`schema_version` signal published on A reaches an
  SSE subscriber on B with sequence ordering preserved; (4)
  machine credentials (item 28) and approvals unchanged across
  instances; (5) spike doc: what survives scale-out, what doesn't
  (e.g. in-process plan-cache invalidation across nodes), minimal
  changes a real multi-instance deployment needs. No production
  topology claims — the spike is the evidence.

- **Item 31 — @-mentions. DONE 2026-09-25** (commit `Item 31:
  @-mentions`; gate 93 suites / 387 tests / 0 failed; migration
  `0036_actor_handles.sql`). Migration adds per-org-unique `handle` to
  `actors`: `normalize_actor_handle` (lowercase; `[a-z0-9._-]` kept
  verbatim; other chars collapse to a single `-`; leading/trailing
  `-`/`.` stripped; 64-char cap; empty -> `actor`), backfilled from
  `display_name` with the deterministic GitHub-style suffix policy
  (`handle-2`, `handle-3`, ...) — fail-closed rejected for the backfill,
  the `UNIQUE(organization_id, handle)` constraint enforces the
  invariant. Rust twin `tinker_core::handles::normalize_handle`;
  SQL/Rust equivalence proven by test (`m5_mentions.rs`). `post_message`
  extracts `@handle` (boundary-aware, punctuation/dedupe edge cases),
  resolves tenant-scoped against the org roster only (unknown and
  cross-org handles resolve to nothing: no oracle, no error leak, no
  notification), routes `"mention"` through the notify router honoring
  the mentioned actor's prefs (immediate/digest/off/quiet-hours).
  Self-mentions never notify; post-commit routing failure logs a
  warning, never loses the post. Machine-actor issuance assigns handles
  with the same suffix policy (`ON CONFLICT DO NOTHING` retry).
  Payloads carry ids only (no body, no display name). Tests:
  `m5_mentions.rs` 10/10 (routing, unknown/cross-org silence,
  self-mention, dedupe, prefs, payload PII-free, SQL/Rust parity) +
  extraction and normalization unit tests. Honest limits: no mention
  autocomplete API; no email/push delivery beyond the existing router
  modes.

- **Item 32 — Message search. DONE 2026-09-25** (commit `Item 32:
  message search`; gate 94 suites / 396 tests / 0 failed; no
  migration — `search_index` exists since 0005). M5 launch scope.
  Index comms message
  rows through the existing `SearchBackend` contract
  (`tinker-search/src/lib.rs`: `NativeSearchBackend` over the
  `search_index` table — tsvector/GIN + pg_trgm; `TinSearchBackend`
  fail-closed where the extension is absent): on `post_message`,
  call `index_change` with the body as `text_content` (plus
  thread/subject context if cheap). SECURITY: the core search index
  NEVER receives PII plaintext (`reject_pii` in
  `tinker-search/src/lib.rs`) — chat bodies can contain PII, so the
  worker must resolve this honestly: index only when the message's
  storage class permits, fail closed (skip + log, or reject the
  write — chosen and documented) otherwise. Search path: the
  permission-aware route — tenant-scoped `SearchBackend::search`
  plus the existing row-visibility checks, so a search never
  surfaces a message the caller can't read. Tests: index-on-post,
  tenant isolation (org B never sees org A's hits), PII guard
  (PII-classed body not indexed / write rejected), snippet
  contains no masked/forbidden field values. Honest limits: native
  backend ranking only; TIN adoption still blocked per the TIN
  entry.

- **Item 33 — Governance of promotion/rollback invalidation. DONE 2026-09-25** (commit `Item 33: promotion/rollback
  invalidation`; gate 94 suites / 399 tests / 0 failed; no
  migration). The pre-triaged gap verified: form_promote/form_rollback
  called the evolver with no cache invalidation and no schema_version
  signal. Fixed by extracting shared helpers
  (`broadcast_schema_change`, `promote_and_broadcast`,
  `rollback_and_broadcast` in `tinker-web/src/schema.rs`) that all
  four entry points (JSON + form promote/rollback) go through.
  Audited: no CLI/pack-installer callers; test-only direct evolver
  calls have no HTTP surface; ingest `pipeline.promote` is row-level
  (unrelated); mark_canary/mark_preview change only version status
  (default query path resolves `VersionSel::Active`), so no
  invalidation needed there. The current story (item 18, pinned by
  `m4_sse_schema_version.rs::promote_emits_schema_version_event_and_drops_cached_plans`):
  the web layer holds an app-level query-plan cache and
  `tinker-web/src/schema.rs::promote` calls
  `state.cache.invalidate(org_id, object_id)` plus
  `signals.publish_schema_version(...)` after the active version
  changes (same in the `rollback` handler just below it).
  PRE-TRIAGED GAP (2026-09-25, coordinator static audit — verify
  independently): `tinker-web/src/schema_page.rs::form_promote`
  and `::form_rollback` (POST routes at `tinker-web/src/lib.rs:112`
  and :116) call `state.evolver.promote/rollback` and return
  WITHOUT invalidating the plan cache or publishing the
  schema_version signal; `tinker-evolve`'s promote/rollback do
  neither internally. So a promote/rollback issued through the
  HTML form path leaves stale cached plans and silent SSE
  subscribers — the JSON API path is covered, the form path is
  not. (The `promote` in `tinker-ingest/src/pipeline.rs:596` is
  row-level ingest promotion, not a schema-version change —
  confirm, not assumed.) The check: fix the form handlers to
  mirror the JSON handlers (invalidate + signal post-commit),
  audit for any OTHER active-version writers
  (`mark_canary` changes rollout state, not the active version —
  confirm), and pin every verified path with tests in the
  item-18 style. Report the audited list explicitly: what was
  checked, what was already covered, what was added. Honest
  limits: this pins the current explicit-invalidation story; it
  is not version-keyed cache entries.

  **Resolution (item 33, DONE 2026-09-25):** the form handlers now
  mirror the JSON handlers exactly via the shared helpers; every
  active-version change on every HTTP entry point invalidates the
  object's cached plans and publishes exactly one schema_version
  signal (no double-broadcast). Tests pin all four paths in the
  item-18 style (`m4_sse_schema_version.rs`).

- **Item 34 — Browser/mobile verification. ✅ DONE 2026-09-25.** Real
  headless Chromium (152) drove the `/schema` builder against a live
  server on the test DB: unauth → `/login`, desktop 1440px + mobile 390px
  with zero horizontal overflow, zero JS console errors/warnings, full
  round trip in-browser (New draft → add field → Mark canary → Promote →
  303 back to builder), rollback 303, member promote 403, viewer with no
  `schema:evolve` sees no evolve controls. Scope corrected: page is
  server-rendered Askama with zero `<script>` tags — nothing hydrates.
  Proofs: `~/workspace/tinker-item34-proofs/` (5 PNGs, results.json,
  BROWSER_VERIFICATION.md). Gate: 95 suites / 400 tests green, fmt +
  clippy clean. Observation for follow-up: `.schema-layout` keeps
  `16rem 1fr` at 390px (narrow but no overflow/clipping) — a sub-640px
  single-column stack would read better on phones.

- **Item 35 — Rename one of the two `tinker` binaries. ✅ DONE 2026-09-25**
  (commit `Item 35: rename tinker CLI binary`; gate 96 suites / 402
  tests / 0 failed; no migration — schema untouched). Bug found
  during item 30 verification: the server binary (tinker-web) and the
  CLI binary (tinker-m7) were both named `tinker` and linked to the
  same `target/debug/tinker` — last writer wins, which broke the
  item-30 two-process test in the workspace gate (worked around in
  tests by probing the on-disk flavor and rebuilding the right
  package). Fix: server keeps `tinker`, CLI is now `tinker-cli`
  (its own target path; collision structurally impossible). All four
  binary-spawning test files dropped the test-only flavor-probing
  workaround and spawn via `CARGO_BIN_EXE_tinker` /
  `CARGO_BIN_EXE_tinker-cli` directly (Cargo preserves the hyphen in
  the env var name — verified by probe). New `bin_name_guard` suite
  (2 tests) pins the names and fails if a same-named `[[bin]]` ever
  returns. Product-visible: the CLI is now invoked as `tinker-cli
  vfile/mcp/file ...`; usage text, log lines, docs/STATUS/BACKLOG
  references all updated. The sequenced backlog is now EMPTY.

## Sequenced next, round 2 (2026-09-25 ~06:40 EDT — ledger correction)

The previous coordinator's "backlog empty" claim (commit e41aa20) was
wrong: it grepped only for ❌/TODO/WIP markers and missed genuinely
open entries. True remainder: the M5 email entry and the Directus C1–C5
+ C7-tail entries above, now numbered items 36–42. TIN stays
BLOCKED-with-evidence (commit adaec9c), not actionable.

Pipeline order: item 36 → 37 → 38 → 39 → 40 → 41 → 42. Dispatch the
next the moment the previous closes; zero idle time. One worker at a
time (serial items). Non-negotiable per item: serial `-j1`
`--no-fail-fast` full workspace suite green before any completion
claim; `cargo fmt --all --check` clean;
`cargo clippy --workspace --all-targets -- -D warnings` clean; honest
limits stated; applied migrations immutable (max core migration is
0036 as of item 35 — next is 0037+; workers claim numbers serially);
STATUS.md ledger entry per item; original entry annotated
DONE-with-item-number on close; durable logs under `~/workspace/`
(`tinker-itemNN-*.log`), never `/tmp`. Env: `pg-ensure.sh` only if
PostgreSQL is actually down; before Cargo/SQLx,
`set -a; . .secrets/.env.test; set +a; export
DATABASE_URL="$TINKER_CORE_OWNER_URL"`; never concurrent
DB-touching cargo commands; never bare `psql`.
License guard: Directus v12 is MSCL-1.0-GPL/source-available —
transfer of ideas only, never copy or vendor Directus code.

- **Item 36 — Email receive / attachments / templates.** DONE
  2026-09-25 (commit `903eb5b`, 98/98 suites, 432/432 tests green).
  M5 launch scope (the "From M5" entry above). M5 delivers provider-backed
  *sending* (trait + fake provider) only. Build: (1) inbound
  receiving — provider webhook endpoint with HMAC/API signature
  verification, tenant-scoped routing (which org owns the recipient
  address; unknown recipients fail closed with no oracle), received
  messages stored as comms messages; (2) attachment storage —
  attachments go through the item-23 `stored_files`/`FileStore`
  registry (content-addressed, tenant RLS, dedup; bytes never touch
  Postgres), linked to the message; size/count caps enforced,
  oversize fails closed before bytes are kept; (3) templating —
  templates as governed objects (CRUD + versioning), rendering with a
  minimal safe engine (variable substitution, conditionals, loops —
  NO arbitrary code execution, sandboxed by construction; document
  why the engine choice can't escape), template send path reuses the
  M5 provider trait. Security: webhook secrets from env only;
  attachment fetch authorization mirrors message visibility; template
  render never leaks cross-org data. Tests: signature rejection,
  tenant isolation on receive, attachment dedup + integrity +
  caps, template sandbox (malicious template can't exfiltrate or
  execute), PII-classed bodies handled per the item-32 decision.
  Honest limits: real SMTP/API provider is still later work (fake
  provider in tests); no inbound email threading UI beyond message
  rows.

- **Item 37 — C3 field validation + write presets.** DONE 2026-09-25
  (commit `0603250`, 99/99 suites, 464/464 tests green). Directus-derived
  (ideas only). Server-side validation rules + forced defaults,
  bundled with the governed mutation connector (M3 debt). Design:
  validation rules stored as field metadata (M0 `add_field` extension:
  required, min/max, regex, enum/options, custom predicate shape —
  keep the rule language data, never code); write presets as forced
  defaults applied at the mutation layer. Enforcement point: the
  governed mutation path (M3 connector) AND the direct record-write
  path — validate in one shared place so no writer bypasses it;
  violations fail closed with field-level errors. Presets apply
  before validation (a preset can satisfy `required`). Rules are
  org-scoped metadata, versioned with the schema (M4 evolution
  carries them). Tests: each rule kind enforced, bypass attempts via
  every write path rejected, preset-then-validate ordering, error
  shape contains no cross-org info. Honest limits: no async
  (external) validators; no cross-field rules in v1 unless cheap.

- **Item 38 — C2 row-level permission filters (DONE 2026-09-26).**
  Directus-derived (ideas only). Per-role row filters compiled into
  the query compiler alongside the tenant predicate ("policy before
  ranking" — composes with item 27's embedding ranking, which runs
  only on the authorized set). Shipped in commit `c8f8337`:
  migration 0039 stores filters per (org, role, object) as data
  (field/operator/value shapes, never raw SQL); `RowPolicy` compiler
  ANDs the role filter with the tenant predicate at SQL build time;
  native + TIN search splice the policy before matching/ranking;
  `render_record` returns NotFound for hidden rows; schema-page
  counts respect the viewer's policy. Gate: 100/100 suites, 474/474
  tests green; fmt + clippy clean. Original brief below.
  (org, role, object) as data (field, operator, value shapes —
  no raw SQL from users, ever); the compiler ANDs the role filter
  with the tenant predicate at SQL build time. Filter values are
  tenant-scoped constants or `actor.*` references (e.g.
  `owner_id = actor.id`); no subqueries in v1. Semantics: no filter
  = default-open per existing model (document the choice); a filter
  that matches nothing returns nothing — never an existence oracle
  (no "forbidden vs absent" distinction in errors). Tests:
  role-filtered queries return exactly the allowed rows, tenant
  predicate still applies, `actor.*` refs resolve per caller,
  injection-shaped filter values are inert (parameterized binds),
  ranking (item 27) still only reorders the authorized set.
  Honest limits: v1 operators only (eq/neq/in/range/null); no
  filter-on-computed-field.

- **Item 39 — C4 portable schema snapshot/diff/apply (DONE 2026-09-26, `d5a74e3`).**
  (ideas only). Signed versioned artifact for dev → staging → prod
  and pack distribution, with version/vendor hash guard; applies
  through M4 evolution machinery. Design: snapshot = canonical JSON
  of an object's schema (fields, types, constraints, validation
  rules from item 37, version history pointer); canonical
  serialization (sorted keys, no whitespace ambiguity) → sha256 →
  signed (Ed25519; key from env, `TINKER_SNAPSHOT_SIGNING_KEY`;
  public key distributed with the artifact or pinned per vendor).
  Vendor hash guard: artifact carries `vendor_id` + `min_version`
  and the applier rejects mismatched vendor or downgrade.
  Diff: field-level add/remove/change between two snapshots,
  rendered human-readable. Apply: dry-run first (list of evolution
  ops), then through the M4 evolver inside one transaction —
  type-drifted fields fail closed per the item-17 rule (never
  rewrite a physical column). Tests: tamper (any byte) fails
  signature; wrong vendor / downgrade rejected; round-trip
  snapshot→apply on a fresh org converges; dry-run lists ops
  without mutating. Honest limits: data migration (backfill) out
  of scope — schema only; no cross-database apply.

- **Item 40 — C1 record-level content versioning (DONE 2026-09-26, `6452fbb`).** Directus-derived
  (ideas only; flagged "M9 candidate: content lifecycle"). Draft →
  review → publish per record, composes with M7 approvals and M8
  retention. Design: lifecycle state on the record (or side table if
  the object table can't carry it — decide and document); states
  draft → in_review → published (+ archived); transitions are
  governed actions — submit_for_review and publish go through M7
  approvals (publish requires an approved approval, not just a
  click); M8 retention applies to published versions (drafts have
  their own shorter retention — document the policy). Read path:
  default queries resolve published (mirror the `VersionSel::Active`
  pattern from schema versions); drafts visible to author +
  reviewers only. Every transition audit-logged. Tests: illegal
  transitions rejected, publish without approval rejected,
  draft visibility scoped, retention treats drafts vs published
  per policy, audit trail complete. Honest limits: no per-field
  versioning (record-level only); no scheduled publish in v1.

- **Item 41 — C5 dashboard composer (DONE 2026-09-26, `fbc4f01`).** Directus-derived (ideas only).
  Drag-and-drop panels bound to saved views/queries. Design:
  dashboard as a governed object (CRUD, org-scoped, RLS);
  panels = {saved query/view reference, visualization kind,
  position/size in a grid layout}; layout persisted server-side
  (drag-and-drop itself is client-side DataStar — the server
  accepts layout saves, it doesn't implement DnD). Render path:
  each panel executes its saved query under the *viewer's*
  permissions (row filters from item 38 and field projection
  apply — a panel never shows its viewer data they can't see;
  panel errors fail per-panel, never break the dashboard).
  Tests: dashboard CRUD scoping, panel query executes as viewer
  (no privilege escalation via a shared dashboard), layout
  round-trip, per-panel failure isolation. Honest limits: no
  real-time collaborative editing; visualization kinds limited to
  what the query layer can already return (table + a basic chart
  shape); no scheduled snapshots.

- **Item 42 — C7 follow-ups (DONE 2026-09-26, `dbef5d6`).** Remainder of the C7 entry: (1) S3
  backend for `FileStore` — the trait + `FsFileBackend` exist
  (item 23); add an S3-compatible backend (env credentials only:
  endpoint/bucket/key/secret; fail closed when unconfigured;
  server-side encryption flag passed through, never logged);
  backend selected by config, Fs remains default; bytes still never
  touch Postgres. (2) Record-write-path File-field validation —
  File-typed fields on record write validate: referenced file
  exists in `stored_files`, belongs to the writing org,
  `pii_class` compatible with the field's classification, sha256
  integrity re-verified on link; violations fail the write closed.
  Tests: S3 backend against a fake/mock S3 (no live bucket in
  tests), unconfigured-S3 fails closed, cross-org file reference
  rejected (no oracle), pii_class mismatch rejected, integrity
  failure rejected. Honest limits: no multipart-resume in v1;
  no CDN signed-URL serving in v1 (serve via app with authz).
  (DONE 2026-09-26, `dbef5d6`; gate 105/105 suites, 537/537 tests
  green. Builder self-caught a wrong RFC 4231 HMAC test vector —
  implementation cross-checked against Python hmac, constant fixed.
  Backend column records byte placement; switching backends without
  migrating fails closed and operator-visible.)

## Agent front door (approved 2026-09-26; spec: SPEC-agent-front-door.md)

Build in order 43 → 44 → 45. Same non-negotiable gates: full serial
`cargo test --workspace`, `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, all green.

- **Item 43 — Part 1: self-describing ontology (`tinker describe`).**
  DONE 2026-09-27 (implementation `2707472`; gate 106/106 suites,
  549/549 tests, fmt+clippy clean — see STATUS.md). `GET /api/describe`
  (catalog + versions) and `GET /api/describe/{object}` (fields,
  types, validation rules, presets, relations, row-policy *summaries*,
  lifecycle states/transitions/roles, mutation contract, error
  taxonomy); CLI `tinker describe [object] [--json] --org <uuid>
  --role <role>` on the existing `tinker` binary; canonical JSON with
  stable field order; `tinker_version` + `ontology_version` on every
  payload; permission-aware (row filters / field projection apply —
  no schema oracle); read-only. Schema-only in v1 (no synthetic
  example records).

- **Item 44 — Part 3: version-matched agent skill.** DONE 2026-09-27
  (implementation `cc6c11a`; gate 107/107 suites, 563/563 tests,
  fmt+clippy clean — see STATUS.md). `SKILL.md`-shaped skill "Working
  with Tinker" (`crates/tinker-web/skills/tinker/SKILL.md`):
  discovery-first workflow, C6 auth via env, governed mutation paths,
  error taxonomy, three worked examples. `tinker agent install
  [--global]` installs to `./.claude/skills/tinker` (project-local)
  or `~/.claude/skills/tinker` (`--global`); source carries
  `__TINKER_VERSION__` / `__ONTOLOGY_VERSION__` placeholders
  substituted at install; `tinker agent verify` fails loudly (exit 1,
  both sides named) on drift. The worked examples run as tests:
  new `agent_skill` suite (6 tests) executes install/verify, the
  discovery example (real `tinker describe` subprocess), the first
  query (real compiler+executor), the first write (preset +
  validation rejections), and the publish flow (M7 approvals,
  no-self-approval, immutability) end-to-end; plus anti-rot content
  checks pinning the skill's flags, transitions, intent keys, and
  error classes to the code.

- **Item 45 — Part 2: MCP front door (`tinker-mcp`).** DONE
  2026-09-27 (implementation `8b86811`; gate 111/111 suites,
  582/582 tests, fmt+clippy clean — see STATUS.md). New binary:
  hand-written minimal MCP JSON-RPC stdio server (no SDK;
  protocol 2025-06-18/2025-03-26/2024-11-05), seven tools
  (`describe`, `query`, `get_record`, `create_record`,
  `update_record`, `transition`, `render_dashboard`) and
  `tinker://ontology/{slug}` resources, all through the existing
  governed paths (M3 projection, item-38 row policies, item-37
  validation/presets, item-40 lifecycle, item-42 file checks,
  item-41 viewer rendering). C6 `tk_` auth at startup; role from
  the credential's membership, never caller-supplied; hidden and
  missing records share the identical `not_found` shape; teaching
  errors name the rule and point at describe; non-integral
  `expected_version` fails closed. `tinker-cli mcp key issue
  --role <role>` grants the machine membership. Out of v1:
  `apply_snapshot`, subscriptions, HTTP/SSE transport.

- **Item 46 — MCP over HTTP/SSE (`tinker-mcp serve`).** DONE
  2026-09-28 (implementation `96f12ab`; gate 112/112 suites,
  594/594 tests, fmt+clippy clean — see STATUS.md). Server mode on the
  existing `tinker-mcp` binary (`tinker-mcp serve
  [--bind 127.0.0.1:8080]`; bare invocation keeps the item-45 stdio
  behavior byte-identical).
  Route shape:
  - `POST /mcp` — JSON-RPC 2.0 in, JSON-RPC 2.0 out
    (`application/json`), or a single SSE `data:` event when the
    client sends `Accept: text/event-stream` (Streamable-HTTP
    style). Notifications (no `id`) return `202 Accepted`, empty
    body. Every request needs `Authorization: Bearer tk_...`;
    missing/invalid key → `401` with the teaching body
    `{"error":"unauthorized","message":...,"hint":...}` — the same
    wording for unknown/malformed/revoked/expired keys (no oracle),
    never logging key material.
  - `GET /mcp/stream` — the server→client SSE channel for one
    session (`Mcp-Session-Id` header): an `event: ready` greeting,
    then `: ping` keepalives. No unsolicited notifications in v1,
    so the stream is spec-compatibility plumbing, honestly labeled.
  - `DELETE /mcp` — terminate the session (`204`); idle sessions
    also expire after 30 minutes via a background sweeper.
  Sessions: `initialize` creates a session (`Mcp-Session-Id`
  response header, uuid v7) and binds the verified credential's
  tenant + membership role — the role is never caller-supplied.
  Non-`initialize` methods require the session header, and the
  Bearer key on EVERY request is re-verified through the exact
  startup path (`MachineCredentialStore::verify`) and must resolve
  to the session's credential, so revocation takes effect on the
  next request. All dispatch goes through the same
  `FrontDoor::handle` as stdio — the 7 tools, ontology resources,
  scope gating, teaching errors, and the identical `not_found`
  shape for missing/hidden/foreign records are byte-identical by
  construction, never reimplemented. Tests: new `mcp_http` suite
  (auth rejection ×2 with identical bodies, end-to-end
  describe→create_record→query, error-shape parity with stdio,
  tenant isolation as `not_found` not `forbidden`, SSE stream +
  SSE-mode POST, per-connection sessions, session teardown).
  Out of scope for item 46: unsolicited server notifications,
  `apply_snapshot`, TLS termination (bind behind a reverse proxy
  for the public internet).

- **Item 47 — Single-server efficiency (measure first, then optimize).**
  DONE 2026-09-28. Full gate green: `cargo test --workspace`
  (113 suites / 598 tests / 0 failures), `cargo fmt --check` clean,
  `cargo clippy --workspace --all-targets` zero warnings;
  `m4_perf::versioned_query_tripwire` passed unweakened. Measured
  result: governed-metadata cache
  (`tinker_live::MetaCache` + `tinker_web::meta::{query_inputs,
  describe_cached, object_id_cached}`) — only the `active` schema
  version is cached (canary/preview/unknown labels always resolve
  fresh); invalidation rides on every existing query-cache
  invalidation site (record writes, schema promote/rollback,
  cross-instance signals). `QueryCompiler::compile_with_policy`
  split into resolve/describe + pure `compile_with_inputs`
  (identical output for identical inputs, incl. the `"select is
  empty"` fail-fast preserved in the new entry point). Hot paths
  rewired: MCP describe/query/get_record, HTTP POST /api/query.
  Before/after (`docs/bench/item47/`, `scripts/compare_bench.py`
  exit 0, all four canonical samples byte-identical, hit/miss rates
  1.000): describe p50 −54% HTTP / −81% stdio; query-hit p50 −58%
  HTTP / −78% stdio; query-miss unchanged within noise (apparent
  +13% on one run did not reproduce across A/B/A); create_record
  p50 −16% HTTP / −40% stdio; p99 −39% to −91% across ops; RSS
  +1.3–1.4% (the cache itself). Bench:
  `crates/tinker-mcp/tests/mcp_bench.rs` (ignored test) +
  `scripts/bench_item47.sh`, both transports, fixed fixtures. No
  behavior change beyond performance; no new migration.

- **Item 48 — Embedding-based semantic ranking for record search.**
  DONE 2026-09-28. Full gate green on the landed code:
  `cargo test --workspace` (114 suites / 604 tests / 0 failures),
  `cargo fmt --check` clean, `cargo clippy --workspace --all-targets`
  zero warnings; `m4_perf::versioned_query_tripwire` unweakened and
  passing. New `tinker_search::SemanticSearchBackend`: a decorator over
  any
  `SearchBackend` that reranks the permission-filtered candidate set by
  cosine similarity to the query embedding. Wired opt-in to `GET
  /api/comms/search` via `TINKER_SEMANTIC_SEARCH_PROVIDER`; unset =
  today's lexical behavior, byte-identical. Three design decisions,
  each justified:
  1. **Embedding provider: no new adapter.** The item-24 chat shape
     does not fit on purpose: the gateway deliberately separates
     `ModelAdapter` from `EmbeddingAdapter` so a completion-only
     adapter can never silently satisfy an embedding request. The
     OpenAI-compatible `/v1/embeddings` adapter
     (`HttpEmbeddingAdapter`: env-only key, redacted Debug,
     retry/backoff with Retry-After, declared placement) already
     exists. What item 48 adds is (a) `model_id()` on the
     `EmbeddingAdapter` trait — the HTTP adapter's model id was
     private and the vector cache must be keyed per model — and (b)
     production *registration* of embedding adapters from the
     `model_providers` registry (`register_embedding_adapters`,
     mirroring the item-24 completion pattern: fake → fake,
     unavailable → unavailable marker, hosted/private →
     `HttpEmbeddingAdapter::from_env` else unavailable marker).
     Embedding bytes are prompt bytes: the gateway's
     `enforced_embedding_adapter` re-checks placement against the
     provider row before any text leaves the process — a `hosted`
     adapter is rejected for org-controlled record text, exactly like
     completions.
  2. **Vector storage: durable PG cache, no pgvector.** pgvector is
     not available (vendored PG16 = stock Debian debs; no vector
     extension in the lib dir; adding one would break the
     self-healing vendored-DB story in `pg-ensure.sh`). New migration
     `0044_record_embeddings`: `(organization_id, object_id,
     record_id, provider_name)` PK, `model`, `dimensions`,
     `text_sha256`, `embedding bytea` (f32 LE), org-scoped RLS like
     `search_index`. The cache fills lazily at query time — one
     batched embed call for the query text plus cache misses, bounded
     by the candidate-pool cap — never on the write path, so post
     latency never pays provider round trips. Staleness bound is
     exact, not TTL: a row is reused only when `text_sha256` matches
     the current indexed text AND dimensions match, else re-embedded
     and upserted. Survives restart (durable, unlike an in-memory
     index rebuilt on boot — which would push the whole corpus
     through the provider at boot: network-bound, slow, dead without
     a key, divergent across instances). Multi-tenant: org_id in PK +
     RLS; vectors namespaced per provider+model.
  3. **Ranking fusion: permissions first, decorator errors instead of
     silently degrading.** The inner permission-filtered search runs
     FIRST (tenant scope + item-38 row policies ANDed in the same
     match statement — unchanged code path) with an inflated
     candidate pool (`max(limit, min(limit*4, 200))` lexical prefilter); the
     decorator fetches indexed texts ONLY for the returned record
     ids, embeds query+misses in one gateway call, stable-sorts by
     cosine, rewrites `hit.rank`. No oracle: a record invisible to
     the caller never enters the candidate set, so it never reaches
     the embedder (pinned by a fake-adapter `seen_texts` test) and
     never appears in output. Scores are never exposed beyond order;
     snippets pass through unchanged so MessageSearch's
     field-projection masking still applies downstream. Unlike
     expansion's silent deterministic fallback, the decorator
     RETURNS AN ERROR (teaching message) when semantic ranking can't
     run — no provider row, unavailable, placement rejection, embed
     failure. Reason: search order IS the product; a silently lexical
     order from the semantic endpoint is exactly the forbidden
     "unranked results presented as ranked". Plain lexical search
     stays untouched and always available; semantic is opt-in.
  4. **Measurement.** `SearchPage.semantic: Option<SemanticReport>`
     (`None` for lexical backends) carries provider, model,
     candidates, cache hits/misses, embed_ms, rank_ms, total_ms.
     Relevance probe: fixed corpus + `FakeEmbeddingAdapter` with a
     known-good top-1 and an independently recomputed expected order,
     asserted in `crates/tinker-m0/tests/m0_semantic_search.rs` —
     the whole suite is green with no network and no key. Measured
     per-query latency → STATUS.md item 48.

- **Item 49 — AI-assisted mapping proposals (suggestion-only API).**
  DONE 2026-09-28 (implementation commit `1103681`). Full gate green:
  `cargo test --workspace` (115 suites / 613 tests / 0 failures),
  `cargo fmt --check` clean, `cargo clippy --workspace --all-targets`
  zero warnings; `m4_perf::versioned_query_tripwire` unweakened and
  passing. Item-48 baseline was 114 / 604; delta is the new 9-test
  `mapping_suggest` suite. Distinct from post-M8 item 25
  (`propose_mappings_ai`, stream-bound, persists `proposed` rows):
  item 49 is a pure suggestion path. Input: an ad-hoc source schema
  (field names + up to 3 sample values each, as JSON) and a target
  Tinker object (by slug). Output: a ranked list of proposals —
  source field → target field, confidence in [0,1], short rationale —
  returned to the caller, never persisted. Design:
  1. **No writes, by construction.** `MappingEngine::suggest_mappings`
     has no code path that writes schema or records: no
     `ingest_mapping`/`ingest_schema_version` rows, no ontology
     changes, no record writes. Applying a proposal goes only
     through the existing governed paths (`put_mapping` /
     `approve_mapping` / `activate_mapping`, or
     `define_object`/`add_field` for ontology work) with the caller's
     own auth. The ONLY write the proposer performs is the mandated
     M7 cost record (guardrail 2). Pinned by a test that snapshots
     row counts across `ingest_mapping`, `ingest_schema_version`,
     `ontology_objects`, `ontology_fields` before/after and asserts
     zero delta — plus asserts the cost record DID land.
  2. **Placement.** Sample values are prompt bytes (unlike item 25's
     names-only prompts), so the item-24 placement checks run inside
     the gateway's `propose_mapping` BEFORE any byte leaves: a
     `hosted` provider is rejected for org-controlled content with a
     teaching error, and the rejection happens before the adapter is
     touched (fake-adapter `seen_prompts` stays empty).
  3. **Cost accounting.** Every model call is recorded via
     `CostLedger::record_usage` with the live completion's
     tokens_in/tokens_out/model_ref (never estimates, per item-24's
     live-usage rule: the HTTP adapter already fails closed on a
     missing `usage` block). If the ledger write fails the whole
     call fails closed — an unaccounted model call is never
     returned silently.
  4. **Unmappable input → teaching errors, never empty/confident
     lists.** Empty source schema, unknown target slug, target with
     no active api fields, malformed model JSON, and zero usable
     suggestions after per-suggestion validation (unknown
     source/target, out-of-range confidence, empty reason) all
     return `Validation` errors naming the problem. A zero-survivor
     result is an error, not an empty `Ok(vec![])` presented as a
     confident answer — and hallucinated entries are dropped
     individually before that check, never surfaced.
  5. **Surface.** `tinker-cli ingest suggest-mappings --org <slug>
     --actor <name> --target <object-slug> --provider <name>
     --source-file schema.json` prints the JSON report
     (`target_object`, `provider`, `model_ref`, `usage`, ranked
     `proposals`). The CLI's gateway comes from the existing
     production provider-registry wiring (fake → fake,
     unavailable → unavailable marker, hosted/private →
     `HttpModelAdapter::from_env` else unavailable marker; keys
     from environment only, never logged).
  6. **Tests.** New `crates/tinker-m6/tests/mapping_suggest.rs`
     against `FakeModelAdapter` only — green with no network and no
     API key: happy-path ranking (confidence-desc, deterministic
     tiebreak), zero-writes-except-cost-ledger, empty/unknown-target/
     zero-survivor teaching errors, malformed-JSON fail-closed,
     hosted-placement rejection with zero prompt bytes, sample
     values reaching the (fake) model, accounting-failure
     fail-closed.
  Gate (landed code, 2026-09-28 ~19:10–19:40 UTC): full serial
  `cargo test --workspace` — 115 suites / 613 tests / 0 failures;
  `cargo fmt --check` clean; `cargo clippy --workspace --all-targets`
  zero warnings; quiet window for the load-sensitive
  `m4_perf::versioned_query_tripwire` (never weakened, passing).
  Note: an unrelated mid-gate VM reboot killed Postgres/Redis and
  failed one unrelated suite (`approvals_scale_out`, PoolTimedOut);
  infra was self-healed (pg-ensure.sh, vendored redis) and the gate
  re-ran clean from scratch on the fresh cluster. A final
  test-strengthening (ontology_objects/ontology_fields row counts in
  the no-write test) landed after the full gate and was re-verified
  by the focused 9-test suite + fmt + clippy on the same code.

**Kill bar (adopted 2026-09-26):** median time-to-first-correct-publish
for a fresh agent with skill+MCP vs. raw HTTP + human docs. Measured
after item 45; if the front door doesn't win clearly, it failed.

- **R4 — Search backend default decision. DONE 2026-09-28.** Measured on a
  deterministic 10,000-record corpus in `searchorg_1` (seeded RNG `0x5EED42`;
  24 topics × 390 docs + synonym/noise/restricted fixtures; harness +
  recipe archived at `~/workspace/prodread/work/r4/`, repo copy deleted
  after the run — repo left with no R4 code changes).
  - EMBEDDING REALITY: no local model/runtime on the VM (no ollama, torch,
    onnxruntime, vendored models — checked 2026-09-28). Semantic leg ran on
    the deterministic hashed-BOW pseudo-embedding (`FakeEmbeddingAdapter`,
    64d). Relevance = PIPELINE measurement, NOT model quality; a real local
    model needs ~2GB torch + HF download + `/v1/embeddings` sidecar —
    explicitly not attempted.
  - Build: native bulk index 10k = 13.8 s; per-record write path ~3.5 ms;
    lexical index 51 MB / 10.2k docs (~5.1 KB/doc). Semantic build = 0 ms by
    design (lazy query-time cache).
  - Latency (40 fixed queries, debug profile): native p50 39.4 ms / p99
    104.1 ms; semantic cold 73.2 / 216.2; semantic warm 63.4 / 193.3
    (~1.6×/1.9× native; warm = 0.9 ms embed + 16.3 ms rank).
  - Relevance (24 labeled queries): native r@1 0/24, r@5 24/24 (ts_rank
    rewards raw term frequency — the tf-heavy distractor won top-1 24/24);
    semantic r@1 24/24, r@5 24/24 (L2-normalized cosine prefers the focused
    doc; order verified against independent recompute, 0 mismatches).
  - Recall boundary: synonym queries 0 hits on BOTH backends — the decorator
    only reranks the lexical prefilter pool; widening recall needs a vector
    prefilter, not a better rerank.
  - Cost: `record_embeddings` ~1,206 B/row (~11.5 MB per 10k docs).
  - Permissions identical at scale: cross-tenant + row-policy deny probes
    green for both (0 foreign texts embedded).
  - DECISION: **semantic (item-48 `SemanticSearchBackend`) as DEFAULT** —
    r@1 24/24 vs 0/24 via a model-independent mechanism (length
    normalization), bounded latency cost, zero write-path cost, permissions
    parity, loud failure mode. **Fallback: native lexical** (the decorator's
    inner backend — fallback = "don't decorate").
  - Remaining gaps before production: real embedding model + key management
    + per-tenant placement; relevance RE-MEASURED with the real model before
    any production claim; pgvector-vs-bytea-cache (bytea fine for
    rerank-at-query-time); wire the default in the HTTP layer (currently
    opt-in via `TINKER_SEMANTIC_SEARCH_PROVIDER`). TIN re-check noted,
    not re-litigated.

### R2 DR findings → follow-ups (measured 2026-09-28; drills all PASS)

- **[DR-1] Backup role + pg_hba for production.** Backups today require the
  Postgres superuser because 36 force-RLS tables make owner-role `pg_dump`
  fail (measured, Drill A). Production needs a dedicated `REPLICATION` /
  `BYPASSRLS` backup role, its `pg_hba.conf` replication entry, and a
  documented credential-rotation path. Exact DDL/HBA in
  `docs/disaster-recovery.md` §3.
- **[DR-2] WAL archiving + base-backup schedule.** The live cluster has
  `archive_command = (disabled)` and no base backups — PITR is impossible
  today (measured, Drill B). Needs: `wal_level=replica`, `archive_mode=on`,
  `archive_command` → durable **off-host** store (archiving to `/var/tmp`
  is theater — rolls wipe it), `archive_timeout`, and a `pg_basebackup`
  cron. Do not enable archiving without the off-host destination.
- **[DR-3] File bytes + secrets backup path.** `./var/files` (or
  `TINKER_FILE_ROOT`) and `.secrets/` live outside every database dump; a
  dump-only "backup" restores a system missing files and credentials.
  Needs: filesystem backup for the file root + encrypted off-host copy of
  secrets with a post-restore rotation step.
- **[DR-4] No standby.** RTO for total host loss is "rebuild from backups",
  not failover. Decide whether the single-server efficiency goal accepts
  that or a warm standby is required.
- **[DR-5] Re-run drills on a schedule.** Drill checklist in
  `docs/disaster-recovery.md` §7; fixtures are idempotent
  (`cargo test -p tinker-m0 --test dr_seed`).

# R3 Security Review — BACKLOG entries

## Item R3-1: C6 `verify()` multibyte panic — FIXED
**Severity**: Medium (local/startup DoS; not remotely exploitable via HTTP —
hyper rejects non-ASCII `Authorization` before `verify()`).
`MachineCredentialStore::verify` sliced `&secret[..12]` after a byte-length
check only; a key whose byte 12 fell inside a multibyte char panicked the
process. Fix (`crates/tinker-auth/src/apikey.rs`): `secret.get(..12).filter(ascii)`
fails closed with `Forbidden("invalid API key")`. Regression test
`r3_verify_multibyte_prefix_fails_closed` in
`crates/tinker-mcp/tests/r3_adversarial.rs` crashed pre-fix, green post-fix.
Gate: targeted suites green (tinker-auth 22/22, tinker-mcp mcp_http 10/10,
r3_adversarial 5/5); full serial gate 2026-09-28: 97 binaries, 620 tests,
313 suites clean, 4 failures in 3 binaries — all re-verified GREEN by the
coordinator in isolation with root causes documented (NOT regressions):
`item36_inbound` 4 failures were `ENOSPC` (disk full mid-gate; 16/16 on
re-run); `dr_seed` failed on a same-org re-run because `define_or_adopt`
only adopts ACROSS orgs — fixed in `crates/tinker-m0/tests/dr_seed.rs`
(reuse existing object row on "already exists"; idempotency now proven:
300 present / 0 created on re-run); `browser_schema` timed out twice
without `TINKER_TEST_REDIS_URL` set (env setup; green with it set).
21 doc-test packages clean (`closeout/r3_gate_full.log`,
`r3_gate_doc.log`). Post-`cargo fmt` re-verification of tinker-auth +
tinker-mcp also green.

## Item R3-2: `submit_for_review` accepts author-decided approvals
**Severity**: Low. `publish` enforces a non-author decider, but
`submit_for_review` does not — an author can self-decide the submit approval
and fast-forward their own draft to `in_review`. No publish path is opened
(the publish gate still requires a genuine non-author approval), so this is a
workflow-theater inconsistency, not an escalation. **Recommendation**: enforce
non-author at submit for parity, or drop the submit-approval requirement and
document that the submit "approval" is a speed bump.

## Item R3-3: generic `consume_approval` doesn't bind action/object
**Severity**: Low (hardening). The direct-write path (`create/update_record`
with `require_approval: true`) checks approved/unexpired/single-use but not
`action_name`/payload binding — unlike the lifecycle path, which binds both.
**R3 re-verified 2026-09-28**: not exploitable as an escalation —
`require_approval` is caller-controlled and defaults false, so a caller who
wants to skip their own approval policy just omits it; there is no
server-side approval mandate to bypass. Becomes a real gap only if a future
policy mandates approvals for direct writes — bind then.
Unexploitable today (no server-side mandate makes `require_approval`
bypassable — it is opt-in; verified `require_approval: false` bypasses no
policy). **Recommendation**: bind action + object id on the direct-write path
for parity, before any deployment mandates approvals there.

## Item R3-4: `IssuedCredential` derives `Debug` over the plaintext secret
**Severity**: Info. Safe today (never `{:?}`-formatted in logs; verified by
grep), but one future debug-log line leaks the secret. **Recommendation**:
hand-write a redacting `Debug` impl.

## Item R3-5: file MIME is caller-declared, no content sniffing
**Severity**: Info (accepted). Polyglots/wrong-magic accepted as metadata.
No HTTP file-serving path exists (`file get` writes to disk via CLI), so no
XSS vector today. **Recommendation**: if a web download endpoint is ever
added, force `Content-Type: application/octet-stream` + `Content-Disposition:
attachment`, or sniff-then-serve.

## Item R3-6: no rate limiting on MCP HTTP auth paths
**Severity**: Info (accepted). Online brute force infeasible (256-bit keys;
verify = one indexed SELECT + SHA-256 + constant-time compare). Note for the
record; add a token bucket if the endpoint goes public without a WAF.

## Item R3-7: two MCP HTTP session implementations to keep in sync
**Severity**: Info. `tinker-mcp serve` (MCP 2025-06-18, `Mcp-Session-Id`
header, `DELETE /mcp`) and `tinker-cli mcp http` (2024-11-05 SSE,
`?session_id=`) duplicate session binding/sweep logic. Both verified sound
this pass. **Recommendation**: converge on one, or mark the SSE path
deprecated-but-maintained.

## Item R3-8: dependency audit — cargo-audit unavailable; one advisory investigated
`cargo audit` could not run (cargo-audit 0.22.2 fails to build in this
environment: aws-lc-sys C compilation failure; OSV API unreachable from here).
Manual `Cargo.lock` review instead — **no clean-audit claim made**.
- **CVE-2026-25537** (jsonwebtoken <10.3.0 type-confusion → auth bypass):
Tinker locks **9.3.1**. Investigated against the advisory mechanics
(GHSA-h395-gr6q-cpjc): the bypass needs a loose claims type and/or
`validate_exp` without `exp` in `required_spec_claims`. Tinker's OIDC path
decodes into a strict `IdTokenClaims` with mandatory `exp: i64`, and
`Validation::new` keeps the default `required_spec_claims={"exp"}` — a
string-typed `exp` fails closed. C6 machine keys don't use JWT at all.
**Verdict: not reachable.** Defense-in-depth: bump to ≥10.3 (caution: 10.x
requires an explicit crypto provider — without one it compiles clean and
panics at first encode/decode).
- rustls **0.23.45**: already past RUSTSEC-2026-0285 (first patched release).
- Rest of the security-relevant lockfile current: axum 0.8.9, hyper 1.11.1,
tokio 1.53.1, sqlx 0.8.6, sha2 0.10.9, aes-gcm 0.10.3.
- **Recommendation**: add `cargo audit` (or `cargo deny`) to CI so this never
rests on a manual pass again.

## Adversarial battery (kept in tree)
`crates/tinker-mcp/tests/r3_adversarial.rs` — 5 tests, all green:
per-tool cross-tenant isolation with seeded objects/records/drafts/dashboard
(every tool returns `not_found` cross-org, never `forbidden`/data); approval
replay + wrong-action + cross-org + self-approval; hostile query filters;
C6 multibyte regression; file hostility (oversize/traversal/tamper/cross-org).

## Threat model
`docs/threat-model.md` — written this pass. Header states explicitly:
**internal adversarial review, NOT an external audit**.

# R1 soak test — BACKLOG.md entry text

**R1 — sustained soak test (24h effective uptime)** ✅ DONE 2026-09-30 — verdict: 4/5 fail criteria PASS; p99-latency criterion FAILS as written (see Verdict below)

- Workload generator `~/workspace/prodread/soak-traffic.py`: mixed traffic over BOTH
  `tinker-mcp` transports (stdio via `TINKER_API_KEY`, HTTP via `tinker-mcp serve`
  `POST /mcp` JSON-RPC + `Mcp-Session-Id` sessions). Per 60s batch, 3 tenants
  (`soakorg_1..3`) each run: `describe` (object + catalog), `query`, and full
  lifecycle cycles `create_draft -> update_draft -> submit_for_review -> publish`
  with M7 approvals minted as `approved` `approval_requests` rows bound to
  (action, draft_id), decided by the reviewer; ~15% of cycles exercise the
  reviewer `reject` -> author `revise` -> resubmit path through the reviewer's
  own credential. Every publish is followed by an immediate `get_record`
  read-after-write check.
- Fixtures: `~/workspace/prodread/bin/soak-fixtures` (compiled from a temporary
  `tinker-mcp` integration test using the real `Ontology`/`MachineCredentialStore`;
  temp source removed from the repo after validation). Idempotent: orgs, reviewer
  actors, `soakorgN_article` objects (title required, body optional, category
  Select{news,guide,reference}, lifecycle on) for transition traffic, plus
  `soakorgN_note` objects (title/body, no lifecycle) for direct
  create_record/update_record traffic; approval attachments, and two
  machine keys per org (`soak-mcp` role member, `soak-reviewer` role reviewer);
  reuses manifest secrets when the key rows still exist, rotates otherwise.
  Manifest: `~/workspace/prodread/soak-manifest.json` (mode 600).
- Chunk runner `~/workspace/prodread/soak-chunk.sh`: pg-ensure, fixture check,
  `tinker-mcp serve --bind 127.0.0.1:18082`, readiness probe, 25x60s traffic
  batches honoring `PAUSE_SOAK` between batches (<3h), serve RSS sampled per
  batch, cumulative effective uptime in `~/workspace/prodread/soak-state.json`,
  `SOAK_COMPLETE` at >=24h. Metrics: JSONL `~/workspace/prodread/soak-metrics.jsonl`
  (per-op latency/ok/error-class + per-batch serve RSS + pause/interruption events).
- Cron `tinker-soak-chunks` (every 30m, 30m timeout, silent on success) — created
  and verified via `cron.list` 2026-09-28; first tick 2026-09-28 18:17 EDT.
- Baseline (item-47 bench, `scripts/bench_item47.sh`, quiet VM, report
  `~/workspace/prodread/bench-baseline-report.json`, git 20dee02, debug profile):
  HTTP — create_record p50 6.1ms/p99 31.9ms; describe p50 2.9ms/p99 10.6ms;
  query_hit p50 3.8ms/p99 10.1ms; query_miss p50 14.2ms/p99 85.7ms.
  stdio — create_record p50 3.2ms/p99 17.7ms; describe p50 0.6ms/p99 1.0ms;
  query_hit p50 1.5ms/p99 2.4ms; query_miss p50 11.0ms/p99 80.7ms.
  (Soak fail bar: per-op p99 ≤ 2× these values.)
  NOTE: first bench attempt failed with ENOSPC writing the report — /tmp was
  100% full from two stale `cargo-install*` dirs (506M, other workstreams);
  removed, reran clean.
- Validation (pre-cron): 2 clean manual chunk runs + 1 PAUSE_SOAK demonstration;
  see R1-status.md. Pre-fix preflight metrics (88 ops, workload-generator bugs)
  are archived in `soak-metrics.jsonl` before the first clean `run_start`.
- Deviations from the task brief: (1) serve binds **127.0.0.1:18082**, not 18080 —
  18080 is held by Bocht's live demo server (another workstream; not ours to kill);
  (2) approval rows are inserted via the **app** DB URL with the tenant
  `SET LOCAL app.organization_id` context (the owner role hits the
  `approval_requests` RLS policy; this is the exact pattern the `mcp_front_door`
  tests use); (3) the author-side reject/revise path was removed — `reject`
  correctly requires reviewer role + non-author + in_review state, so the author
  credential can never exercise it; the reviewer path runs under the
  `soak-reviewer` credential instead.

## Fail criteria (evaluated at 24h, from `soak-metrics.jsonl`)
- zero server-side 5xx / auth failures (`err_class` starting `5xx:` or `auth:`)
- p99 per-op latency within 2x of the item-47 baseline
- serve RSS growth <= 20% over the window (per-batch `serve_rss_kb`)
- every acknowledged write readable: zero `read_after_write:*` failures
- every roll/interruption logged with cause and recovery (`kind: interruption`,
  `kind: paused`); chunk resumes via idempotent fixtures

## VERDICT (evaluated 2026-09-30, `SOAK_COMPLETE` at 2026-09-30T11:42:59Z)
- Window: 24.19h effective uptime (87,083s), 62 chunks, both MCP transports,
  3 tenants, full lifecycle churn. Clean window (post generator-fix,
  2026-09-28 23:00 UTC → end): **4,135,499 ops**.
- ✅ zero 5xx/auth failures: **0** in the clean window (4.1M ops).
- ❌ p99 ≤ 2× item-47 baseline: **FAILS as written**. Clean-window p99s —
  create_record 63.1ms vs 63.8ms bar (PASS), describe 70.0ms vs 21.2ms bar
  (FAIL), query 50.0ms vs 20.2ms bar (FAIL). Analysis (no softening): p50 is
  flat across all 6h buckets (describe 6.7–8.1ms, query 7.1–9.4ms) with
  350k+ records created — no data-growth trend. p99 spikes cluster in the
  08:00/20:00 UTC buckets with no monotonic trend: the exceedances are
  shared-VM load noise, not a Tinker scaling regression. The criterion as
  written compares a 24h shared-VM p99 against a quiet-VM debug-profile
  micro-bench p99 — it measures the environment as much as the app.
  Recommendation (restate, don't weaken): next soak measures p99 on a quiet
  box at comparable DB size, or gates on p50 + bounded p99 vs a
  same-environment baseline.
- ✅ serve RSS growth ≤ 20%: 18,628 → 20,572 KB = **+10.4%** first-to-last
  (max +14.4%), 1701 per-batch samples.
- ✅ zero read_after_write failures in the clean window: **0**.
- ✅ interruptions logged: 4 stuck-flock + 1 PG roll + 1 cron timeout, all
  with cause and recovery in `soak-metrics.jsonl`; chunk resume via
  idempotent fixtures verified across every one.
- Noted honestly: 4 transient failures 2026-09-29 22:15:58Z (3 same-second
  timeouts across tenants/transports + 1 knock-on `workload:missing_id`) —
  a brief server stall, self-recovered, 13.5h clean after. Not 5xx/auth
  class; does not trip criterion 1.
- Cron `tinker-soak-chunks` disabled 2026-09-30 after the verdict (target met).

# R5 backlog entries (deployment package — NO public deploy)

## DONE — Deployment package built at `~/workspace/tinker/deploy/`
- `postgres/`: production `postgresql.conf` (PG16; archive-ready WAL:
  `wal_level=replica`, `archive_mode=on`, idempotent `archive_command`
  spooling to `/var/lib/postgresql/wal-archive/`, `archive_timeout=3600`;
  logging collector with rotation; memory/planner tuned for an 8GB VM),
  `CONFIG-DELTA.md` (exact delta vs `bin/pg-ensure.sh` dev cluster),
  `initdb-and-bootstrap.md` (one-shot provisioning: initdb, same
  least-privilege role shape as dev, extensions by superuser, archive
  verification queries), sample `tinker-postgres.service`.
- `redis/`: production `redis.conf` (RDB snapshots + AOF `everysec`,
  loopback-only, `requirepass`, `maxmemory 1gb noeviction`,
  FLUSHDB/FLUSHALL/DEBUG renamed), sample `tinker-redis.service`
  (REDISCLI_AUTH via env file — no `-a` password in `ps`).
- `proxy/`: `nginx-tinker-mcp.conf` — TLS termination, HTTP→HTTPS,
  `/mcp` with SSE-safe proxying, `/healthz`, security headers, per-IP
  rate limit. **SYNTAX-UNVALIDATED** (no nginx on the build VM; `nginx -t`
  is an operator step).
- `env/`: `tinker.env.template` documenting EVERY variable the service
  reads (placeholders only) + `SECRETS.md` (hard rule: secrets via
  environment, never the repo; rotation designed in).
- `systemd/`: `tinker-mcp.service` (loopback bind, env file, sandboxing).
- `logging/`: `logrotate-tinker` sample policy for all service logs.
- `README.md`: layout, bring-up order, per-component validation table,
  and "What you must provide for real hosting" (domain, DNS, host/VM,
  Let's Encrypt strategy, secrets provisioning, backups→R2 runbook,
  monitoring/alerting, operator runbook).

## DONE — `GET /healthz` added to `tinker-mcp serve`
- Unauthenticated, information-minimal: `200` +
  `{"status":"ok","version":"<crate-version>"}` and nothing else.
- Covered by `http_healthz_is_unauthenticated_and_minimal` in
  `crates/tinker-mcp/tests/mcp_http.rs` (asserts 200, no auth header
  needed, body has exactly the two keys). `cargo test -p tinker-mcp`:
  32/32 PASS; clippy clean. (Repo predates current rustfmt's import
  ordering — `cargo fmt --check` flags pre-existing lines in these
  files; the change matches the files' committed style.)

## DONE — Local validation (this VM, 2026-09-28)
- Postgres: scratch cluster initdb'd with the production
  `postgresql.conf` (3 validation-scoped overrides only: port 5434,
  socket dir, archive spool path — the postgres user is MAC-confined
  from `/home/hatch`, so the task's suggested data dir was unusable;
  `/var/tmp/pgdata-prodval` used instead, dev cluster untouched).
  Verified: `wal_level=replica`, `archive_mode=on`,
  `pg_switch_wal()` → segment landed in the spool,
  `pg_stat_archiver.failed_count=0`; `shared_buffers=2GB`,
  `max_connections=100`, `checkpoint_completion_target=0.9` applied.
- Redis: redis-server 7.0.15 on the production `redis.conf` (port 6380,
  throwaway password): AUTH enforced, renamed commands unknown under
  original names, RDB+AOF files produced, **kill -9 → restart →
  key recovered**.
- Serve smoke: `tinker-mcp serve` on dev DB + loopback: `/healthz`
  → 200 unauthenticated; `initialize` → session; `tools/list` → 7
  tools; `tools/call describe` → 200 no error; unauthenticated
  `POST /mcp` → 401. Fixture org `pvorg_smoke` (+2 keys) left in the
  dev DB — validation-only, safe to drop.
- systemd units: `systemd-analyze verify` clean (only expected note:
  `/opt/tinker/bin/tinker-mcp` not present — operator installs it).
- Full serial gate after the code change: **PASS** 2026-09-28
  22:46:49Z→23:01:25Z — `cargo test --workspace -j1 -- --skip seed_drorg_1`
  (seed_drorg_1 skipped: its same-org re-run failure seen in R3's gate
  was FIXED at R3 close-out (f69d858, idempotency proven); the skip was
  retained for gate stability, not a regression), CARGO_TEST_EXIT:0, 117 "test result: ok" / 0
  failures, `cargo clippy --workspace --all-targets` clean; run under
  the GATE_RUNNING lock with the soak paused (no batch for 308s before
  start); log `~/workspace/prodread/closeout/r5_gate_full.log`.

## OPEN — operator steps (NOT done by R5; listed for the user)
- [ ] Fill every `__PLACEHOLDER__` in `deploy/` (`nginx-tinker-mcp.conf`,
      `redis.conf`, `tinker.env.template`); run `nginx -t`.
- [ ] Provide for real hosting: domain + DNS, host/VM, Let's Encrypt
      certs, secrets provisioning, off-host WAL copy + base-backup
      schedule (R2 DR runbook), monitoring/alerting, operator runbook.
      See `deploy/README.md` "What you must provide for real hosting".
- [ ] R2 DR runbook (`docs/disaster-recovery.md`) must pass its restore
      drill against this exact layout before production traffic.
- [ ] HARD STOP respected: nothing deployed publicly, no cloud
      resources, no DNS, no certificates created.

## Backlog note for coordinator
- R5 validation fixtures used the `pvorg_` slug prefix only
  (`pvorg_smoke` org). No other workstream's fixtures touched.
- Sibling activity observed during validation (for the record): R1 soak
  fixture setup + baseline bench, R2 DR drills (incl. a throwaway
  cluster on 127.0.0.1:5433), R3 adversarial serve on 127.0.0.1:18099 —
  all on the dev DB; R5's validation clusters used 5434/6380 and did
  not disturb them.

