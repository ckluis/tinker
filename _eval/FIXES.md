# Tinker — fixes log (round 1, 2026-09-30)

Environment: macOS arm64, Rust 1.98.1, **PostgreSQL 18.6** (upgraded from the project's 16), Redis 8. Run everything with `bin/test-mac.sh`.

**Baseline (code as received, on PG18):** 619 passed / 1 failed / 1 ignored. The one failure is `browser_verifies_schema_builder`, an environment issue (Linux-only Chrome path + Redis on :6379), not a product bug.

Every fix ships with a regression test. "Proven" means the test was run with the fix removed and **failed**, then passed with it.

| # | Finding (EVALUATION.md id) | Fix | Test | Proven |
|---|---|---|---|---|
| 1 | Template `{%}` panics the request (S-5) | Search for the closer only after the 2-byte opener (`close_after_opener`); also covers `{{}` and `consume_tag` | `templates::engine_tests::closer_overlapping_opener_is_unclosed_not_a_panic` | ✔ panics without fix |
| 2 | Ontology RLS: visible ⇒ writable. Platform rows **and an adopted object's base fields owned by another org** were UPDATE/DELETE-able by a tenant (S-4, worse than reported) | Migration `0045_ontology_write_policies.sql`: SELECT keeps old visibility; writes are restricted to the caller's own org rows | `m0_adopt::visible_shared_and_platform_rows_are_not_writable_by_tenants` | ✔ cross-org UPDATE landed without 0045 |
| 3 | Stale approvals survive reject → edit → resubmit and publish unreviewed content (S-3) | `supersede_draft_approvals`: rejecting a draft or editing its content expires every pending/approved approval bound to that draft | `m0_record_lifecycle::stale_publish_approval_does_not_survive_reject_and_edit`, `draft_edit_retires_pending_and_approved_approvals` | ✔ both fail without fix |
| 4 | `TINKER_CORE_URL` means owner in `tinker` and app role in `tinker-mcp`; a swap silently disables RLS (arch #1) | `CoreDb::connect` refuses any role RLS doesn't bind (superuser / BYPASSRLS / owns RLS tables). `tinker` accepts the canonical names (`TINKER_CORE_OWNER_URL` + `TINKER_CORE_URL`), and the legacy layout still works | `tinker-db/tests/rls_bound_role.rs` | ✔ **guard immediately caught two existing tests** (`m7_agents::cli_reads_share_the_semantic_pipeline`, `m7_mcp_stdio::spawned_binary_serves_full_mcp_session`) that ran `tinker-cli`'s tenant pool as the owner, so those tests never exercised RLS. Fixed. |
| 5 | File `pii_class` downgrade on re-upload; also the reverse: dedup silently **dropped** a stricter re-declaration (S-8) | Both paths keep the stricter class | `m7_files::pii_class_never_downgrades_for_identical_bytes` | |
| 6 | Passkey start: unauthenticated membership oracle (500 vs 200) + unbounded challenge inserts (S-7) | Unknown/unenrolled (org, actor) gets a decoy of the same shape and nothing is written; live challenges capped at 5 per actor | `m1_hardening::passkey_start_is_uniform_and_bounded` | |
| 7 | Web sessions outlive membership removal for up to 12h (S-6) | `load_session` treats a session as dead once its membership is gone | `m1_hardening::session_dies_with_membership` | |
| 8 | MCP session role frozen at `initialize` (S-6) | Role re-read per request; any change ends the session (re-initialize picks up the new role) | `mcp_http::http_session_ends_when_membership_changes` | |
| 9 | `Secure` cookie flag opt-in, default off (S-6) | On by default; `TINKER_COOKIE_SECURE=0` to opt out for plain-HTTP dev | n/a (config default) | |
| 10 | Flaky tests: pack/ingest/m1 tags used the **timestamp head** of a v7 UUID, so tests started in the same ms collided (seen on this Mac) | Use the random tail | the affected suites themselves | ✔ reproduced in a full run |

## Postgres 18 upgrade
- All 45 core + 4 PII migrations apply and checksum-verify on 18.6; full suite green.
- `deploy/postgres/postgresql.conf` validated by starting a scratch 18.6 cluster on it (all 47 settings accepted).
- Deploy docs and systemd unit moved to `/usr/lib/postgresql/18`; `initdb-and-bootstrap.md §7` documents a 16→18 `pg_upgrade` (checksum gotcha: PG18 initdb enables data checksums by default; a 16 cluster without them needs `--no-data-checksums`).
- Unlocks backlog items that were blocked on PG16: pgvector (Homebrew ships it for 17/18) and the `planetscale/lead` TIN extension (PG17/18 only).

## Not done: needs a decision
- **PII vault wiring (S-1).** Vault primitives are sound and tested, but no field type seals into them. See the decision list in the session summary.
- **Self-approval of generic approvals.** `approval_requests` has no requester column; `publish` already enforces a second person.
- **OIDC bare `id_token` login / non-WebAuthn passkeys labelled MFA.** Needs a login-flow redesign.
- **Browser test on macOS.** Chrome path is now configurable (`TINKER_TEST_CHROME`); the CDP driver still times out on `Page.enable` with Chrome for Testing.
