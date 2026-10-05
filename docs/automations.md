# Automations over sealed fields

Status: ACCEPTED 2026-10-01. The operator decided: show a key instead of the value, and build the key layer, the engine and the samen-parity items.

## Idea
Sensitive fields (`docs/pii-sensitive-fields.md`; every email and phone field) never leave the vault in plaintext. Automations still need to act on them: route, dedupe, react to changes, contact the person. They do that through **keys**, not values:

- **Conditions compare keys.** A literal in a condition is hashed with the field's blind index **when the automation is saved**, and only the digest is stored. The definition never holds plaintext.
- **Actions resolve values at execution.** "Send an email to `email`" puts a vault *reference* in the delivery outbox. The worker resolves it in-process at send time (audited), and it is never written back.
- **What people see is a key.** Run logs, webhook payloads and `query` selects of `field:key` show an **automation key** (`pk_…`). It is derived from the blind index with a separate HMAC domain, so it is stable for a value and useless for querying the index.

## Decisions
| # | Decision | Choice |
|---|---|---|
| A1 | Key shown to people and integrations | `pk_` + 40 hex of HMAC-SHA256(blind-index key, "tinker-automation-key-v1" ‖ bidx). Stable per (org, field, normalized value) |
| A2 | Key scope | Per field (as the blind index). Cross-object keys ("same person as a lead") are not offered: they widen linkage across objects |
| A3 | Conditions on sensitive fields | `eq`, `ne`, `in` (on keys), `is_set`, `is_empty`, `changed`. Anything that needs plaintext (`contains`, ranges) is refused when the automation is saved |
| A4 | Conditions on other fields | `eq ne in gt gte lt lte contains is_set is_empty changed`, evaluated on the record as read through the governed compiler |
| A5 | Who an automation runs as | The saving actor and their role at save time. Membership is re-checked on every run (removed or changed role: the run fails closed). Reads use that role's projection and row policy, so an automation never sees more than its author |
| A6 | Triggers | `record.created`, `record.updated` (optionally only when given fields changed), `record.published` (lifecycle). Events come from a **transactional outbox** written in the same transaction as the mutation, so no event is lost and none is invented |
| A7 | Actions | `update_record` (literal values; sensitive targets refused), `send_email` (to a sensitive email field; subject and body rendered with non-sensitive fields, sensitive placeholders shown masked), `webhook` (HTTPS or an allow-listed host; payload holds ids, non-sensitive fields and keys) |
| A8 | Loops | Actions run with purpose `automation:<id>:<depth>`; the events they cause carry the depth; depth ≥ 3 records `loop_blocked` |
| A9 | Guessing | An equality literal is a yes/no question about a value. Saves are audited with counts (never literals), and each actor may save at most 20 sensitive literals per hour. Automations run only from saved definitions, never interactively |
| A10 | Who may manage automations | `owner`/`admin`, MCP scope `mcp:tool:automation` (explicit only, like `reveal` and `erase`), because automations can send email and call out |

## Samen parity (same branch)
- **Reveal needs a second person.** `reveal` requires an approved, unexpired, single-use `pii.reveal` approval for exactly that (object, record, field), decided by someone other than the requester. That reuses four-eyes approvals.
- **Crypto-shred erasure.** Vault DEKs are per subject (the record), not per organization. Erasing a record destroys its subjects' DEKs, so every ciphertext under them, in any copy of `pii_values`, becomes unreadable. Backups that also contain `wrapped_deks` must age out first; see `docs/pii-sensitive-fields.md`.

## Built (branch `automations`)
| Piece | Where | Proof |
|---|---|---|
| Automation keys; `field:key` selects | `tinker-core/src/blind_index.rs`, `tinker-query` (`finish_key_columns`) | `tinker-automate/tests/automations.rs` |
| Outbox events from create, update (with changed fields), publish and ingest promotion | `tinker-ontology/src/mutate.rs` (`record_automation_event`), migration 0050 | same |
| Engine: keyed conditions, `update_record`, `send_email` (vault-resolved recipient), `webhook` (allow-list), depth-3 loop guard, 20/h guessing guard, author's role re-checked per run | `crates/tinker-automate` | 5 tests: sealed conditions route and resolve only at send; saves refuse plaintext paths and non-managers; guessing rate limit; depth limit; author losing the role fails closed |
| MCP `automation` tool (save/list/enable/disable/runs); background worker in web and MCP servers (`TINKER_AUTOMATIONS=off` disables) | `tinker-mcp`, `tinker-web` (`spawn_automation_worker`) | `mcp_front_door` (12 tools) |
| Reveal with second-person approval: `request_reveal`, `approvals` (list/approve/deny), `reveal` consumes the approval atomically | `tinker-mcp`, `tinker-agents` (unattached approvals, migration 0051) | `pii_sensitive::reveal_needs_a_fresh_second_person_approval_for_that_field` |
| Per-subject DEKs and crypto-shred | `tinker-vault`, pii migration 0005, `PiiSealer::erase_record` | `pii_sensitive::erasure_crypto_shreds_copies_of_the_ciphertext`, `kek_rotation`, `m0_pii` |

## Known limits
- **Email in the servers.** The worker queues `send_email` deliveries but the servers configure no real email provider, so they stay queued. Tests use `FakeEmailProvider`.
- **Actions are not one transaction.** A run that fails after an earlier action succeeded (for example, a webhook after an update) records `failed`; the earlier action stands, and the run is not retried, so the event is not replayed.
- **Legacy values.** Values sealed under the organization DEK before per-subject keys are destroyed one by one, not shredded.
