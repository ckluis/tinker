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
- **Crypto-shred erasure.** Vault DEKs are per subject (the record), not per organization. Erasing a record destroys its subjects' DEKs, so every ciphertext under them, in any copy or backup of `pii_values`, becomes unreadable.
