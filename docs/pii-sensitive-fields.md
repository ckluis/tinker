# Sensitive fields: PII sealed in the vault

Status: ACCEPTED 2026-09-30. Decisions D1–D3 were made by the operator; the rest are design choices recorded here.

## Problem
`tinker-vault` (AES-256-GCM, per-org DEK wrapped by a KEK, two-phase `pii_refs`, audited `PiiProjector::resolve`) was built and tested, but no field ever used it. A field holding an email or a name was stored as plaintext in `data.<slug>`, and from there it was copied into drafts, version history and mutation audit rows. The overview's claim that "PII fields are sealed into the vault" did not hold for the running system.

## Decisions
| # | Decision | Choice |
|---|---|---|
| D1 | How a field becomes vault-backed | `sensitive: true` on a `text`, `email` or `phone` field. Set when the field is defined, and immutable afterwards |
| D2 | What normal reads return | A fixed mask (`"••••••"`) for a present value, `null` for an absent one. Plaintext comes only from the `reveal` tool, which requires a purpose, is role-gated and is audited per value |
| D3 | Lookups | Exact match only, through a keyed blind index. No sorting, ranges, `contains` or `starts_with` on sensitive fields |
| D4 | Physical storage | The field's column is `UUID` and holds the `pii_refs` id. A sibling `"<col>__bidx" TEXT` holds the blind index, with an index on `(organization_id, bidx)` |
| D5 | Where sealing happens | At the point values enter the governed write path, after validation and before any copy is made. Drafts, `record_versions`, `mutation_audit` and the data row then only ever hold the sealed form `{"pii_ref": <uuid>, "bidx": <hex>}` (in jsonb) or the ref plus bidx columns (in the row) |
| D6 | Blind-index key | `TINKER_BLIND_INDEX_KEY` (32 bytes, hex). It is separate from the KEK, so KEK rotation never invalidates indexes. `bidx = HMAC-SHA256(key, org_id ‖ field_id ‖ normalize(value))`; normalization trims, lowercases emails, and keeps only `+` and digits in phone numbers |
| D7 | Who may reveal | Roles `owner` and `admin`, and only for fields the role can see (field projection). MCP keys also need the `mcp:pii` scope. Row policies apply: an invisible record is `not_found` |
| D8 | Fail closed | Writing a sensitive field without a configured vault and index key is a typed error. A sensitive filter without an index key is rejected. A caller can never supply a sealed form: caller values are always treated as plaintext and sealed |

## Structural guards
- **The column type is the guard.** Any writer that skips sealing (ingest `write_canonical_tx`, `durable::cas_update`, comms `insert_row`) binds text into a `UUID` column and Postgres rejects it. Any reader that skips masking (agents `render_record`, comms unfurl, schema preview) sees only an opaque ref id, which is useless without `reveal`.
- **Search and embeddings**: records in `data.*` are not indexed today (only comms messages are), and comms messages go through the existing storage-class guard. If a future record indexer is added, it must skip `sensitive` fields.

## Erasure
`erase_sensitive(ctx, object, record_id)` destroys every vault value for the record (refs referenced by the row, drafts and versions), tombstones the `pii_refs` rows, and nulls the row's sensitive columns. History rows keep their ref ids, which then resolve to "pii value unavailable".

## Not in v1
- Toggling `sensitive` on an existing field. That would need a data migration: seal the existing plaintext, then rewrite the column.
- Sensitive fields on evolved (`ext_*`) objects; rejected at definition time.
- Presets on sensitive fields; rejected, because a static preset would sit in plaintext in `ontology_fields.preset_json`.
