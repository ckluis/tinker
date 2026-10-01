# Sensitive fields: PII sealed in the vault

Status: ACCEPTED 2026-09-30. Decisions D1–D3 were made by the operator; the rest are design choices recorded here.

## Problem
`tinker-vault` (AES-256-GCM, per-org DEK wrapped by a KEK, two-phase `pii_refs`, audited `PiiProjector::resolve`) was built and tested, but no field ever used it. A field holding an email or a name was stored as plaintext in `data.<slug>`, and from there it was copied into drafts, version history and mutation audit rows. The overview's claim that "PII fields are sealed into the vault" did not hold for the running system.

## Decisions
| # | Decision | Choice |
|---|---|---|
| D1 | How a field becomes vault-backed | **PII by type** (as in samen): every `email` and `phone` field is always sensitive, and the flag cannot turn it off. A `text` field opts in with `sensitive: true`. Fixed at definition; an existing field converts through Retrofit |
| D2 | What normal reads return | A fixed mask (`"••••••"`) for a present value, `null` for an absent one. Plaintext comes only from the `reveal` tool, which requires a purpose, is role-gated and is audited per value |
| D3 | Lookups | Exact match only, through a keyed blind index. No sorting, ranges, `contains` or `starts_with` on sensitive fields |
| D4 | Physical storage | The field's column is `UUID` and holds the `pii_refs` id. A sibling `"<col>__bidx" TEXT` holds the blind index, with an index on `(organization_id, bidx)` |
| D5 | Where sealing happens | At the point values enter the governed write path, after validation and before any copy is made. Drafts, `record_versions`, `mutation_audit` and the data row then only ever hold the sealed form `{"pii_ref": <uuid>, "bidx": <hex>}` (in jsonb) or the ref plus bidx columns (in the row) |
| D6 | Blind-index key | `TINKER_BLIND_INDEX_KEY` (32 bytes, hex). It is separate from the KEK, so KEK rotation never invalidates indexes. `bidx = HMAC-SHA256(key, org_id ‖ field_id ‖ normalize(value))`; normalization trims, lowercases emails, and keeps only `+` and digits in phone numbers |
| D7 | Who may reveal | Roles `owner` and `admin`, and only for fields the role can see (field projection). MCP keys also need the `mcp:pii` scope. Row policies apply: an invisible record is `not_found` |
| D8 | Fail closed | Writing a sensitive field without a configured vault and index key is a typed error. A sensitive filter without an index key is rejected. A caller can never supply a sealed form: caller values are always treated as plaintext and sealed |

## Structural guards
- **The column type is the guard.** Any writer that skips sealing (`durable::cas_update`, comms `insert_row`; ingest now seals through `IngestPipeline::with_pii`) binds text into a `UUID` column and Postgres rejects it. Any reader that skips masking (agents `render_record`, comms unfurl, schema preview) sees only an opaque ref id, which is useless without `reveal`.
- **Search and embeddings**: records in `data.*` are not indexed today (only comms messages are), and comms messages go through the existing storage-class guard. If a future record indexer is added, it must skip `sensitive` fields.

## Erasure
`PiiSealer::erase_record(core, ctx, object, record_id)`, exposed as the MCP `erase` tool (owner/admin, explicit `mcp:tool:erase` scope, purpose audited as `pii.erase`), destroys every vault value for the record (refs referenced by the row, drafts and versions, and refs superseded by updates), tombstones the `pii_refs` rows, and nulls the row's sensitive columns. History rows keep their ref ids, which then resolve to "pii value unavailable".

Erasure also **crypto-shreds** (pii migration 0005): each subject (record) has its own DEK, and erasing the record destroys its subjects' DEKs in `wrapped_deks`. A copy of the record's ciphertext, in a dump or a replica, is then AES-GCM under a key that no longer exists. Two limits remain. A backup that also holds `wrapped_deks` still holds the key, so crypto-shred holds against restored backups only once those backups age out, or when `wrapped_deks` is backed up on a shorter retention than `pii_values`. Values sealed before migration 0005 sit under the organization's legacy DEK (`subject_id IS NULL`); erasure destroys those values row by row but cannot shred that DEK, because other subjects share it.

## Retrofit: making a populated field sensitive
`tinker-cli field make-sensitive --object <slug> --field <api_name>` (or `PiiSealer::make_field_sensitive` followed by `IngestPipeline::retrofit_sensitive`):
1. Inside one owner transaction, with a `SHARE ROW EXCLUSIVE` lock on the data table, every live value is sealed (per row, per org) into a **new** UUID column plus a blind index.
2. Every plaintext copy in `record_drafts`, `record_versions` and `mutation_audit` (for the object and its adopters) becomes a sealed form.
3. The field row is repointed and flagged, and the old column is dropped.
4. The ingest half replaces provenance values with digests and landing copies with digest markers, so the next ingest run matches by digest and re-seals nothing.

Refused: fields with a preset, fields driving a row filter, and fields that are already sensitive.

**Erasure is not complete until** servers are restarted (cached plans name the old column), `VACUUM FULL` has rewritten the table, and backups taken before the retrofit have aged out. WAL and backups still hold the plaintext until then.

## Gates and hygiene
- `tinker-cli pii verify` is the no-plaintext-PII gate. It exits 1 if any email or phone field is not vault-backed, and `bin/test-mac.sh` runs it after the suite.
- `tinker-cli pii retrofit` converts every field `verify` reports. It works in batches: rows are keyset-paged in chunks of 2,000, sealed with one vault call per chunk, then registered and updated in bulk. On the dev database, 1,019,943 rows plus 234,189 ingest copies took 92 seconds. If it fails, it destroys every vault value it sealed.
- `tinker-cli pii sweep [--grace-minutes N]` deletes vault ciphertext that no `pii_refs` row references and that is older than the grace period (default 60 minutes). Such values are left behind when a core transaction rolls back after the vault write. They can never be revealed, but they are still PII at rest, and erasure cannot reach them. Run it on a schedule.

## Not in v1
- Turning `sensitive` back off. That would be a disclosure; it is deliberately not offered.
- Sensitive fields on evolved (`ext_*`) objects; rejected at definition time.
- Presets on sensitive fields; rejected, because a static preset would sit in plaintext in `ontology_fields.preset_json`.
