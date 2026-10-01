//! Sensitive (vault-backed) field values — docs/pii-sensitive-fields.md.
//!
//! A sensitive field never holds plaintext outside the PII vault. Caller
//! values are validated as plaintext, then sealed here before any copy is
//! made, and replaced by the sealed form `{"pii_ref": <uuid>, "bidx":
//! <hex>}`. Drafts, version history, the mutation audit trail and the
//! data row (ref + blind-index columns) only ever see that form.
//!
//! Callers can never supply a sealed form: [`seal_values`] treats every
//! caller value as plaintext and rejects anything that is not a string,
//! so a ref copied from another record cannot be smuggled in.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;
use sqlx::{Postgres, Transaction};
use tinker_core::blind_index::BlindIndexKey;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_vault::Vault;
use uuid::Uuid;

use crate::FieldDescription;

/// What a normal read returns for a present sensitive value.
pub const MASK: &str = "••••••";

/// Vault + blind-index key: everything needed to write sensitive fields.
#[derive(Clone)]
pub struct PiiSealer {
    vault: Vault,
    bidx: Arc<BlindIndexKey>,
}

impl PiiSealer {
    pub fn new(vault: Vault, bidx: BlindIndexKey) -> Self {
        Self {
            vault,
            bidx: Arc::new(bidx),
        }
    }

    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    pub fn blind_index(&self) -> &BlindIndexKey {
        &self.bidx
    }

    /// Resolve one sealed value to plaintext through the vault projector:
    /// the ref must be an active `pii_refs` row of the caller's org, and
    /// the disclosure is audited (`pii.resolve`, purpose + storage class,
    /// never the value). Authorization — role, field visibility, row
    /// policy — is the caller's job and must happen first.
    pub async fn reveal(
        &self,
        core: &tinker_db::CoreDb,
        ctx: &TenantContext,
        ref_id: Uuid,
        purpose: &str,
    ) -> Result<String> {
        tinker_vault::PiiProjector::new(core.clone(), self.vault.clone())
            .resolve(ctx, ref_id, purpose)
            .await
    }
}

/// A value sealed by [`seal_values`], waiting for its `pii_refs` row.
#[derive(Debug, Clone)]
pub struct SealedRef {
    pub ref_id: Uuid,
    pub subject: Uuid,
    pub storage_class: String,
}

/// The vault storage class for a field's values.
pub fn storage_class(field: &FieldDescription) -> String {
    format!("pii.{}", field.api_name)
}

pub fn sealed_json(ref_id: Uuid, bidx: &str) -> Value {
    serde_json::json!({ "pii_ref": ref_id.to_string(), "bidx": bidx })
}

/// `(ref, bidx)` from a sealed form; `None` for anything else.
pub fn parse_sealed(v: &Value) -> Option<(Uuid, String)> {
    let m = v.as_object()?;
    if m.len() != 2 {
        return None;
    }
    let r = m.get("pii_ref")?.as_str()?.parse().ok()?;
    let b = m.get("bidx")?.as_str()?.to_string();
    Some((r, b))
}

/// Replace every caller-supplied value of a sensitive field with its
/// sealed form. Run on CALLER values only, after `validate_fields` has
/// checked them as plaintext and before they are merged with stored
/// content or copied anywhere. `subject` is the vault subject (record or
/// draft id). Returns the refs to register with [`register_refs`] inside
/// the core transaction that persists them.
pub async fn seal_values(
    sealer: Option<&PiiSealer>,
    ctx: &TenantContext,
    fields: &[FieldDescription],
    subject: Uuid,
    values: &mut HashMap<String, Value>,
) -> Result<Vec<SealedRef>> {
    let mut sealed = Vec::new();
    for f in fields.iter().filter(|f| f.sensitive) {
        let Some(v) = values.get(&f.api_name) else {
            continue;
        };
        if v.is_null() {
            continue;
        }
        let Some(plaintext) = v.as_str() else {
            return Err(TinkerError::Validation(format!(
                "field '{}': sensitive fields take a string value",
                f.api_name
            )));
        };
        let sealer = sealer.ok_or_else(|| {
            TinkerError::Validation(format!(
                "field '{}' is sensitive, but this server has no PII vault configured \
                 (TINKER_PII_URL, TINKER_KEK, TINKER_BLIND_INDEX_KEY)",
                f.api_name
            ))
        })?;
        let class = storage_class(f);
        let bidx = sealer
            .bidx
            .digest(ctx.organization_id.0, f.id, &f.field_type, plaintext);
        let ref_id = sealer.vault.seal(ctx, subject, &class, plaintext).await?;
        values.insert(f.api_name.clone(), sealed_json(ref_id, &bidx));
        sealed.push(SealedRef {
            ref_id,
            subject,
            storage_class: class,
        });
    }
    Ok(sealed)
}

/// Commit the core half of the two-phase write: one active `pii_refs`
/// row per sealed value, in the same transaction as the row (or draft)
/// that references it. If that transaction rolls back, the vault value is
/// left unreferenced and can never resolve.
pub async fn register_refs(
    tx: &mut Transaction<'_, Postgres>,
    ctx: &TenantContext,
    refs: &[SealedRef],
) -> Result<()> {
    for r in refs {
        sqlx::query(
            "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(r.ref_id)
        .bind(ctx.organization_id.0)
        .bind(r.subject)
        .bind(&r.storage_class)
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
    }
    Ok(())
}

/// Replace every sealed form at the top level of a JSON object with
/// [`MASK`]. Used where field metadata is not at hand (draft output).
pub fn mask_sealed(content: &Value) -> Value {
    match content {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let v = if parse_sealed(v).is_some() {
                        Value::String(MASK.to_string())
                    } else {
                        v.clone()
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Mask sensitive values in an api_name-keyed JSON object (draft or
/// version content, audit images) for output. Present → [`MASK`].
pub fn mask_content(fields: &[FieldDescription], content: &mut Value) {
    let Some(map) = content.as_object_mut() else {
        return;
    };
    for f in fields.iter().filter(|f| f.sensitive) {
        if let Some(v) = map.get_mut(&f.api_name) {
            if !v.is_null() {
                *v = Value::String(MASK.to_string());
            }
        }
    }
}

impl PiiSealer {
    /// Erase every sensitive value of one record (right to erasure).
    ///
    /// Collects the record's vault refs wherever a sealed form may live —
    /// the row's ref columns, its version history, in-flight drafts, and
    /// refs whose subject is the record (values superseded by updates) —
    /// destroys their ciphertext, tombstones the `pii_refs` rows, and
    /// clears the row's sensitive columns. History rows keep their ref
    /// ids, which then resolve to "unavailable". Authorization is the
    /// caller's job. Returns how many vault values were destroyed.
    pub async fn erase_record(
        &self,
        core: &tinker_db::CoreDb,
        ctx: &TenantContext,
        desc: &crate::ObjectDescription,
        record_id: Uuid,
    ) -> Result<usize> {
        let sensitive: Vec<&FieldDescription> =
            desc.fields.iter().filter(|f| f.sensitive).collect();
        if sensitive.is_empty() {
            return Ok(0);
        }
        let table = format!("data.{}", desc.api_slug);
        let mut refs: std::collections::BTreeSet<Uuid> = std::collections::BTreeSet::new();
        let mut tx = core.tenant_tx(ctx).await?;
        for f in &sensitive {
            let r: Option<Option<Uuid>> = sqlx::query_scalar(&format!(
                "SELECT \"{}\" FROM {table} WHERE organization_id = $1 AND id = $2",
                f.physical_column
            ))
            .bind(ctx.organization_id.0)
            .bind(record_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            refs.extend(r.flatten());
        }
        let contents: Vec<Value> = sqlx::query_scalar(
            "SELECT content FROM record_versions WHERE organization_id = $1 AND record_id = $2 \
             UNION ALL \
             SELECT content FROM record_drafts WHERE organization_id = $1 AND record_id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(record_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        for c in &contents {
            for f in &sensitive {
                if let Some((r, _)) = c.get(&f.api_name).and_then(parse_sealed) {
                    refs.insert(r);
                }
            }
        }
        let by_subject: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM pii_refs WHERE organization_id = $1 AND subject_id = $2 \
             AND state = 'active'",
        )
        .bind(ctx.organization_id.0)
        .bind(record_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        refs.extend(by_subject);
        tx.commit().await.map_err(TinkerError::Db)?;

        // Destroy ciphertext first: once it is gone the value is erased
        // whatever happens to the bookkeeping below.
        let mut destroyed = 0;
        for r in &refs {
            match self.vault.destroy(ctx, *r).await {
                Ok(()) => destroyed += 1,
                Err(TinkerError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }
        let mut tx = core.tenant_tx(ctx).await?;
        let ids: Vec<Uuid> = refs.into_iter().collect();
        sqlx::query(
            "UPDATE pii_refs SET state = 'tombstoned' \
             WHERE organization_id = $1 AND id = ANY($2)",
        )
        .bind(ctx.organization_id.0)
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let clear = sensitive
            .iter()
            .map(|f| {
                format!(
                    "\"{}\" = NULL, \"{}\" = NULL",
                    f.physical_column,
                    crate::bidx_column(&f.physical_column)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        sqlx::query(&format!(
            "UPDATE {table} SET {clear}, updated_at = now() WHERE organization_id = $1 AND id = $2"
        ))
        .bind(ctx.organization_id.0)
        .bind(record_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(destroyed)
    }
}

/// What [`PiiSealer::make_field_sensitive`] converted.
#[derive(Debug, Clone)]
pub struct RetrofitReport {
    /// Data rows whose value was sealed.
    pub rows: usize,
    /// Plaintext copies replaced in drafts, versions and mutation audit.
    pub history_copies: usize,
    pub old_column: String,
    pub new_column: String,
}

impl PiiSealer {
    /// Convert an existing, populated field to sensitive (operator
    /// maintenance; docs/pii-sensitive-fields.md "Retrofit").
    ///
    /// In one owner transaction holding a write-blocking lock on the data
    /// table: every value is sealed (per row, per organization) into a NEW
    /// UUID column + blind index; every plaintext copy in record drafts,
    /// version history and the mutation audit (for the object and its
    /// adopters) is replaced by a sealed form; the field row is repointed
    /// and flagged; the old plaintext column is dropped. Ingest copies
    /// (provenance, landing) are converted by `tinker-ingest`'s
    /// counterpart. Postgres keeps dropped-column bytes until the table is
    /// rewritten, and WAL / backups keep them until they age out: run
    /// `VACUUM FULL` on the table and rotate backups to finish erasure.
    pub async fn make_field_sensitive(
        &self,
        owner: &tinker_db::OwnerDb,
        object_id: Uuid,
        api_name: &str,
    ) -> Result<RetrofitReport> {
        // Every value sealed by this run, so a failure can destroy them:
        // the vault write is not part of the core transaction, and an
        // unreferenced ciphertext is still PII at rest.
        let mut sealed: Vec<(Uuid, Uuid)> = Vec::new();
        let result = self
            .retrofit_inner(owner, object_id, api_name, &mut sealed)
            .await;
        if result.is_err() {
            let mut by_org: std::collections::HashMap<Uuid, Vec<Uuid>> = Default::default();
            for (org, id) in sealed {
                by_org.entry(org).or_default().push(id);
            }
            for (org, ids) in by_org {
                let ctx = retrofit_ctx(org);
                // Best effort; `sweep_orphans` collects anything left.
                let _ = self.vault.destroy_many(&ctx, &ids).await;
            }
        }
        result
    }

    async fn retrofit_inner(
        &self,
        owner: &tinker_db::OwnerDb,
        object_id: Uuid,
        api_name: &str,
        sealed: &mut Vec<(Uuid, Uuid)>,
    ) -> Result<RetrofitReport> {
        let mut tx = owner.0.begin().await.map_err(TinkerError::Db)?;
        let field: Option<(Uuid, String, String, bool, serde_json::Value, String)> =
            sqlx::query_as(
                "SELECT f.id, f.physical_column, f.field_type, f.sensitive, f.preset_json, o.api_slug \
                 FROM ontology_fields f JOIN ontology_objects o ON o.id = f.object_id \
                 WHERE f.object_id = $1 AND f.api_name = $2 AND f.state = 'active' \
                 FOR UPDATE OF f",
            )
            .bind(object_id)
            .bind(api_name)
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        let (field_id, old_col, kind, already, preset, slug) =
            field.ok_or_else(|| TinkerError::NotFound(format!("field {api_name}")))?;
        if already {
            return Err(TinkerError::Validation(format!(
                "field '{api_name}' is already sensitive"
            )));
        }
        if !matches!(kind.as_str(), "text" | "email" | "phone") {
            return Err(TinkerError::Validation(format!(
                "field '{api_name}': only text, email and phone fields can be sensitive"
            )));
        }
        if !preset.is_null() {
            return Err(TinkerError::Validation(format!(
                "field '{api_name}' carries a write preset; remove it first"
            )));
        }
        let filters: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM row_filters WHERE object_id = $1 AND field_api_name = $2",
        )
        .bind(object_id)
        .bind(api_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        if filters > 0 {
            return Err(TinkerError::Validation(format!(
                "field '{api_name}' is used by {filters} row filter(s); sensitive fields cannot \
                 drive row policy — remove them first"
            )));
        }
        let table = format!("data.{slug}");
        sqlx::query(&format!("LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE"))
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        let new_col = crate::new_physical_column();
        let bidx_col = crate::bidx_column(&new_col);
        sqlx::query(&format!(
            "ALTER TABLE {table} ADD COLUMN \"{new_col}\" UUID, ADD COLUMN \"{bidx_col}\" TEXT"
        ))
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let class = format!("pii.{api_name}");
        let f = RetrofitField {
            id: field_id,
            kind: &kind,
            class: &class,
        };

        // 1. Live rows, keyset-paged and sealed in bulk per chunk.
        let mut rows = 0usize;
        let mut after: (Uuid, Uuid) = (Uuid::nil(), Uuid::nil());
        loop {
            let page: Vec<(Uuid, Uuid, String)> = sqlx::query_as(&format!(
                "SELECT organization_id, id, \"{old_col}\" FROM {table} \
                 WHERE \"{old_col}\" IS NOT NULL AND (organization_id, id) > ($1, $2) \
                 ORDER BY organization_id, id LIMIT {RETROFIT_CHUNK}"
            ))
            .bind(after.0)
            .bind(after.1)
            .fetch_all(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            let Some(last) = page.last() else { break };
            after = (last.0, last.1);
            rows += page.len();
            let (mut orgs, mut ids, mut refs, mut bidxs) = (vec![], vec![], vec![], vec![]);
            for (org, items) in group_by_org(page.into_iter().map(|(o, i, v)| (o, (i, v)))) {
                let sealed_chunk = self.seal_chunk(&mut tx, org, &f, &items, sealed).await?;
                for ((id, _), (r, b)) in items.iter().zip(sealed_chunk) {
                    orgs.push(org);
                    ids.push(*id);
                    refs.push(r);
                    bidxs.push(b);
                }
            }
            sqlx::query(&format!(
                "UPDATE {table} t SET \"{new_col}\" = v.r, \"{bidx_col}\" = v.b \
                 FROM unnest($1::uuid[], $2::uuid[], $3::uuid[], $4::text[]) AS v(o, i, r, b) \
                 WHERE t.organization_id = v.o AND t.id = v.i"
            ))
            .bind(&orgs)
            .bind(&ids)
            .bind(&refs)
            .bind(&bidxs)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        }
        sqlx::query(&format!(
            "CREATE INDEX \"{bidx_col}_idx\" ON {table} (organization_id, \"{bidx_col}\")"
        ))
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;

        // 2. Plaintext copies in history, for the object and its adopters.
        let mut copies = 0usize;
        let objects =
            "(SELECT $1::uuid UNION SELECT id FROM ontology_objects WHERE adopted_from = $1)";
        for (table_name, key, json_cols) in [
            // (table, row-key expression as text, plaintext-bearing columns)
            ("record_drafts", "draft_id::text", &["content"][..]),
            (
                "record_versions",
                "record_id::text || ':' || version_no::text",
                &["content"][..],
            ),
            (
                "mutation_audit",
                "id::text",
                &["before_json", "after_json"][..],
            ),
        ] {
            for col in json_cols {
                let hits: Vec<(Uuid, String, Uuid, String)> = sqlx::query_as(&format!(
                    "SELECT organization_id, {key}, \
                            COALESCE(record_id, '00000000-0000-0000-0000-000000000000'::uuid), \
                            {col}->>$2 \
                     FROM {table_name} WHERE object_id IN {objects} \
                       AND jsonb_typeof({col}->$2) = 'string'"
                ))
                .bind(object_id)
                .bind(api_name)
                .fetch_all(&mut *tx)
                .await
                .map_err(TinkerError::Db)?;
                copies += hits.len();
                for chunk in hits.chunks(RETROFIT_CHUNK) {
                    let (mut orgs, mut keys, mut refs, mut bidxs) =
                        (vec![], vec![], vec![], vec![]);
                    for (org, items) in
                        group_by_org(chunk.iter().map(|(o, k, subj, v)| (*o, (k, *subj, v))))
                    {
                        let values: Vec<(Uuid, String)> =
                            items.iter().map(|(_, s, v)| (*s, (*v).clone())).collect();
                        let sealed_chunk =
                            self.seal_chunk(&mut tx, org, &f, &values, sealed).await?;
                        for ((k, _, _), (r, b)) in items.into_iter().zip(sealed_chunk) {
                            orgs.push(org);
                            keys.push(k.clone());
                            refs.push(r);
                            bidxs.push(b);
                        }
                    }
                    sqlx::query(&format!(
                        "UPDATE {table_name} SET {col} = jsonb_set({col}, ARRAY[$1], \
                             jsonb_build_object('pii_ref', v.r::text, 'bidx', v.b)) \
                         FROM unnest($2::uuid[], $3::text[], $4::uuid[], $5::text[]) AS v(o, k, r, b) \
                         WHERE organization_id = v.o AND {key} = v.k"
                    ))
                    .bind(api_name)
                    .bind(&orgs)
                    .bind(&keys)
                    .bind(&refs)
                    .bind(&bidxs)
                    .execute(&mut *tx)
                    .await
                    .map_err(TinkerError::Db)?;
                }
            }
        }

        // 3. Repoint the field, then drop the plaintext column.
        sqlx::query(
            "UPDATE ontology_fields SET physical_column = $2, sensitive = true, \
             version = version + 1 WHERE id = $1",
        )
        .bind(field_id)
        .bind(&new_col)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let drop = format!("ALTER TABLE {table} DROP COLUMN \"{old_col}\"");
        sqlx::query(&drop)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        sqlx::query(
            "INSERT INTO ontology_changes \
             (organization_id, object_id, change_kind, detail, ddl_statements, applied_by) \
             SELECT organization_id, id, 'field.made_sensitive', $2, $3, NULL \
             FROM ontology_objects WHERE id = $1",
        )
        .bind(object_id)
        .bind(serde_json::json!({
            "api_name": api_name,
            "old_physical_column": old_col,
            "physical_column": new_col,
            "rows": rows,
            "history_copies": copies,
        }))
        .bind(vec![drop.clone()])
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(RetrofitReport {
            rows,
            history_copies: copies,
            old_column: old_col,
            new_column: new_col,
        })
    }

    /// Seal one organization's `(subject, plaintext)` items in bulk and
    /// register their active `pii_refs` in `tx`. Returns `(ref, bidx)`
    /// per item, in order; records sealed ids for failure cleanup.
    async fn seal_chunk(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        org: Uuid,
        f: &RetrofitField<'_>,
        items: &[(Uuid, String)],
        sealed: &mut Vec<(Uuid, Uuid)>,
    ) -> Result<Vec<(Uuid, String)>> {
        let ctx = retrofit_ctx(org);
        let batch: Vec<(Uuid, String, String)> = items
            .iter()
            .map(|(subject, v)| (*subject, f.class.to_string(), v.clone()))
            .collect();
        let ids = self.vault.seal_batch(&ctx, &batch).await?;
        sealed.extend(ids.iter().map(|i| (org, *i)));
        let subjects: Vec<Uuid> = items.iter().map(|(s, _)| *s).collect();
        sqlx::query(
            "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state) \
             SELECT i, $2, s, $4, 'active' FROM unnest($1::uuid[], $3::uuid[]) AS v(i, s)",
        )
        .bind(&ids)
        .bind(org)
        .bind(&subjects)
        .bind(f.class)
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(ids
            .into_iter()
            .zip(items)
            .map(|(r, (_, v))| (r, self.bidx.digest(org, f.id, f.kind, v)))
            .collect())
    }
}

/// Column writes for one sealed value: the vault-ref column and its
/// blind-index column, as returned by [`PiiSealer::seal_for_write`].
#[derive(Debug, Clone)]
pub struct SealedColumns {
    pub ref_column: String,
    pub ref_id: Uuid,
    pub bidx_column: String,
    pub bidx: String,
}

impl PiiSealer {
    /// Seal one value of `object_id.api_name` for `org` outside the
    /// governed write path — fixtures and bulk loaders that write rows
    /// with SQL. Registers the active `pii_refs` row (owner pool) and
    /// returns the two columns to write. Writing the plaintext instead
    /// fails on the UUID column, by design.
    pub async fn seal_for_write(
        &self,
        owner_pool: &sqlx::PgPool,
        org: Uuid,
        object_id: Uuid,
        api_name: &str,
        value: &str,
    ) -> Result<SealedColumns> {
        let (field_id, physical, kind, sensitive): (Uuid, String, String, bool) = sqlx::query_as(
            "SELECT id, physical_column, field_type, sensitive FROM ontology_fields \
             WHERE object_id = $1 AND api_name = $2 AND state = 'active'",
        )
        .bind(object_id)
        .bind(api_name)
        .fetch_optional(owner_pool)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound(format!("field {api_name}")))?;
        if !sensitive {
            return Err(TinkerError::Validation(format!(
                "field '{api_name}' is not sensitive; write the value directly"
            )));
        }
        let ctx = retrofit_ctx(org);
        let class = format!("pii.{api_name}");
        let subject = Uuid::now_v7();
        let ref_id = self.vault.seal(&ctx, subject, &class, value).await?;
        sqlx::query(
            "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(ref_id)
        .bind(org)
        .bind(subject)
        .bind(&class)
        .execute(owner_pool)
        .await
        .map_err(TinkerError::Db)?;
        Ok(SealedColumns {
            bidx_column: crate::bidx_column(&physical),
            bidx: self.bidx.digest(org, field_id, &kind, value),
            ref_column: physical,
            ref_id,
        })
    }
}

/// Rows per bulk seal / update during a retrofit.
const RETROFIT_CHUNK: usize = 2000;

struct RetrofitField<'a> {
    id: Uuid,
    kind: &'a str,
    class: &'a str,
}

fn retrofit_ctx(org: Uuid) -> TenantContext {
    TenantContext::new(
        tinker_core::OrganizationId(org),
        Uuid::nil(),
        "pii.retrofit",
    )
}

/// `(org, item)` → per-org item lists, in first-seen org order (inputs
/// arrive org-sorted, so each org's run stays contiguous).
fn group_by_org<T>(items: impl Iterator<Item = (Uuid, T)>) -> Vec<(Uuid, Vec<T>)> {
    let mut out: Vec<(Uuid, Vec<T>)> = Vec::new();
    for (org, item) in items {
        match out.last_mut() {
            Some((o, list)) if *o == org => list.push(item),
            _ => out.push((org, vec![item])),
        }
    }
    out
}

/// Delete vault ciphertext that no core `pii_refs` row references and
/// that is older than `grace` (in-flight two-phase writes take seconds).
/// Such values exist when a core transaction rolled back after the vault
/// write — they can never be revealed, but they are still PII at rest
/// and erasure cannot reach them. Owner pools on both databases.
pub async fn sweep_orphans(
    core_owner: &sqlx::PgPool,
    pii_owner: &sqlx::PgPool,
    grace: chrono::Duration,
) -> Result<u64> {
    let cutoff = chrono::Utc::now() - grace;
    let mut after = Uuid::nil();
    let mut removed = 0u64;
    loop {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM pii_values WHERE id > $1 AND created_at < $2 ORDER BY id LIMIT 5000",
        )
        .bind(after)
        .bind(cutoff)
        .fetch_all(pii_owner)
        .await
        .map_err(TinkerError::Db)?;
        let Some(last) = ids.last() else { break };
        after = *last;
        let referenced: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM pii_refs WHERE id = ANY($1)")
                .bind(&ids)
                .fetch_all(core_owner)
                .await
                .map_err(TinkerError::Db)?;
        let referenced: std::collections::HashSet<Uuid> = referenced.into_iter().collect();
        let orphans: Vec<Uuid> = ids
            .into_iter()
            .filter(|i| !referenced.contains(i))
            .collect();
        if !orphans.is_empty() {
            removed += sqlx::query("DELETE FROM pii_values WHERE id = ANY($1)")
                .bind(&orphans)
                .execute(pii_owner)
                .await
                .map_err(TinkerError::Db)?
                .rows_affected();
        }
    }
    Ok(removed)
}

/// Build the sealer from the environment for a server process.
///
/// All three of `TINKER_PII_URL` (vault database, PII app role),
/// `TINKER_KEK` and `TINKER_BLIND_INDEX_KEY` set → `Some`. None set →
/// `None`: the server runs without sensitive-field support and any such
/// write fails closed. A partial configuration is a startup error, never
/// a silently disabled vault.
pub async fn sealer_from_env() -> Result<Option<PiiSealer>> {
    let set = |k: &str| std::env::var(k).map(|v| !v.is_empty()).unwrap_or(false);
    let keys = [
        "TINKER_PII_URL",
        "TINKER_KEK",
        tinker_core::blind_index::BLIND_INDEX_KEY_ENV,
    ];
    let present: Vec<&str> = keys.iter().copied().filter(|k| set(k)).collect();
    if present.is_empty() {
        return Ok(None);
    }
    if present.len() != keys.len() {
        let missing: Vec<&str> = keys.iter().copied().filter(|k| !set(k)).collect();
        return Err(TinkerError::Validation(format!(
            "PII vault partially configured: set {} too (or unset {})",
            missing.join(", "),
            present.join(", ")
        )));
    }
    let pii =
        tinker_db::PiiDb::connect(&std::env::var("TINKER_PII_URL").unwrap_or_default()).await?;
    let vault = Vault::from_env(pii)?;
    let bidx = BlindIndexKey::from_env()?.ok_or_else(|| {
        TinkerError::Validation("TINKER_BLIND_INDEX_KEY vanished during startup".into())
    })?;
    Ok(Some(PiiSealer::new(vault, bidx)))
}
