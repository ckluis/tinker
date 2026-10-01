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
        sqlx::query(&format!(
            "CREATE INDEX \"{bidx_col}_idx\" ON {table} (organization_id, \"{bidx_col}\")"
        ))
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;

        let class = format!("pii.{api_name}");
        let ctx_for = |org: Uuid| {
            TenantContext::new(
                tinker_core::OrganizationId(org),
                Uuid::nil(),
                "pii.retrofit",
            )
        };
        // 1. Live rows.
        let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(&format!(
            "SELECT organization_id, id, \"{old_col}\" FROM {table} WHERE \"{old_col}\" IS NOT NULL"
        ))
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        for (org, id, value) in &rows {
            let ctx = ctx_for(*org);
            let (ref_id, bidx) = self
                .seal_one(&ctx, field_id, &kind, *id, &class, value)
                .await?;
            register_refs(
                &mut tx,
                &ctx,
                &[SealedRef {
                    ref_id,
                    subject: *id,
                    storage_class: class.clone(),
                }],
            )
            .await?;
            sqlx::query(&format!(
                "UPDATE {table} SET \"{new_col}\" = $3, \"{bidx_col}\" = $4 \
                 WHERE organization_id = $1 AND id = $2"
            ))
            .bind(org)
            .bind(id)
            .bind(ref_id)
            .bind(&bidx)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        }

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
                for (org, key_val, subject, value) in hits {
                    let ctx = ctx_for(org);
                    let (ref_id, bidx) = self
                        .seal_one(&ctx, field_id, &kind, subject, &class, &value)
                        .await?;
                    register_refs(
                        &mut tx,
                        &ctx,
                        &[SealedRef {
                            ref_id,
                            subject,
                            storage_class: class.clone(),
                        }],
                    )
                    .await?;
                    sqlx::query(&format!(
                        "UPDATE {table_name} SET {col} = jsonb_set({col}, ARRAY[$3], $4) \
                         WHERE organization_id = $1 AND {key} = $2"
                    ))
                    .bind(org)
                    .bind(&key_val)
                    .bind(api_name)
                    .bind(sealed_json(ref_id, &bidx))
                    .execute(&mut *tx)
                    .await
                    .map_err(TinkerError::Db)?;
                    copies += 1;
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
            "rows": rows.len(),
            "history_copies": copies,
        }))
        .bind(vec![drop.clone()])
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(RetrofitReport {
            rows: rows.len(),
            history_copies: copies,
            old_column: old_col,
            new_column: new_col,
        })
    }

    async fn seal_one(
        &self,
        ctx: &TenantContext,
        field_id: Uuid,
        kind: &str,
        subject: Uuid,
        class: &str,
        value: &str,
    ) -> Result<(Uuid, String)> {
        let bidx = self
            .bidx
            .digest(ctx.organization_id.0, field_id, kind, value);
        let ref_id = self.vault.seal(ctx, subject, class, value).await?;
        Ok((ref_id, bidx))
    }
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
