//! Schema fingerprinting and drift detection.
//!
//! Additive source fields land automatically behind a new schema version.
//! Type narrowing, identifier change, deletion, and relation breakage pause
//! promotion and create a review item. Historical batches retain the schema
//! that interpreted them.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tinker_core::{Result, TenantContext};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::connector::SourceField;

/// Deterministic fingerprint of an observed schema: sorted
/// `name:type` pairs hashed with SHA-256.
pub fn fingerprint_schema(fields: &[SourceField]) -> String {
    let mut parts: Vec<String> = fields
        .iter()
        .map(|f| format!("{}:{}", f.name, f.type_name))
        .collect();
    parts.sort();
    let mut h = Sha256::new();
    h.update(parts.join("|"));
    format!("{:x}", h.finalize())
}

/// Drift between the last recorded schema version and a newly observed one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDrift {
    /// New fields never seen before (safe: land automatically).
    pub added: Vec<String>,
    /// Fields that vanished (pauses promotion, review item).
    pub removed: Vec<String>,
    /// Fields whose type changed (pauses promotion, review item).
    pub type_changed: Vec<(String, String, String)>,
}

impl SchemaDrift {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.type_changed.is_empty()
    }

    pub fn is_breaking(&self) -> bool {
        !self.removed.is_empty() || !self.type_changed.is_empty()
    }
}

pub fn diff_schemas(old: &[SourceField], new: &[SourceField]) -> SchemaDrift {
    let old_map: HashMap<&str, &str> = old
        .iter()
        .map(|f| (f.name.as_str(), f.type_name.as_str()))
        .collect();
    let new_map: HashMap<&str, &str> = new
        .iter()
        .map(|f| (f.name.as_str(), f.type_name.as_str()))
        .collect();
    let mut added = vec![];
    let mut removed = vec![];
    let mut type_changed = vec![];
    for (name, new_ty) in &new_map {
        match old_map.get(name) {
            None => added.push(name.to_string()),
            Some(old_ty) if old_ty != new_ty => {
                type_changed.push((name.to_string(), old_ty.to_string(), new_ty.to_string()))
            }
            _ => {}
        }
    }
    for name in old_map.keys() {
        if !new_map.contains_key(name) {
            removed.push(name.to_string());
        }
    }
    added.sort();
    removed.sort();
    type_changed.sort();
    SchemaDrift {
        added,
        removed,
        type_changed,
    }
}

fn fields_from_json(v: &serde_json::Value) -> Vec<SourceField> {
    v.as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|f| {
            Some(SourceField {
                name: f.get("name")?.as_str()?.to_string(),
                type_name: f.get("type")?.as_str()?.to_string(),
            })
        })
        .collect()
}

/// Observe a schema: record the version (idempotent) and report drift vs.
/// the previous version.
///
/// Returns `(fingerprint, drift)` where `drift` is:
/// - `None` on first observation (nothing to compare against),
/// - `Some(empty)` when the schema is unchanged,
/// - `Some(drift)` describing added/removed/type-changed fields.
pub async fn drift_check(
    core: &CoreDb,
    ctx: &TenantContext,
    stream_id: Uuid,
    fields: &[SourceField],
) -> Result<(String, Option<SchemaDrift>)> {
    let fingerprint = fingerprint_schema(fields);
    let observed = serde_json::json!(fields
        .iter()
        .map(|f| serde_json::json!({
            "name": f.name, "type": f.type_name
        }))
        .collect::<Vec<_>>());
    let mut tx = core.tenant_tx(ctx).await?;
    let prev: Option<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT fingerprint, observed_schema FROM ingest_schema_version
         WHERE organization_id=$1 AND stream_id=$2
         ORDER BY observed_at DESC LIMIT 1",
    )
    .bind(ctx.organization_id.0)
    .bind(stream_id)
    .fetch_optional(&mut *tx)
    .await?;
    let drift = match prev {
        None => None,
        Some((prev_fp, prev_schema)) => {
            if prev_fp == fingerprint {
                Some(SchemaDrift {
                    added: vec![],
                    removed: vec![],
                    type_changed: vec![],
                })
            } else {
                Some(diff_schemas(&fields_from_json(&prev_schema), fields))
            }
        }
    };
    sqlx::query(
        "INSERT INTO ingest_schema_version
         (id, organization_id, stream_id, fingerprint, observed_schema)
         VALUES ($1,$2,$3,$4,$5)
         ON CONFLICT (stream_id, fingerprint) DO NOTHING",
    )
    .bind(Uuid::now_v7())
    .bind(ctx.organization_id.0)
    .bind(stream_id)
    .bind(&fingerprint)
    .bind(&observed)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((fingerprint, drift))
}
