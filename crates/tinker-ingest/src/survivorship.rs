//! Field-level survivorship with provenance.
//!
//! Survivorship rules: field-level source priority, not one winner for the
//! whole record. Blank never overwrites a known value unless policy allows
//! it. Every winning value retains provenance.

use std::collections::HashMap;
use tinker_core::{Result, TenantContext};
use tinker_db::CoreDb;
use uuid::Uuid;

/// One field value proposed for a canonical record.
#[derive(Debug, Clone)]
pub struct FieldProposal {
    pub field: String,
    pub value: serde_json::Value,
    /// Lower number = higher priority (0 beats 1).
    pub priority: i32,
    pub stream_id: Uuid,
    pub source_id: String,
    pub source_field: String,
}

#[derive(Debug, Clone)]
pub struct Provenance {
    pub tinker_record_id: Uuid,
    pub field: String,
    pub stream_id: Uuid,
    pub source_id: String,
    pub source_field: String,
    pub value: serde_json::Value,
}

pub struct Survivorship {
    core: CoreDb,
}

impl Survivorship {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Pick winners: highest priority (lowest number) wins per field;
    /// blank (null/empty string) never overwrites a known value.
    pub fn winners(
        proposals: &[FieldProposal],
        current: &HashMap<String, serde_json::Value>,
    ) -> Vec<FieldProposal> {
        let mut best: HashMap<&str, &FieldProposal> = HashMap::new();
        for p in proposals {
            let is_blank = p.value.is_null()
                || p.value
                    .as_str()
                    .map(|s| s.trim().is_empty())
                    .unwrap_or(false);
            if is_blank {
                continue;
            }
            match best.get(p.field.as_str()) {
                Some(cur) if cur.priority <= p.priority => {}
                _ => {
                    best.insert(p.field.as_str(), p);
                }
            }
        }
        // Drop winners that equal the current canonical value (no-op).
        best.into_values()
            .filter(|p| current.get(&p.field) != Some(&p.value))
            .cloned()
            .collect()
    }

    /// Record provenance for each winning value.
    ///
    /// Transactional core: the caller owns `tx`, so provenance commits
    /// atomically with the canonical write it describes. The
    /// non-transactional [`record_provenance`](Self::record_provenance) is
    /// a convenience wrapper.
    pub async fn record_provenance_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        tinker_record_id: Uuid,
        winners: &[FieldProposal],
    ) -> Result<()> {
        for w in winners {
            sqlx::query(
                "INSERT INTO ingest_provenance
                 (id, organization_id, tinker_record_id, field, stream_id,
                  source_id, source_field, value)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            )
            .bind(Uuid::now_v7())
            .bind(ctx.organization_id.0)
            .bind(tinker_record_id)
            .bind(&w.field)
            .bind(w.stream_id)
            .bind(&w.source_id)
            .bind(&w.source_field)
            .bind(&w.value)
            .execute(&mut **tx)
            .await?;
        }
        Ok(())
    }

    /// Record provenance for each winning value (own transaction).
    pub async fn record_provenance(
        &self,
        ctx: &TenantContext,
        tinker_record_id: Uuid,
        winners: &[FieldProposal],
    ) -> Result<()> {
        if winners.is_empty() {
            return Ok(());
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        self.record_provenance_tx(&mut tx, ctx, tinker_record_id, winners)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn provenance_for(
        &self,
        ctx: &TenantContext,
        tinker_record_id: Uuid,
    ) -> Result<Vec<Provenance>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, String, Uuid, String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT tinker_record_id, field, stream_id, source_id, source_field, value
                 FROM ingest_provenance
                 WHERE organization_id=$1 AND tinker_record_id=$2
                 ORDER BY won_at",
        )
        .bind(ctx.organization_id.0)
        .bind(tinker_record_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|r| Provenance {
                tinker_record_id: r.0,
                field: r.1,
                stream_id: r.2,
                source_id: r.3,
                source_field: r.4,
                value: r.5,
            })
            .collect())
    }
}
