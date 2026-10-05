//! Reconciliation: source counts vs. landed counts, on a separate cadence.
//!
//! Reconciliation detects drift; it never mutates canonical data.
//!
//! Each run writes an `ingest_reconciliation` history row and updates the
//! stream row's reconciliation rollup (`reconcile_fingerprint`,
//! `reconcile_seen_at`, `reconcile_expected`, `reconcile_unexpected`)
//! in the same transaction, so the rollup can never diverge from
//! history.

use sha2::{Digest, Sha256};
use tinker_core::{Result, TenantContext};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::connector::SourceConnector;
use crate::landing::LandingWriter;

#[derive(Debug, Clone)]
pub struct ReconciliationReport {
    pub id: Uuid,
    pub source_count: i64,
    pub landed_count: i64,
    pub differences: Vec<String>,
}

impl ReconciliationReport {
    pub fn is_clean(&self) -> bool {
        self.differences.is_empty() && self.source_count == self.landed_count
    }
}

pub struct Reconciler {
    core: CoreDb,
    landing: LandingWriter,
}

impl Reconciler {
    pub fn new(core: CoreDb, landing: LandingWriter) -> Self {
        Self { core, landing }
    }

    pub async fn reconcile(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_object: &str,
        connector: &dyn SourceConnector,
    ) -> Result<ReconciliationReport> {
        let source_count = connector.count(source_object).await? as i64;
        let landed_count = self.landing.landed_count(ctx, stream_id).await?;
        let mut differences = vec![];
        if source_count != landed_count {
            differences.push(format!(
                "count drift: source={source_count} landed={landed_count}"
            ));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO ingest_reconciliation
             (id, organization_id, stream_id, source_count, landed_count, differences)
             VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(source_count)
        .bind(landed_count)
        .bind(serde_json::json!(differences))
        .fetch_one(&mut *tx)
        .await?;
        // Per-stream rollup: the latest outcome on the stream row itself,
        // so operators see the last-known-good state without scanning
        // history. The fingerprint is a stable identity of the observed
        // state — a change across runs means the source drifted.
        let fingerprint = Self::fingerprint(
            stream_id,
            source_object,
            source_count,
            landed_count,
            &differences,
        );
        sqlx::query(
            "UPDATE ingest_stream
             SET reconcile_fingerprint=$1, reconcile_seen_at=now(),
                 reconcile_expected=$2, reconcile_unexpected=$3
             WHERE id=$4 AND organization_id=$5",
        )
        .bind(&fingerprint)
        .bind(source_count)
        .bind(serde_json::json!(differences))
        .bind(stream_id)
        .bind(ctx.organization_id.0)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ReconciliationReport {
            id,
            source_count,
            landed_count,
            differences,
        })
    }

    /// Stable identity of one reconciliation outcome. Deliberately
    /// excludes timestamps: identical observations hash identically.
    fn fingerprint(
        stream_id: Uuid,
        source_object: &str,
        source_count: i64,
        landed_count: i64,
        differences: &[String],
    ) -> String {
        let canonical = serde_json::json!({
            "stream_id": stream_id,
            "source_object": source_object,
            "source_count": source_count,
            "landed_count": landed_count,
            "differences": differences,
        });
        let mut h = Sha256::new();
        h.update(canonical.to_string().as_bytes());
        format!("{:x}", h.finalize())
    }
}
