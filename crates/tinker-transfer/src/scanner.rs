//! Dependency scanner and replacement dashboard (PRD v0.6 §22).
//!
//! The scanner records the strict reference graph: which apps, queries,
//! views, transforms, mutation mappings, and agent attachments reference
//! which fields — including references whose target is still owned by an
//! external system. Retirement is blocked while any edge points at the
//! retiring system. The dashboard renders the replacement state for one
//! system: authority split, sync health, reconciliation drift, external
//! dependencies, and retirement readiness.

use serde::{Deserialize, Serialize};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::model::SyncHealth;

/// One recorded dependency edge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub source_kind: String,
    pub source_id: String,
    pub target_object_id: Option<Uuid>,
    pub target_field_api: Option<String>,
    pub edge_kind: String,
    pub external_system_key: Option<String>,
}

/// Raw row shape behind [`DependencyEdge`].
type EdgeRow = (
    String,
    String,
    Option<Uuid>,
    Option<String>,
    String,
    Option<String>,
);

pub struct DependencyScanner {
    core: CoreDb,
}

impl DependencyScanner {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Record one edge. `external_system_key` is set when the edge's
    /// target is still owned by an external system (authority
    /// `external`) or the source itself is that system's connector.
    /// Source kinds are allowlisted: arbitrary strings would make the
    /// graph unqueryable.
    pub async fn record_edge(&self, ctx: &TenantContext, edge: &DependencyEdge) -> Result<()> {
        const KINDS: &[&str] = &[
            "app",
            "query",
            "view",
            "transform",
            "mutation",
            "agent",
            "connector",
        ];
        if !KINDS.contains(&edge.source_kind.as_str()) {
            return Err(TinkerError::Validation(format!(
                "unknown source_kind: {}",
                edge.source_kind
            )));
        }
        if edge.source_id.trim().is_empty() || edge.source_id.len() > 256 {
            return Err(TinkerError::Validation(
                "source_id must be 1..=256 chars".into(),
            ));
        }
        if edge.edge_kind.trim().is_empty() || edge.edge_kind.len() > 64 {
            return Err(TinkerError::Validation(
                "edge_kind must be 1..=64 chars".into(),
            ));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO dependency_edges
                 (organization_id, source_kind, source_id, target_object_id,
                  target_field_api, edge_kind, external_system_key)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(ctx.organization_id.0)
        .bind(&edge.source_kind)
        .bind(&edge.source_id)
        .bind(edge.target_object_id)
        .bind(edge.target_field_api.clone())
        .bind(&edge.edge_kind)
        .bind(edge.external_system_key.clone())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Remove all edges from one source (e.g. an app that was rewired off
    /// the external system). Returns the removed count.
    pub async fn remove_source_edges(
        &self,
        ctx: &TenantContext,
        source_kind: &str,
        source_id: &str,
    ) -> Result<i64> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "DELETE FROM dependency_edges
             WHERE organization_id = $1 AND source_kind = $2 AND source_id = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(source_kind)
        .bind(source_id)
        .execute(&mut *tx)
        .await?
        .rows_affected() as i64;
        tx.commit().await?;
        Ok(n)
    }

    /// All edges still pointing at an external system. Non-empty blocks
    /// retirement — this is the scan the cutover gate's `dependency_scan`
    /// item records.
    pub async fn external_refs(
        &self,
        ctx: &TenantContext,
        system_key: &str,
    ) -> Result<Vec<DependencyEdge>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<EdgeRow> = sqlx::query_as(
            "SELECT source_kind, source_id, target_object_id,
                    target_field_api, edge_kind, external_system_key
             FROM dependency_edges
             WHERE organization_id = $1 AND external_system_key = $2
             ORDER BY source_kind, source_id",
        )
        .bind(ctx.organization_id.0)
        .bind(system_key)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    source_kind,
                    source_id,
                    target_object_id,
                    target_field_api,
                    edge_kind,
                    external_system_key,
                )| {
                    DependencyEdge {
                        source_kind,
                        source_id,
                        target_object_id,
                        target_field_api,
                        edge_kind,
                        external_system_key,
                    }
                },
            )
            .collect())
    }

    /// Count of edges still pointing at the system.
    pub async fn external_ref_count(&self, ctx: &TenantContext, system_key: &str) -> Result<i64> {
        Ok(self.external_refs(ctx, system_key).await?.len() as i64)
    }
}

/// The replacement dashboard for one system (PRD v0.6 §22): objects and
/// fields mapped/unmapped/conflicting, sync freshness and lag, errors and
/// retries, reconciliation drift, native vs dual-write health, external
/// dependencies, and retirement readiness. Read-only over M8 tables plus
/// sync health supplied from the ingest control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplacementReport {
    pub system_key: String,
    pub display_name: String,
    pub state: String,
    pub connector_state: String,
    /// (tinker-owned fields, external-owned fields) at the current
    /// authority version.
    pub authority_split: (i64, i64),
    pub sync: SyncHealth,
    pub external_dependency_count: i64,
    /// Retirement readiness: each gate item and whether the latest
    /// completed retire run verified it.
    pub retirement_readiness: Vec<(String, bool)>,
    /// State history for the audit trail.
    pub state_history: serde_json::Value,
}

pub struct ReplacementDashboard {
    core: CoreDb,
}

impl ReplacementDashboard {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    pub async fn report(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
        sync: SyncHealth,
    ) -> Result<ReplacementReport> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let sys: Option<(String, String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT system_key, display_name, current_state, state_history
             FROM transfer_systems
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (system_key, display_name, state, history) =
            sys.ok_or_else(|| TinkerError::NotFound("transfer system".into()))?;
        let conn: (String,) = sqlx::query_as(
            "SELECT connector_state FROM transfer_systems
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_one(&mut *tx)
        .await?;
        let split: (i64, i64) = sqlx::query_as(
            "SELECT COUNT(*) FILTER (WHERE authority = 'tinker'),
                    COUNT(*) FILTER (WHERE authority = 'external')
             FROM authority_matrix
             WHERE organization_id = $1 AND system_id = $2
               AND superseded_at IS NULL",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_one(&mut *tx)
        .await?;
        let dep_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM dependency_edges
             WHERE organization_id = $1 AND external_system_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(&system_key)
        .fetch_one(&mut *tx)
        .await?;
        // Retirement readiness from the latest completed retire run.
        let latest: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT checklist FROM cutover_runs
             WHERE organization_id = $1 AND system_id = $2
               AND kind = 'retire' AND status = 'complete'
             ORDER BY completed_at DESC NULLS LAST LIMIT 1",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        let readiness = crate::model::FULL_GATE
            .iter()
            .map(|item| {
                let ok = latest
                    .as_ref()
                    .and_then(|(c,)| c.get(*item))
                    .and_then(|v| v.get("verified"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                (item.to_string(), ok)
            })
            .collect();

        Ok(ReplacementReport {
            system_key,
            display_name,
            state,
            connector_state: conn.0,
            authority_split: split,
            sync,
            external_dependency_count: dep_count.0,
            retirement_readiness: readiness,
            state_history: history,
        })
    }
}
