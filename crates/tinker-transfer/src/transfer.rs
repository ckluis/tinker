//! Authority transfer engine (PRD v0.6 §22).
//!
//! Per-system state machine, versioned field-level authority matrix, and
//! cutover/rollback/retire runs with evidence checklists. Every write goes
//! through a tenant transaction; RLS is the backstop.

use chrono::Utc;
use serde_json::json;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::model::{
    Authority, CutoverKind, TransferState, CHECKLIST_ITEM_MAX_EVIDENCE, FULL_GATE, ROLLBACK_GATE,
};

/// Checklist items allowed per run kind.
fn gate_for(kind: CutoverKind) -> &'static [&'static str] {
    match kind {
        CutoverKind::Cutover | CutoverKind::Retire => FULL_GATE,
        CutoverKind::Rollback => ROLLBACK_GATE,
    }
}

pub struct TransferEngine {
    core: CoreDb,
}

impl TransferEngine {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Register an external system for strangler migration. Starts in
    /// `connected`; idempotent per (org, system_key).
    pub async fn register_system(
        &self,
        ctx: &TenantContext,
        system_key: &str,
        display_name: &str,
    ) -> Result<Uuid> {
        if system_key.trim().is_empty() || system_key.len() > 128 {
            return Err(TinkerError::Validation(
                "system_key must be 1..=128 chars".into(),
            ));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO transfer_systems (organization_id, system_key, display_name)
             VALUES ($1, $2, $3)
             ON CONFLICT (organization_id, system_key)
             DO UPDATE SET display_name = EXCLUDED.display_name,
                           updated_at = now()
             RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(system_key)
        .bind(display_name)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Current state + connector state for a system (tenant-scoped).
    pub async fn state_of(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
    ) -> Result<(TransferState, String)> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT current_state, connector_state FROM transfer_systems
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            Some((s, c)) => Ok((TransferState::parse(&s)?, c)),
            None => Err(TinkerError::NotFound("transfer system".into())),
        }
    }

    /// Advance one forward step. Gate requirements:
    /// - `controlled -> primary` needs a completed `cutover` run.
    /// - `draining -> retired` needs a completed `retire` run, the
    ///   connector removed, and zero external dependency edges.
    /// - `retired` is terminal.
    pub async fn advance(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
        by: Uuid,
        reason: &str,
    ) -> Result<TransferState> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT current_state, connector_state FROM transfer_systems
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (cur_s, connector_state) =
            row.ok_or_else(|| TinkerError::NotFound("transfer system".into()))?;
        let cur = TransferState::parse(&cur_s)?;
        let next = cur.forward().ok_or_else(|| {
            TinkerError::Validation("retired is terminal: no transitions out".into())
        })?;

        // Gate: cutover into primary requires a completed cutover run.
        if next == TransferState::Primary
            && !Self::has_completed_run_tx(&mut tx, ctx.organization_id.0, system_id, "cutover")
                .await?
        {
            return Err(TinkerError::Validation(
                "controlled -> primary requires a completed cutover run".into(),
            ));
        }
        // Gate: retirement requires a completed retire run, the connector
        // gone, and no remaining external dependency edges.
        if next == TransferState::Retired {
            if !Self::has_completed_run_tx(&mut tx, ctx.organization_id.0, system_id, "retire")
                .await?
            {
                return Err(TinkerError::Validation(
                    "draining -> retired requires a completed retire run".into(),
                ));
            }
            if connector_state != "removed" {
                return Err(TinkerError::Validation(
                    "retirement blocked: connector is still registered".into(),
                ));
            }
            let system_key: (String,) = sqlx::query_as(
                "SELECT system_key FROM transfer_systems WHERE organization_id = $1 AND id = $2",
            )
            .bind(ctx.organization_id.0)
            .bind(system_id)
            .fetch_one(&mut *tx)
            .await?;
            let refs: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM dependency_edges
                 WHERE organization_id = $1 AND external_system_key = $2",
            )
            .bind(ctx.organization_id.0)
            .bind(&system_key.0)
            .fetch_one(&mut *tx)
            .await?;
            if refs.0 > 0 {
                return Err(TinkerError::Validation(format!(
                    "retirement blocked: {} external dependency edge(s) still reference this system",
                    refs.0
                )));
            }
        }

        let history = json!([{
            "from": cur.as_str(), "to": next.as_str(),
            "at": Utc::now(), "by": by, "reason": reason,
        }]);
        sqlx::query(
            "UPDATE transfer_systems
             SET current_state = $3,
                 state_history = state_history || $4::jsonb,
                 updated_at = now()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .bind(next.as_str())
        .bind(history)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(next)
    }

    /// Roll back to `mirrored` from `primary` or `draining`. Requires a
    /// completed `rollback` run (plan + owner sign-off).
    pub async fn rollback(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
        by: Uuid,
        reason: &str,
    ) -> Result<TransferState> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT current_state FROM transfer_systems
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        let cur_s = row
            .ok_or_else(|| TinkerError::NotFound("transfer system".into()))?
            .0;
        let cur = TransferState::parse(&cur_s)?;
        if cur != TransferState::Primary && cur != TransferState::Draining {
            return Err(TinkerError::Validation(format!(
                "rollback is only defined from primary/draining, not {}",
                cur.as_str()
            )));
        }
        if !Self::has_completed_run_tx(&mut tx, ctx.organization_id.0, system_id, "rollback")
            .await?
        {
            return Err(TinkerError::Validation(
                "rollback requires a completed rollback run".into(),
            ));
        }
        let history = json!([{
            "from": cur.as_str(), "to": "mirrored",
            "at": Utc::now(), "by": by, "reason": reason,
        }]);
        sqlx::query(
            "UPDATE transfer_systems
             SET current_state = 'mirrored',
                 state_history = state_history || $3::jsonb,
                 updated_at = now()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .bind(history)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(TransferState::Mirrored)
    }

    /// Deregister the connector (and revoke its credential, recorded in
    /// evidence by the caller). Allowed from `draining`: the source is
    /// cut off except for rollback and audit.
    pub async fn remove_connector(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
        by: Uuid,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT current_state, connector_state FROM transfer_systems
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (cur_s, conn) = row.ok_or_else(|| TinkerError::NotFound("transfer system".into()))?;
        if conn == "removed" {
            return Err(TinkerError::Validation("connector already removed".into()));
        }
        let cur = TransferState::parse(&cur_s)?;
        if cur != TransferState::Draining {
            return Err(TinkerError::Validation(format!(
                "connector removal is only defined while draining, not {}",
                cur.as_str()
            )));
        }
        let history = json!([{
            "from": cur.as_str(), "to": cur.as_str(),
            "at": Utc::now(), "by": by,
            "reason": "connector deregistered; credential revoked",
        }]);
        sqlx::query(
            "UPDATE transfer_systems
             SET connector_state = 'removed',
                 state_history = state_history || $3::jsonb,
                 updated_at = now()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .bind(history)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Flip field authority with versioning: supersede the current
    /// effective rows, insert new ones at version+1. History is never
    /// rewritten. Objects must be tenant-visible (platform or own org).
    pub async fn set_authority(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
        object_id: Uuid,
        fields: &[(String, Authority)],
        _by: Uuid,
    ) -> Result<i64> {
        if fields.is_empty() {
            return Err(TinkerError::Validation("no fields to flip".into()));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        // The system must belong to this org (also pins the tenant FK).
        let sys: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM transfer_systems WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        if sys.is_none() {
            return Err(TinkerError::NotFound("transfer system".into()));
        }
        // Object visibility: platform objects (organization_id NULL) or
        // this org's own objects. Anything else is a 404 with no oracle.
        let vis: Option<(String,)> = sqlx::query_as(
            "SELECT scope_kind FROM ontology_objects
             WHERE id = $1 AND (organization_id IS NULL OR organization_id = $2)",
        )
        .bind(object_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await?;
        if vis.is_none() {
            return Err(TinkerError::NotFound("ontology object".into()));
        }
        let (max_v,): (Option<i64>,) = sqlx::query_as(
            "SELECT MAX(version) FROM authority_matrix
             WHERE organization_id = $1 AND system_id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_one(&mut *tx)
        .await?;
        let new_v = max_v.unwrap_or(0) + 1;
        for (api_name, auth) in fields {
            if api_name.trim().is_empty() || api_name.len() > 128 {
                return Err(TinkerError::Validation(
                    "field_api_name must be 1..=128 chars".into(),
                ));
            }
            sqlx::query(
                "UPDATE authority_matrix SET superseded_at = now()
                 WHERE organization_id = $1 AND system_id = $2
                   AND object_id = $3 AND field_api_name = $4
                   AND superseded_at IS NULL",
            )
            .bind(ctx.organization_id.0)
            .bind(system_id)
            .bind(object_id)
            .bind(api_name)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO authority_matrix
                     (organization_id, system_id, object_id, field_api_name,
                      authority, version)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(ctx.organization_id.0)
            .bind(system_id)
            .bind(object_id)
            .bind(api_name)
            .bind(auth.as_str())
            .bind(new_v)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(new_v)
    }

    /// Effective authority for one field, if any row exists.
    pub async fn effective_authority(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
        object_id: Uuid,
        field_api_name: &str,
    ) -> Result<Option<Authority>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT authority FROM authority_matrix
             WHERE organization_id = $1 AND system_id = $2
               AND object_id = $3 AND field_api_name = $4
               AND superseded_at IS NULL",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .bind(object_id)
        .bind(field_api_name)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(match row {
            Some((a,)) if a == "tinker" => Some(Authority::Tinker),
            Some((a,)) if a == "external" => Some(Authority::External),
            _ => None,
        })
    }

    /// Count effective rows per authority for the dashboard.
    pub async fn authority_split(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
    ) -> Result<(i64, i64)> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: (i64, i64) = sqlx::query_as(
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
        tx.commit().await?;
        Ok(row)
    }

    // ------------------------------------------------------------------
    // Cutover runs with evidence checklists.
    // ------------------------------------------------------------------

    pub async fn start_run(
        &self,
        ctx: &TenantContext,
        system_id: Uuid,
        kind: CutoverKind,
    ) -> Result<Uuid> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let sys: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM transfer_systems WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .fetch_optional(&mut *tx)
        .await?;
        if sys.is_none() {
            return Err(TinkerError::NotFound("transfer system".into()));
        }
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO cutover_runs (organization_id, system_id, kind)
             VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(system_id)
        .bind(kind.as_str())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Record one checklist item with real evidence. The item must belong
    /// to the run's kind gate; unknown keys are rejected (a typo must not
    /// silently pass the gate).
    pub async fn verify_checklist_item(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        item_key: &str,
        by: Uuid,
        evidence: &str,
    ) -> Result<()> {
        if evidence.trim().is_empty() || evidence.len() > CHECKLIST_ITEM_MAX_EVIDENCE {
            return Err(TinkerError::Validation(format!(
                "evidence must be 1..={CHECKLIST_ITEM_MAX_EVIDENCE} chars"
            )));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT kind, status FROM cutover_runs
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (kind_s, status) = row.ok_or_else(|| TinkerError::NotFound("cutover run".into()))?;
        if status != "pending" {
            return Err(TinkerError::Validation(format!(
                "run is {status}; checklist is frozen"
            )));
        }
        let kind = match kind_s.as_str() {
            "cutover" => CutoverKind::Cutover,
            "rollback" => CutoverKind::Rollback,
            _ => CutoverKind::Retire,
        };
        if !gate_for(kind).contains(&item_key) {
            return Err(TinkerError::Validation(format!(
                "unknown checklist item for {kind_s} runs: {item_key}"
            )));
        }
        let item = serde_json::to_value(crate::model::ChecklistItem {
            verified: true,
            by,
            at: Utc::now(),
            evidence: evidence.to_string(),
        })?;
        sqlx::query(
            "UPDATE cutover_runs
             SET checklist = checklist || jsonb_build_object($3::text, $4::jsonb)
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .bind(item_key)
        .bind(item)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Complete a run: every gate item must be verified with evidence.
    /// A missing item fails the run closed.
    pub async fn complete_run(&self, ctx: &TenantContext, run_id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT kind, status, checklist FROM cutover_runs
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (kind_s, status, checklist) =
            row.ok_or_else(|| TinkerError::NotFound("cutover run".into()))?;
        if status != "pending" {
            return Err(TinkerError::Validation(format!(
                "run is {status}; cannot complete twice"
            )));
        }
        let kind = match kind_s.as_str() {
            "cutover" => CutoverKind::Cutover,
            "rollback" => CutoverKind::Rollback,
            _ => CutoverKind::Retire,
        };
        for item_key in gate_for(kind) {
            let item = checklist.get(*item_key);
            let ok = item
                .and_then(|v| v.get("verified"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
                && item
                    .and_then(|v| v.get("evidence"))
                    .and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
            if !ok {
                return Err(TinkerError::Validation(format!(
                    "gate item missing or unverified: {item_key}"
                )));
            }
        }
        sqlx::query(
            "UPDATE cutover_runs SET status = 'complete', completed_at = now()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn fail_run(&self, ctx: &TenantContext, run_id: Uuid, reason: &str) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let evidence = json!({"failure_reason": reason});
        let n = sqlx::query(
            "UPDATE cutover_runs
             SET status = 'failed', completed_at = now(),
                 evidence = evidence || $3::jsonb
             WHERE organization_id = $1 AND id = $2 AND status = 'pending'",
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .bind(evidence)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::Validation(
                "run is not pending or does not exist".into(),
            ));
        }
        Ok(())
    }

    async fn has_completed_run_tx(
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        org_id: Uuid,
        system_id: Uuid,
        kind: &str,
    ) -> Result<bool> {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM cutover_runs
             WHERE organization_id = $1 AND system_id = $2
               AND kind = $3 AND status = 'complete'",
        )
        .bind(org_id)
        .bind(system_id)
        .bind(kind)
        .fetch_one(&mut **tx)
        .await?;
        Ok(n > 0)
    }
}
