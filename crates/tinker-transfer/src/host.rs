//! Host/portfolio operator plane (PRD v0.6 §34).
//!
//! Token-blind aggregates: aggregate actors read only
//! `host_usage_daily`, which structurally cannot carry message bodies,
//! email content, field values, prompts, or record payloads — those
//! columns do not exist. Masked support: support actors enter
//! time-boxed, reason-bound sessions that are masked by default; a
//! sensitive reveal requires a second-party approval and becomes
//! tenant-visible audit.

use bigdecimal::BigDecimal;
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::model::ActorMode;

/// One token-blind aggregate row: counts and sums only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateRow {
    pub host_id: Uuid,
    pub organization_id: Uuid,
    pub day: NaiveDate,
    pub metric_id: String,
    pub count_value: i64,
    pub sum_value: BigDecimal,
    pub dimensions: serde_json::Value,
}

/// Raw row shape behind `AggregateRow`.
type AggregateRowTuple = (
    Uuid,
    Uuid,
    NaiveDate,
    String,
    i64,
    BigDecimal,
    serde_json::Value,
);

/// One token-blind metric observation: counts and sums only, never a
/// payload. Dimensions must be a JSON object of low-cardinality,
/// non-identifying labels.
#[derive(Debug, Clone)]
pub struct TelemetryPoint {
    pub host_id: Uuid,
    pub day: NaiveDate,
    pub metric_id: String,
    pub count: i64,
    pub sum: BigDecimal,
    pub dimensions: serde_json::Value,
}

/// A token-blind aggregate read. `org_filter` narrows the portfolio
/// view to one organization; tenant mode ignores it and uses the
/// caller's own organization.
#[derive(Debug, Clone)]
pub struct AggregateQuery {
    pub host_id: Uuid,
    pub org_filter: Option<Uuid>,
    pub day_from: NaiveDate,
    pub day_to: NaiveDate,
    pub metric_ids: Vec<String>,
}

pub struct Telemetry {
    core: CoreDb,
}

impl Telemetry {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    fn dimensions_hash(dimensions: &serde_json::Value) -> String {
        // Canonical hash: BTreeMap ordering makes the JSON deterministic.
        let canon = serde_json::to_string(dimensions).unwrap_or_default();
        let mut h = Sha256::new();
        h.update(canon.as_bytes());
        format!("{:x}", h.finalize())
    }

    /// Record one metric observation. Upserts the
    /// (host, org, day, metric, dimensions) row — never a payload.
    pub async fn record(&self, ctx: &TenantContext, point: &TelemetryPoint) -> Result<()> {
        if point.metric_id.trim().is_empty() || point.metric_id.len() > 128 {
            return Err(TinkerError::Validation(
                "metric_id must be 1..=128 chars".into(),
            ));
        }
        if !point.dimensions.is_object() {
            return Err(TinkerError::Validation(
                "dimensions must be a JSON object".into(),
            ));
        }
        let hash = Self::dimensions_hash(&point.dimensions);
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO host_usage_daily
                 (host_id, organization_id, day, metric_id,
                  count_value, sum_value, dimensions_json, dimensions_hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (host_id, organization_id, day, metric_id, dimensions_hash)
             DO UPDATE SET count_value = host_usage_daily.count_value + EXCLUDED.count_value,
                           sum_value = host_usage_daily.sum_value + EXCLUDED.sum_value,
                           collected_at = now()",
        )
        .bind(point.host_id)
        .bind(ctx.organization_id.0)
        .bind(point.day)
        .bind(&point.metric_id)
        .bind(point.count)
        .bind(&point.sum)
        .bind(&point.dimensions)
        .bind(hash)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Read token-blind aggregates.
    ///
    /// - `ActorMode::Aggregate`: may read across organizations (the
    ///   portfolio view). This is the only cross-org read in the
    ///   operator plane, and the table cannot carry payloads.
    /// - `ActorMode::Tenant`: may read only its own organization.
    /// - `ActorMode::Support`: denied — support uses masked sessions,
    ///   not the aggregate table.
    pub async fn read_aggregates(
        &self,
        ctx: &TenantContext,
        mode: ActorMode,
        query: &AggregateQuery,
    ) -> Result<Vec<AggregateRow>> {
        match mode {
            ActorMode::Support => {
                return Err(TinkerError::Forbidden(
                    "support actors cannot read aggregates; use a masked session".into(),
                ))
            }
            ActorMode::Tenant => {
                if query.org_filter.is_some_and(|o| o != ctx.organization_id.0) {
                    return Err(TinkerError::Forbidden(
                        "tenant actors read only their own organization".into(),
                    ));
                }
            }
            ActorMode::Aggregate => {}
        }
        if query.metric_ids.is_empty() || query.metric_ids.len() > 64 {
            return Err(TinkerError::Validation(
                "metric_ids must be 1..=64 entries".into(),
            ));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        // NOTE: metric_ids are bound as an array — never interpolated —
        // so a hostile metric id cannot alter the statement.
        let rows: Vec<AggregateRowTuple> = sqlx::query_as(
            "SELECT host_id, organization_id, day, metric_id,
                    count_value, sum_value, dimensions_json
             FROM host_usage_daily
             WHERE host_id = $1
               AND ($2::uuid IS NULL OR organization_id = $2)
               AND day BETWEEN $3 AND $4
               AND metric_id = ANY($5)
             ORDER BY day, metric_id",
        )
        .bind(query.host_id)
        .bind(query.org_filter)
        .bind(query.day_from)
        .bind(query.day_to)
        .bind(&query.metric_ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(
                |(host_id, organization_id, day, metric_id, count_value, sum_value, dimensions)| {
                    AggregateRow {
                        host_id,
                        organization_id,
                        day,
                        metric_id,
                        count_value,
                        sum_value,
                        dimensions,
                    }
                },
            )
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Masked support sessions.
// ---------------------------------------------------------------------------

/// A masked projection of one record for a support session.
pub type MaskedRecord = BTreeMap<String, serde_json::Value>;

pub const MASK: &str = "▪▪▪";

pub struct SupportEngine {
    core: CoreDb,
}

impl SupportEngine {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Open a time-boxed, reason-bound session. `field_classes` maps
    /// field names to "restricted" (masked) or "operational" (visible).
    /// TTL is clamped to [60s, 8h]: a support session must not be
    /// permanent, and must not be so short it is useless.
    pub async fn open_session(
        &self,
        ctx: &TenantContext,
        support_actor_id: Uuid,
        host_id: Uuid,
        field_classes: &BTreeMap<String, String>,
        reason: &str,
        ttl_secs: i64,
    ) -> Result<Uuid> {
        if reason.trim().is_empty() || reason.len() > 1024 {
            return Err(TinkerError::Validation(
                "reason must be 1..=1024 chars".into(),
            ));
        }
        if !(60..=28_800).contains(&ttl_secs) {
            return Err(TinkerError::Validation(
                "support session TTL must be 60s..=8h".into(),
            ));
        }
        for (field, class) in field_classes {
            if class != "restricted" && class != "operational" {
                return Err(TinkerError::Validation(format!(
                    "unknown field class for {field}: {class}"
                )));
            }
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        // The support actor must be provisioned in this org (audit
        // attribution). Cross-org actor ids fail the composite FK.
        let actor_ok: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM actors WHERE organization_id = $1 AND id = $2")
                .bind(ctx.organization_id.0)
                .bind(support_actor_id)
                .fetch_optional(&mut *tx)
                .await?;
        if actor_ok.is_none() {
            return Err(TinkerError::NotFound("support actor".into()));
        }
        let classes = serde_json::to_value(field_classes)?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO support_sessions
                 (organization_id, host_id, support_actor_id,
                  field_classes, reason, expires_at)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
             RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(host_id)
        .bind(support_actor_id)
        .bind(classes)
        .bind(reason)
        .bind(ttl_secs as f64)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO support_audit
                 (organization_id, session_id, action, actor_id, details)
             VALUES ($1, $2, 'session.opened', $3,
                     jsonb_build_object('reason', $4::text))",
        )
        .bind(ctx.organization_id.0)
        .bind(id)
        .bind(support_actor_id)
        .bind(reason)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Masked read: restricted fields render as MASK. The session must be
    /// active and unexpired; expiry is applied lazily and fails closed.
    pub async fn masked_read(
        &self,
        ctx: &TenantContext,
        session_id: Uuid,
        record: &BTreeMap<String, serde_json::Value>,
    ) -> Result<MaskedRecord> {
        let classes = self.active_classes(ctx, session_id).await?;
        Ok(Self::apply_mask(&classes, record))
    }

    /// Request a reveal of one target (a field or record ref). The reveal
    /// itself needs a *second-party* approval before anything unmasks.
    pub async fn request_reveal(
        &self,
        ctx: &TenantContext,
        session_id: Uuid,
        target_ref: &str,
        reason: &str,
    ) -> Result<Uuid> {
        if target_ref.trim().is_empty() || target_ref.len() > 512 {
            return Err(TinkerError::Validation(
                "target_ref must be 1..=512 chars".into(),
            ));
        }
        if reason.trim().is_empty() || reason.len() > 1024 {
            return Err(TinkerError::Validation(
                "reason must be 1..=1024 chars".into(),
            ));
        }
        self.active_classes(ctx, session_id).await?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO reveal_requests
                 (organization_id, session_id, target_ref, reason, requested_by)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(session_id)
        .bind(target_ref)
        .bind(reason)
        .bind(ctx.actor_id)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO support_audit
                 (organization_id, session_id, action, actor_id, details)
             VALUES ($1, $2, 'reveal.requested', $3,
                     jsonb_build_object('target_ref', $4::text))",
        )
        .bind(ctx.organization_id.0)
        .bind(session_id)
        .bind(ctx.actor_id)
        .bind(target_ref)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Decide a reveal request. The decider must differ from the
    /// requester: self-approval is forbidden. Every decision is
    /// tenant-visible audit.
    pub async fn decide_reveal(
        &self,
        ctx: &TenantContext,
        reveal_id: Uuid,
        approve: bool,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(Uuid, Uuid, String, Uuid)> = sqlx::query_as(
            "SELECT session_id, requested_by, status, organization_id
             FROM reveal_requests
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(reveal_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (session_id, requested_by, status, _) =
            row.ok_or_else(|| TinkerError::NotFound("reveal request".into()))?;
        if status != "pending" {
            return Err(TinkerError::Validation(format!(
                "reveal request is {status}; decision is frozen"
            )));
        }
        if ctx.actor_id == requested_by {
            return Err(TinkerError::Forbidden(
                "second-party approval required: the requester cannot approve their own reveal"
                    .into(),
            ));
        }
        // The session must still be live at decision time.
        let live = self
            .session_live_tx(&mut tx, ctx.organization_id.0, session_id)
            .await?;
        if !live {
            return Err(TinkerError::Validation(
                "support session is no longer active".into(),
            ));
        }
        let new_status = if approve { "approved" } else { "denied" };
        sqlx::query(
            "UPDATE reveal_requests
             SET status = $3, decided_by = $4, decided_at = now()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(reveal_id)
        .bind(new_status)
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO support_audit
                 (organization_id, session_id, action, actor_id, details)
             VALUES ($1, $2, $3, $4,
                     jsonb_build_object('reveal_id', $5::text))",
        )
        .bind(ctx.organization_id.0)
        .bind(session_id)
        .bind(format!("reveal.{new_status}"))
        .bind(ctx.actor_id)
        .bind(reveal_id.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Read a record with an approved reveal: the revealed target field
    /// unmasks; everything else stays masked. Requires the reveal to be
    /// approved and the session live.
    pub async fn revealed_read(
        &self,
        ctx: &TenantContext,
        session_id: Uuid,
        reveal_id: Uuid,
        record: &BTreeMap<String, serde_json::Value>,
    ) -> Result<MaskedRecord> {
        let classes = self.active_classes(ctx, session_id).await?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT target_ref, status FROM reveal_requests
             WHERE organization_id = $1 AND id = $2 AND session_id = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(reveal_id)
        .bind(session_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let (target_ref, status) =
            row.ok_or_else(|| TinkerError::NotFound("reveal request".into()))?;
        if status != "approved" {
            return Err(TinkerError::Forbidden(
                "reveal is not approved; masked read only".into(),
            ));
        }
        let mut out = Self::apply_mask(&classes, record);
        // Unmask exactly the approved target.
        if let Some(v) = record.get(&target_ref) {
            out.insert(target_ref, v.clone());
        }
        Ok(out)
    }

    pub async fn revoke_session(&self, ctx: &TenantContext, session_id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE support_sessions SET status = 'revoked'
             WHERE organization_id = $1 AND id = $2 AND status = 'active'",
        )
        .bind(ctx.organization_id.0)
        .bind(session_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(TinkerError::NotFound("active support session".into()));
        }
        sqlx::query(
            "INSERT INTO support_audit
                 (organization_id, session_id, action, actor_id)
             VALUES ($1, $2, 'session.revoked', $3)",
        )
        .bind(ctx.organization_id.0)
        .bind(session_id)
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Tenant-visible audit trail for one session.
    pub async fn audit_trail(
        &self,
        ctx: &TenantContext,
        session_id: Uuid,
    ) -> Result<Vec<(String, Uuid, serde_json::Value)>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(String, Uuid, serde_json::Value)> = sqlx::query_as(
            "SELECT action, actor_id, details FROM support_audit
             WHERE organization_id = $1 AND session_id = $2
             ORDER BY created_at",
        )
        .bind(ctx.organization_id.0)
        .bind(session_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().collect())
    }

    fn apply_mask(
        classes: &BTreeMap<String, String>,
        record: &BTreeMap<String, serde_json::Value>,
    ) -> MaskedRecord {
        let mut out = MaskedRecord::new();
        for (field, value) in record {
            match classes.get(field).map(String::as_str) {
                Some("restricted") => {
                    out.insert(field.clone(), serde_json::Value::String(MASK.into()));
                }
                _ => {
                    out.insert(field.clone(), value.clone());
                }
            }
        }
        out
    }

    /// Load the session's field classes, failing closed when the session
    /// is expired, revoked, or missing. Expiry is applied lazily.
    ///
    /// The session is bound to its opening support actor: only that
    /// actor may use the session (masked reads, reveal requests,
    /// reveal consumption). Anyone else in the tenant gets `Forbidden`
    /// — a second support agent cannot borrow a colleague's session.
    async fn active_classes(
        &self,
        ctx: &TenantContext,
        session_id: Uuid,
    ) -> Result<BTreeMap<String, String>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let live = self
            .session_live_tx(&mut tx, ctx.organization_id.0, session_id)
            .await?;
        if !live {
            return Err(TinkerError::Forbidden(
                "support session is not active".into(),
            ));
        }
        let row: (serde_json::Value, Uuid) = sqlx::query_as(
            "SELECT field_classes, support_actor_id FROM support_sessions
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(session_id)
        .fetch_one(&mut *tx)
        .await?;
        if row.1 != ctx.actor_id {
            return Err(TinkerError::Forbidden(
                "support session is bound to its opening support actor".into(),
            ));
        }
        tx.commit().await?;
        Ok(serde_json::from_value(row.0)?)
    }

    async fn session_live_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        org_id: Uuid,
        session_id: Uuid,
    ) -> Result<bool> {
        let row: Option<(String, chrono::DateTime<Utc>)> = sqlx::query_as(
            "SELECT status, expires_at FROM support_sessions
             WHERE organization_id = $1 AND id = $2 FOR UPDATE",
        )
        .bind(org_id)
        .bind(session_id)
        .fetch_optional(&mut **tx)
        .await?;
        let (status, expires_at) = match row {
            Some(r) => r,
            None => return Ok(false),
        };
        if status != "active" {
            return Ok(false);
        }
        if expires_at <= Utc::now() {
            sqlx::query(
                "UPDATE support_sessions SET status = 'expired'
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(org_id)
            .bind(session_id)
            .execute(&mut **tx)
            .await?;
            return Ok(false);
        }
        Ok(true)
    }
}
