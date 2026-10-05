//! Approval flows: destructive and external operations queue behind
//! explicit confirmation.
//!
//! Lifecycle: request (pending, with a deadline) → approve/deny (human or
//! policy) → execute. A pending request past its `expires_at` can never be
//! decided or executed — it transitions to `expired` (lazily on
//! decide/execute, or in bulk via [`ApprovalEngine::expire_stale_approvals`])
//! and the caller must queue a fresh request. A pending request that sits
//! past the escalation threshold is surfaced by
//! [`ApprovalEngine::escalation_due`] and flagged by
//! [`ApprovalEngine::mark_escalated`], which returns the rows needing a
//! human nudge — the human-notification hook. Escalation never changes
//! decidability; expiry is fail-closed.
//!
//! Idempotency keys make retries safe: the same key returns the same
//! request row instead of queueing a duplicate. Generated text from
//! executed actions is attributed with model/run metadata.

use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

/// Default time-to-live for a queued approval request: 24 hours. A pending
/// request older than this can never be approved — stale context must not
/// authorize destructive or external actions.
pub const DEFAULT_APPROVAL_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Default escalation threshold: a pending request sitting longer than
/// this is due for a human nudge. 4 hours keeps it well inside the TTL.
pub const DEFAULT_ESCALATION_AFTER: std::time::Duration = std::time::Duration::from_secs(4 * 3600);

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: Uuid,
    /// The agent attachment that raised the request; `None` for requests
    /// a person raised directly (e.g. a PII reveal).
    pub attachment_id: Option<Uuid>,
    pub action_name: String,
    pub payload: serde_json::Value,
    pub idempotency_key: String,
    pub status: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub escalated_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The actor who queued the request; `None` only for rows created
    /// before requesters were recorded (migration 0047).
    pub requested_by: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct ApprovalPolicy {
    /// e.g. human_before_external_send: external actions need a human.
    pub human_before_external_send: bool,
    /// Seconds a queued request stays decidable (default 86400).
    pub ttl_secs: u64,
    /// Seconds a pending request may sit before it is escalation-due
    /// (default 14400).
    pub escalation_after_secs: u64,
}

impl Default for ApprovalPolicy {
    fn default() -> Self {
        Self {
            human_before_external_send: false,
            ttl_secs: DEFAULT_APPROVAL_TTL.as_secs(),
            escalation_after_secs: DEFAULT_ESCALATION_AFTER.as_secs(),
        }
    }
}

impl ApprovalPolicy {
    pub fn from_json(v: &serde_json::Value) -> Self {
        Self {
            human_before_external_send: v
                .get("human_before_external_send")
                .and_then(|b| b.as_bool())
                .unwrap_or(false),
            ttl_secs: v
                .get("ttl_secs")
                .and_then(|n| n.as_u64())
                .unwrap_or(DEFAULT_APPROVAL_TTL.as_secs()),
            escalation_after_secs: v
                .get("escalation_after_secs")
                .and_then(|n| n.as_u64())
                .unwrap_or(DEFAULT_ESCALATION_AFTER.as_secs()),
        }
    }
}

pub struct ApprovalEngine {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
}

/// A decoded approval_requests row: id, attachment_id, action_name,
/// payload, idempotency_key, status, expires_at, escalated_at.
type ApprovalRow = (
    Uuid,
    Option<Uuid>,
    String,
    serde_json::Value,
    String,
    String,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<Uuid>,
);

const ROW_COLUMNS: &str = "id, attachment_id, action_name, payload, idempotency_key, status, \
     expires_at, escalated_at, requested_by";

impl ApprovalEngine {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    fn to_request(row: ApprovalRow) -> ApprovalRequest {
        ApprovalRequest {
            id: row.0,
            attachment_id: row.1,
            action_name: row.2,
            payload: row.3,
            idempotency_key: row.4,
            status: row.5,
            expires_at: row.6,
            escalated_at: row.7,
            requested_by: row.8,
        }
    }

    /// Queue an approval request with the default TTL. Idempotent on
    /// (org, idempotency_key): a retry returns the existing row, never a
    /// duplicate.
    pub async fn request(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        action_name: &str,
        payload: serde_json::Value,
        idempotency_key: &str,
    ) -> Result<ApprovalRequest> {
        self.request_with_ttl(
            ctx,
            attachment_id,
            action_name,
            payload,
            idempotency_key,
            DEFAULT_APPROVAL_TTL,
        )
        .await
    }

    /// Queue an approval request with an explicit time-to-live. The
    /// idempotency retry returns the existing row as-is — including an
    /// already-expired one, so the caller sees `status = "expired"` and
    /// queues a fresh request under a new key rather than silently
    /// reviving a dead approval.
    pub async fn request_with_ttl(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        action_name: &str,
        payload: serde_json::Value,
        idempotency_key: &str,
        ttl: std::time::Duration,
    ) -> Result<ApprovalRequest> {
        self.insert_request(
            ctx,
            Some(attachment_id),
            action_name,
            payload,
            idempotency_key,
            ttl,
        )
        .await
    }

    /// A request a person raises directly (no agent attachment), e.g. a
    /// PII reveal awaiting a second person. Same TTL, idempotency and
    /// four-eyes rules as attached requests.
    pub async fn request_unattached(
        &self,
        ctx: &TenantContext,
        action_name: &str,
        payload: serde_json::Value,
        idempotency_key: &str,
    ) -> Result<ApprovalRequest> {
        self.insert_request(
            ctx,
            None,
            action_name,
            payload,
            idempotency_key,
            DEFAULT_APPROVAL_TTL,
        )
        .await
    }

    async fn insert_request(
        &self,
        ctx: &TenantContext,
        attachment_id: Option<Uuid>,
        action_name: &str,
        payload: serde_json::Value,
        idempotency_key: &str,
        ttl: std::time::Duration,
    ) -> Result<ApprovalRequest> {
        let ttl_chrono = chrono::Duration::from_std(ttl)
            .map_err(|_| TinkerError::Validation("approval ttl out of range".into()))?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let existing: Option<ApprovalRow> = sqlx::query_as(&format!(
            "SELECT {ROW_COLUMNS} FROM approval_requests
             WHERE organization_id = $1 AND idempotency_key = $2",
        ))
        .bind(ctx.organization_id.0)
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = existing {
            // Same key, same attachment: the retry is the same request.
            // A key reused for a DIFFERENT attachment/action fails closed —
            // it would otherwise cross an authorization boundary.
            if row.1 != attachment_id || row.2 != action_name {
                tx.rollback().await?;
                return Err(TinkerError::Forbidden(
                    "idempotency key reused across attachment/action boundary".into(),
                ));
            }
            tx.commit().await?;
            return Ok(Self::to_request(row));
        }
        let row: ApprovalRow = sqlx::query_as(&format!(
            "INSERT INTO approval_requests
                 (organization_id, attachment_id, action_name, payload, idempotency_key, expires_at,
                  requested_by)
             VALUES ($1, $2, $3, $4, $5, now() + $6::interval, $7)
             RETURNING {ROW_COLUMNS}",
        ))
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .bind(action_name)
        .bind(&payload)
        .bind(idempotency_key)
        .bind(ttl_chrono)
        .bind(ctx.actor_id)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Self::to_request(row))
    }

    /// Transition this org's pending requests past their deadline to
    /// `expired`. Returns the number expired. The operator loop calls this
    /// per org on a schedule; decide/execute also expire lazily, so a
    /// missed sweep can never leave a decidable-but-stale request.
    pub async fn expire_stale_approvals(&self, ctx: &TenantContext) -> Result<u64> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE approval_requests SET status = 'expired'
             WHERE organization_id = $1 AND status = 'pending'
               AND expires_at IS NOT NULL AND expires_at <= now()",
        )
        .bind(ctx.organization_id.0)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        tx.commit().await?;
        Ok(n)
    }

    /// Decide a pending, unexpired request. Only the owning org's actors
    /// can decide (RLS), and only pending requests transition. An expired
    /// request fails closed with a distinct error — the caller must queue
    /// a fresh request; a stale approval can never authorize an action.
    pub async fn decide(
        &self,
        ctx: &TenantContext,
        request_id: Uuid,
        approve: bool,
    ) -> Result<ApprovalRequest> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Lazily expire: a request past its deadline is dead even if the
        // sweeper has not run yet.
        sqlx::query(
            "UPDATE approval_requests SET status = 'expired'
             WHERE organization_id = $1 AND id = $2 AND status = 'pending'
               AND expires_at IS NOT NULL AND expires_at <= now()",
        )
        .bind(ctx.organization_id.0)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let new_status = if approve { "approved" } else { "denied" };
        let row: Option<ApprovalRow> = sqlx::query_as(&format!(
            "UPDATE approval_requests
                 SET status = $3, decided_by = $4, decided_at = now()
                 WHERE organization_id = $1 AND id = $2 AND status = 'pending'
                   AND (expires_at IS NULL OR expires_at > now())
                   AND requested_by IS DISTINCT FROM $4
                 RETURNING {ROW_COLUMNS}",
        ))
        .bind(ctx.organization_id.0)
        .bind(request_id)
        .bind(new_status)
        .bind(ctx.actor_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = row {
            tx.commit().await?;
            return Ok(Self::to_request(row));
        }
        let state: Option<(String, Option<Uuid>)> = sqlx::query_as(
            "SELECT status, requested_by FROM approval_requests
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;
        // Commit, not rollback: the lazy expiry above is a legitimate state
        // transition that must persist even though the decision did not.
        tx.commit().await?;
        match state.as_ref().map(|s| (s.0.as_str(), s.1)) {
            Some(("expired", _)) => Err(TinkerError::Forbidden(
                "approval request expired; queue a new request".into(),
            )),
            // Four eyes: whoever queued a request can never decide it,
            // in either direction (a self-denial is as much a decision).
            Some(("pending", Some(requester))) if requester == ctx.actor_id => {
                Err(TinkerError::Forbidden(
                    "the requester cannot decide their own approval request".into(),
                ))
            }
            _ => Err(TinkerError::NotFound(
                "approval request not found or not pending".into(),
            )),
        }
    }

    /// Mark an approved, unexpired request executed. The executor must
    /// present the approval; executing without one fails closed at the
    /// action layer. An approval that lapsed between decision and
    /// execution fails closed too — the action needs a fresh approval.
    pub async fn mark_executed(
        &self,
        ctx: &TenantContext,
        request_id: Uuid,
    ) -> Result<ApprovalRequest> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "UPDATE approval_requests SET status = 'expired'
             WHERE organization_id = $1 AND id = $2 AND status = 'approved'
               AND expires_at IS NOT NULL AND expires_at <= now()",
        )
        .bind(ctx.organization_id.0)
        .bind(request_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let row: Option<ApprovalRow> = sqlx::query_as(&format!(
            "UPDATE approval_requests SET status = 'executed'
                 WHERE organization_id = $1 AND id = $2 AND status = 'approved'
                   AND (expires_at IS NULL OR expires_at > now())
                 RETURNING {ROW_COLUMNS}",
        ))
        .bind(ctx.organization_id.0)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(row) = row {
            tx.commit().await?;
            return Ok(Self::to_request(row));
        }
        let state: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM approval_requests
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;
        // Commit, not rollback: the lazy expiry above must persist even
        // though the execution did not.
        tx.commit().await?;
        match state.as_ref().map(|s| s.0.as_str()) {
            Some("expired") => Err(TinkerError::Forbidden(
                "approval expired before execution; queue a new request".into(),
            )),
            _ => Err(TinkerError::Forbidden(
                "action executed without an approval".into(),
            )),
        }
    }

    /// Pending requests that have sat longer than `after` without being
    /// decided and were never escalated, oldest first. This is the
    /// human-notification hook's input: the caller delivers the nudge
    /// (chat/email/page) and then calls `mark_escalated`.
    pub async fn escalation_due(
        &self,
        ctx: &TenantContext,
        after: std::time::Duration,
    ) -> Result<Vec<ApprovalRequest>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<ApprovalRow> = sqlx::query_as(&format!(
            "SELECT {ROW_COLUMNS} FROM approval_requests
             WHERE organization_id = $1 AND status = 'pending'
               AND escalated_at IS NULL
               AND created_at <= now() - make_interval(secs => $2)
             ORDER BY created_at ASC",
        ))
        .bind(ctx.organization_id.0)
        .bind(after.as_secs_f64())
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(Self::to_request).collect())
    }

    /// Flag requests as escalated (a human has been nudged). Only pending,
    /// never-escalated rows transition; returns the rows that were
    /// actually flagged, so the notifier knows exactly what it announced.
    /// Escalation never changes decidability — an escalated request is
    /// still decided or expired by the normal rules.
    pub async fn mark_escalated(
        &self,
        ctx: &TenantContext,
        request_ids: &[Uuid],
    ) -> Result<Vec<ApprovalRequest>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<ApprovalRow> = sqlx::query_as(&format!(
            "UPDATE approval_requests SET escalated_at = now()
             WHERE organization_id = $1 AND id = ANY($2)
               AND status = 'pending' AND escalated_at IS NULL
             RETURNING {ROW_COLUMNS}",
        ))
        .bind(ctx.organization_id.0)
        .bind(request_ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(Self::to_request).collect())
    }

    pub async fn get(&self, ctx: &TenantContext, request_id: Uuid) -> Result<ApprovalRequest> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<ApprovalRow> = sqlx::query_as(&format!(
            "SELECT {ROW_COLUMNS} FROM approval_requests
             WHERE organization_id = $1 AND id = $2",
        ))
        .bind(ctx.organization_id.0)
        .bind(request_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(Self::to_request)
            .ok_or_else(|| TinkerError::NotFound("approval request".into()))
    }
}
