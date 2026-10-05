//! Notification routing: preferences, quiet hours, batching.
//!
//! Every notification intent is routed through the member's preferences
//! with an injected `now` (tests use fixed clocks, never wall time):
//!
//! - `off` -> recorded as `suppressed` (auditable, never delivered).
//! - inside the quiet-hours window -> `deferred` until the window ends.
//! - `digest` -> collected into one delivery per batch window: a second
//!   notification in the same window appends to the existing outbox row
//!   instead of enqueueing a new one.
//! - otherwise -> `queued` for immediate delivery.
//!
//! Payloads carry ids and opaque refs only — no PII, no bodies.

use chrono::{DateTime, NaiveTime, TimeZone, Utc};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::delivery::{DeliveryWorker, EnqueueRequest};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryMode {
    Immediate,
    Digest,
    Off,
}

impl DeliveryMode {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "immediate" => Ok(Self::Immediate),
            "digest" => Ok(Self::Digest),
            "off" => Ok(Self::Off),
            other => Err(TinkerError::Validation(format!(
                "bad delivery mode: {other}"
            ))),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Immediate => "immediate",
            Self::Digest => "digest",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone)]
pub struct NotificationPrefs {
    pub mode: DeliveryMode,
    pub quiet_start: Option<NaiveTime>,
    pub quiet_end: Option<NaiveTime>,
    pub digest_window_minutes: i64,
}

impl Default for NotificationPrefs {
    fn default() -> Self {
        Self {
            mode: DeliveryMode::Immediate,
            quiet_start: None,
            quiet_end: None,
            digest_window_minutes: 60,
        }
    }
}

/// Validated preference input (also the shape of the HTTP PUT body).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PrefsInput {
    pub mode: String,
    pub quiet_start: Option<String>,
    pub quiet_end: Option<String>,
    pub digest_window_minutes: Option<i64>,
}

/// One notification item: a kind plus an opaque record ref. Never PII.
#[derive(Debug, Clone, serde::Serialize)]
pub struct NotificationItem {
    pub kind: String,
    pub ref_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingOutcome {
    Queued(Uuid),
    Deferred(Uuid),
    Batched(Uuid),
    Suppressed(Uuid),
}

impl RoutingOutcome {
    pub fn delivery_id(&self) -> Uuid {
        match self {
            Self::Queued(id) | Self::Deferred(id) | Self::Batched(id) | Self::Suppressed(id) => *id,
        }
    }
}

#[derive(Clone)]
pub struct NotificationRouter {
    core: CoreDb,
}
impl NotificationRouter {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Validate and store a member's preferences. Malformed input is
    /// rejected here — never persisted half-applied.
    pub async fn set_prefs(
        &self,
        ctx: &TenantContext,
        actor_id: Uuid,
        input: PrefsInput,
    ) -> Result<NotificationPrefs> {
        let prefs = validate_prefs(input)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO notification_prefs
             (organization_id, actor_id, mode, quiet_start, quiet_end, digest_window_minutes, updated_at)
             VALUES ($1,$2,$3,$4,$5,$6,now())
             ON CONFLICT (organization_id, actor_id) DO UPDATE SET
               mode=EXCLUDED.mode, quiet_start=EXCLUDED.quiet_start,
               quiet_end=EXCLUDED.quiet_end,
               digest_window_minutes=EXCLUDED.digest_window_minutes,
               updated_at=now()",
        )
        .bind(ctx.organization_id.0)
        .bind(actor_id)
        .bind(prefs.mode.as_str())
        .bind(prefs.quiet_start)
        .bind(prefs.quiet_end)
        .bind(prefs.digest_window_minutes as i32)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(prefs)
    }

    pub async fn get_prefs(
        &self,
        ctx: &TenantContext,
        actor_id: Uuid,
    ) -> Result<NotificationPrefs> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, Option<NaiveTime>, Option<NaiveTime>, i32)> = sqlx::query_as(
            "SELECT mode, quiet_start, quiet_end, digest_window_minutes
             FROM notification_prefs WHERE organization_id=$1 AND actor_id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(actor_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            None => Ok(NotificationPrefs::default()),
            Some((mode, qs, qe, window)) => Ok(NotificationPrefs {
                mode: DeliveryMode::parse(&mode)?,
                quiet_start: qs,
                quiet_end: qe,
                digest_window_minutes: window as i64,
            }),
        }
    }

    /// Route one notification intent for a member at `now`.
    pub async fn route(
        &self,
        ctx: &TenantContext,
        worker: &DeliveryWorker,
        member_actor_id: Uuid,
        item: NotificationItem,
        now: DateTime<Utc>,
    ) -> Result<RoutingOutcome> {
        let prefs = self.get_prefs(ctx, member_actor_id).await?;
        let item_json = serde_json::json!({ "kind": item.kind, "ref": item.ref_id.to_string() });

        match prefs.mode {
            DeliveryMode::Off => {
                let (id, _) = worker
                    .enqueue(
                        ctx,
                        EnqueueRequest {
                            kind: "notification",
                            idempotency_key: format!("notif:{}:{}", member_actor_id, item.ref_id),
                            payload: serde_json::json!({
                                "to_actor": member_actor_id.to_string(),
                                "subject": "notification",
                                "items": [item_json],
                            }),
                            status: "suppressed",
                            deliver_after: None,
                        },
                    )
                    .await?;
                Ok(RoutingOutcome::Suppressed(id))
            }
            _ if in_quiet_hours(&prefs, now) => {
                let deliver_after = quiet_window_end(&prefs, now)
                    .ok_or_else(|| TinkerError::Internal("quiet window has no end".into()))?;
                let (id, _) = worker
                    .enqueue(
                        ctx,
                        EnqueueRequest {
                            kind: "notification",
                            idempotency_key: format!("notif:{}:{}", member_actor_id, item.ref_id),
                            payload: serde_json::json!({
                                "to_actor": member_actor_id.to_string(),
                                "subject": "notification",
                                "items": [item_json],
                            }),
                            status: "deferred",
                            deliver_after: Some(deliver_after),
                        },
                    )
                    .await?;
                Ok(RoutingOutcome::Deferred(id))
            }
            DeliveryMode::Digest => {
                let window = prefs.digest_window_minutes.max(1);
                let window_secs = window * 60;
                let epoch = now.timestamp();
                let window_start = epoch - (epoch % window_secs);
                let key = format!("digest:{member_actor_id}:{window_start}");
                let deliver_after = Utc.timestamp_opt(window_start + window_secs, 0).single();
                let (id, created) = worker
                    .enqueue(
                        ctx,
                        EnqueueRequest {
                            kind: "notification",
                            idempotency_key: key,
                            payload: serde_json::json!({
                                "to_actor": member_actor_id.to_string(),
                                "subject": "digest",
                                "items": [item_json],
                                "window_start": window_start,
                            }),
                            status: "queued",
                            deliver_after,
                        },
                    )
                    .await?;
                if !created {
                    // Same window, same member: append to the batch instead
                    // of enqueueing a second delivery.
                    let mut tx = self.core.tenant_tx(ctx).await?;
                    sqlx::query(
                        "UPDATE delivery_outbox
                         SET payload_ref = jsonb_set(payload_ref, '{items}',
                               (payload_ref->'items') || $3::jsonb),
                             updated_at=now()
                         WHERE id=$1 AND organization_id=$2",
                    )
                    .bind(id)
                    .bind(ctx.organization_id.0)
                    .bind(serde_json::json!([item_json]))
                    .execute(&mut *tx)
                    .await?;
                    tx.commit().await?;
                }
                Ok(RoutingOutcome::Batched(id))
            }
            DeliveryMode::Immediate => {
                let (id, _) = worker
                    .enqueue(
                        ctx,
                        EnqueueRequest {
                            kind: "notification",
                            idempotency_key: format!("notif:{}:{}", member_actor_id, item.ref_id),
                            payload: serde_json::json!({
                                "to_actor": member_actor_id.to_string(),
                                "subject": "notification",
                                "items": [item_json],
                            }),
                            status: "queued",
                            deliver_after: None,
                        },
                    )
                    .await?;
                Ok(RoutingOutcome::Queued(id))
            }
        }
    }
}

fn validate_prefs(input: PrefsInput) -> Result<NotificationPrefs> {
    let mode = DeliveryMode::parse(&input.mode)?;
    let quiet_start = match input.quiet_start {
        Some(s) => Some(s.parse::<NaiveTime>().map_err(|_| {
            TinkerError::Validation(format!("bad quiet_start (want HH:MM:SS): {s}"))
        })?),
        None => None,
    };
    let quiet_end =
        match input.quiet_end {
            Some(s) => Some(s.parse::<NaiveTime>().map_err(|_| {
                TinkerError::Validation(format!("bad quiet_end (want HH:MM:SS): {s}"))
            })?),
            None => None,
        };
    // A half window is ambiguous: both or neither (the DB CHECK agrees).
    if quiet_start.is_some() != quiet_end.is_some() {
        return Err(TinkerError::Validation(
            "quiet_start and quiet_end must both be set or both be absent".into(),
        ));
    }
    if let (Some(s), Some(e)) = (quiet_start, quiet_end) {
        if s == e {
            return Err(TinkerError::Validation(
                "quiet window must be non-empty".into(),
            ));
        }
    }
    let window = input.digest_window_minutes.unwrap_or(60);
    if window <= 0 || window > 24 * 60 {
        return Err(TinkerError::Validation(
            "digest_window_minutes must be 1-1440".into(),
        ));
    }
    Ok(NotificationPrefs {
        mode,
        quiet_start,
        quiet_end,
        digest_window_minutes: window,
    })
}

/// True when `now` falls inside the member's quiet window. Overnight
/// windows (start > end, e.g. 22:00-07:00) wrap past midnight.
fn in_quiet_hours(prefs: &NotificationPrefs, now: DateTime<Utc>) -> bool {
    let (Some(start), Some(end)) = (prefs.quiet_start, prefs.quiet_end) else {
        return false;
    };
    let t = now.time();
    if start < end {
        t >= start && t < end
    } else {
        t >= start || t < end
    }
}

/// When the current quiet window ends (today or tomorrow).
fn quiet_window_end(prefs: &NotificationPrefs, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let (Some(start), Some(end)) = (prefs.quiet_start, prefs.quiet_end) else {
        return None;
    };
    let t = now.time();
    let date = now.date_naive();
    if start < end {
        // Same-day window; now is inside it.
        Some(date.and_time(end).and_utc())
    } else if t >= start {
        // Overnight window entered this evening: ends tomorrow.
        Some((date + chrono::Days::new(1)).and_time(end).and_utc())
    } else {
        // Overnight window entered before midnight: ends today.
        Some(date.and_time(end).and_utc())
    }
}
