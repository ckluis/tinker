//! Durable, idempotent delivery over the transactional outbox.
//!
//! Exactly-once has two independent layers, and the tests pin both:
//!
//! 1. **Tinker-side fencing** ([`tinker_durable::DurableRuntime::run_step`]
//!    with `effect_key = idempotency_key`): claim -> provider send ->
//!    checkpoint, with lease tokens so a stale worker's completion is
//!    rejected instead of clobbering the new owner's checkpoint.
//! 2. **Provider-side idempotency**: the provider dedupes on the same
//!    idempotency key. [`FakeEmailProvider`] models this with an in-memory
//!    send log: a second `send` with a recorded key returns the recorded
//!    receipt without a second actual send.
//!
//! An interrupted workflow (provider recorded the send, worker "crashed"
//! before the checkpoint) resumes with exactly one provider-side send and
//! one delivered row — the resume replays the recorded receipt.
//!
//! PII boundary: outbox `payload_ref` holds opaque refs only. The worker
//! resolves a `vault_body_ref` cross-plane at send time (via
//! [`PiiProjector`]); the resolved body is passed to the provider
//! in-process and never written back to core.

use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_durable::{DurableRuntime, RunDef};
use tinker_vault::PiiProjector;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Provider abstraction
// ---------------------------------------------------------------------------

/// One delivery attempt. `body` is resolved plaintext held in-process only.
#[derive(Debug, Clone)]
pub struct SendRequest {
    pub idempotency_key: String,
    pub to_actor: Uuid,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SendReceipt {
    pub provider_message_id: String,
}

#[derive(Debug)]
pub enum ProviderError {
    Transient(String),
    Permanent(String),
    /// Test-only: the provider performed the send, then the worker
    /// "crashed" before checkpointing. Drives the interrupted-resume test.
    CrashSimulated,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(s) => write!(f, "transient provider error: {s}"),
            Self::Permanent(s) => write!(f, "permanent provider error: {s}"),
            Self::CrashSimulated => write!(f, "simulated crash after provider send"),
        }
    }
}

#[async_trait]
pub trait EmailProvider: Send + Sync {
    async fn send(&self, req: &SendRequest) -> std::result::Result<SendReceipt, ProviderError>;
}

// ---------------------------------------------------------------------------
// Fake provider (tests + local dev; real SMTP is backlog)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeMode {
    Normal,
    /// Record the send, then fail as if the worker crashed before the
    /// checkpoint. The NEXT send with the same idempotency key returns the
    /// recorded receipt without a second actual send.
    CrashAfterRecord,
}

/// In-process provider with provider-side idempotency. No network, no
/// credentials — real SMTP is a backlog item.
pub struct FakeEmailProvider {
    /// Provider-side idempotency log: key -> receipt.
    log: Mutex<HashMap<String, SendReceipt>>,
    bodies: Mutex<HashMap<String, String>>,
    subjects: Mutex<HashMap<String, String>>,
    actual_sends: AtomicU64,
    mode: Mutex<FakeMode>,
}

impl FakeEmailProvider {
    pub fn new() -> Self {
        Self {
            log: Mutex::new(HashMap::new()),
            bodies: Mutex::new(HashMap::new()),
            subjects: Mutex::new(HashMap::new()),
            actual_sends: AtomicU64::new(0),
            mode: Mutex::new(FakeMode::Normal),
        }
    }

    pub fn set_mode(&self, mode: FakeMode) {
        *self.mode.lock().unwrap() = mode;
    }

    /// How many times the provider actually performed a send (as opposed
    /// to returning a recorded receipt).
    pub fn actual_sends(&self) -> u64 {
        self.actual_sends.load(Ordering::SeqCst)
    }

    pub fn receipt_for(&self, idempotency_key: &str) -> Option<SendReceipt> {
        self.log.lock().unwrap().get(idempotency_key).cloned()
    }

    /// The resolved body the provider received for a key (proves the
    /// cross-plane vault resolution happened; the body never hit core).
    pub fn body_for(&self, idempotency_key: &str) -> Option<String> {
        self.bodies.lock().unwrap().get(idempotency_key).cloned()
    }

    /// The rendered subject the provider received for a key (item 36:
    /// template subjects are rendered too).
    pub fn subject_for(&self, idempotency_key: &str) -> Option<String> {
        self.subjects.lock().unwrap().get(idempotency_key).cloned()
    }

    fn record_send(&self, req: &SendRequest) -> SendReceipt {
        let receipt = SendReceipt {
            provider_message_id: format!("fake-{}", req.idempotency_key),
        };
        self.log
            .lock()
            .unwrap()
            .insert(req.idempotency_key.clone(), receipt.clone());
        self.bodies
            .lock()
            .unwrap()
            .insert(req.idempotency_key.clone(), req.body.clone());
        self.subjects
            .lock()
            .unwrap()
            .insert(req.idempotency_key.clone(), req.subject.clone());
        self.actual_sends.fetch_add(1, Ordering::SeqCst);
        receipt
    }
}

impl Default for FakeEmailProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EmailProvider for FakeEmailProvider {
    async fn send(&self, req: &SendRequest) -> std::result::Result<SendReceipt, ProviderError> {
        // Provider-side idempotency FIRST: a recorded key never sends twice.
        if let Some(receipt) = self.log.lock().unwrap().get(&req.idempotency_key) {
            return Ok(receipt.clone());
        }
        match *self.mode.lock().unwrap() {
            FakeMode::CrashAfterRecord => {
                self.record_send(req);
                Err(ProviderError::CrashSimulated)
            }
            FakeMode::Normal => Ok(self.record_send(req)),
        }
    }
}

// ---------------------------------------------------------------------------
// Outbox rows
// ---------------------------------------------------------------------------

/// One outbox row as read back (tuple form for sqlx).
type OutboxRow = (
    Uuid,
    String,
    String,
    String,
    serde_json::Value,
    Option<String>,
    i32,
);

#[derive(Debug, Clone)]
pub struct OutboxDelivery {
    pub id: Uuid,
    pub idempotency_key: String,
    pub kind: String,
    pub status: String,
    pub payload: serde_json::Value,
    pub provider_message_id: Option<String>,
    pub attempts: i32,
}

#[derive(Debug, Clone)]
pub struct ClaimedDelivery {
    pub id: Uuid,
    pub idempotency_key: String,
    pub payload: serde_json::Value,
    pub lease_token: Uuid,
}

pub struct EnqueueRequest {
    pub kind: &'static str, // "email" | "notification"
    pub idempotency_key: String,
    pub payload: serde_json::Value,
    pub status: &'static str, // "queued" | "deferred" | "suppressed"
    pub deliver_after: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

/// Drives outbox rows to completion through the durable runtime.
#[derive(Clone)]
pub struct DeliveryWorker {
    core: CoreDb,
    durable: DurableRuntime,
    projector: Option<PiiProjector>,
}

impl DeliveryWorker {
    pub fn new(core: CoreDb, durable: DurableRuntime, projector: Option<PiiProjector>) -> Self {
        Self {
            core,
            durable,
            projector,
        }
    }

    /// Enqueue a delivery, deduplicating on (organization_id,
    /// idempotency_key): a duplicate enqueue returns the existing row and
    /// `created = false`. Exactly-once starts here.
    pub async fn enqueue(&self, ctx: &TenantContext, req: EnqueueRequest) -> Result<(Uuid, bool)> {
        if req.idempotency_key.trim().is_empty() || req.idempotency_key.len() > 200 {
            return Err(TinkerError::Validation(
                "idempotency_key must be 1-200 chars".into(),
            ));
        }
        if !matches!(req.kind, "email" | "notification") {
            return Err(TinkerError::Validation(format!(
                "bad delivery kind: {}",
                req.kind
            )));
        }
        if !matches!(req.status, "queued" | "deferred" | "suppressed") {
            return Err(TinkerError::Validation(format!(
                "bad initial delivery status: {}",
                req.status
            )));
        }
        // PII boundary: the outbox row holds opaque refs only. A plaintext
        // `body` key would persist message text in the core database;
        // bodies travel via `vault_body_ref` and resolve at send time.
        if req.payload.get("body").is_some() {
            return Err(TinkerError::Validation(
                "delivery payload must not contain a plaintext body; use vault_body_ref".into(),
            ));
        }
        let id = Uuid::now_v7();
        let mut tx = self.core.tenant_tx(ctx).await?;
        let inserted: Option<(Uuid,)> = sqlx::query_as(
            "INSERT INTO delivery_outbox
             (id, organization_id, idempotency_key, kind, status, payload_ref, deliver_after)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (organization_id, idempotency_key) DO NOTHING
             RETURNING id",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(&req.idempotency_key)
        .bind(req.kind)
        .bind(req.status)
        .bind(&req.payload)
        .bind(req.deliver_after)
        .fetch_optional(&mut *tx)
        .await?;
        let (row_id, created) = match inserted {
            Some((rid,)) => (rid, true),
            None => {
                let existing: (Uuid,) = sqlx::query_as(
                    "SELECT id FROM delivery_outbox WHERE organization_id=$1 AND idempotency_key=$2",
                )
                .bind(ctx.organization_id.0)
                .bind(&req.idempotency_key)
                .fetch_one(&mut *tx)
                .await?;
                (existing.0, false)
            }
        };
        tx.commit().await?;
        Ok((row_id, created))
    }

    pub async fn get(&self, ctx: &TenantContext, delivery_id: Uuid) -> Result<OutboxDelivery> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<OutboxRow> = sqlx::query_as(
            "SELECT id, idempotency_key, kind, status, payload_ref, provider_message_id, attempts
             FROM delivery_outbox WHERE id=$1 AND organization_id=$2",
        )
        .bind(delivery_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let (id, key, kind, status, payload, pmid, attempts) =
            row.ok_or_else(|| TinkerError::NotFound(format!("delivery {delivery_id}")))?;
        Ok(OutboxDelivery {
            id,
            idempotency_key: key,
            kind,
            status,
            payload,
            provider_message_id: pmid,
            attempts,
        })
    }

    /// Claim one delivery for this worker. FOR UPDATE SKIP LOCKED plus the
    /// status/lease predicate makes concurrent claims single-winner: the
    /// loser's UPDATE sees the row already claimed and matches nothing.
    /// Mints a fencing `lease_token` the worker must present to complete.
    pub async fn claim(
        &self,
        ctx: &TenantContext,
        delivery_id: Uuid,
        lease: Duration,
    ) -> Result<ClaimedDelivery> {
        let lease_token = Uuid::now_v7();
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, serde_json::Value)> = sqlx::query_as(
            "UPDATE delivery_outbox SET status='sending', attempts=attempts+1,
                    lease_until=now() + make_interval(secs => $3),
                    lease_owner=$4, lease_token=$5, updated_at=now()
             WHERE id=$1 AND organization_id=$2
               AND status IN ('queued','failed','sending','deferred')
               AND (deliver_after IS NULL OR deliver_after <= now())
               AND (lease_until IS NULL OR lease_until < now())
             RETURNING idempotency_key, payload_ref",
        )
        .bind(delivery_id)
        .bind(ctx.organization_id.0)
        .bind(lease.as_secs() as i32)
        .bind("delivery-worker")
        .bind(lease_token)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let (idempotency_key, payload) = row.ok_or_else(|| {
            TinkerError::NotFound(format!("delivery {delivery_id} not claimable"))
        })?;
        Ok(ClaimedDelivery {
            id: delivery_id,
            idempotency_key,
            payload,
            lease_token,
        })
    }

    /// Checkpoint a completed send. Fenced by the lease token: a worker
    /// whose lease was taken over gets 0 rows and a typed error instead
    /// of clobbering the new owner's outcome.
    pub async fn complete(
        &self,
        ctx: &TenantContext,
        delivery_id: Uuid,
        lease_token: Uuid,
        receipt: &SendReceipt,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE delivery_outbox SET status='sent', provider_message_id=$4,
                    lease_until=NULL, lease_owner=NULL, lease_token=NULL,
                    error=NULL, updated_at=now()
             WHERE id=$1 AND organization_id=$2 AND lease_token=$3",
        )
        .bind(delivery_id)
        .bind(ctx.organization_id.0)
        .bind(lease_token)
        .bind(&receipt.provider_message_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::Internal(format!(
                "stale worker: delivery {delivery_id} lease was taken over; discarding result"
            )));
        }
        Ok(())
    }

    /// Record a failed attempt. Fenced like [`Self::complete`]; the row
    /// returns to `failed` so a later worker can reclaim it.
    pub async fn fail(
        &self,
        ctx: &TenantContext,
        delivery_id: Uuid,
        lease_token: Uuid,
        error: &str,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE delivery_outbox SET status='failed', error=$4,
                    lease_until=NULL, lease_owner=NULL, lease_token=NULL,
                    updated_at=now()
             WHERE id=$1 AND organization_id=$2 AND lease_token=$3",
        )
        .bind(delivery_id)
        .bind(ctx.organization_id.0)
        .bind(lease_token)
        .bind(error)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::Internal(format!(
                "stale worker: delivery {delivery_id} lease was taken over; discarding failure"
            )));
        }
        Ok(())
    }

    /// Drive one delivery to completion: claim -> durable step (provider
    /// send, effect_key = idempotency_key) -> checkpoint.
    ///
    /// Idempotent: calling it on an already-`sent` row returns the recorded
    /// receipt; calling it concurrently from two workers sends once (the
    /// claim is single-winner, the step is effect-fenced).
    pub async fn run_delivery(
        &self,
        ctx: &TenantContext,
        delivery_id: Uuid,
        provider: &dyn EmailProvider,
    ) -> Result<SendReceipt> {
        // Fast path: already delivered.
        let current = self.get(ctx, delivery_id).await?;
        if current.status == "sent" {
            return Ok(SendReceipt {
                provider_message_id: current.provider_message_id.unwrap_or_default(),
            });
        }

        let claimed = self
            .claim(ctx, delivery_id, Duration::from_secs(300))
            .await?;
        let run_id = self
            .durable
            .start_run(
                ctx,
                &RunDef {
                    definition_id: "comm-delivery".into(),
                    definition_version: "1".into(),
                    input: serde_json::json!({ "delivery_id": delivery_id }),
                    queue: "comm-delivery".into(),
                    partition_key: claimed.idempotency_key.clone(),
                    ..Default::default()
                },
            )
            .await?;

        let req = self.build_send_request(ctx, &claimed).await?;
        let effect_key = claimed.idempotency_key.clone();
        // The closure runs OUTSIDE any DB transaction (side effects never
        // hold one open across a network call); the step checkpoint is
        // fenced by the lease token minted in claim_step.
        let outcome: Result<SendReceipt> = self
            .durable
            .run_step(
                ctx,
                run_id,
                "deliver",
                Some(&effect_key),
                &serde_json::json!({ "delivery_id": delivery_id }),
                || async {
                    provider
                        .send(&req)
                        .await
                        .map_err(|e| TinkerError::Internal(e.to_string()))
                },
            )
            .await;

        match outcome {
            Ok(receipt) => {
                self.complete(ctx, delivery_id, claimed.lease_token, &receipt)
                    .await?;
                Ok(receipt)
            }
            Err(e) => {
                let _ = self
                    .fail(ctx, delivery_id, claimed.lease_token, &e.to_string())
                    .await;
                Err(e)
            }
        }
    }

    /// Build the provider request, resolving the opaque body ref
    /// cross-plane. The resolved body is held in-process only.
    async fn build_send_request(
        &self,
        ctx: &TenantContext,
        claimed: &ClaimedDelivery,
    ) -> Result<SendRequest> {
        let payload = &claimed.payload;
        let to_actor: Uuid = payload
            .get("to_actor")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| TinkerError::Validation("delivery payload missing to_actor".into()))?;
        let subject = payload
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let body = match payload.get("vault_body_ref").and_then(|v| v.as_str()) {
            Some(ref_id) => {
                let projector = self.projector.as_ref().ok_or_else(|| {
                    TinkerError::Internal("email delivery needs a vault projector".into())
                })?;
                let rid: Uuid = ref_id
                    .parse()
                    .map_err(|_| TinkerError::Validation("bad vault_body_ref".into()))?;
                projector.resolve(ctx, rid, "delivery").await?
            }
            None => {
                // Notifications render from item refs (ids only — no PII in
                // the payload, so nothing sensitive to resolve).
                let items = payload
                    .get("items")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                let ids: Vec<String> = items
                    .iter()
                    .filter_map(|i| i.get("ref").and_then(|r| r.as_str()))
                    .map(|s| s.to_string())
                    .collect();
                format!("{} notification(s): {}", ids.len(), ids.join(", "))
            }
        };
        Ok(SendRequest {
            idempotency_key: claimed.idempotency_key.clone(),
            to_actor,
            subject,
            body,
        })
    }
}
