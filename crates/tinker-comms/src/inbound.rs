//! Inbound email receiving over a provider webhook (item 36, M5 launch
//! scope).
//!
//! M5 delivers provider-backed *sending* only ([`crate::delivery`]).
//! This module is the receiving half:
//!
//! 1. **Webhook verification** ([`receive_email`]): the provider POSTs a
//!    JSON payload; authenticity is HMAC-SHA256 over the raw body. The
//!    key is derived per-organization from the
//!    `TINKER_INBOUND_WEBHOOK_SECRET` master secret (env only — never
//!    stored in the DB) via
//!    `HMAC(master, "tinker-inbound-email-v1:" || org_id)`. Comparison is
//!    constant-time. The signature header is `X-Tinker-Signature:
//!    sha256=<hex>`. ALL verification failures — missing/bad signature,
//!    stale or replayed timestamp, unknown recipient, malformed payload
//!    — return the same generic [`ReceiveOutcome::Rejected`]: the caller
//!    (the tinker-web handler) maps every one of them to an identical
//!    401 `{"error":"rejected"}`, so there is no existence oracle for
//!    recipient addresses and no reason-distinguishing.
//! 2. **Tenant-scoped routing**: `inbound_addresses` maps a recipient
//!    address to exactly one organization (globally unique on
//!    `lower(address)`). The address itself identifies the org, so the
//!    lookup runs through the owner pool (mirroring 0034
//!    `machine_credentials`; table owners bypass RLS).
//! 3. **Replay protection**: the provider's message id is claimed in
//!    `inbound_email_log` (`INSERT ... ON CONFLICT DO NOTHING`) BEFORE
//!    any bytes are stored; a second presentation of a claimed id is
//!    rejected as a replay. The claim is released if the receive fails
//!    after claiming, so a transient failure does not burn a legitimate
//!    message. Payloads also carry a `timestamp`; anything outside the
//!    replay window (default 300s, 60s future skew for clock drift) is
//!    rejected.
//! 4. **Attachment storage** through the item-23 [`FileStore`] (content-
//!    addressed sha256, tenant RLS, dedup; bytes NEVER touch Postgres).
//!    Size/count caps are enforced BEFORE any bytes are kept: per-file,
//!    total, and count. A violation fails the whole receive closed — no
//!    partial attachments linger. Links land in `message_attachments`;
//!    [`fetch_message_attachment`] re-checks tenant-scoped message
//!    visibility plus the link row before serving bytes, so attachment
//!    fetch authorization mirrors message visibility.
//! 5. **PII policy** (item-32 decision applied): the provider may flag
//!    the message (`pii_class: "pii"`/`"restricted"`) or individual
//!    attachments. A flagged body is still stored as a `comm_message`
//!    row (chat bodies can contain PII; we make no content-scanning
//!    claims) but is posted with a PII storage class, so
//!    `SearchBackend::index_change` → `reject_pii` fails CLOSED and the
//!    body never enters the core search index — skip + log, row kept.
//!    Attachments are stored with their `pii_class` in the registry
//!    (audit-logged on every access per 0032).
//!
//! Received mail lands in the address's `shared_inbox` channel: one new
//! thread per email (subject = the email subject), one message authored
//! by the org's lazily-created `inbound-email` actor.
//!
//! Honest limits: no threading/in-reply-to correlation, no HTML part
//! rendering (text body only), no bounce/DSN handling, no real provider
//! integration (the fake provider covers the send half in tests).

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use tinker_agents::files::{FileRef, FileStore, PiiClass};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_live::SignalBus;
use tinker_ontology::Ontology;
use tinker_search::SearchBackend;
use uuid::Uuid;

use crate::install::InstalledComms;
use crate::write::CommsWriter;

/// Hard ceiling on the raw webhook body, defense-in-depth behind the
/// route layer's own body limit.
const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Handle of the lazily-created per-org actor that authors inbound mail.
const INBOUND_ACTOR_HANDLE: &str = "inbound-email";

// ---------------------------------------------------------------------------
// Configuration (env only)
// ---------------------------------------------------------------------------

/// Inbound webhook configuration. Secrets come from the environment
/// only — never from the database, never from the payload.
#[derive(Debug, Clone)]
pub struct InboundConfig {
    pub master_secret: Vec<u8>,
    pub max_attachments: usize,
    pub max_attachment_bytes: u64,
    pub max_total_attachment_bytes: u64,
    pub replay_window: Duration,
}

impl InboundConfig {
    fn env_u64(key: &str, default: u64) -> Result<u64> {
        match std::env::var(key) {
            Ok(v) => v
                .parse::<u64>()
                .map_err(|_| TinkerError::Internal(format!("{key} is not a valid integer"))),
            Err(_) => Ok(default),
        }
    }

    /// Load from the environment. A missing
    /// `TINKER_INBOUND_WEBHOOK_SECRET` fails closed (the endpoint 500s
    /// rather than verifying against an empty key).
    pub fn from_env() -> Result<Self> {
        let master_secret = std::env::var("TINKER_INBOUND_WEBHOOK_SECRET")
            .map(|s| s.into_bytes())
            .map_err(|_| {
                TinkerError::Internal("TINKER_INBOUND_WEBHOOK_SECRET is not set".into())
            })?;
        if master_secret.len() < 16 {
            return Err(TinkerError::Internal(
                "TINKER_INBOUND_WEBHOOK_SECRET is too short (min 16 bytes)".into(),
            ));
        }
        Ok(Self {
            master_secret,
            max_attachments: Self::env_u64("TINKER_INBOUND_MAX_ATTACHMENTS", 10)? as usize,
            max_attachment_bytes: Self::env_u64(
                "TINKER_INBOUND_MAX_ATTACHMENT_BYTES",
                10 * 1024 * 1024,
            )?,
            max_total_attachment_bytes: Self::env_u64(
                "TINKER_INBOUND_MAX_TOTAL_ATTACHMENT_BYTES",
                20 * 1024 * 1024,
            )?,
            replay_window: Duration::from_secs(Self::env_u64("TINKER_INBOUND_REPLAY_SECS", 300)?),
        })
    }
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Per-org HMAC key: `HMAC-SHA256(master, "tinker-inbound-email-v1:" ||
/// org_id)`. The provider is provisioned with its org's derived key out
/// of band; the master secret never leaves the server.
pub fn derive_org_key(master: &[u8], org_id: Uuid) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(master).expect("HMAC accepts any key length");
    mac.update(b"tinker-inbound-email-v1:");
    mac.update(org_id.as_bytes());
    mac.finalize().into_bytes().into()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        out.push(hex_val(bytes[i])? << 4 | hex_val(bytes[i + 1])?);
        i += 2;
    }
    Some(out)
}

/// Verify `X-Tinker-Signature: sha256=<hex>` against the raw body.
/// Constant-time comparison via `verify_slice`; the `sha256=` prefix is
/// mandatory (strict format, no lenient fallbacks).
pub fn verify_signature(key: &[u8], raw_body: &[u8], provided: &str) -> bool {
    let hex = match provided.strip_prefix("sha256=") {
        Some(h) => h,
        None => return false,
    };
    let expected = match hex_decode(hex) {
        Some(v) => v,
        None => return false,
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(raw_body);
    mac.verify_slice(&expected).is_ok()
}

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InboundAttachmentPayload {
    pub filename: String,
    pub mime: String,
    /// Base64-encoded bytes (standard alphabet).
    pub content_base64: String,
    /// "none" | "pii" | "restricted"; default "none".
    #[serde(default)]
    pub pii_class: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InboundEmailPayload {
    /// Provider-supplied unique id (idempotency / replay protection).
    pub provider_id: String,
    /// Recipient address — the tenant routing key.
    pub to: String,
    pub from: String,
    pub subject: String,
    /// Plain-text body.
    pub text_body: String,
    /// Unix seconds; must be within the replay window.
    pub timestamp: i64,
    /// "none" | "pii" | "restricted"; default "none". Drives the
    /// item-32 fail-closed indexing policy (see module docs).
    #[serde(default)]
    pub pii_class: Option<String>,
    #[serde(default)]
    pub attachments: Vec<InboundAttachmentPayload>,
}

fn parse_pii_class(raw: Option<&str>, what: &str) -> Result<PiiClass> {
    match raw.unwrap_or("none") {
        "none" => Ok(PiiClass::None),
        "pii" => Ok(PiiClass::Pii),
        "restricted" => Ok(PiiClass::Restricted),
        other => Err(TinkerError::Validation(format!(
            "bad {what} pii_class: {other}"
        ))),
    }
}

/// Storage class for the message body: only "none" is indexable.
/// "restricted" maps to "pii.restricted" so `reject_pii` (which matches
/// `pii.*` / `secret.*` / exactly `pii`) fails closed on it too.
fn body_storage_class(class: PiiClass) -> &'static str {
    match class {
        PiiClass::None => "text",
        PiiClass::Pii => "pii",
        PiiClass::Restricted => "pii.restricted",
    }
}

fn normalize_address(addr: &str) -> Result<String> {
    let a = addr.trim().to_lowercase();
    if a.len() < 3 || a.len() > 320 {
        return Err(TinkerError::Validation("bad recipient address".into()));
    }
    let mut parts = a.split('@');
    let (local, domain) = (parts.next(), parts.next());
    if !matches!((local, domain), (Some(l), Some(d)) if !l.is_empty() && !d.is_empty())
        || parts.next().is_some()
    {
        return Err(TinkerError::Validation("bad recipient address".into()));
    }
    Ok(a)
}

// ---------------------------------------------------------------------------
// Routing registry
// ---------------------------------------------------------------------------

/// Register a recipient address for an org: creates a `shared_inbox`
/// channel and the routing row. A globally-taken address fails with a
/// generic "unavailable" — the same message regardless of which org
/// holds it (no existence oracle).
pub async fn register_inbound_address(
    core: &CoreDb,
    ontology: &Ontology,
    signals: &SignalBus,
    installed: &InstalledComms,
    ctx: &TenantContext,
    address: &str,
    channel_name: &str,
) -> Result<Uuid> {
    let address = normalize_address(address)?;
    if channel_name.trim().is_empty() || channel_name.len() > 120 {
        return Err(TinkerError::Validation(
            "channel name must be 1-120 chars".into(),
        ));
    }
    let writer = CommsWriter::new(core.clone(), ontology.clone(), signals.clone());
    let channel_id = writer
        .create_channel(ctx, installed, channel_name, "shared_inbox")
        .await?;
    let mut tx = core.tenant_tx(ctx).await?;
    let insert = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO inbound_addresses (organization_id, address, channel_id)
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(ctx.organization_id.0)
    .bind(&address)
    .bind(channel_id)
    .fetch_one(&mut *tx)
    .await;
    match insert {
        Ok(id) => {
            tx.commit().await?;
            Ok(id)
        }
        Err(e) => {
            drop(tx);
            let taken = e
                .as_database_error()
                .and_then(|d| d.code())
                .is_some_and(|c| c == "23505");
            if taken {
                // Deliberately generic: the caller must not learn whether
                // the address exists or which org holds it.
                Err(TinkerError::Validation("address unavailable".into()))
            } else {
                Err(TinkerError::Db(e))
            }
        }
    }
}

struct Route {
    organization_id: Uuid,
    channel_id: Uuid,
}

/// Owner-pool routing lookup: the address identifies the org, so this
/// cannot be tenant-RLS-scoped (mirrors 0034). Returns None for unknown
/// or inactive addresses — the caller rejects generically.
async fn route_address(owner: &OwnerDb, address: &str) -> Result<Option<Route>> {
    let row: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT organization_id, channel_id FROM inbound_addresses
         WHERE lower(address) = $1 AND active",
    )
    .bind(address)
    .fetch_optional(&owner.0)
    .await
    .map_err(TinkerError::Db)?;
    Ok(row.map(|(organization_id, channel_id)| Route {
        organization_id,
        channel_id,
    }))
}

/// Lazily get-or-create the per-org `inbound-email` actor that authors
/// received mail. Runs on the owner pool (pre-tenant).
async fn ensure_inbound_actor(owner: &OwnerDb, org_id: Uuid) -> Result<Uuid> {
    let id: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO actors (id, organization_id, display_name, handle)
         VALUES (gen_random_uuid(), $1, 'Inbound Email', $2)
         ON CONFLICT (organization_id, handle) DO NOTHING
         RETURNING id",
    )
    .bind(org_id)
    .bind(INBOUND_ACTOR_HANDLE)
    .fetch_optional(&owner.0)
    .await
    .map_err(TinkerError::Db)?;
    match id {
        Some(id) => Ok(id),
        None => {
            sqlx::query_scalar("SELECT id FROM actors WHERE organization_id = $1 AND handle = $2")
                .bind(org_id)
                .bind(INBOUND_ACTOR_HANDLE)
                .fetch_one(&owner.0)
                .await
                .map_err(TinkerError::Db)
        }
    }
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// Everything [`receive_email`] needs. Assembled by the caller (the
/// tinker-web handler or tests).
pub struct InboundDeps {
    pub owner: OwnerDb,
    pub core: CoreDb,
    pub ontology: Ontology,
    pub signals: SignalBus,
    pub installed: InstalledComms,
    pub file_store: FileStore,
    pub search_backend: Option<Arc<dyn SearchBackend>>,
}

/// Outcome of one webhook call. `Rejected` is deliberately reason-free:
/// bad/missing signature, stale timestamp, replay, unknown recipient,
/// and malformed payload ALL map to the same generic rejection — the
/// HTTP layer renders an identical 401 for each, so the endpoint is not
/// an existence oracle for recipient addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Accepted { message_id: Uuid, thread_id: Uuid },
    Rejected,
}

struct DecodedAttachment {
    filename: String,
    mime: String,
    bytes: Vec<u8>,
    pii_class: PiiClass,
}

/// Verify, route, and store one inbound email. See the module docs for
/// the security argument.
pub async fn receive_email(
    deps: &InboundDeps,
    config: &InboundConfig,
    signature: Option<&str>,
    raw_body: &[u8],
) -> Result<ReceiveOutcome> {
    // 1. Parse. Malformed JSON is a generic rejection (pre-auth).
    if raw_body.len() > MAX_BODY_BYTES {
        return Ok(ReceiveOutcome::Rejected);
    }
    let payload: InboundEmailPayload = match serde_json::from_slice(raw_body) {
        Ok(p) => p,
        Err(_) => return Ok(ReceiveOutcome::Rejected),
    };

    // 2. Freshness. The timestamp is inside the signed body, so it
    // cannot be altered without invalidating the signature.
    let now = Utc::now().timestamp();
    let window = config.replay_window.as_secs() as i64;
    if payload.timestamp > now + 60 || payload.timestamp < now - window {
        return Ok(ReceiveOutcome::Rejected);
    }

    // 3. Route. Unknown/inactive addresses reject exactly like a bad
    // signature — no oracle.
    let address = match normalize_address(&payload.to) {
        Ok(a) => a,
        Err(_) => return Ok(ReceiveOutcome::Rejected),
    };
    let route = match route_address(&deps.owner, &address).await? {
        Some(r) => r,
        None => return Ok(ReceiveOutcome::Rejected),
    };

    // 4. Verify the signature with the routed org's derived key.
    let key = derive_org_key(&config.master_secret, route.organization_id);
    match signature {
        Some(s) if verify_signature(&key, raw_body, s) => {}
        _ => return Ok(ReceiveOutcome::Rejected),
    }

    // From here on the sender is authenticated; validation failures are
    // honest errors (the sender already knows it signed correctly).

    // Validate the provider id BEFORE claiming it: an empty or oversized
    // id is a clean validation error, never a database error or a
    // burned replay claim.
    let provider_id = payload.provider_id.trim();
    if provider_id.is_empty() || provider_id.len() > 256 {
        return Err(TinkerError::Validation("bad provider_id".into()));
    }

    // 5. Claim the provider id BEFORE any bytes are stored.
    let claimed: bool = sqlx::query_scalar(
        "INSERT INTO inbound_email_log (organization_id, provider_id)
         VALUES ($1, $2)
         ON CONFLICT (organization_id, provider_id) DO NOTHING
         RETURNING true",
    )
    .bind(route.organization_id)
    .bind(payload.provider_id.trim())
    .fetch_optional(&deps.owner.0)
    .await
    .map_err(TinkerError::Db)?
    .unwrap_or(false);
    if !claimed {
        // A valid signature on an already-seen id: replay. Same generic
        // rejection — the provider retries with a fresh id.
        return Ok(ReceiveOutcome::Rejected);
    }
    // If anything below fails, release the claim so a retry can proceed
    // (fail closed on duplicates, fail open on retries).
    let release_claim = |owner: &OwnerDb, org: Uuid, pid: &str| {
        let owner = owner.clone();
        let pid = pid.to_string();
        async move {
            let _ = sqlx::query(
                "DELETE FROM inbound_email_log
                 WHERE organization_id = $1 AND provider_id = $2 AND message_id IS NULL",
            )
            .bind(org)
            .bind(pid)
            .execute(&owner.0)
            .await;
        }
    };

    let outcome: Result<ReceiveOutcome> = receive_inner(deps, config, &route, &payload).await;
    match outcome {
        Ok(o) => Ok(o),
        Err(e) => {
            release_claim(
                &deps.owner,
                route.organization_id,
                payload.provider_id.trim(),
            )
            .await;
            Err(e)
        }
    }
}

async fn receive_inner(
    deps: &InboundDeps,
    config: &InboundConfig,
    route: &Route,
    payload: &InboundEmailPayload,
) -> Result<ReceiveOutcome> {
    // 6. Field validation (provider_id was validated before the replay
    // claim in receive_email).
    let provider_id = payload.provider_id.trim();
    if payload.from.trim().is_empty() || payload.from.len() > 320 {
        return Err(TinkerError::Validation("bad from address".into()));
    }
    if payload.subject.len() > 1000 {
        return Err(TinkerError::Validation("subject too long".into()));
    }
    if payload.text_body.trim().is_empty() || payload.text_body.len() > 20_000 {
        return Err(TinkerError::Validation(
            "message body must be 1-20000 chars".into(),
        ));
    }
    let msg_pii = parse_pii_class(payload.pii_class.as_deref(), "message")?;

    // 7. Attachment caps BEFORE any bytes are kept: decode (to measure
    // real sizes), then check count, per-file, and total.
    if payload.attachments.len() > config.max_attachments {
        return Err(TinkerError::Validation(format!(
            "too many attachments: {} > {}",
            payload.attachments.len(),
            config.max_attachments
        )));
    }
    let mut decoded = Vec::with_capacity(payload.attachments.len());
    let mut total: u64 = 0;
    for a in &payload.attachments {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(a.content_base64.trim())
            .map_err(|_| TinkerError::Validation("attachment is not valid base64".into()))?;
        if bytes.len() as u64 > config.max_attachment_bytes {
            return Err(TinkerError::Validation(format!(
                "attachment {} too large: {} bytes > {} max",
                a.filename,
                bytes.len(),
                config.max_attachment_bytes
            )));
        }
        total += bytes.len() as u64;
        if total > config.max_total_attachment_bytes {
            return Err(TinkerError::Validation(format!(
                "attachments total too large: {total} bytes > {} max",
                config.max_total_attachment_bytes
            )));
        }
        decoded.push(DecodedAttachment {
            filename: a.filename.clone(),
            mime: a.mime.clone(),
            bytes,
            pii_class: parse_pii_class(a.pii_class.as_deref(), "attachment")?,
        });
    }

    // 8. Tenant context for the routed org, authored by inbound-email.
    let actor_id = ensure_inbound_actor(&deps.owner, route.organization_id).await?;
    let ctx = TenantContext::new(
        tinker_core::OrganizationId(route.organization_id),
        actor_id,
        "inbound-email",
    );

    // 9. Store attachments through the governed FileStore (dedup,
    // content-addressed, bytes never touch Postgres).
    let mut file_ids = Vec::with_capacity(decoded.len());
    for d in &decoded {
        let r = deps
            .file_store
            .store(&ctx, &d.filename, &d.mime, d.pii_class, &d.bytes)
            .await?;
        file_ids.push(r.id);
    }

    // 10. Thread + message. One thread per email; subject truncated to
    // the thread field's 200-char cap on a char boundary.
    let mut writer = CommsWriter::new(
        deps.core.clone(),
        deps.ontology.clone(),
        deps.signals.clone(),
    );
    if let Some(b) = deps.search_backend.clone() {
        writer = writer.with_search_backend(b);
    }
    let subject: String = payload.subject.chars().take(200).collect();
    let subject = if subject.trim().is_empty() {
        "(no subject)".to_string()
    } else {
        subject
    };
    let thread_id = writer
        .create_thread(&ctx, &deps.installed, route.channel_id, &subject)
        .await?;
    let body = format!("From: {}\n\n{}", payload.from.trim(), payload.text_body);
    let body = if body.len() > 20_000 {
        // The From: header pushed it over; truncate the TEXT body part
        // (never the header) on a char boundary.
        let keep = 20_000 - "From: \n\n".len() - payload.from.trim().len();
        let text: String = payload.text_body.chars().take(keep).collect();
        format!("From: {}\n\n{}", payload.from.trim(), text)
    } else {
        body
    };
    let message_id = writer
        .post_message_classified(
            &ctx,
            &deps.installed,
            thread_id,
            actor_id,
            &body,
            body_storage_class(msg_pii),
        )
        .await?;

    // 11. Link attachments to the message (tenant-scoped).
    {
        let mut tx = deps.core.tenant_tx(&ctx).await?;
        for (pos, file_id) in file_ids.iter().enumerate() {
            sqlx::query(
                "INSERT INTO message_attachments
                     (organization_id, message_id, file_id, position)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (organization_id, message_id, file_id) DO NOTHING",
            )
            .bind(ctx.organization_id.0)
            .bind(message_id)
            .bind(file_id)
            .bind(pos as i32)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        }
        tx.commit().await?;
    }

    // 12. Complete the idempotency log row.
    sqlx::query(
        "UPDATE inbound_email_log
         SET message_id = $3, thread_id = $4
         WHERE organization_id = $1 AND provider_id = $2",
    )
    .bind(route.organization_id)
    .bind(provider_id)
    .bind(message_id)
    .bind(thread_id)
    .execute(&deps.owner.0)
    .await
    .map_err(TinkerError::Db)?;

    tracing::info!(
        message_id = %message_id,
        thread_id = %thread_id,
        attachments = file_ids.len(),
        "inbound email accepted"
    );
    Ok(ReceiveOutcome::Accepted {
        message_id,
        thread_id,
    })
}

// ---------------------------------------------------------------------------
// Attachment fetch (authorization mirrors message visibility)
// ---------------------------------------------------------------------------

/// Fetch an attachment's bytes. Fail-closed: the message row must be
/// visible in the caller's tenant AND the link row must exist in the
/// caller's tenant, else NotFound (no oracle). The [`FileStore`] then
/// re-verifies the sha256 — tampered backend bytes fail closed.
pub async fn fetch_message_attachment(
    core: &CoreDb,
    file_store: &FileStore,
    installed: &InstalledComms,
    ctx: &TenantContext,
    message_id: Uuid,
    file_id: Uuid,
) -> Result<(FileRef, Vec<u8>)> {
    let mut tx = core.tenant_tx(ctx).await?;
    // The table name comes from the installer (validated identifiers at
    // DDL time), never from the caller.
    let msg_visible: Option<Uuid> = sqlx::query_scalar(&format!(
        "SELECT id FROM {} WHERE organization_id = $1 AND id = $2",
        installed.message_table
    ))
    .bind(ctx.organization_id.0)
    .bind(message_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(TinkerError::Db)?;
    let linked: Option<Uuid> = sqlx::query_scalar(
        "SELECT file_id FROM message_attachments
         WHERE organization_id = $1 AND message_id = $2 AND file_id = $3",
    )
    .bind(ctx.organization_id.0)
    .bind(message_id)
    .bind(file_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(TinkerError::Db)?;
    tx.commit().await?;
    if msg_visible.is_none() || linked.is_none() {
        return Err(TinkerError::NotFound("attachment".into()));
    }
    file_store.fetch(ctx, file_id).await
}
