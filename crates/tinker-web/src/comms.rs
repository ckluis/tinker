//! M5: HTTP API for native communications.
//!
//! - `POST /api/comms/channels`, `POST /api/comms/threads`,
//!   `POST /api/comms/threads/{id}/messages` — the typed write path.
//!   Require the `thread:write` grant at organization scope.
//! - `GET /api/threads/{id}/card` — the actor-parameterized thread card.
//!   Same-org viewers need `thread:read`; cross-plane viewers need a live
//!   [`cross_plane_grant`][tinker_comms::crossplane] naming the thread's
//!   organization. Sibling ids and missing grants both yield 404 (no
//!   existence oracle). Field masking is driven by field grants; identity
//!   disclosure by the versioned disclosure rows.
//! - `PUT /api/comms/prefs` — the caller's own notification preferences.
//!   Malformed input is rejected with 400, never half-applied.
//! - `POST /api/comms/disclosures` — record an identity disclosure choice.
//!   An actor may set their own; setting another actor's requires an
//!   owner/admin membership.
//! - `GET /api/comms/grants`, `GET /api/comms/grants/{id}/uses` — the
//!   cross-plane grant audit surface. Owner/admin only: every grant ever
//!   issued in the org (live, expired, revoked) with use counts, and the
//!   audited reads under one grant.
//!
//! Every handler fails closed with 503 until `Comms::install` has run.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tinker_auth::{AuthzDecision, AuthzScope};
use tinker_comms::{find_valid_grant, PrefsInput};
use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_identity::authz_input;
use uuid::Uuid;

use crate::{live::ApiError, RequestContext, SharedState};

fn tenant_ctx(ctx: &RequestContext, org: Uuid) -> TenantContext {
    TenantContext::new(OrganizationId(org), ctx.0.actor_id, "comms")
}

async fn installed_or_503(state: &SharedState) -> Result<tinker_comms::InstalledComms, ApiError> {
    state
        .comms
        .installed()
        .await
        .ok_or(ApiError(StatusCode::SERVICE_UNAVAILABLE))
}

async fn require_thread_cap(
    state: &SharedState,
    ctx: &RequestContext,
    action: &str,
) -> Result<(), ApiError> {
    let input = authz_input(
        &ctx.0,
        AuthzScope::Organization {
            organization_id: ctx.0.organization_id,
        },
        action,
        "thread",
        "*",
        "comms",
    );
    let decision = state
        .authorizer
        .authorize(&input, ctx.0.assurance)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    if !matches!(decision, AuthzDecision::Allow) {
        return Err(ApiError(StatusCode::FORBIDDEN));
    }
    Ok(())
}

/// The viewer's masking role: their membership role in the thread's org.
/// Callers without a membership row fail closed to "viewer".
async fn viewer_role(state: &SharedState, org: Uuid, actor_id: Uuid) -> String {
    let ctx = TenantContext::new(OrganizationId(org), actor_id, "comms-role");
    let mut tx = match state.core.tenant_tx(&ctx).await {
        Ok(tx) => tx,
        Err(_) => return "viewer".into(),
    };
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM memberships WHERE organization_id=$1 AND actor_id=$2")
            .bind(org)
            .bind(actor_id)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);
    let _ = tx.commit().await;
    role.unwrap_or_else(|| "viewer".into())
}

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateChannelInput {
    pub name: String,
    pub kind: String,
}

#[derive(Serialize)]
pub struct IdResponse {
    id: Uuid,
}

pub async fn create_channel(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Json(input): Json<CreateChannelInput>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    require_thread_cap(&state, &ctx, "thread:write").await?;
    let installed = installed_or_503(&state).await?;
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    let id = state
        .comms
        .writer()
        .create_channel(&tenant, &installed, &input.name, &input.kind)
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(IdResponse { id })))
}

#[derive(Deserialize)]
pub struct CreateThreadInput {
    pub channel_id: Uuid,
    pub subject: String,
}

pub async fn create_thread(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Json(input): Json<CreateThreadInput>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    require_thread_cap(&state, &ctx, "thread:write").await?;
    let installed = installed_or_503(&state).await?;
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    let id = state
        .comms
        .writer()
        .create_thread(&tenant, &installed, input.channel_id, &input.subject)
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(IdResponse { id })))
}

#[derive(Deserialize)]
pub struct PostMessageInput {
    pub body: String,
}

pub async fn post_message(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(thread_id): Path<Uuid>,
    Json(input): Json<PostMessageInput>,
) -> Result<(StatusCode, Json<IdResponse>), ApiError> {
    require_thread_cap(&state, &ctx, "thread:write").await?;
    let installed = installed_or_503(&state).await?;
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    // @-mentions route through the notify router as "mention" intents.
    // The notifier is built per request (both halves are cheap handle
    // wrappers); mention payloads carry ids only, so no PII projector.
    let notifier = tinker_comms::MentionNotifier::production(&state.core, state.owner.0.clone());
    // Search indexing rides the same opt-in pattern: the backend is a
    // cheap pool-handle wrapper, built per request.
    let search_backend: Arc<dyn tinker_search::SearchBackend> =
        Arc::new(tinker_search::NativeSearchBackend::new(state.core.clone()));
    let id = state
        .comms
        .writer()
        .with_mention_notifier(notifier)
        .with_search_backend(search_backend)
        .post_message(&tenant, &installed, thread_id, ctx.0.actor_id, &input.body)
        .await
        .map_err(ApiError::from)?;
    Ok((StatusCode::CREATED, Json(IdResponse { id })))
}

// ---------------------------------------------------------------------------
// Permission-aware message search
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct MessageSearchParams {
    pub q: String,
    pub limit: Option<u32>,
}

#[derive(Serialize)]
pub struct MessageSearchHitResponse {
    pub message_id: Uuid,
    pub thread_id: Uuid,
    pub snippet: String,
    pub rank: f32,
}

/// `GET /api/comms/search?q=...` — message search over the caller's
/// organization (item 32).
///
/// Same-org only. The backend scopes every match/rank statement to the
/// caller's tenant (RLS on `search_index` is the backstop), so org B can
/// never see org A's hits. The `thread:read` grant gates the endpoint;
/// the body snippet follows the caller's field projection — a caller
/// whose projection hides `body` gets the "▪▪▪" sentinel, never raw
/// text (the same rule the thread card uses). Cross-plane corpus search
/// is out of scope: cross-org reads stay on the per-thread card path
/// with its explicit grant + audit.
pub async fn search_messages(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Query(params): Query<MessageSearchParams>,
) -> Result<Json<Vec<MessageSearchHitResponse>>, ApiError> {
    require_thread_cap(&state, &ctx, "thread:read").await?;
    let installed = installed_or_503(&state).await?;
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    let role = viewer_role(&state, ctx.0.organization_id, ctx.0.actor_id).await;
    let backend: Arc<dyn tinker_search::SearchBackend> =
        Arc::new(tinker_search::NativeSearchBackend::new(state.core.clone()));
    // Item 48: opt-in semantic ranking. When TINKER_SEMANTIC_SEARCH_PROVIDER
    // names an embedding provider, the native backend is wrapped in the
    // semantic decorator — permissions still filter first inside the inner
    // backend; embeddings only reorder. Unset = today's lexical behavior,
    // byte-identical. A misconfigured provider fails LOUD with a teaching
    // error on the request, never a silent lexical page presented as ranked.
    let backend: Arc<dyn tinker_search::SearchBackend> =
        match std::env::var("TINKER_SEMANTIC_SEARCH_PROVIDER") {
            Ok(provider) if !provider.trim().is_empty() => {
                let mut gateway = tinker_agents::gateway::ModelGateway::new(
                    state.core.clone(),
                    state.owner.clone(),
                );
                tinker_agents::gateway::register_embedding_adapters(
                    &mut gateway,
                    &state.core,
                    &tenant,
                )
                .await
                .map_err(ApiError::from)?;
                Arc::new(tinker_search::SemanticSearchBackend::new(
                    backend,
                    state.core.clone(),
                    gateway,
                    provider,
                ))
            }
            _ => backend,
        };
    let hits = state
        .comms
        .message_search(backend)
        .search_messages(
            &tenant,
            &installed,
            &role,
            &params.q,
            params.limit.unwrap_or(20),
        )
        .await
        .map_err(ApiError::from)?;
    Ok(Json(
        hits.into_iter()
            .map(|h| MessageSearchHitResponse {
                message_id: h.message_id,
                thread_id: h.thread_id,
                snippet: h.snippet,
                rank: h.rank,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Actor-parameterized card
// ---------------------------------------------------------------------------

/// Resolve a thread id to its organization without tenant RLS (metadata
/// only: an unguessable id mapping to another unguessable id). Content is
/// always read through the tenant pool afterwards.
async fn thread_org(state: &SharedState, thread_id: Uuid) -> Result<Option<Uuid>, ApiError> {
    let installed = installed_or_503(state).await?;
    let org: Option<Uuid> = sqlx::query_scalar(&format!(
        "SELECT organization_id FROM {} WHERE id=$1",
        installed.thread_table
    ))
    .bind(thread_id)
    .fetch_optional(&state.owner.0)
    .await
    .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(org)
}

pub async fn get_card(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(thread_id): Path<Uuid>,
) -> Result<Json<tinker_comms::ThreadCard>, ApiError> {
    let installed = installed_or_503(&state).await?;
    let org = thread_org(&state, thread_id)
        .await?
        .ok_or_else(|| ApiError::from(TinkerError::NotFound(format!("thread {thread_id}"))))?;

    if org == ctx.0.organization_id {
        require_thread_cap(&state, &ctx, "thread:read").await?;
        let tenant = tenant_ctx(&ctx, org);
        let role = viewer_role(&state, org, ctx.0.actor_id).await;
        let card = state
            .comms
            .renderer()
            .render_thread_card(&tenant, &installed, thread_id, ctx.0.actor_id, &role)
            .await
            .map_err(ApiError::from)?;
        Ok(Json(card))
    } else {
        // Cross-plane: the grant names THIS organization and is unexpired.
        // No grant (or an expired one) -> 404, indistinguishable from a
        // missing thread.
        let tenant = TenantContext::new(OrganizationId(org), ctx.0.actor_id, "comms-xplane");
        let grant = find_valid_grant(&state.core, &tenant, ctx.0.actor_id)
            .await
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
        let Some(grant) = grant else {
            return Err(ApiError::from(TinkerError::NotFound(format!(
                "thread {thread_id}"
            ))));
        };
        // Every cross-plane read is audited against the grant that
        // authorized it. The audit write fails the read closed: an
        // unaudited cross-plane read is a gap, not an optimization.
        tinker_comms::log_grant_use(&state.core, &tenant, grant.id, thread_id)
            .await
            .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
        // Operators have no membership in the tenant org: role "operator"
        // is masked by default unless explicit grants say otherwise.
        let card = state
            .comms
            .renderer()
            .render_thread_card(&tenant, &installed, thread_id, ctx.0.actor_id, "operator")
            .await
            .map_err(ApiError::from)?;
        Ok(Json(card))
    }
}

// ---------------------------------------------------------------------------
// Cross-plane grant audit surface
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct GrantSummaryResponse {
    id: Uuid,
    grantee_actor_id: Uuid,
    purpose: String,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    created_by: Uuid,
    created_at: DateTime<Utc>,
    use_count: i64,
}

#[derive(Serialize)]
pub struct GrantUseResponse {
    id: Uuid,
    grant_id: Uuid,
    grantee_actor_id: Uuid,
    thread_id: Uuid,
    used_at: DateTime<Utc>,
}

async fn require_grant_auditor(state: &SharedState, ctx: &RequestContext) -> Result<(), ApiError> {
    // Auditing the exceptional cross-org path is an admin act: the
    // surface names external actors and their purposes.
    let role = viewer_role(state, ctx.0.organization_id, ctx.0.actor_id).await;
    if role != "owner" && role != "admin" {
        return Err(ApiError(StatusCode::FORBIDDEN));
    }
    Ok(())
}

/// List every cross-plane grant ever issued in the caller's org (live,
/// expired, revoked) with audited use counts. Owner/admin only.
pub async fn list_grants(
    State(state): State<SharedState>,
    ctx: RequestContext,
) -> Result<Json<Vec<GrantSummaryResponse>>, ApiError> {
    installed_or_503(&state).await?;
    require_grant_auditor(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    let grants = tinker_comms::list_grants(&state.core, &tenant)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(
        grants
            .into_iter()
            .map(|g| GrantSummaryResponse {
                id: g.id,
                grantee_actor_id: g.grantee_actor_id,
                purpose: g.purpose,
                expires_at: g.expires_at,
                revoked_at: g.revoked_at,
                created_by: g.created_by,
                created_at: g.created_at,
                use_count: g.use_count,
            })
            .collect(),
    ))
}

/// The audited reads under one grant, newest first. Owner/admin only;
/// a foreign grant id yields an empty list, never a cross-org peek.
pub async fn grant_uses(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(grant_id): Path<Uuid>,
) -> Result<Json<Vec<GrantUseResponse>>, ApiError> {
    installed_or_503(&state).await?;
    require_grant_auditor(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    let uses = tinker_comms::list_grant_uses(&state.core, &tenant, grant_id)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(Json(
        uses.into_iter()
            .map(|u| GrantUseResponse {
                id: u.id,
                grant_id: u.grant_id,
                grantee_actor_id: u.grantee_actor_id,
                thread_id: u.thread_id,
                used_at: u.used_at,
            })
            .collect(),
    ))
}

// ---------------------------------------------------------------------------
// Preferences + disclosures
// ---------------------------------------------------------------------------

pub async fn put_prefs(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Json(input): Json<PrefsInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    installed_or_503(&state).await?;
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    let router = tinker_comms::NotificationRouter::new(state.core.clone());
    router
        .set_prefs(&tenant, ctx.0.actor_id, input)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
pub struct DisclosureInput {
    pub thread_id: Option<Uuid>,
    pub actor_id: Uuid,
    pub disclosed: bool,
}

pub async fn post_disclosure(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Json(input): Json<DisclosureInput>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_thread_cap(&state, &ctx, "thread:read").await?;
    let installed = installed_or_503(&state).await?;
    // Setting another actor's disclosure is an admin act.
    if input.actor_id != ctx.0.actor_id {
        let role = viewer_role(&state, ctx.0.organization_id, ctx.0.actor_id).await;
        if role != "owner" && role != "admin" {
            return Err(ApiError(StatusCode::FORBIDDEN));
        }
    }
    let tenant = tenant_ctx(&ctx, ctx.0.organization_id);
    // A thread-scoped disclosure must name a real thread in the caller's
    // organization. Otherwise the row is orphaned (or smuggles a foreign
    // thread id into this org's disclosure table).
    if let Some(tid) = input.thread_id {
        let mut tx = state
            .core
            .tenant_tx(&tenant)
            .await
            .map_err(ApiError::from)?;
        let exists: Option<(Uuid,)> = sqlx::query_as(&format!(
            "SELECT id FROM {} WHERE organization_id=$1 AND id=$2",
            installed.thread_table
        ))
        .bind(ctx.0.organization_id)
        .bind(tid)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)
        .map_err(ApiError::from)?;
        if exists.is_none() {
            return Err(ApiError::from(TinkerError::NotFound(format!(
                "thread {tid}"
            ))));
        }
    }
    tinker_comms::set_disclosure(
        &state.core,
        &tenant,
        input.thread_id,
        input.actor_id,
        input.disclosed,
        ctx.0.actor_id,
    )
    .await
    .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

// ---------------------------------------------------------------------------
// Inbound email webhook (item 36)
// ---------------------------------------------------------------------------

/// Route-layer body ceiling (defense in depth behind the 64 MiB hard
/// ceiling inside `tinker_comms::receive_email`). Larger files arrive
/// via the governed FileStore upload path, not the webhook.
const INBOUND_BODY_LIMIT: usize = 32 * 1024 * 1024;

/// POST /api/comms/inbound/email — provider webhook for inbound mail.
///
/// Authenticated by HMAC-SHA256 (`X-Tinker-Signature: sha256=<hex>`)
/// with a per-org key derived from `TINKER_INBOUND_WEBHOOK_SECRET`
/// (env only) — NOT by session. Every verification failure
/// (bad/missing signature, stale timestamp, replay, unknown recipient,
/// malformed payload, oversize body) returns the identical 401
/// `{"error":"rejected"}`: no existence oracle for recipient
/// addresses, no reason-distinguishing. Validation failures on an
/// authenticated payload are 400; anything else is a generic 500.
pub async fn inbound_email(
    State(state): State<SharedState>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    use axum::http::StatusCode;
    if body.len() > INBOUND_BODY_LIMIT {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "rejected" })),
        );
    }
    let installed = match state.comms.installed().await {
        Some(i) => i,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({ "error": "unavailable" })),
            );
        }
    };
    let config = match tinker_comms::InboundConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("inbound webhook misconfigured: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "unavailable" })),
            );
        }
    };
    let signature = headers
        .get("x-tinker-signature")
        .and_then(|v| v.to_str().ok());
    let backend = match tinker_agents::files::backend_from_env() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("file backend misconfigured: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "unavailable" })),
            );
        }
    };
    let file_store = tinker_agents::files::FileStore::new(state.core.clone(), backend);
    let search_backend: Arc<dyn tinker_search::SearchBackend> =
        Arc::new(tinker_search::NativeSearchBackend::new(state.core.clone()));
    let deps = tinker_comms::InboundDeps {
        owner: state.owner.clone(),
        core: state.core.clone(),
        ontology: state.ontology.clone(),
        signals: state.signals.clone(),
        installed,
        file_store,
        search_backend: Some(search_backend),
    };
    match tinker_comms::receive_email(&deps, &config, signature, &body).await {
        Ok(tinker_comms::ReceiveOutcome::Accepted {
            message_id,
            thread_id,
        }) => (
            StatusCode::OK,
            Json(serde_json::json!({ "message_id": message_id, "thread_id": thread_id })),
        ),
        Ok(tinker_comms::ReceiveOutcome::Rejected) => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "rejected" })),
        ),
        Err(tinker_core::TinkerError::Validation(msg)) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": msg })),
        ),
        Err(e) => {
            tracing::error!("inbound email failed: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "unavailable" })),
            )
        }
    }
}
