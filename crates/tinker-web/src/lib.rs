//! Tinker web tier (M1): one Axum binary rendering versioned apps inside
//! the mandatory (host, organization, workspace) context.
//!
//! Request pipeline:
//!
//! 1. Extract the `tinker_session` cookie → [`SessionManager::load_session`].
//!    Unknown, expired, or revoked tokens yield no session — never a
//!    degraded identity.
//! 2. Resolve the published app version through the registry in the
//!    session's organization (RLS fail-closed).
//! 3. Authorize (`app:view`) through [`Authorizer`] — Tinker-owned, no
//!    provider concepts.
//! 4. Render the immutable version with Askama; serve vendored assets
//!    from the binary itself (`include_bytes!`, no CDN, no runtime path).

use std::sync::Arc;

use askama::Template;
use axum::{
    extract::{FromRequestParts, OptionalFromRequestParts, Path, State},
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use tinker_apps::{render_app, AppRegistry};
use tinker_auth::{
    AuthBroker, AuthnContext, AuthzDecision, AuthzScope, Credential, CredentialKind,
};
use tinker_identity::{authz_input, Authorizer, Session, SessionManager};
use tinker_live::{QueryCache, QueryExecutor, SignalBus};
use tinker_ontology::Ontology;
use tinker_query::QueryCompiler;

pub const SESSION_COOKIE: &str = "tinker_session";

/// Vendored frontend assets — compiled into the binary, served from memory.
const DATASTAR_JS: &[u8] = include_bytes!("../assets/datastar.js");
const TINKER_JS: &[u8] = include_bytes!("../assets/tinker.js");
const TINKER_CSS: &[u8] = include_bytes!("../assets/tinker.css");

/// Item 44: the version-matched agent skill (`tinker agent install` /
/// `tinker agent verify`).
pub mod agent;
pub mod comms;
pub mod dashboards;
/// Item 43: the self-describing ontology (`tinker describe`,
/// `GET /api/describe`, `GET /api/describe/{slug}`).
pub mod describe;
pub mod live;
/// Item 47: governed-metadata cache orchestration (query inputs +
/// describe output). Same freshness contract as the query cache.
pub mod meta;
pub mod oidc_flow;
pub mod schema;
pub mod schema_page;

pub struct AppState {
    pub sessions: SessionManager,
    pub authorizer: Authorizer,
    pub registry: AppRegistry,
    pub broker: AuthBroker,
    /// Mandatory host context, e.g. "tinker.internal".
    pub host_name: String,
    pub cookie_secure: bool,
    // M2: governed reactivity loop.
    pub compiler: QueryCompiler,
    pub ontology: Ontology,
    pub executor: QueryExecutor,
    pub cache: QueryCache,
    // Item 47: governed-metadata cache (object descriptions, field
    // projections, row policies). Same 30s freshness contract and same
    // invalidation sites as `cache`.
    pub meta: tinker_live::MetaCache,
    pub signals: SignalBus,
    // M3: field-level projections.
    pub grants: tinker_live::FieldGrants,
    // C2 (item 38): row-level permission filters.
    pub row_filters: tinker_query::RowFilters,
    // C5 (item 41): dashboard composer.
    pub dashboards: tinker_query::dashboard::DashboardService,
    pub core: tinker_db::CoreDb,
    // M4: schema evolution.
    pub evolver: tinker_evolve::SchemaEvolver,
    // M5: communications handle (installed lazily via `Comms::install`).
    pub comms: tinker_comms::Comms,
    /// Owner pool for RLS-blind metadata lookups (thread id -> org id).
    /// Never serves tenant content reads.
    pub owner: tinker_db::OwnerDb,
    /// PII vault + blind-index key for sensitive fields
    /// (docs/pii-sensitive-fields.md). `None`: sensitive writes, lookups
    /// and reveals fail closed.
    pub pii: Option<tinker_ontology::sensitive::PiiSealer>,
    /// WebAuthn relying party (RP ID + allowed origins) for passkey
    /// registration; login verification uses the adapter's own copy.
    pub rp: tinker_auth::webauthn::RelyingParty,
    /// Automations over sealed fields (docs/automations.md).
    pub automations: Arc<tinker_automate::AutomationEngine>,
}

pub type SharedState = Arc<AppState>;

pub fn build_router(state: SharedState) -> Router {
    build_router_with_oidc(state, None)
}

/// [`build_router`] with an OIDC relying-party client: enables the
/// authorization-code login at `/login/oidc/start` + `/login/oidc/callback`.
/// Without one, both routes are 404 (OIDC login disabled).
pub fn build_router_with_oidc(state: SharedState, oidc: Option<oidc_flow::OidcClient>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/login", get(login_page))
        .route("/login/passkey/start", post(passkey_start))
        .route("/login/passkey/finish", post(passkey_finish))
        .route("/passkey/register/start", post(passkey_register_start))
        .route("/passkey/register/finish", post(passkey_register_finish))
        .route("/login/oidc/start", get(oidc_flow::start))
        .route("/login/oidc/callback", get(oidc_flow::callback))
        .route("/logout", post(logout))
        .route("/apps", get(app_list))
        .route("/apps/{slug}", get(render_published_app))
        .route("/schema", get(schema_page::schema_page))
        .route(
            "/schema/objects/{object_id}/drafts",
            post(schema_page::form_create_draft),
        )
        .route(
            "/schema/versions/{version_id}/fields",
            post(schema_page::form_add_field),
        )
        .route(
            "/schema/versions/{version_id}/relations",
            post(schema_page::form_add_relation),
        )
        .route(
            "/schema/versions/{version_id}/preview",
            post(schema_page::form_mark_preview),
        )
        .route(
            "/schema/versions/{version_id}/canary",
            post(schema_page::form_mark_canary),
        )
        .route(
            "/schema/versions/{version_id}/promote",
            post(schema_page::form_promote),
        )
        .route(
            "/schema/versions/{version_id}/rollback",
            post(schema_page::form_rollback),
        )
        .route(
            "/assets/datastar.js",
            get(|| async { js_response(DATASTAR_JS) }),
        )
        .route(
            "/assets/tinker.js",
            get(|| async { js_response(TINKER_JS) }),
        )
        .route(
            "/assets/tinker.css",
            get(|| async { css_response(TINKER_CSS) }),
        )
        .route("/api/query", post(live::api_query))
        .route("/api/sse", get(live::api_sse))
        // Item 43: the self-describing ontology. Catalog and per-object
        // documentation, permission-projected through the caller's role.
        .route("/api/describe", get(describe::get_catalog))
        .route("/api/describe/{slug}", get(describe::get_object))
        // C5 (item 41): dashboard composer.
        .route(
            "/api/dashboards",
            post(dashboards::create_dashboard).get(dashboards::list_dashboards),
        )
        .route(
            "/api/dashboards/{id}",
            get(dashboards::get_dashboard)
                .put(dashboards::update_dashboard)
                .delete(dashboards::delete_dashboard),
        )
        .route(
            "/api/dashboards/{id}/render",
            post(dashboards::render_dashboard),
        )
        // M5: native communications.
        .route("/api/comms/channels", post(comms::create_channel))
        .route("/api/comms/threads", post(comms::create_thread))
        .route(
            "/api/comms/threads/{thread_id}/messages",
            post(comms::post_message),
        )
        .route("/api/threads/{thread_id}/card", get(comms::get_card))
        .route("/api/comms/search", get(comms::search_messages))
        .route("/api/comms/prefs", put(comms::put_prefs))
        .route("/api/comms/disclosures", post(comms::post_disclosure))
        .route("/api/comms/grants", get(comms::list_grants))
        .route("/api/comms/grants/{grant_id}/uses", get(comms::grant_uses))
        // Item 36: provider webhook for inbound email (HMAC-authenticated,
        // no session required).
        .route("/api/comms/inbound/email", post(comms::inbound_email))
        .route(
            "/api/schema/objects/{object_id}/drafts",
            post(schema::create_draft),
        )
        .route(
            "/api/schema/objects/{object_id}/versions",
            get(schema::list_versions),
        )
        .route(
            "/api/schema/objects/{object_id}/diff",
            get(schema::diff_versions),
        )
        .route(
            "/api/schema/versions/{version_id}/fields",
            post(schema::add_field),
        )
        .route(
            "/api/schema/versions/{version_id}/relations",
            post(schema::add_relation),
        )
        .route(
            "/api/schema/versions/{version_id}/preview",
            post(schema::mark_preview),
        )
        .route(
            "/api/schema/versions/{version_id}/canary",
            post(schema::mark_canary),
        )
        .route(
            "/api/schema/versions/{version_id}/promote",
            post(schema::promote),
        )
        .route(
            "/api/schema/versions/{version_id}/rollback",
            post(schema::rollback),
        )
        .layer(axum::Extension(oidc_flow::OidcFlow(oidc.map(Arc::new))))
        .with_state(state)
}

fn js_response(bytes: &[u8]) -> Response {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        bytes.to_vec(),
    )
        .into_response()
}

fn css_response(bytes: &[u8]) -> Response {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        bytes.to_vec(),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Session extraction
// ---------------------------------------------------------------------------

/// The mandatory request context. Extracting it fails closed: no cookie,
/// bad token, expired or revoked session → 401, never anonymous access to
/// app routes.
pub struct RequestContext(pub Session);

impl FromRequestParts<SharedState> for RequestContext {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Self, Self::Rejection> {
        optional_context(parts, state)
            .await
            .map(RequestContext)
            .ok_or_else(|| Redirect::to("/login").into_response())
    }
}

impl OptionalFromRequestParts<SharedState> for RequestContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &SharedState,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(optional_context(parts, state).await.map(RequestContext))
    }
}

async fn optional_context(parts: &mut Parts, state: &SharedState) -> Option<Session> {
    let token = session_token_from_headers(&parts.headers)?;
    state.sessions.load_session(&token).await.ok()?
}

fn session_token_from_headers(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(value) = part.strip_prefix(&format!("{SESSION_COOKIE}=")) {
            return Some(value.to_string());
        }
    }
    None
}

fn set_session_cookie(headers: &mut HeaderMap, token: &str, secure: bool, host: &str) {
    let _ = host;
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    );
    headers.insert(header::SET_COOKIE, cookie.parse().unwrap());
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn index(ctx: Option<RequestContext>) -> Response {
    if ctx.is_some() {
        Redirect::to("/apps").into_response()
    } else {
        Redirect::to("/login").into_response()
    }
}

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    host_name: String,
}

async fn login_page(State(state): State<SharedState>) -> impl IntoResponse {
    let tpl = LoginTemplate {
        host_name: state.host_name.clone(),
    };
    Html(tpl.render().unwrap_or_else(|_| "login".into()))
}

#[derive(Debug, Deserialize)]
struct PasskeyStart {
    organization_id: Uuid,
    actor_id: Uuid,
}

#[derive(Debug, Serialize)]
struct PasskeyStartResponse {
    challenge_id: String,
    challenge: String,
    rp_id: String,
}

async fn passkey_start(
    State(state): State<SharedState>,
    Json(body): Json<PasskeyStart>,
) -> Result<Json<PasskeyStartResponse>, StatusCode> {
    let (id, challenge) = state
        .sessions
        .mint_passkey_challenge(body.organization_id, body.actor_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(PasskeyStartResponse {
        challenge_id: id.to_string(),
        challenge,
        rp_id: state.rp.id.clone(),
    }))
}

#[derive(Debug, Deserialize)]
struct PasskeyFinish {
    organization_id: Uuid,
    workspace_id: Uuid,
    credential_id: String,
    challenge_id: String,
    /// WebAuthn assertion fields, base64url (navigator.credentials.get).
    client_data_json: String,
    authenticator_data: String,
    signature: String,
}

async fn passkey_finish(
    State(state): State<SharedState>,
    Json(body): Json<PasskeyFinish>,
) -> Response {
    let credential = Credential {
        kind: CredentialKind::WebAuthn,
        payload: serde_json::json!({
            "organization_id": body.organization_id.to_string(),
            "credential_id": body.credential_id,
            "challenge_id": body.challenge_id,
            "client_data_json": body.client_data_json,
            "authenticator_data": body.authenticator_data,
            "signature": body.signature,
        }),
    };
    finish_login(&state, &credential, body.organization_id, body.workspace_id).await
}

#[derive(Debug, Serialize)]
struct RegisterStartResponse {
    challenge_id: Uuid,
    challenge: String,
    rp_id: String,
    user_id: String,
}

/// Begin registering a NEW passkey for the signed-in actor (WebAuthn
/// `navigator.credentials.create`). Requires a live session: a passkey
/// is only ever added by someone already authenticated.
async fn passkey_register_start(
    State(state): State<SharedState>,
    ctx: RequestContext,
) -> Result<Json<RegisterStartResponse>, StatusCode> {
    let (id, challenge) = state
        .sessions
        .mint_registration_challenge(ctx.0.organization_id, ctx.0.actor_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(RegisterStartResponse {
        challenge_id: id,
        challenge: tinker_auth::passkey::b64url(&challenge),
        rp_id: state.rp.id.clone(),
        user_id: tinker_auth::passkey::b64url(ctx.0.actor_id.as_bytes()),
    }))
}

#[derive(Debug, Deserialize)]
struct RegisterFinish {
    challenge_id: Uuid,
    client_data_json: String,
    attestation_object: String,
}

/// Finish registration: the challenge must be live and bound to this
/// session's actor; it is consumed before verification (no grinding
/// oracle), then the attestation is verified against this RP + origin.
async fn passkey_register_finish(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Json(body): Json<RegisterFinish>,
) -> Response {
    use tinker_auth::PasskeyStore;
    let org = ctx.0.organization_id;
    let store = tinker_identity::PgPasskeyStore::new(state.core.0.clone());
    let challenge = match store.find_challenge(org, body.challenge_id).await {
        Ok(Some(c)) if !c.dead && c.actor_id == Some(ctx.0.actor_id) => c,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    if !matches!(
        store.consume_challenge(org, body.challenge_id).await,
        Ok(true)
    ) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let decode = tinker_auth::webauthn::b64url_decode;
    let (Ok(cd), Ok(att)) = (
        decode(&body.client_data_json),
        decode(&body.attestation_object),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let reg = match tinker_auth::webauthn::verify_registration(
        &state.rp,
        &challenge.challenge,
        &cd,
        &att,
    ) {
        Ok(r) => r,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let credential_id = tinker_auth::passkey::b64url(&reg.credential_id);
    match state
        .sessions
        .enroll_webauthn(
            org,
            ctx.0.actor_id,
            &credential_id,
            &reg.key,
            reg.sign_count,
        )
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "credential_id": credential_id,
                "algorithm": reg.key.alg(),
                "user_verified": reg.user_verified,
            })),
        )
            .into_response(),
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}

async fn finish_login(
    state: &SharedState,
    credential: &Credential,
    organization_id: Uuid,
    workspace_id: Uuid,
) -> Response {
    let authn: AuthnContext = match state.broker.authenticate(credential).await {
        Ok(a) => a,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let token = match state
        .sessions
        .create_session(&authn, organization_id, workspace_id)
        .await
    {
        Ok(t) => t,
        Err(_) => return StatusCode::FORBIDDEN.into_response(),
    };
    let mut headers = HeaderMap::new();
    set_session_cookie(&mut headers, &token, state.cookie_secure, &state.host_name);
    (headers, Redirect::to("/apps")).into_response()
}

async fn logout(State(state): State<SharedState>, ctx: RequestContext) -> Response {
    let _ = state.sessions.revoke(ctx.0.id).await;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        format!("{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")
            .parse()
            .unwrap(),
    );
    (headers, Redirect::to("/login")).into_response()
}

#[derive(Template)]
#[template(path = "apps.html")]
struct AppsTemplate {
    host_name: String,
    org_slug: String,
    apps: Vec<AppRow>,
}

struct AppRow {
    slug: String,
    name: String,
    version: String,
}

async fn app_list(State(state): State<SharedState>, ctx: RequestContext) -> Response {
    let apps = match state
        .registry
        .list_apps(ctx.0.organization_id, ctx.0.actor_id)
        .await
    {
        Ok(a) => a,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    // Authorization: listing requires org membership, which the session
    // already proves. Per-app view is checked at render time.
    let tpl = AppsTemplate {
        host_name: state.host_name.clone(),
        org_slug: ctx.0.organization_id.to_string(),
        apps: apps
            .into_iter()
            .map(|a| AppRow {
                slug: a.slug,
                name: a.name,
                version: a
                    .published_version
                    .map(|v| format!("v{v}"))
                    .unwrap_or_else(|| "unpublished".into()),
            })
            .collect(),
    };
    Html(tpl.render().unwrap_or_else(|_| "apps".into())).into_response()
}

async fn render_published_app(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(slug): Path<String>,
) -> Response {
    let app = match state
        .registry
        .get_published(ctx.0.organization_id, ctx.0.actor_id, &slug)
        .await
    {
        Ok(Some(a)) => a,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let input = authz_input(
        &ctx.0,
        AuthzScope::App { app_id: app.app_id },
        "app:view",
        "app",
        &app.app_id.to_string(),
        "render published app",
    );
    let decision = match state.authorizer.authorize(&input, ctx.0.assurance).await {
        Ok(d) => d,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !matches!(decision, AuthzDecision::Allow) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match render_app(&app, &ctx.0.organization_id.to_string(), &state.host_name) {
        Ok(html) => Html(html).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// Build the full application state. The broker is injected so deployments
/// (and tests) choose their auth adapters; nothing downstream knows which
/// providers are configured.
pub fn build_state(
    tenant_pool: PgPool,
    system_pool: PgPool,
    broker: AuthBroker,
    host_name: String,
    cookie_secure: bool,
) -> SharedState {
    build_state_with_pii(
        tenant_pool,
        system_pool,
        broker,
        host_name,
        cookie_secure,
        None,
    )
}

/// [`build_state`] with the PII vault attached: the compiler gets the
/// blind-index key for sensitive lookups, and `state.pii` carries the
/// sealer for write paths and reveal.
pub fn build_state_with_pii(
    tenant_pool: PgPool,
    system_pool: PgPool,
    broker: AuthBroker,
    host_name: String,
    cookie_secure: bool,
    pii: Option<tinker_ontology::sensitive::PiiSealer>,
) -> SharedState {
    let host_for_rp = host_name.clone();
    let (core_for_auto, owner_for_auto, pii_for_auto) = (
        tinker_db::CoreDb(tenant_pool.clone()),
        tinker_db::OwnerDb(system_pool.clone()),
        pii.clone(),
    );
    let core = tinker_db::CoreDb(tenant_pool.clone());
    let owner = tinker_db::OwnerDb(system_pool.clone());
    let signals = SignalBus::new();
    let cache = QueryCache::new();
    let meta = tinker_live::MetaCache::new();
    // Cross-instance schema-version signals (item 30 fan-out) must
    // invalidate this instance's plans too; local publishes already
    // invalidate explicitly at the promote/rollback call sites.
    signals.set_cache_invalidator(cache.clone());
    signals.set_meta_invalidator(meta.clone());
    let ontology = Ontology::new(core.clone(), owner.clone());
    let compiler = {
        let evolver =
            tinker_evolve::SchemaEvolver::new(core.clone(), owner.clone(), ontology.clone());
        let compiler = QueryCompiler::new(ontology.clone()).with_evolver(evolver);
        match &pii {
            Some(p) => compiler.with_blind_index(p.blind_index().clone()),
            None => compiler,
        }
    };
    Arc::new(AppState {
        sessions: SessionManager::new(tenant_pool.clone(), system_pool.clone()),
        authorizer: Authorizer::new(tenant_pool.clone(), system_pool.clone()),
        registry: AppRegistry::new(tenant_pool.clone()),
        broker,
        host_name,
        cookie_secure,
        compiler,
        evolver: tinker_evolve::SchemaEvolver::new(core.clone(), owner.clone(), ontology.clone()),
        ontology: ontology.clone(),
        executor: match &pii {
            Some(p) => QueryExecutor::new(core.clone()).with_keys(p.blind_index().clone()),
            None => QueryExecutor::new(core.clone()),
        },
        cache,
        meta,
        signals: signals.clone(),
        grants: tinker_live::FieldGrants::new(core.clone()),
        row_filters: tinker_query::RowFilters::new(core.clone()),
        dashboards: {
            let d = tinker_query::dashboard::DashboardService::new(core.clone(), ontology.clone());
            match &pii {
                Some(p) => d.with_blind_index(p.blind_index().clone()),
                None => d,
            }
        },
        core: core.clone(),
        // M5: the comms writer publishes into the same signal bus the SSE
        // endpoint reads, so posted messages fan out as id-only envelopes.
        // Platform DDL runs separately via `Comms::install`.
        comms: tinker_comms::Comms::new(core, ontology, signals),
        owner: tinker_db::OwnerDb(system_pool),
        pii,
        rp: tinker_auth::webauthn::RelyingParty::from_env(&host_for_rp),
        automations: Arc::new(
            tinker_automate::AutomationEngine::new(core_for_auto, owner_for_auto, pii_for_auto)
                .with_webhook_policy(tinker_automate::WebhookPolicy::from_env()),
        ),
    })
}

/// Drive automations in the background: every `every`, process pending
/// outbox events for all organizations. `TINKER_AUTOMATIONS=off` disables
/// the loop (events stay queued in the outbox, nothing is lost).
pub fn spawn_automation_worker(state: SharedState, every: std::time::Duration) {
    if std::env::var("TINKER_AUTOMATIONS").as_deref() == Ok("off") {
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        loop {
            tick.tick().await;
            if let Err(e) = state.automations.run_pending(200).await {
                tracing::warn!(error = %e, "automation worker pass failed");
            }
        }
    });
}
