//! Item 46: MCP over HTTP/SSE (`tinker-mcp serve`).
//!
//! # Route shape
//!
//! * `POST /mcp` — JSON-RPC 2.0 in the request body, JSON-RPC 2.0 in
//!   the response body (`application/json`). When the client sends
//!   `Accept: text/event-stream`, the single response is instead
//!   delivered as one SSE `data:` event (Streamable-HTTP style). A
//!   notification (no `id`) returns `202 Accepted` with an empty body.
//! * `GET /mcp/stream` — the server→client SSE channel for one
//!   session: an `event: ready` greeting, then `:keep-alive` comments
//!   every 15 s. v1 emits no unsolicited notifications, so this stream
//!   is spec-compatibility plumbing, honestly labeled as such.
//! * `DELETE /mcp` — terminate the session (`204 No Content`).
//! * `GET /healthz` — unauthenticated liveness probe: `200`,
//!   `{"status":"ok","version":"<crate-version>"}`. Information-minimal
//!   by design; for the reverse proxy / load balancer, not for clients.
//!
//! # Auth
//!
//! Every request carries `Authorization: Bearer tk_...`. The key is
//! verified on *every* request through the exact startup path the
//! stdio server uses (`MachineCredentialStore::verify`); missing and
//! invalid keys both get `401` with a teaching JSON body in the same
//! `{"error","message","hint"}` family as the stdio teaching errors.
//! All verification failures (unknown, malformed, revoked, expired)
//! share one identical body — no oracle — and key material is never
//! logged.
//!
//! # Sessions
//!
//! `initialize` mints a session (`Mcp-Session-Id` response header, a
//! uuid v7) and binds the verified credential's tenant context and
//! membership role — the role comes from `memberships`, never from the
//! caller, exactly like stdio's startup. Every non-`initialize` method
//! requires the session header, and the Bearer key on the request must
//! re-verify to the *same credential* the session was opened with, so
//! revocation takes effect on the next request. Idle sessions expire
//! after 30 minutes via a background sweeper.
//!
//! # Governance
//!
//! All dispatch goes through [`FrontDoor::handle`] — the same code
//! path as stdio — so the 7 tools, the ontology resources, scope
//! gating, the teaching errors, and the identical `not_found` shape
//! for missing/hidden/foreign records are byte-identical by
//! construction. This module adds only HTTP framing, per-request
//! auth, and session bookkeeping; it reimplements no governance.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Router,
};
use serde_json::Value;
use tinker_auth::apikey::MachineCredentialStore;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{build_services, FrontDoor};
use tinker_ontology::lifecycle::LifecycleEngine;
use tinker_ontology::mutate::MutationConnector;
use tinker_web::SharedState;

/// Header carrying the session id (MCP `Mcp-Session-Id`).
const SESSION_HEADER: &str = "mcp-session-id";
/// Idle sessions are reaped after this long without a request.
const SESSION_IDLE_TTL: Duration = Duration::from_secs(30 * 60);
/// How often the reaper scans.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

/// One authenticated MCP-over-HTTP session: the bound front door, the
/// credential it was opened with, and the last request time (for the
/// idle reaper).
struct Session {
    door: FrontDoor,
    cred_id: Uuid,
    last_seen: Mutex<Instant>,
}

impl Session {
    fn touch(&self) {
        if let Ok(mut t) = self.last_seen.lock() {
            *t = Instant::now();
        }
    }

    fn idle_for(&self) -> Duration {
        self.last_seen
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

/// The governed services, built once at startup and shared by every
/// session. `SharedState` is an `Arc`; the connector and engine are
/// `Clone` (item 46) so each session gets a cheap copy bound to its
/// own credential.
#[derive(Clone)]
struct Services {
    state: SharedState,
    mutator: MutationConnector,
    lifecycle: LifecycleEngine,
}

#[derive(Clone)]
struct HttpState {
    core: CoreDb,
    store: Arc<MachineCredentialStore>,
    services: Services,
    sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>,
}

// ---------------------------------------------------------------------------
// Error bodies: the stdio teaching family — {"error","message","hint"}
// ---------------------------------------------------------------------------

fn teaching(status: StatusCode, error: &str, message: &str, hint: Option<&str>) -> Response {
    let mut body = serde_json::Map::with_capacity(3);
    body.insert("error".into(), Value::from(error));
    body.insert("message".into(), Value::from(message));
    if let Some(h) = hint {
        body.insert("hint".into(), Value::from(h));
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (status, headers, Value::from(body).to_string()).into_response()
}

const KEY_ISSUE_HINT: &str = "issue a key with `tinker-cli mcp key issue --role <role>`";

/// A small HTTP-layer failure, rendered to a teaching [`Response`] at
/// the route boundary. Kept small deliberately: returning `Response`
/// (128+ bytes) as a `Result` error trips `clippy::result_large_err`.
struct HttpError {
    status: StatusCode,
    error: &'static str,
    message: String,
    hint: Option<&'static str>,
}

impl HttpError {
    fn response(self) -> Response {
        teaching(self.status, self.error, &self.message, self.hint)
    }
}

/// 401 for a missing or malformed `Authorization` header. This names
/// the expected header — protocol usage, not key validity — so it is
/// not an oracle.
fn unauthorized_missing() -> HttpError {
    HttpError {
        status: StatusCode::UNAUTHORIZED,
        error: "unauthorized",
        message: "this endpoint requires a C6 machine credential: send \
                  `Authorization: Bearer tk_...`"
            .to_string(),
        hint: Some(KEY_ISSUE_HINT),
    }
}

/// 401 for any key-verification failure. Unknown, malformed, revoked,
/// and expired keys all share this one identical body — no oracle —
/// mirroring stdio's uniform "auth failed: invalid API key".
fn unauthorized_invalid() -> HttpError {
    HttpError {
        status: StatusCode::UNAUTHORIZED,
        error: "unauthorized",
        message: "invalid API key: verification failed".to_string(),
        hint: Some("issue a fresh key with `tinker-cli mcp key issue --role <role>`"),
    }
}

// ---------------------------------------------------------------------------
// Request helpers
// ---------------------------------------------------------------------------

/// Extract the Bearer token. `None` covers missing, unparsable, and
/// non-Bearer headers alike.
fn bearer_key(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

/// Verify the request's key through the exact stdio startup path.
/// Returns the verified credential or the 401 response.
async fn authenticate(
    state: &HttpState,
    headers: &HeaderMap,
) -> Result<tinker_auth::apikey::VerifiedCredential, HttpError> {
    let key = bearer_key(headers).ok_or_else(unauthorized_missing)?;
    // The key is used only for this verification; it is never logged,
    // never stored, and dropped at the end of the request — the same
    // discipline as stdio's startup `drop(api_key)`.
    state
        .store
        .verify(&key)
        .await
        .map_err(|_| unauthorized_invalid())
}

/// Look up the session named by the request header. The request's
/// credential must be the one the session was opened with.
async fn find_session(
    state: &HttpState,
    headers: &HeaderMap,
    cred_id: Uuid,
) -> Result<Arc<Session>, HttpError> {
    let id = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| HttpError {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            message: "this method needs an initialized session: send the `Mcp-Session-Id` \
                      header from a prior `initialize` response"
                .to_string(),
            hint: Some(
                "POST /mcp with {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",...} first",
            ),
        })?;
    let session = state
        .sessions
        .read()
        .await
        .get(id)
        .cloned()
        .ok_or_else(|| HttpError {
            status: StatusCode::NOT_FOUND,
            error: "not_found",
            message: "unknown or expired session".to_string(),
            hint: Some("re-run `initialize` to open a new session"),
        })?;
    if session.cred_id != cred_id {
        return Err(HttpError {
            status: StatusCode::UNAUTHORIZED,
            error: "unauthorized",
            message: "the Bearer key does not match the credential this session was opened with"
                .to_string(),
            hint: Some("re-run `initialize` with this key to open its own session"),
        });
    }
    // Membership is re-read on every request: the role was resolved at
    // `initialize`, and a demoted or removed actor must not keep it for
    // as long as the session stays busy (the idle sweep never fires on
    // an active session). Any change ends the session; the client
    // re-initializes and gets the current role, or a teaching 403.
    match FrontDoor::resolve_role(&state.core, session.door.tenant()).await {
        Ok(role) if role == session.door.role() => {}
        _ => {
            state.sessions.write().await.remove(id);
            return Err(HttpError {
                status: StatusCode::UNAUTHORIZED,
                error: "unauthorized",
                message: "this key's membership changed since the session was opened".to_string(),
                hint: Some("re-run `initialize` to open a session with the current role"),
            });
        }
    }
    session.touch();
    Ok(session)
}

/// The stdio-identical `-32700` envelope, for bodies that are not
/// JSON at all. Key order matches stdio's serializer (sorted), so the
/// bytes are identical to what `FrontDoor::handle` would emit.
fn parse_error_response() -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": Value::Null,
        "error": { "code": -32700, "message": "parse error" },
    })
    .to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::OK, headers, body).into_response()
}

fn session_headers(session_id: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(v) = HeaderValue::from_str(session_id) {
        headers.insert(SESSION_HEADER, v);
    }
    headers
}

fn wants_sse(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"))
}

/// Render one JSON-RPC response string: plain JSON, or a single SSE
/// `data:` event when the client asked for `text/event-stream`. The
/// JSON-RPC bytes are identical either way — only the framing differs.
fn render_rpc(body: String, session_id: &str, sse: bool) -> Response {
    if sse {
        let stream = tokio_stream::once(Ok::<_, axum::Error>(Event::default().data(body)));
        let mut headers = HeaderMap::new();
        if let Ok(v) = HeaderValue::from_str(session_id) {
            headers.insert(SESSION_HEADER, v);
        }
        return (headers, Sse::new(stream)).into_response();
    }
    (StatusCode::OK, session_headers(session_id), body).into_response()
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// `POST /mcp`: JSON-RPC over HTTP.
///
/// * `initialize` mints a session and answers through the same
///   `FrontDoor::handle` path as stdio, plus the `Mcp-Session-Id`
///   header.
/// * Any other method needs the session header and dispatches through
///   the session's door — the identical code path as stdio.
/// * Notifications (no `id`) return `202 Accepted`, empty body.
async fn post_mcp(State(state): State<HttpState>, headers: HeaderMap, body: Bytes) -> Response {
    let cred = match authenticate(&state, &headers).await {
        Ok(c) => c,
        Err(e) => return e.response(),
    };
    let raw = match std::str::from_utf8(&body) {
        Ok(s) => s,
        Err(_) => return parse_error_response(),
    };
    let msg: Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return parse_error_response(),
    };
    let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let sse = wants_sse(&headers);

    if method == "initialize" {
        // The role comes from the membership table — the same trusted
        // source as stdio's startup. No row fails closed here with the
        // teaching error; the fix is operator-side, never a default
        // the server invents.
        let tenant = TenantContext::new(
            OrganizationId(cred.organization_id),
            cred.actor_id,
            "tinker-mcp".to_string(),
        );
        let role = match FrontDoor::resolve_role(&state.core, &tenant).await {
            Ok(r) => r,
            Err(e) => {
                return teaching(
                    StatusCode::FORBIDDEN,
                    "forbidden",
                    &e.to_string(),
                    Some(KEY_ISSUE_HINT),
                )
            }
        };
        let door = FrontDoor::new(
            state.services.state.clone(),
            state.services.mutator.clone(),
            state.services.lifecycle.clone(),
            cred.clone(),
            tenant,
            role,
        );
        let session_id = Uuid::now_v7().simple().to_string();
        // The initialize *result* comes from the same dispatch as
        // stdio — byte-identical `result` payload; only the session
        // header is new.
        let response = door.handle(raw).await;
        state.sessions.write().await.insert(
            session_id.clone(),
            Arc::new(Session {
                door,
                cred_id: cred.id,
                last_seen: Mutex::new(Instant::now()),
            }),
        );
        return match response {
            Some(body) => render_rpc(body, &session_id, sse),
            // initialize-as-notification: the session exists; hand the
            // client its id anyway.
            None => (
                StatusCode::ACCEPTED,
                session_headers(&session_id),
                String::new(),
            )
                .into_response(),
        };
    }

    let session = match find_session(&state, &headers, cred.id).await {
        Ok(s) => s,
        Err(e) => return e.response(),
    };
    let session_id = headers
        .get(SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    match session.door.handle(raw).await {
        Some(body) => render_rpc(body, session_id, sse),
        // Notifications get no response — 202, empty body.
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// `GET /mcp/stream`: the server→client SSE channel for one session.
/// An `event: ready` greeting, then `:keep-alive` comments every 15 s
/// (axum's `KeepAlive`). v1 emits no unsolicited notifications; the
/// stream exists so SSE-capable clients have a channel to hold.
async fn get_stream(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    let cred = match authenticate(&state, &headers).await {
        Ok(c) => c,
        Err(e) => return e.response(),
    };
    let session_id = match headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok()) {
        Some(id) => id.to_string(),
        None => return teaching(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the stream needs an initialized session: send the `Mcp-Session-Id` \
                 header from a prior `initialize` response",
            Some(
                "POST /mcp with {\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",...} first",
            ),
        ),
    };
    let session = match find_session(&state, &headers, cred.id).await {
        Ok(s) => s,
        Err(e) => return e.response(),
    };
    drop(session);
    let ready = tokio_stream::once(Ok::<_, axum::Error>(
        Event::default().event("ready").data(session_id.clone()),
    ));
    let sse = Sse::new(ready).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    );
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(&session_id) {
        headers.insert(SESSION_HEADER, v);
    }
    (headers, sse).into_response()
}

/// `GET /healthz`: liveness probe for load balancers and the reverse
/// proxy. Unauthenticated by design (probes carry no credentials) and
/// information-minimal: a status flag and the build version, nothing
/// about the database, sessions, tenants, or configuration. Never logs.
async fn healthz() -> Response {
    let body = serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    })
    .to_string();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::OK, headers, body).into_response()
}

/// `DELETE /mcp`: terminate the session named by the header.
async fn delete_mcp(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    let cred = match authenticate(&state, &headers).await {
        Ok(c) => c,
        Err(e) => return e.response(),
    };
    let session = match find_session(&state, &headers, cred.id).await {
        Ok(s) => s,
        Err(e) => return e.response(),
    };
    drop(session);
    if let Some(id) = headers.get(SESSION_HEADER).and_then(|v| v.to_str().ok()) {
        state.sessions.write().await.remove(id);
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn fallback_404() -> Response {
    teaching(
        StatusCode::NOT_FOUND,
        "not_found",
        "unknown route",
        Some("the MCP surface is POST /mcp, GET /mcp/stream, DELETE /mcp, GET /healthz"),
    )
}

/// Reap sessions idle longer than [`SESSION_IDLE_TTL`].
async fn sweep_loop(sessions: Arc<RwLock<HashMap<String, Arc<Session>>>>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        let mut map = sessions.write().await;
        let before = map.len();
        map.retain(|_, s| s.idle_for() < SESSION_IDLE_TTL);
        let reaped = before - map.len();
        if reaped > 0 {
            eprintln!("tinker-mcp: reaped {reaped} idle session(s)");
        }
    }
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("tinker-mcp: {name} must be set");
        std::process::exit(2);
    })
}

/// Run the HTTP/SSE server. Serve mode needs no `TINKER_API_KEY` —
/// keys arrive per request — but it needs the two database URLs and
/// the file backend environment, exactly like stdio mode.
pub async fn serve(bind: &str) -> Result<(), String> {
    let owner_url = required_env("TINKER_CORE_OWNER_URL");
    let core_url = required_env("TINKER_CORE_URL");

    let owner = OwnerDb::connect(&owner_url)
        .await
        .map_err(|e| format!("owner db connect: {e}"))?;
    // Same cluster-wide migration discipline as the `tinker` server and
    // stdio mode: exactly one instance migrates while the rest wait.
    owner.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    let core = CoreDb::connect(&core_url)
        .await
        .map_err(|e| format!("tenant db connect: {e}"))?;

    let (shared_state, mutator, lifecycle) =
        build_services(core.0.clone(), owner.0.clone()).map_err(|e| e.to_string())?;
    let sessions: Arc<RwLock<HashMap<String, Arc<Session>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn(sweep_loop(sessions.clone()));
    let state = HttpState {
        core,
        store: Arc::new(MachineCredentialStore::new(owner.clone())),
        services: Services {
            state: shared_state,
            mutator,
            lifecycle,
        },
        sessions,
    };

    let app = Router::new()
        .route("/mcp", post(post_mcp).delete(delete_mcp))
        .route("/mcp/stream", get(get_stream))
        .route("/healthz", get(healthz))
        .fallback(fallback_404)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind {bind}: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    // The test harness parses this line to discover the port when
    // binding `:0`. Keep the format stable: "listening on <addr>".
    eprintln!("tinker-mcp: listening on {addr} (http)");
    axum::serve(listener, app)
        .await
        .map_err(|e| format!("serve: {e}"))?;
    Ok(())
}
