//! MCP HTTP+SSE transport (MCP 2024-11-05) plus single-shot JSON-RPC over
//! POST (Directus C6, second half).
//!
//! Endpoints — every one requires `Authorization: Bearer tk_...`:
//! - `GET /sse` — opens an SSE stream. First event is `endpoint` with
//!   `data: /messages?session_id=<id>`; JSON-RPC responses follow as
//!   `message` events. Keepalive comments every 15s; the session dies
//!   with the stream.
//! - `POST /messages?session_id=<id>` — one JSON-RPC message. The Bearer
//!   key must be the same credential that opened the session. The
//!   response (if the message wasn't a notification) is delivered as an
//!   SSE `message` event; HTTP status is 202 either way.
//! - `POST /mcp` — single-shot JSON-RPC: the response body is the
//!   JSON-RPC response (200); notifications get 202 with an empty body.
//!
//! Scope enforcement runs before dispatch
//! (`tinker_auth::apikey::scope_allows`); denied calls get JSON-RPC
//! error -32001, never a transport error. Sessions idle longer than
//! [`SESSION_IDLE_TIMEOUT`] are swept.
//!
//! The listener binds 127.0.0.1 only: TLS termination and public ingress
//! are the deployer's job, documented at the `mcp http` CLI help.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use serde::Deserialize;
use tinker_agents::gateway::ModelGateway;
use tinker_agents::mcp_stdio::StdioMcpServer;
use tinker_agents::profiles::ProfileEngine;
use tinker_agents::{AuditWriter, TransformCache, TransformEngine};
use tinker_auth::apikey::{scope_allows, MachineCredentialStore, VerifiedCredential};
use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::Ontology;
use tokio::sync::{mpsc, RwLock};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;
use uuid::Uuid;

/// Idle sessions are swept after this long without a message.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const SSE_KEEPALIVE: Duration = Duration::from_secs(15);

/// Everything needed to serve one request. Cheap to clone.
#[derive(Clone)]
pub struct HttpStack {
    pub core: CoreDb,
    pub owner: OwnerDb,
    pub ontology: Ontology,
    pub gateway: ModelGateway,
}

impl HttpStack {
    /// A fresh wire server for one message. Mirrors the stdio path:
    /// per-message server construction, same semantic pipeline.
    fn wire_server(&self, ctx: TenantContext) -> StdioMcpServer {
        let audit = AuditWriter::new(self.core.clone(), self.owner.clone());
        let engine = TransformEngine::new(
            self.core.clone(),
            self.owner.clone(),
            self.ontology.clone(),
            self.gateway.clone(),
            audit,
        );
        let cache = TransformCache::new(self.core.clone(), self.owner.clone());
        let profiles = ProfileEngine::new(self.core.clone(), self.owner.clone());
        StdioMcpServer::new(
            ctx,
            self.core.clone(),
            self.owner.clone(),
            self.ontology.clone(),
            engine,
            cache,
            profiles,
            None,
        )
    }
}

struct Session {
    credential_id: Uuid,
    ctx: TenantContext,
    scopes: Vec<String>,
    tx: mpsc::UnboundedSender<String>,
    last_active: Instant,
}

#[derive(Clone)]
struct AppState {
    stack: HttpStack,
    store: Arc<MachineCredentialStore>,
    sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
}

/// Bearer credential → verified machine credential. Every failure is 401
/// with no oracle (the store already collapses all failure modes).
async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<VerifiedCredential, StatusCode> {
    let secret = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    state
        .store
        .verify(secret.trim())
        .await
        .map_err(|e| match e {
            TinkerError::Forbidden(_) => StatusCode::UNAUTHORIZED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })
}

fn rpc_scope_denied(id: &serde_json::Value, method: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": -32001, "message": format!("insufficient scope for {method}")},
    })
}

/// Dispatch one message through the scope gate then the shared wire
/// server. Returns None for notifications — including scoped
/// notifications, which are dropped silently (there is no one to
/// answer).
async fn dispatch(
    stack: &HttpStack,
    ctx: TenantContext,
    scopes: &[String],
    msg: serde_json::Value,
) -> Option<serde_json::Value> {
    let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let tool_name = (method == "tools/call")
        .then(|| {
            msg.get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
        })
        .flatten();
    if !scope_allows(scopes, method, tool_name) {
        let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
        return msg.get("id").map(|_| rpc_scope_denied(&id, method));
    }
    stack.wire_server(ctx).handle(msg).await
}

fn tenant_ctx(cred: &VerifiedCredential) -> TenantContext {
    TenantContext::new(
        OrganizationId(cred.organization_id),
        cred.actor_id,
        "mcp-http",
    )
}

#[derive(Deserialize)]
struct MessagesQuery {
    session_id: Uuid,
}

/// POST /messages?session_id=… — the 2024-11-05 message endpoint.
async fn post_messages(
    State(state): State<AppState>,
    Query(q): Query<MessagesQuery>,
    headers: HeaderMap,
    Json(msg): Json<serde_json::Value>,
) -> Response {
    if msg.is_array() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let cred = match authenticate(&state, &headers).await {
        Ok(c) => c,
        Err(s) => return s.into_response(),
    };
    // Pull the session's pieces out under the lock, then dispatch
    // without holding it.
    let (ctx, scopes, tx) = {
        let mut sessions = state.sessions.write().await;
        let session = match sessions.get_mut(&q.session_id) {
            Some(s) => s,
            None => return StatusCode::NOT_FOUND.into_response(),
        };
        // The session is bound to the credential that opened it: a
        // different valid key cannot hijack another key's stream.
        if session.credential_id != cred.id {
            return StatusCode::FORBIDDEN.into_response();
        }
        session.last_active = Instant::now();
        (
            session.ctx.clone(),
            session.scopes.clone(),
            session.tx.clone(),
        )
    };
    if let Some(resp) = dispatch(&state.stack, ctx, &scopes, msg).await {
        let text = serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into());
        let _ = tx.send(text);
    }
    StatusCode::ACCEPTED.into_response()
}

/// GET /sse — open the event stream for a new session.
async fn get_sse(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cred = match authenticate(&state, &headers).await {
        Ok(c) => c,
        Err(s) => return s.into_response(),
    };
    let (tx, rx) = mpsc::unbounded_channel::<String>();
    let id = Uuid::now_v7();
    // The session dies with the stream: when the client disconnects axum
    // drops the receiver, the watcher's `closed()` fires, and the session
    // is removed. The idle sweeper is the backstop.
    let sessions2 = state.sessions.clone();
    let watch_tx = tx.clone();
    tokio::spawn(async move {
        watch_tx.closed().await;
        sessions2.write().await.remove(&id);
    });
    state.sessions.write().await.insert(
        id,
        Session {
            credential_id: cred.id,
            ctx: tenant_ctx(&cred),
            scopes: cred.scopes,
            tx,
            last_active: Instant::now(),
        },
    );

    let endpoint_event = Event::default()
        .event("endpoint")
        .data(format!("/messages?session_id={id}"));
    let stream = tokio_stream::iter(vec![Ok::<_, Infallible>(endpoint_event)]).chain(
        UnboundedReceiverStream::new(rx)
            .map(|text| Ok::<_, Infallible>(Event::default().event("message").data(text))),
    );

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(SSE_KEEPALIVE).text("ping"))
        .into_response()
}

/// POST /mcp — single-shot JSON-RPC (no SSE stream needed).
async fn post_mcp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(msg): Json<serde_json::Value>,
) -> Response {
    if msg.is_array() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let cred = match authenticate(&state, &headers).await {
        Ok(c) => c,
        Err(s) => return s.into_response(),
    };
    match dispatch(&state.stack, tenant_ctx(&cred), &cred.scopes, msg).await {
        Some(resp) => Json(resp).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

async fn sweep_sessions(state: AppState) {
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let cutoff = Instant::now() - SESSION_IDLE_TIMEOUT;
        let mut sessions = state.sessions.write().await;
        sessions.retain(|_, s| s.last_active >= cutoff);
    }
}

/// Build the router (also used by tests on an ephemeral port).
pub fn router(stack: HttpStack, store: MachineCredentialStore) -> axum::Router {
    let state = AppState {
        stack,
        store: Arc::new(store),
        sessions: Arc::new(RwLock::new(HashMap::new())),
    };
    tokio::spawn(sweep_sessions(state.clone()));
    axum::Router::new()
        .route("/sse", get(get_sse))
        .route("/messages", post(post_messages))
        .route("/mcp", post(post_mcp))
        .with_state(state)
}

/// Serve MCP over HTTP/SSE on 127.0.0.1:port. Runs until cancelled.
/// (Used by the `tinker-cli mcp http` binary; the integration test builds the
/// router directly, so this looks dead from the test's `#[path]` include.)
#[allow(dead_code)]
pub async fn serve_http(
    stack: HttpStack,
    store: MachineCredentialStore,
    port: u16,
) -> tinker_core::Result<()> {
    let app = router(stack, store);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| TinkerError::Internal(format!("mcp http bind: {e}")))?;
    axum::serve(listener, app)
        .await
        .map_err(|e| TinkerError::Internal(format!("mcp http serve: {e}")))
}
