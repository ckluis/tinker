//! MCP wire transport: JSON-RPC 2.0 over stdio (newline-delimited).
//!
//! This is the standard MCP deployment model: the client spawns one
//! server process per user session, so identity is launch-scoped
//! (`--org`/`--actor`, the same dev-grade authn as the `vfile` CLI).
//! Every request still runs through the full semantic pipeline
//! (Identify → Authorize → Transform → Emit → Audit) — the transport
//! adds no new privilege, it only serializes the in-process
//! [`crate::mcp::McpServer`] surface onto the wire.
//!
//! Protocol (MCP 2024-11-05 core):
//! - `initialize` → capabilities + serverInfo (version negotiation)
//! - `notifications/initialized`, `ping`
//! - `tools/list`, `tools/call` (execution errors → `isError` results,
//!   never protocol errors — MCP-idiomatic)
//! - `resources/list`, `resources/read`
//! - unknown method → -32601, bad params → -32602, parse error → -32700
//!
//! HTTP/SSE transport is deliberately NOT here: it needs a
//! machine-credential (API key issuance/verification) story that does
//! not exist yet. See BACKLOG.md.

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::Ontology;
use uuid::Uuid;

use crate::cache::TransformCache;
use crate::expand::ExpansionEngine;
use crate::mcp::McpServer;
use crate::profiles::ProfileEngine;
use crate::transforms::TransformEngine;

/// Newest MCP protocol version this server speaks. `initialize`
/// echoes the client's version when we support it, else ours.
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";
const SUPPORTED_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26"];

fn rpc_error(id: &serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    })
}

fn rpc_ok(id: &serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

/// The stdio MCP server: launch-scoped identity, per-message McpServer.
pub struct StdioMcpServer {
    ctx: TenantContext,
    core: CoreDb,
    owner: OwnerDb,
    ontology: Ontology,
    engine: TransformEngine,
    cache: TransformCache,
    profiles: ProfileEngine,
    default_attachment: Option<Uuid>,
}

impl StdioMcpServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ctx: TenantContext,
        core: CoreDb,
        owner: OwnerDb,
        ontology: Ontology,
        engine: TransformEngine,
        cache: TransformCache,
        profiles: ProfileEngine,
        default_attachment: Option<Uuid>,
    ) -> Self {
        Self {
            ctx,
            core,
            owner,
            ontology,
            engine,
            cache,
            profiles,
            default_attachment,
        }
    }

    /// Resolve an attachment NAME to its id (tenant-scoped), like the CLI.
    async fn resolve_attachment(&self, name: &str) -> Result<Uuid> {
        let mut tx = self.core.tenant_tx(&self.ctx).await?;
        let id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM agent_attachments WHERE organization_id = $1 AND name = $2 AND status = 'active'",
        )
        .bind(self.ctx.organization_id.0)
        .bind(name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        id.ok_or_else(|| TinkerError::NotFound(format!("attachment {name}")))
    }

    /// Handle one decoded JSON-RPC message. Returns None for
    /// notifications (no response); Some(response) otherwise.
    pub async fn handle(&self, msg: serde_json::Value) -> Option<serde_json::Value> {
        let obj = msg.as_object()?;
        if obj.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
            return None;
        }
        let method = obj.get("method").and_then(|v| v.as_str())?;
        // No id → notification: never respond.
        let id = match obj.get("id") {
            Some(id) => id.clone(),
            None => return self.handle_notification(method).await,
        };

        let params = obj
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        Some(self.dispatch_wrapped(&id, method, params).await)
    }

    /// Notifications get no response. Unknown notifications are ignored
    /// (MCP-idiomatic); method-less messages were already filtered.
    async fn handle_notification(&self, _method: &str) -> Option<serde_json::Value> {
        None
    }

    async fn dispatch(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> std::result::Result<serde_json::Value, DispatchError> {
        // Per-message server: borrows only locals, no self-referential struct.
        let expansion = ExpansionEngine::new(
            self.core.clone(),
            self.owner.clone(),
            &self.ontology,
            &self.engine,
        );
        let mcp = McpServer::new(&self.engine, &self.cache, &self.profiles, expansion);
        match method {
            "initialize" => {
                let want = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let version = if SUPPORTED_VERSIONS.contains(&want) {
                    want
                } else {
                    MCP_PROTOCOL_VERSION
                };
                Ok(serde_json::json!({
                    "protocolVersion": version,
                    "capabilities": {
                        "tools": {"listChanged": false},
                        "resources": {"listChanged": false},
                    },
                    "serverInfo": {
                        "name": "tinker",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }))
            }
            "ping" => Ok(serde_json::json!({})),
            "tools/list" => Ok(serde_json::json!({ "tools": McpServer::tools_list() })),
            "resources/list" => Ok(serde_json::json!({ "resources": McpServer::resources_list() })),
            "tools/call" => {
                let name = params
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or(DispatchError::InvalidParams("tools/call needs name"))?;
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                // Attachment: per-call name wins, else the server default.
                // expand_context fails closed without one (in-process rule).
                let attachment_id = match args.get("attachment").and_then(|v| v.as_str()) {
                    Some(name) => Some(self.resolve_attachment(name).await?),
                    None => self.default_attachment,
                };
                match mcp.tools_call(&self.ctx, name, args, attachment_id).await {
                    Ok(value) => Ok(serde_json::json!({
                        "content": [{"type": "text", "text": serde_json::to_string_pretty(&value)
                            .unwrap_or_else(|_| "{}".into())}],
                    })),
                    Err(e) => Ok(serde_json::json!({
                        "content": [{"type": "text", "text": format!("{}: {e}", e.code())}],
                        "isError": true,
                    })),
                }
            }
            "resources/read" => {
                let uri = params
                    .get("uri")
                    .and_then(|v| v.as_str())
                    .ok_or(DispatchError::InvalidParams("resources/read needs uri"))?;
                let attachment_id = match params.get("attachment").and_then(|v| v.as_str()) {
                    Some(name) => Some(self.resolve_attachment(name).await?),
                    None => self.default_attachment,
                };
                match mcp.resources_read(&self.ctx, uri, attachment_id).await {
                    Ok(value) => {
                        let text = value
                            .get("text")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default();
                        let mime = value
                            .get("mimeType")
                            .and_then(|v| v.as_str())
                            .unwrap_or("text/markdown");
                        Ok(serde_json::json!({
                            "contents": [{"uri": uri, "mimeType": mime, "text": text}],
                        }))
                    }
                    Err(e) => Err(DispatchError::Tinker(e)),
                }
            }
            _ => Err(DispatchError::MethodNotFound(method.to_string())),
        }
    }

    /// Run the stdio loop: newline-delimited JSON-RPC on stdin → stdout.
    /// EOF on stdin ends the session (exit 0). Logging goes to stderr —
    /// stdout is protocol-only.
    pub async fn run_stdio(&self) -> Result<()> {
        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();
        let mut stdout = tokio::io::stdout();
        let io_err = |e: std::io::Error| TinkerError::Internal(e.to_string());
        while let Some(line) = lines.next_line().await.map_err(io_err)? {
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(msg) => self.handle(msg).await,
                Err(_) => Some(rpc_error(&serde_json::Value::Null, -32700, "parse error")),
            };
            if let Some(resp) = response {
                let mut out = serde_json::to_string(&resp).map_err(TinkerError::Serde)?;
                out.push('\n');
                stdout.write_all(out.as_bytes()).await.map_err(io_err)?;
                stdout.flush().await.map_err(io_err)?;
            }
        }
        Ok(())
    }
}

/// Dispatch-level failures: protocol errors (-32601/-32602) vs
/// pipeline errors (surfaced as tool isError results or -32603).
enum DispatchError {
    MethodNotFound(String),
    InvalidParams(&'static str),
    Tinker(TinkerError),
}

impl From<TinkerError> for DispatchError {
    fn from(e: TinkerError) -> Self {
        DispatchError::Tinker(e)
    }
}

// DispatchError → JSON-RPC error at the handle() boundary.
impl StdioMcpServer {
    async fn dispatch_wrapped(
        &self,
        id: &serde_json::Value,
        method: &str,
        params: serde_json::Value,
    ) -> serde_json::Value {
        match self.dispatch(method, params).await {
            Ok(value) => rpc_ok(id, value),
            Err(DispatchError::MethodNotFound(m)) => {
                rpc_error(id, -32601, &format!("method not found: {m}"))
            }
            Err(DispatchError::InvalidParams(m)) => rpc_error(id, -32602, m),
            Err(DispatchError::Tinker(e)) => rpc_error(id, -32603, &format!("{e}")),
        }
    }
}
