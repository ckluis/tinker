//! Item 45 (agent front door, Part 2): `tinker-mcp` — the MCP front door
//! over the machine API, stdio transport.
//!
//! Item 46 adds the HTTP/SSE transport (`tinker-mcp serve`); see the
//! `http` module. The stdio path below is unchanged.
//!
//! # Transport decision (honest account)
//!
//! The MCP wire protocol needed here is small and stable: `initialize`,
//! `ping`, `tools/list`, `tools/call`, `resources/list`, `resources/read`,
//! and `notifications/*`, as newline-delimited JSON-RPC 2.0 over stdio
//! (unchanged across MCP 2024-11-05 → 2025-06-18). The Rust SDK (`rmcp`
//! 3.4.1) exists and `cargo` can fetch it, but the spec's hard
//! requirements all live at the dispatch layer — C6 scope gating per
//! method/tool, the tinker-version handshake inside `initialize`, and
//! no-oracle teaching errors — where an SDK adds indirection without
//! value. So the dispatch is hand-rolled (~300 lines) against the MCP
//! spec, with zero new dependencies (the build stays hermetic after
//! rootfs rolls), and the compatibility guarantee comes from the test
//! suite driving a real JSON-RPC handshake over a pipe, not from SDK
//! conformance by construction.
//!
//! # Architecture: a thin front door, not a parallel governance stack
//!
//! Every tool routes through the exact production services the HTTP API
//! uses — the same [`tinker_web`] `AppState` (query compiler, executor,
//! cache, field grants, row filters, dashboard service), the same
//! [`MutationConnector`](tinker_ontology::mutate::MutationConnector),
//! the same [`LifecycleEngine`](tinker_ontology::lifecycle::LifecycleEngine),
//! and the same [`Describer`](tinker_web::describe::Describer). The MCP
//! layer adds only: stdio JSON-RPC framing, C6 API-key authentication,
//! per-method scope gating, the version handshake, and error shaping.
//!
//! # Security model
//!
//! - Auth: one C6 API key from `TINKER_API_KEY`, verified by
//!   [`MachineCredentialStore`](tinker_auth::apikey::MachineCredentialStore).
//!   Every verification failure is the same error — no oracle.
//! - The credential binds (organization, actor). The actor's *role* comes
//!   from the `memberships` table — the same trusted source the HTTP
//!   tier uses — and every tool executes as that role: row filters
//!   (item 38), field projection (M3), lifecycle visibility (item 40),
//!   validation (item 37), and file-field checks (item 42) all apply.
//!   A machine actor with no membership fails closed with a teaching
//!   error; `tinker-cli mcp key issue --role <role>` grants one.
//! - Scopes (`mcp:tools`, `mcp:resources`, `mcp:tool:<name>`) gate which
//!   protocol methods the key may invoke, via
//!   [`scope_allows`](tinker_auth::apikey::scope_allows).
//! - Unknown vs hidden is never distinguished: missing records, hidden
//!   records, and foreign objects all produce the same `not_found`
//!   shape.

pub mod http;

use std::sync::Arc;

use serde_json::Value;
use tinker_auth::apikey::{scope_allows, VerifiedCredential};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_ontology::lifecycle::LifecycleEngine;
use tinker_ontology::mutate::{CreateRequest, MutationConnector, NoHooks, UpdateRequest};
use tinker_query::QueryIntent;
use tinker_web::describe::{self, Describer, VersionPin};
use tinker_web::SharedState;
use uuid::Uuid;

/// MCP server name reported in `initialize`.
pub const SERVER_NAME: &str = "tinker-mcp";
/// MCP protocol versions this server speaks, newest first.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// The version offered when the client asks for one we don't know.
pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

// JSON-RPC 2.0 error codes.
pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_INTERNAL: i64 = -32603;
// Server-defined (-32000..-32099, reserved for implementation use):
/// Client declared tinker/ontology versions that don't match the server.
pub const ERR_VERSION_MISMATCH: i64 = -32000;
/// The credential's scopes don't allow this method/tool.
pub const ERR_SCOPE_DENIED: i64 = -32001;
/// Resource (or resource template parameter) not found.
pub const ERR_RESOURCE_NOT_FOUND: i64 = -32002;

// ---------------------------------------------------------------------------
// The front door
// ---------------------------------------------------------------------------

/// One authenticated MCP session: the verified credential, its tenant
/// context, and its resolved role. The binary builds exactly one of
/// these at startup from `TINKER_API_KEY`; tests build one per
/// credential to prove isolation.
pub struct FrontDoor {
    state: SharedState,
    mutator: MutationConnector,
    lifecycle: LifecycleEngine,
    cred: VerifiedCredential,
    tenant: TenantContext,
    role: String,
}

impl FrontDoor {
    pub fn new(
        state: SharedState,
        mutator: MutationConnector,
        lifecycle: LifecycleEngine,
        cred: VerifiedCredential,
        tenant: TenantContext,
        role: String,
    ) -> Self {
        Self {
            state,
            mutator,
            lifecycle,
            cred,
            tenant,
            role,
        }
    }

    /// Resolve the machine actor's role from the memberships table — the
    /// same trusted source the HTTP tier's `role_of` reads. No row (or a
    /// revoked membership, which the join excludes by RLS) fails closed
    /// with a teaching error: the fix is operator-side
    /// (`tinker-cli mcp key issue --role <role>`), never a default the
    /// server invents.
    /// The tenant this session is pinned to (org + actor from the key).
    pub fn tenant(&self) -> &TenantContext {
        &self.tenant
    }

    /// The membership role resolved at `initialize`.
    pub fn role(&self) -> &str {
        &self.role
    }

    pub async fn resolve_role(core: &CoreDb, tenant: &TenantContext) -> Result<String> {
        let mut tx = core.tenant_tx(tenant).await?;
        let row: Option<(String,)> =
            sqlx::query_as("SELECT role FROM memberships WHERE actor_id=$1 AND organization_id=$2")
                .bind(tenant.actor_id)
                .bind(tenant.organization_id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        row.map(|(r,)| r).ok_or_else(|| {
            TinkerError::Forbidden(
                "this machine credential has no membership in its organization, \
                 so it has no role to execute as; have an operator re-issue it with \
                 `tinker-cli mcp key issue --role <role>`"
                    .into(),
            )
        })
    }

    fn describer(&self) -> Describer {
        Describer::from_state(&self.state)
    }

    // ------------------------------------------------------------------
    // JSON-RPC dispatch
    // ------------------------------------------------------------------

    /// Dispatch one raw JSON-RPC message. Returns `None` for
    /// notifications (no `id`) — including scoped notifications, which
    /// are dropped silently because there is no one to answer.
    pub async fn handle(&self, raw: &str) -> Option<String> {
        let msg: Value = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return Some(rpc_error(&Value::Null, ERR_PARSE, "parse error", None)),
        };
        let obj = match msg.as_object() {
            Some(o) => o,
            None => {
                return Some(rpc_error(
                    &Value::Null,
                    ERR_INVALID_REQUEST,
                    "request must be a JSON object",
                    None,
                ))
            }
        };
        if let Some(v) = obj.get("jsonrpc") {
            if v != "2.0" {
                return Some(rpc_error(
                    &Value::Null,
                    ERR_INVALID_REQUEST,
                    "jsonrpc must be \"2.0\"",
                    None,
                ));
            }
        }
        let method = obj.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = obj.get("id").cloned();
        let params = obj.get("params").cloned().unwrap_or(Value::Null);

        // Notifications carry no id and get no response.
        let is_notification = id.is_none();
        let respond = |v: Value| -> Option<String> {
            if is_notification {
                return None;
            }
            let id = id.clone().unwrap_or(Value::Null);
            let mut envelope = serde_json::Map::with_capacity(3);
            envelope.insert("jsonrpc".into(), Value::from("2.0"));
            envelope.insert("id".into(), id);
            match v.get("error") {
                Some(_) => {
                    envelope.insert("error".into(), v["error"].clone());
                }
                None => {
                    envelope.insert("result".into(), v);
                }
            }
            Some(Value::from(envelope).to_string())
        };

        // initialize / ping / notifications need auth only (the key was
        // verified at startup); everything else is scope-gated.
        //
        // Order matters: an unknown method is -32601 even for a
        // scope-starved credential — telling a fully-authorized client
        // "insufficient scope" for a method that does not exist would
        // be a lie. Scope checks apply to known methods only.
        let known = matches!(
            method,
            "initialize"
                | "ping"
                | "tools/list"
                | "tools/call"
                | "resources/list"
                | "resources/read"
                | "notifications/initialized"
                | "notifications/cancelled"
        );
        if !known {
            if is_notification {
                return None;
            }
            let idv = id.clone().unwrap_or(Value::Null);
            return Some(rpc_error(
                &idv,
                ERR_METHOD_NOT_FOUND,
                &format!("unknown method: {method}"),
                None,
            ));
        }
        let tool_name = (method == "tools/call")
            .then(|| {
                params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or_default()
            })
            .filter(|n| !n.is_empty());
        if !scope_allows(&self.cred.scopes, method, tool_name) {
            // initialize/ping/notifications always pass scope_allows, so
            // reaching here with no id means a scoped notification:
            // drop it silently.
            if is_notification {
                return None;
            }
            let idv = id.clone().unwrap_or(Value::Null);
            let need = match method {
                "tools/list" => "mcp:tools".to_string(),
                "tools/call" => match tool_name {
                    Some(n) => format!("mcp:tools or mcp:tool:{n}"),
                    None => "mcp:tools".to_string(),
                },
                _ => "mcp:resources".to_string(),
            };
            return Some(rpc_error(
                &idv,
                ERR_SCOPE_DENIED,
                &format!(
                    "insufficient scope for {method}{}: the credential needs {need}; \
                     re-issue with `tinker-cli mcp key issue --scopes ...`",
                    tool_name
                        .map(|n| format!(" (tool {n})"))
                        .unwrap_or_default()
                ),
                None,
            ));
        }

        let outcome: Option<Value> = match method {
            "initialize" => Some(self.handle_initialize(&params).await),
            "ping" => Some(Value::Object(serde_json::Map::new())),
            "tools/list" => Some(tools_list_result()),
            "tools/call" => Some(self.handle_tool_call(&params).await),
            "resources/list" => Some(self.handle_resources_list().await),
            "resources/read" => Some(self.handle_resource_read(&params).await),
            "notifications/initialized" | "notifications/cancelled" => None,
            // `known` was checked above; this arm is unreachable.
            _ => None,
        };
        outcome.and_then(respond)
    }

    // ------------------------------------------------------------------
    // initialize + version handshake
    // ------------------------------------------------------------------

    /// MCP `initialize`: negotiate the protocol version and run the
    /// tinker-version handshake (spec design rule 3). The client may
    /// declare the versions it was built against as
    /// `client_tinker_version` / `client_ontology_version` (camelCase
    /// aliases accepted); a declared-but-wrong version fails the whole
    /// handshake with both sides named — never silent drift.
    async fn handle_initialize(&self, params: &Value) -> Value {
        let pin = VersionPin {
            client_tinker_version: params
                .get("client_tinker_version")
                .or_else(|| params.get("clientTinkerVersion"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
            client_ontology_version: params
                .get("client_ontology_version")
                .or_else(|| params.get("clientOntologyVersion"))
                .and_then(|v| v.as_str())
                .map(str::to_string),
        };
        if let Some(m) = describe::check_client_versions(&pin) {
            return rpc_error_value(
                ERR_VERSION_MISMATCH,
                &format!(
                    "version mismatch: client built against Tinker {}, this server is Tinker {}; \
                     refusing to silently drift (run `tinker describe` against this server)",
                    m.got_tinker.as_deref().unwrap_or("?"),
                    m.expected_tinker,
                ),
                Some(serde_json::json!({
                    "expected": {
                        "tinker_version": m.expected_tinker,
                        "ontology_version": m.expected_ontology,
                    },
                    "got": {
                        "tinker_version": m.got_tinker,
                        "ontology_version": m.got_ontology,
                    },
                    "hint": "re-run initialize without version pins, or update the client/skill \
                             (tinker agent install) to the server versions",
                })),
            );
        }
        let asked = params
            .get("protocolVersion")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let negotiated = if SUPPORTED_PROTOCOL_VERSIONS.contains(&asked) {
            asked
        } else {
            LATEST_PROTOCOL_VERSION
        };
        serde_json::json!({
            "protocolVersion": negotiated,
            "capabilities": { "tools": {}, "resources": {} },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": describe::tinker_version(),
            },
        })
    }

    // ------------------------------------------------------------------
    // tools/call
    // ------------------------------------------------------------------

    async fn handle_tool_call(&self, params: &Value) -> Value {
        let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let args = params.get("arguments").cloned().unwrap_or(Value::Null);
        if !args.is_object() {
            return rpc_error_value(
                ERR_INVALID_PARAMS,
                "tools/call params.arguments must be an object",
                None,
            );
        }
        let result = match name {
            "describe" => self.tool_describe(&args).await,
            "query" => self.tool_query(&args).await,
            "get_record" => self.tool_get_record(&args).await,
            "create_record" => self.tool_create_record(&args).await,
            "update_record" => self.tool_update_record(&args).await,
            "transition" => self.tool_transition(&args).await,
            "render_dashboard" => self.tool_render_dashboard(&args).await,
            "reveal" => self.tool_reveal(&args).await,
            "erase" => self.tool_erase(&args).await,
            _ => {
                return rpc_error_value(
                    ERR_INVALID_PARAMS,
                    &format!("unknown tool: {name}"),
                    Some(serde_json::json!({
                        "known_tools": tool_names(),
                        "hint": "call tools/list for the tool set and their input schemas",
                    })),
                )
            }
        };
        match result {
            Ok(payload) => tool_ok(&payload),
            Err(e) => tool_err_governance(&e),
        }
    }

    /// `describe`: ontology discovery — the catalog, or one object's
    /// documentation, projected through the caller's role. Unknown and
    /// foreign slugs are both `not_found`: no existence oracle.
    async fn tool_describe(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(args, &["object"], "describe")?;
        let slug = match args.get("object") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => {
                return Err(TinkerError::Validation(
                    "describe: \"object\" must be a string slug".into(),
                ))
            }
        };
        let value = match slug {
            None => {
                let c = self.describer().catalog(&self.tenant, &self.role).await?;
                serde_json::to_value(&c).map_err(TinkerError::Serde)?
            }
            Some(s) => {
                // Item 47: governed describe output is cached per
                // (org, object, role); byte-identical to a fresh describe.
                tinker_web::meta::describe_cached(&self.state, &self.tenant, &self.role, &s)
                    .await
                    .map_err(|e| teach(e, "describe"))?
            }
        };
        Ok(value)
    }

    /// `query`: run a query intent through the exact production path —
    /// role projection (M3), row policy (item 38), compiled plan, shared
    /// `query`: governed reads — the query compiler with the caller's
    /// field projection and row policy, through the plan cache. The
    /// agent names the object by slug and supplies the intent *without*
    /// `from`; the object id is resolved server-side and injected, so a
    /// client can never smuggle in another object's id. Mirrors
    /// `POST /api/query`.
    async fn tool_query(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(args, &["object", "intent"], "query")?;
        let intent_value = args
            .get("intent")
            .ok_or_else(|| TinkerError::Validation("query: \"intent\" is required".into()))?;
        let slug = require_str(args, "object")?;
        let object_id = self
            .object_id(&slug)
            .await
            .map_err(|e| teach(e, "describe"))?;
        // `from` is server-resolved; deny_unknown_fields keeps a
        // client-supplied `from` from being silently overwritten.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct IntentBody {
            #[serde(default)]
            select: Vec<String>,
            #[serde(default)]
            filters: Vec<tinker_query::Filter>,
            #[serde(default)]
            order: Vec<tinker_query::Order>,
            #[serde(default)]
            limit: Option<u32>,
            #[serde(default)]
            schema_version: Option<String>,
        }
        let body: IntentBody = serde_json::from_value(intent_value.clone())
            .map_err(|e| TinkerError::Validation(format!("query: invalid intent: {e}")))?;
        let intent = QueryIntent {
            from: object_id,
            select: body.select,
            filters: body.filters,
            order: body.order,
            limit: body.limit,
            schema_version: body.schema_version,
        };
        // Item 47: the governed metadata (description, projection, row
        // policy) is cached per (org, object, role, version); on a hit
        // the compiler gets cloneable values with zero DB round trips.
        // Error behavior is unchanged: slug errors are teach-mapped
        // above, projection/policy/compile errors propagate raw.
        let inputs = tinker_web::meta::query_inputs(
            &self.state,
            &self.tenant,
            &self.role,
            object_id,
            intent.schema_version.as_deref(),
        )
        .await?;
        let plan = self
            .state
            .compiler
            .compile_with_inputs(
                &self.tenant,
                &intent,
                &inputs.projection,
                &inputs.policy,
                &inputs.desc,
                inputs.version_sel,
            )
            .await?;
        let hash = tinker_live::QueryExecutor::plan_hash(&plan);
        let (rows, cached) = if let Some(rows) = self
            .state
            .cache
            .get(self.tenant.organization_id.0, &hash)
            .await
        {
            (rows, true)
        } else {
            let rows = self.state.executor.execute(&self.tenant, &plan).await?;
            self.state
                .cache
                .put(
                    self.tenant.organization_id.0,
                    &hash,
                    plan.object_id,
                    rows.clone(),
                )
                .await;
            (rows, false)
        };
        Ok(serde_json::json!({
            "rows": rows,
            "plan_hash": hash,
            "object_id": plan.object_id,
            "cached": cached,
        }))
    }

    /// Resolve an object slug to its id, tenant-scoped. Unknown and
    /// foreign slugs are both `NotFound` — the query compiler and the
    /// mutation connector already enforce this; the helper keeps the
    /// tool layer honest in one place. Item 47: resolved via the cached
    /// slug mapping (slugs are immutable, objects are never deleted).
    async fn object_id(&self, slug: &str) -> Result<Uuid> {
        tinker_web::meta::object_id_cached(&self.state, &self.tenant, slug).await
    }

    /// `get_record`: one record through the governed read path — the
    /// query compiler with the caller's projection and row policy, plus
    /// the `__id` system filter. Zero rows (missing, hidden by policy,
    /// or foreign) all produce the identical `not_found` shape: there is
    /// no oracle here by construction.
    async fn tool_get_record(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(args, &["object", "record_id"], "get_record")?;
        let slug = require_str(args, "object")?;
        let id_str = require_str(args, "record_id")?;
        let record_id: Uuid = id_str.parse().map_err(|_| {
            TinkerError::Validation("get_record: \"record_id\" must be a uuid".into())
        })?;
        let object_id = self.object_id(&slug).await?;
        // The visible field list comes from the same permission
        // projection describe uses — hidden fields are never named.
        // Item 47: served from the describe cache when warm.
        let described_value =
            tinker_web::meta::describe_cached(&self.state, &self.tenant, &self.role, &slug).await?;
        let mut select: Vec<String> = described_value
            .get("fields")
            .and_then(|f| f.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|f| f.get("api_name")?.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        select.push("__id".to_string());
        let intent = QueryIntent {
            from: object_id,
            select,
            filters: vec![tinker_query::Filter {
                field: "__id".to_string(),
                op: tinker_query::FilterOp::Eq,
                value: Value::from(record_id.to_string()),
            }],
            order: vec![],
            limit: Some(1),
            schema_version: None,
        };
        // Item 47: governed inputs from the metadata cache when warm;
        // error behavior unchanged (all raw here, like the uncached path).
        let inputs = tinker_web::meta::query_inputs(
            &self.state,
            &self.tenant,
            &self.role,
            object_id,
            intent.schema_version.as_deref(),
        )
        .await?;
        let plan = self
            .state
            .compiler
            .compile_with_inputs(
                &self.tenant,
                &intent,
                &inputs.projection,
                &inputs.policy,
                &inputs.desc,
                inputs.version_sel,
            )
            .await?;
        let rows = self.state.executor.execute(&self.tenant, &plan).await?;
        match rows.into_iter().next() {
            Some(row) => Ok(serde_json::json!({ "record": row })),
            None => Err(TinkerError::NotFound(format!("record {record_id}"))),
        }
    }

    /// Shared authorization for the PII tools (`reveal`, `erase`): role,
    /// a configured vault, then the record through the caller's role
    /// projection and row policy — invisible records are not_found, the
    /// same as every governed read. Returns the sealer and governed inputs.
    async fn pii_gate(
        &self,
        tool: &str,
        slug: &str,
        record_id: Uuid,
    ) -> Result<(
        &tinker_ontology::sensitive::PiiSealer,
        Uuid,
        tinker_live::QueryInputs,
    )> {
        if !matches!(self.role.as_str(), "owner" | "admin") {
            return Err(TinkerError::Forbidden(format!(
                "{tool} needs the owner or admin role"
            )));
        }
        let sealer = self.state.pii.as_ref().ok_or_else(|| {
            TinkerError::Validation(format!("{tool}: this server has no PII vault configured"))
        })?;
        let object_id = self.object_id(slug).await?;
        let inputs =
            tinker_web::meta::query_inputs(&self.state, &self.tenant, &self.role, object_id, None)
                .await?;
        let intent = QueryIntent {
            from: object_id,
            select: vec!["__id".to_string()],
            filters: vec![tinker_query::Filter {
                field: "__id".to_string(),
                op: tinker_query::FilterOp::Eq,
                value: Value::from(record_id.to_string()),
            }],
            order: vec![],
            limit: Some(1),
            schema_version: None,
        };
        let plan = self
            .state
            .compiler
            .compile_with_inputs(
                &self.tenant,
                &intent,
                &inputs.projection,
                &inputs.policy,
                &inputs.desc,
                inputs.version_sel,
            )
            .await?;
        if self
            .state
            .executor
            .execute(&self.tenant, &plan)
            .await?
            .is_empty()
        {
            return Err(TinkerError::NotFound(format!("record {record_id}")));
        }
        Ok((sealer, object_id, inputs))
    }

    /// `erase`: destroy every sensitive value of one record (right to
    /// erasure). Same gate as `reveal`; the erasure itself is audited as
    /// `pii.erase` with the purpose and count, never values.
    async fn tool_erase(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(args, &["object", "record_id", "purpose"], "erase")?;
        let slug = require_str(args, "object")?;
        let purpose = require_str(args, "purpose")?;
        let record_id: Uuid = require_str(args, "record_id")?
            .parse()
            .map_err(|_| TinkerError::Validation("erase: \"record_id\" must be a uuid".into()))?;
        let purpose = purpose.trim();
        if purpose.len() < 3 || purpose.len() > 500 {
            return Err(TinkerError::Validation(
                "erase: \"purpose\" must be 3-500 chars; it is recorded in the audit trail".into(),
            ));
        }
        let (sealer, object_id, inputs) = self.pii_gate("erase", &slug, record_id).await?;
        let destroyed = sealer
            .erase_record(&self.state.core, &self.tenant, &inputs.desc, record_id)
            .await?;
        let mut tx = self.state.core.tenant_tx(&self.tenant).await?;
        sqlx::query(
            "INSERT INTO audit_events \
             (organization_id, actor_id, action, resource_type, resource_id, status, metadata) \
             VALUES ($1, $2, 'pii.erase', $3, $4, 'ok', $5)",
        )
        .bind(self.tenant.organization_id.0)
        .bind(self.tenant.actor_id)
        .bind(&slug)
        .bind(record_id.to_string())
        .bind(serde_json::json!({ "purpose": purpose, "values_destroyed": destroyed }))
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        self.invalidate_query_cache(object_id).await;
        Ok(serde_json::json!({
            "object": slug,
            "record_id": record_id,
            "values_destroyed": destroyed,
        }))
    }

    /// `reveal`: the only path that returns a sensitive field's plaintext
    /// (docs/pii-sensitive-fields.md). Authorization runs in the same
    /// order as every governed read — role, field projection, then the
    /// record through the role's row policy — before the vault is
    /// touched, and the vault projector audits the disclosure.
    async fn tool_reveal(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(args, &["object", "record_id", "field", "purpose"], "reveal")?;
        let slug = require_str(args, "object")?;
        let field = require_str(args, "field")?;
        let purpose = require_str(args, "purpose")?;
        let record_id: Uuid = require_str(args, "record_id")?
            .parse()
            .map_err(|_| TinkerError::Validation("reveal: \"record_id\" must be a uuid".into()))?;
        let purpose = purpose.trim();
        if purpose.len() < 3 || purpose.len() > 500 {
            return Err(TinkerError::Validation(
                "reveal: \"purpose\" must be 3-500 chars; it is recorded in the audit trail".into(),
            ));
        }
        let (sealer, object_id, inputs) = self.pii_gate("reveal", &slug, record_id).await?;
        // Hidden and unknown fields look the same: not_found.
        let f = inputs
            .desc
            .fields
            .iter()
            .find(|f| f.api_name == field && inputs.projection.allows(object_id, &field))
            .ok_or_else(|| TinkerError::NotFound(format!("field {field}")))?;
        if !f.sensitive {
            return Err(TinkerError::Validation(format!(
                "reveal: field '{field}' is not sensitive; read it with get_record"
            )));
        }
        let mut tx = self.state.core.tenant_tx(&self.tenant).await?;
        let ref_id: Option<Uuid> = sqlx::query_scalar(&format!(
            "SELECT \"{}\" FROM data.{} WHERE organization_id = $1 AND id = $2",
            f.physical_column, inputs.desc.api_slug
        ))
        .bind(self.tenant.organization_id.0)
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .flatten();
        tx.commit().await.map_err(TinkerError::Db)?;
        let value = match ref_id {
            Some(r) => Value::String(
                sealer
                    .reveal(&self.state.core, &self.tenant, r, purpose)
                    .await?,
            ),
            None => Value::Null,
        };
        Ok(serde_json::json!({
            "object": slug,
            "record_id": record_id,
            "field": field,
            "value": value,
        }))
    }

    /// Drop cached query plans that read `object_id`, for this
    /// organization only. Called after every tool action that changes
    /// query-visible records; without it a `query` inside the 30s TTL
    /// would serve stale rows. Scoping is (organization_id, object_id):
    /// other objects' entries — and every other tenant's — are untouched.
    /// The plan hash already folds in the caller's projection and row
    /// policy, so dropping by object is safe across roles.
    async fn invalidate_query_cache(&self, object_id: Uuid) {
        self.state
            .cache
            .invalidate(self.tenant.organization_id.0, object_id)
            .await;
        // Item 47: the governed-metadata cache shares the query cache's
        // freshness contract, so every invalidation site covers both.
        self.state
            .meta
            .invalidate(self.tenant.organization_id.0, object_id)
            .await;
    }

    /// `create_record`: the governed mutation connector — presets, then
    /// validation, then file-field checks, in one transaction. Lifecycle
    /// objects refuse here with a teaching error (use `transition`).
    async fn tool_create_record(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(
            args,
            &[
                "object",
                "values",
                "record_id",
                "require_approval",
                "approval_request_id",
            ],
            "create_record",
        )?;
        let slug = require_str(args, "object")?;
        let values = require_object(args, "values")?;
        let object_id = self.object_id(&slug).await?;
        let (require_approval, approval_request_id) = approval_args(args)?;
        let outcome = self
            .mutator
            .create(
                &self.tenant,
                &CreateRequest {
                    object_id,
                    values,
                    require_approval,
                    approval_request_id,
                },
                &NoHooks,
            )
            .await
            .map_err(|e| teach_lifecycle(e, &slug))?;
        // The record table changed: cached query plans for this object
        // are stale as of now, not as of the TTL.
        self.invalidate_query_cache(object_id).await;
        Ok(serde_json::json!({
            "record_id": outcome.record_id,
            "version": outcome.version,
        }))
    }

    /// `update_record`: same governed path, with optimistic locking via
    /// `expected_version`.
    async fn tool_update_record(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(
            args,
            &[
                "object",
                "record_id",
                "values",
                "expected_version",
                "require_approval",
                "approval_request_id",
            ],
            "update_record",
        )?;
        let slug = require_str(args, "object")?;
        let record_id_str = require_str(args, "record_id")?;
        let record_id: Uuid = record_id_str.parse().map_err(|_| {
            TinkerError::Validation("update_record: \"record_id\" must be a uuid".into())
        })?;
        let values = require_object(args, "values")?;
        let expected_version = match args.get("expected_version") {
            None | Some(Value::Null) => None,
            Some(Value::Number(n)) => {
                // A non-integral version must fail closed: silently
                // dropping it would disable optimistic locking.
                match n
                    .as_i64()
                    .or_else(|| n.as_u64().and_then(|u| i64::try_from(u).ok()))
                {
                    Some(v) => Some(v),
                    None => {
                        return Err(TinkerError::Validation(
                            "update_record: \"expected_version\" must be an integer".into(),
                        ))
                    }
                }
            }
            Some(_) => {
                return Err(TinkerError::Validation(
                    "update_record: \"expected_version\" must be an integer".into(),
                ))
            }
        };
        let object_id = self.object_id(&slug).await?;
        let (require_approval, approval_request_id) = approval_args(args)?;
        let outcome = self
            .mutator
            .update(
                &self.tenant,
                &UpdateRequest {
                    object_id,
                    record_id,
                    values,
                    expected_version,
                    require_approval,
                    approval_request_id,
                },
                &NoHooks,
            )
            .await
            .map_err(|e| teach_lifecycle(e, &slug))?;
        // The record table changed: cached query plans for this object
        // are stale as of now, not as of the TTL.
        self.invalidate_query_cache(object_id).await;
        Ok(serde_json::json!({
            "record_id": outcome.record_id,
            "version": outcome.version,
        }))
    }

    /// `transition`: the record-lifecycle engine (item 40) behind one
    /// tool with an `action` discriminator. Every gate the engine
    /// enforces — author-only drafts, reviewer-only rejects, bound M7
    /// approvals, no self-approval on publish — applies unchanged; the
    /// tool only translates arguments and shapes errors.
    async fn tool_transition(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(
            args,
            &[
                "object",
                "action",
                "draft_id",
                "values",
                "record_id",
                "approval_id",
                "comment",
            ],
            "transition",
        )?;
        let action = require_str(args, "action")?;
        let see = "describe.<object>.lifecycle.transitions";
        // Cache discipline: only the actions that change query-visible
        // records invalidate (publish, archive, unarchive). Draft-only
        // actions (create_draft, update_draft, submit_for_review, reject,
        // revise) touch `record_drafts`, which `query` never reads, so
        // invalidating there would just burn cache entries.
        match action.as_str() {
            "create_draft" => {
                let slug = require_str(args, "object")?;
                let object_id = self.object_id(&slug).await?;
                let record_id = opt_uuid(args, "record_id", "transition")?;
                let values = args
                    .get("values")
                    .map(|v| {
                        v.as_object().cloned().ok_or_else(|| {
                            TinkerError::Validation(
                                "transition: \"values\" must be an object".into(),
                            )
                        })
                    })
                    .transpose()?
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let draft = self
                    .lifecycle
                    .create_draft(&self.tenant, object_id, record_id, &values)
                    .await
                    .map_err(|e| teach(e, &format!("describe.{slug}.lifecycle")))?;
                Ok(draft_json(&draft))
            }
            "update_draft" => {
                let draft_id = require_uuid(args, "draft_id", "transition")?;
                let values = require_object(args, "values")?;
                let draft = self
                    .lifecycle
                    .update_draft(&self.tenant, draft_id, &values)
                    .await
                    .map_err(|e| teach(e, see))?;
                Ok(draft_json(&draft))
            }
            "submit_for_review" => {
                let draft_id = require_uuid(args, "draft_id", "transition")?;
                let approval = require_uuid(args, "approval_id", "transition")?;
                let draft = self
                    .lifecycle
                    .submit_for_review(&self.tenant, draft_id, approval)
                    .await
                    .map_err(|e| teach(e, see))?;
                Ok(draft_json(&draft))
            }
            "publish" => {
                let draft_id = require_uuid(args, "draft_id", "transition")?;
                let approval = require_uuid(args, "approval_id", "transition")?;
                let outcome = self
                    .lifecycle
                    .publish(&self.tenant, draft_id, approval)
                    .await
                    .map_err(|e| teach(e, see))?;
                // A record was materialized: cached query plans for this
                // object are stale as of now, not as of the TTL.
                self.invalidate_query_cache(outcome.object_id).await;
                Ok(serde_json::json!({
                    "record_id": outcome.record_id,
                    "version": outcome.version,
                    "state": "published",
                }))
            }
            "reject" => {
                let draft_id = require_uuid(args, "draft_id", "transition")?;
                let reason = require_str(args, "comment")?;
                let draft = self
                    .lifecycle
                    .reject(&self.tenant, draft_id, &reason)
                    .await
                    .map_err(|e| teach(e, see))?;
                Ok(draft_json(&draft))
            }
            "revise" => {
                let draft_id = require_uuid(args, "draft_id", "transition")?;
                let draft = self
                    .lifecycle
                    .revise(&self.tenant, draft_id)
                    .await
                    .map_err(|e| teach(e, see))?;
                Ok(draft_json(&draft))
            }
            "archive" => {
                let slug = require_str(args, "object")?;
                let object_id = self.object_id(&slug).await?;
                let record_id = require_uuid(args, "record_id", "transition")?;
                let approval = require_uuid(args, "approval_id", "transition")?;
                self.lifecycle
                    .archive(&self.tenant, object_id, record_id, approval)
                    .await
                    .map_err(|e| teach(e, &format!("describe.{slug}.lifecycle")))?;
                // lifecycle_state changed: cached query plans for this
                // object are stale as of now, not as of the TTL.
                self.invalidate_query_cache(object_id).await;
                Ok(serde_json::json!({ "record_id": record_id, "state": "archived" }))
            }
            "unarchive" => {
                let slug = require_str(args, "object")?;
                let object_id = self.object_id(&slug).await?;
                let record_id = require_uuid(args, "record_id", "transition")?;
                let approval = require_uuid(args, "approval_id", "transition")?;
                self.lifecycle
                    .unarchive(&self.tenant, object_id, record_id, approval)
                    .await
                    .map_err(|e| teach(e, &format!("describe.{slug}.lifecycle")))?;
                // lifecycle_state changed: cached query plans for this
                // object are stale as of now, not as of the TTL.
                self.invalidate_query_cache(object_id).await;
                Ok(serde_json::json!({ "record_id": record_id, "state": "published" }))
            }
            other => Err(TinkerError::Validation(format!(
                "transition: unknown action {other:?}; want one of \
                 create_draft, update_draft, submit_for_review, publish, \
                 reject, revise, archive, unarchive \
                 (see describe.<object>.lifecycle.transitions)"
            ))),
        }
    }

    /// `render_dashboard`: the item-41 viewer-context render — the
    /// *caller's* role, from the membership table, never the request.
    /// Shared dashboards never escalate: panels the caller may not see
    /// fail per-panel, exactly like the HTTP route.
    async fn tool_render_dashboard(&self, args: &Value) -> Result<Value> {
        check_unknown_keys(args, &["dashboard_id"], "render_dashboard")?;
        let id = require_uuid(args, "dashboard_id", "render_dashboard")?;
        let rendered = self
            .state
            .dashboards
            .render(&self.tenant, &self.role, id)
            .await?;
        serde_json::to_value(&rendered).map_err(TinkerError::Serde)
    }

    // ------------------------------------------------------------------
    // resources
    // ------------------------------------------------------------------

    async fn handle_resources_list(&self) -> Value {
        let catalog = match self.describer().catalog(&self.tenant, &self.role).await {
            Ok(c) => c,
            Err(e) => return tool_err_governance_value(&e),
        };
        let mut resources = vec![serde_json::json!({
            "uri": "tinker://ontology",
            "name": "ontology catalog",
            "mimeType": "application/json",
        })];
        for o in &catalog.objects {
            resources.push(serde_json::json!({
                "uri": format!("tinker://ontology/{}", o.api_slug),
                "name": format!("describe {}", o.api_slug),
                "mimeType": "application/json",
            }));
        }
        serde_json::json!({ "resources": resources })
    }

    async fn handle_resource_read(&self, params: &Value) -> Value {
        let uri = params.get("uri").and_then(|u| u.as_str()).unwrap_or("");
        let value: Value = if uri == "tinker://ontology" {
            match self.describer().catalog(&self.tenant, &self.role).await {
                Ok(c) => serde_json::to_value(&c).unwrap_or(Value::Null),
                Err(e) => return tool_err_governance_value(&e),
            }
        } else if let Some(slug) = uri.strip_prefix("tinker://ontology/") {
            if slug.is_empty() || slug.contains('/') || slug.contains('?') || slug.contains('#') {
                return rpc_error_value(
                    ERR_INVALID_PARAMS,
                    &format!("malformed ontology resource URI: {uri}"),
                    None,
                );
            }
            match self
                .describer()
                .object(&self.tenant, &self.role, slug)
                .await
            {
                Ok(o) => serde_json::to_value(&o).unwrap_or(Value::Null),
                Err(TinkerError::NotFound(_)) => {
                    return rpc_error_value(
                        ERR_RESOURCE_NOT_FOUND,
                        "resource not found",
                        Some(serde_json::json!({ "uri": uri })),
                    )
                }
                Err(e) => return tool_err_governance_value(&e),
            }
        } else {
            return rpc_error_value(
                ERR_INVALID_PARAMS,
                &format!("unknown resource URI: {uri}"),
                Some(serde_json::json!({
                    "hint": "call resources/list for the resource set",
                })),
            );
        };
        let text = String::from_utf8(describe::canonical_json(&value))
            .unwrap_or_else(|_| value.to_string());
        serde_json::json!({
            "contents": [{ "uri": uri, "mimeType": "application/json", "text": text }]
        })
    }
}

// ---------------------------------------------------------------------------
// Tool definitions (tools/list)
// ---------------------------------------------------------------------------

fn tool_names() -> Vec<&'static str> {
    vec![
        "describe",
        "query",
        "get_record",
        "create_record",
        "update_record",
        "transition",
        "render_dashboard",
        "reveal",
        "erase",
    ]
}

fn tools_list_result() -> Value {
    let tool = |name: &str, description: &str, input_schema: Value| {
        serde_json::json!({
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        })
    };
    let obj = |properties: Value, required: &[&str]| {
        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    };
    serde_json::json!({
        "tools": [
            tool(
                "describe",
                "Discover the ontology: catalog, or one object's fields, validation, presets, relations, row-policy summary, lifecycle, and mutation/read contracts. Always the first call — never guess a field name or transition.",
                obj(serde_json::json!({
                    "object": { "type": "string", "description": "Object api_slug. Omit for the catalog." }
                }), &[]),
            ),
            tool(
                "query",
                "Run a query intent under the caller's permissions (role projection, row policy, field grants all apply). Build the intent from describe.<object>.reads.intent_shape.",
                obj(serde_json::json!({
                    "intent": { "type": "object", "description": "QueryIntent minus `from`: select, filters, order, limit, schema_version. The object comes from the `object` slug; `from` is resolved server-side and rejected if supplied." }
                }), &["intent"]),
            ),
            tool(
                "get_record",
                "Fetch one record by id through the governed read path. Missing, hidden-by-policy, and foreign records all return the same not_found error — there is no existence oracle.",
                obj(serde_json::json!({
                    "object": { "type": "string", "description": "Object api_slug" },
                    "record_id": { "type": "string", "description": "Record UUID" }
                }), &["object", "record_id"]),
            ),
            tool(
                "create_record",
                "Create a record through the governed mutation connector: presets, then validation, then file-field checks. Refused for lifecycle-managed objects — use transition/create_draft instead.",
                obj(serde_json::json!({
                    "object": { "type": "string" },
                    "values": { "type": "object", "description": "api_name -> value" },
                    "require_approval": { "type": "boolean" },
                    "approval_request_id": { "type": "string" }
                }), &["object", "values"]),
            ),
            tool(
                "update_record",
                "Update a record through the governed mutation connector. expected_version enables optimistic locking.",
                obj(serde_json::json!({
                    "object": { "type": "string" },
                    "record_id": { "type": "string" },
                    "values": { "type": "object", "description": "api_name -> value" },
                    "expected_version": { "type": "integer" },
                    "require_approval": { "type": "boolean" },
                    "approval_request_id": { "type": "string" }
                }), &["object", "record_id", "values"]),
            ),
            tool(
                "transition",
                "Drive a record through the lifecycle engine: create_draft, update_draft, submit_for_review, publish, reject, revise, archive, unarchive. See describe.<object>.lifecycle.transitions for the allowed transitions, who may initiate, and which need a bound M7 approval.",
                obj(serde_json::json!({
                    "action": { "type": "string" },
                    "object": { "type": "string", "description": "Object api_slug (create_draft, archive, unarchive)" },
                    "record_id": { "type": "string", "description": "Record UUID (create_draft for edits, archive, unarchive)" },
                    "draft_id": { "type": "string", "description": "Draft UUID (update_draft, submit_for_review, publish, reject, revise)" },
                    "values": { "type": "object", "description": "api_name -> value (create_draft, update_draft)" },
                    "comment": { "type": "string", "description": "Reviewer comment (reject, revise)" },
                    "approval_id": { "type": "string", "description": "Bound M7 approval (submit_for_review, publish, archive, unarchive)" }
                }), &["action"]),
            ),
            tool(
                "reveal",
                "Return the plaintext of ONE sensitive field (describe marks them `sensitive: true`; every other read returns them masked as \"••••••\"). Requires the owner or admin role and a key with the explicit mcp:tool:reveal scope. Every reveal is audited with its purpose. Hidden fields and invisible records are not_found.",
                obj(serde_json::json!({
                    "object": { "type": "string", "description": "Object api_slug" },
                    "record_id": { "type": "string", "description": "Record UUID" },
                    "field": { "type": "string", "description": "api_name of a sensitive field" },
                    "purpose": { "type": "string", "description": "Why this value is needed (3-500 chars); stored in the audit trail" }
                }), &["object", "record_id", "field", "purpose"]),
            ),
            tool(
                "erase",
                "Irreversibly destroy every sensitive value of ONE record (right to erasure): vault ciphertext for the live row, its version history and drafts, refs tombstoned, sensitive columns cleared. Non-sensitive fields are untouched. Requires the owner or admin role and a key with the explicit mcp:tool:erase scope; audited with its purpose. Invisible records are not_found.",
                obj(serde_json::json!({
                    "object": { "type": "string", "description": "Object api_slug" },
                    "record_id": { "type": "string", "description": "Record UUID" },
                    "purpose": { "type": "string", "description": "Why (3-500 chars), e.g. the erasure request id; stored in the audit trail" }
                }), &["object", "record_id", "purpose"]),
            ),
            tool(
                "render_dashboard",
                "Render a dashboard as the caller: every panel executes under the caller's role. Shared dashboards never escalate — panels the caller may not see fail per-panel.",
                obj(serde_json::json!({
                    "dashboard_id": { "type": "string", "description": "Dashboard UUID" }
                }), &["dashboard_id"]),
            ),
        ]
    })
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A JSON-RPC error envelope (not the full response — the dispatcher
/// wraps it with jsonrpc/id).
fn rpc_error_value(code: i64, message: &str, data: Option<Value>) -> Value {
    let mut error = serde_json::Map::with_capacity(3);
    error.insert("code".into(), Value::from(code));
    error.insert("message".into(), Value::from(message));
    if let Some(d) = data {
        error.insert("data".into(), d);
    }
    let mut envelope = serde_json::Map::with_capacity(1);
    envelope.insert("error".into(), Value::from(error));
    Value::from(envelope)
}

fn rpc_error(id: &Value, code: i64, message: &str, data: Option<Value>) -> String {
    let mut envelope = serde_json::Map::with_capacity(3);
    envelope.insert("jsonrpc".into(), Value::from("2.0"));
    envelope.insert("id".into(), id.clone());
    if let Value::Object(e) = rpc_error_value(code, message, data) {
        envelope.insert("error".into(), e["error"].clone());
    }
    Value::from(envelope).to_string()
}

/// Success tool result: canonical JSON text content.
fn tool_ok(payload: &Value) -> Value {
    let text = String::from_utf8(describe::canonical_json(payload))
        .unwrap_or_else(|_| payload.to_string());
    serde_json::json!({
        "content": [{ "type": "text", "text": text }],
    })
}

/// Governance failures are tool *results* with `isError: true` (MCP
/// convention) — the payload names the rule that fired and points at
/// the describe section documenting it ("errors teach"). Internal and
/// database errors collapse to a generic message: never leak internals.
fn tool_err_governance(e: &TinkerError) -> Value {
    let (class, message) = match e {
        TinkerError::Validation(m) => ("invalid", m.clone()),
        TinkerError::Forbidden(m) => ("forbidden", m.clone()),
        TinkerError::NotFound(m) => ("not_found", m.clone()),
        TinkerError::Conflict { .. } => ("conflict", e.to_string()),
        TinkerError::Busy(m) => ("conflict", m.clone()),
        _ => (
            "internal",
            "internal error; the failure was logged server-side".to_string(),
        ),
    };
    let mut payload = serde_json::Map::with_capacity(3);
    payload.insert("error".into(), Value::from(class));
    payload.insert("message".into(), Value::from(message));
    let text = Value::from(payload).to_string();
    serde_json::json!({
        "content": [{ "type": "text", "text": text }],
        "isError": true,
    })
}

/// Same shaping as a tool-call governance error, for the resources path
/// (which has no tool envelope to hang `isError` on — so it becomes a
/// JSON-RPC server error with the same payload in `data`).
fn tool_err_governance_value(e: &TinkerError) -> Value {
    let as_result = tool_err_governance(e);
    let text = as_result["content"][0]["text"].clone();
    let data: Value = serde_json::from_str(text.as_str().unwrap_or("{}")).unwrap_or(Value::Null);
    rpc_error_value(ERR_INTERNAL, "resource read failed", Some(data))
}

/// Attach the teaching pointer to an error from a write/transition
/// path. The underlying error is unchanged — only the message gains
/// its documentation reference.
fn teach(e: TinkerError, see: &str) -> TinkerError {
    let msg = |m: &str| format!("{m} (see {see})");
    match e {
        TinkerError::Validation(m) => TinkerError::Validation(msg(&m)),
        TinkerError::Forbidden(m) => TinkerError::Forbidden(msg(&m)),
        TinkerError::NotFound(m) => TinkerError::NotFound(msg(&m)),
        TinkerError::Conflict {
            object,
            record_id,
            expected,
            current,
        } => TinkerError::Conflict {
            object: format!("{object} (see {see})"),
            record_id,
            expected,
            current,
        },
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Argument helpers — unknown/mistyped arguments fail closed as
// validation errors, never as panics or silent defaults.
// ---------------------------------------------------------------------------

/// Strict argument validation: unknown keys are a validation error,
/// not silently ignored — an agent passing a misspelled or removed
/// argument must learn about it immediately, not wonder why the call
/// had no effect.
fn check_unknown_keys(args: &Value, allowed: &[&str], tool: &str) -> Result<()> {
    if let Some(obj) = args.as_object() {
        let mut unknown: Vec<&str> = obj
            .keys()
            .filter(|k| !allowed.contains(&k.as_str()))
            .map(String::as_str)
            .collect();
        unknown.sort_unstable();
        if !unknown.is_empty() {
            return Err(TinkerError::Validation(format!(
                "unknown argument(s) for tool `{tool}`: {} (see describe.{tool})",
                unknown.join(", ")
            )));
        }
    }
    Ok(())
}

/// Error teaching for the mutation tools: the lifecycle refusal
/// names the `transition` tool explicitly (the shared mutator message
/// only says "record lifecycle API"); everything else gets the
/// standard describe pointer.
fn teach_lifecycle(e: TinkerError, slug: &str) -> TinkerError {
    match &e {
        TinkerError::Forbidden(m) if m.contains("lifecycle-managed") => {
            TinkerError::Forbidden(format!(
                "{m} — write it with the `transition` tool instead                  (see describe.{slug}.lifecycle)"
            ))
        }
        _ => teach(e, &format!("describe.{slug}.mutation")),
    }
}

fn require_str(args: &Value, key: &str) -> Result<String> {
    match args.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(TinkerError::Validation(format!(
            "\"{key}\" is required and must be a non-empty string"
        ))),
    }
}

fn require_uuid(args: &Value, key: &str, tool: &str) -> Result<Uuid> {
    let s = require_str(args, key)?;
    s.parse()
        .map_err(|_| TinkerError::Validation(format!("{tool}: \"{key}\" must be a uuid")))
}

fn opt_uuid(args: &Value, key: &str, tool: &str) -> Result<Option<Uuid>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => s
            .parse()
            .map(Some)
            .map_err(|_| TinkerError::Validation(format!("{tool}: \"{key}\" must be a uuid"))),
        Some(_) => Err(TinkerError::Validation(format!(
            "{tool}: \"{key}\" must be a uuid string"
        ))),
    }
}

fn require_object(args: &Value, key: &str) -> Result<std::collections::HashMap<String, Value>> {
    match args.get(key) {
        Some(Value::Object(m)) => Ok(m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        _ => Err(TinkerError::Validation(format!(
            "\"{key}\" is required and must be an object"
        ))),
    }
}

fn approval_args(args: &Value) -> Result<(bool, Option<Uuid>)> {
    let require_approval = match args.get("require_approval") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            return Err(TinkerError::Validation(
                "\"require_approval\" must be a boolean".into(),
            ))
        }
    };
    let approval_request_id = opt_uuid(args, "approval_request_id", "mutation")?;
    if require_approval && approval_request_id.is_none() {
        return Err(TinkerError::Validation(
            "\"approval_request_id\" is required when \"require_approval\" is true".into(),
        ));
    }
    Ok((require_approval, approval_request_id))
}

fn draft_json(draft: &tinker_ontology::lifecycle::Draft) -> Value {
    serde_json::json!({
        "draft_id": draft.draft_id,
        "object_id": draft.object_id,
        "record_id": draft.record_id,
        "state": draft.state.as_str(),
        // Sensitive values are sealed in drafts; agents see the mask,
        // never the vault ref or blind index (reveal reads published rows).
        "content": tinker_ontology::sensitive::mask_sealed(&draft.content),
        "base_version": draft.base_version,
    })
}

/// Build the shared [`FrontDoor`] pieces the binary and tests share:
/// the web [`SharedState`], a file-validated [`MutationConnector`], and
/// a file-validated [`LifecycleEngine`]. The file backend comes from the
/// environment and fails closed when misconfigured — never a silent
/// fallback (item 42).
pub fn build_services(
    tenant_pool: sqlx::PgPool,
    system_pool: sqlx::PgPool,
) -> Result<(SharedState, MutationConnector, LifecycleEngine)> {
    build_services_with_pii(tenant_pool, system_pool, None)
}

/// [`build_services`] with the PII vault attached to the state, the
/// mutation connector and the lifecycle engine (sensitive fields).
pub fn build_services_with_pii(
    tenant_pool: sqlx::PgPool,
    system_pool: sqlx::PgPool,
    pii: Option<tinker_ontology::sensitive::PiiSealer>,
) -> Result<(SharedState, MutationConnector, LifecycleEngine)> {
    let state = tinker_web::build_state_with_pii(
        tenant_pool,
        system_pool,
        tinker_auth::AuthBroker::new(vec![]),
        "tinker-mcp".to_string(),
        false,
        pii.clone(),
    );
    let backend = tinker_agents::files::backend_from_env()
        .map_err(|e| TinkerError::Internal(format!("file backend misconfigured: {e}")))?;
    let store = Arc::new(tinker_agents::files::FileStore::new(
        state.core.clone(),
        backend,
    ));
    let mut mutator = MutationConnector::new(state.core.clone(), state.ontology.clone())
        .with_file_validator(store.clone());
    let mut lifecycle =
        LifecycleEngine::new(state.core.clone(), state.ontology.clone()).with_file_validator(store);
    if let Some(p) = pii {
        mutator = mutator.with_pii(p.clone());
        lifecycle = lifecycle.with_pii(p);
    }
    Ok((state, mutator, lifecycle))
}
