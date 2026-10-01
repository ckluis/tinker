//! Item 45: the MCP front door (`tinker-mcp`), tested end-to-end.
//!
//! The contract under test:
//! - JSON-RPC handshake: `initialize` negotiates the protocol version,
//!   reports `serverInfo.name = "tinker-mcp"` with the real
//!   `tinker_version`, and runs the version handshake — a declared but
//!   wrong client version fails the handshake with both sides named.
//! - Scope gating: `mcp:tools` / `mcp:resources` / `mcp:tool:<name>`
//!   gate protocol methods; denials are -32001 with a teaching hint.
//! - Every tool executes as the calling credential through the real
//!   governance stack: `describe` (permission-projected), `query`
//!   (M3 projection + item-38 row policy), `get_record` (no oracle:
//!   hidden and missing are byte-identical), `create_record` /
//!   `update_record` (item-37 validation + presets + item-42 file
//!   checks), `transition` (item-40 engine, approvals enforced),
//!   `render_dashboard` (item-41 viewer context, no escalation).
//! - Resources: `tinker://ontology` and `tinker://ontology/{slug}`
//!   serve the item-43 describe payloads as canonical JSON.
//! - Fail-closed: malformed JSON, unknown methods, unknown tools, and
//!   mistyped arguments all produce the documented errors; governance
//!   failures are `isError` tool results that name the rule and point
//!   at the describe section documenting it.
//! - The real binary speaks the protocol over a pipe (spawned with
//!   `CARGO_BIN_EXE_tinker-mcp`), and exits non-zero on a bad key.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::{json, Value};
use tinker_auth::apikey::{MachineCredentialStore, VerifiedCredential};
use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_mcp::{build_services, FrontDoor, LATEST_PROTOCOL_VERSION, SERVER_NAME};
use tinker_ontology::mutate::{CreateRequest, MutationConnector, NoHooks};
use tinker_ontology::{
    FieldDef, FieldType, ObjectDef, Ontology, PresetMode, PresetValue, Scope, ValidationRules,
    WritePreset,
};
use tinker_query::dashboard::{DashboardInput, PanelDef, VisualizationKind};
use tinker_query::{QueryIntent, RowFilterDef, RowFilters};
use tinker_web::describe;
use tokio::sync::OnceCell;
use uuid::Uuid;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

struct Env {
    core: CoreDb,
    core_owner: sqlx::PgPool,
    host_id: Uuid,
}

static MIGRATED: OnceCell<()> = OnceCell::const_new();

async fn setup() -> Env {
    // The file backend resolves from the environment; pin it at a temp
    // root so the suite never touches the repo working tree.
    std::env::set_var(
        "TINKER_FILE_ROOT",
        std::env::temp_dir().join(format!("tinker-mcp-test-{}", std::process::id())),
    );
    let core_owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("core owner connect");
    MIGRATED
        .get_or_init(|| async {
            tinker_db::MIGRATOR_CORE
                .run(&core_owner)
                .await
                .expect("core migrations");
        })
        .await;
    let core = CoreDb::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("core app-role connect");
    let host_id = Uuid::from_u128(0x0);
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,'test') ON CONFLICT (id) DO NOTHING")
        .bind(host_id)
        .execute(&core_owner)
        .await
        .expect("host upsert");
    Env {
        core,
        core_owner,
        host_id,
    }
}

async fn new_org(env: &Env) -> TenantContext {
    let org_id = Uuid::now_v7();
    let s = Uuid::now_v7().simple().to_string();
    let slug = format!("mcporg{}", &s[24..32]);
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(&slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "mcp-test".to_string(),
    )
}

fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{prefix}{}", &s[24..32])
}

fn ontology(env: &Env) -> Ontology {
    Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
}

fn object_def(slug: &str) -> ObjectDef {
    ObjectDef {
        name: slug.into(),
        api_slug: slug.into(),
        label: slug.into(),
        scope: Scope::Organization,
        pack_id: None,
        pack_version: None,
    }
}

fn text_field(api_name: &str, required: bool) -> FieldDef {
    FieldDef {
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type: FieldType::Text,
        options: serde_json::json!({}),
        required,
        validation: ValidationRules::default(),
        preset: None,
        max_pii_class: "none".into(),
        sensitive: false,
    }
}

/// Issue a machine credential and grant its actor `role`. Returns the
/// plaintext secret (for the pipe test) and the verified credential.
async fn issue_key(
    env: &Env,
    org_id: Uuid,
    name: &str,
    role: &str,
    scopes: &[&str],
) -> (String, VerifiedCredential) {
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let issued = store
        .issue(org_id, name, &scopes, None, None)
        .await
        .expect("key issue");
    store
        .grant_machine_role(org_id, issued.credential.actor_id, role)
        .await
        .expect("grant role");
    let verified = store.verify(&issued.secret).await.expect("key verify");
    (issued.secret, verified)
}

/// One authenticated front door for `cred`, with the real services.
async fn door(env: &Env, cred: &VerifiedCredential) -> FrontDoor {
    let (state, mutator, lifecycle) =
        build_services(env.core.0.clone(), env.core_owner.clone()).expect("build_services");
    let tenant = TenantContext::new(
        OrganizationId(cred.organization_id),
        cred.actor_id,
        "mcp-test".to_string(),
    );
    let role = FrontDoor::resolve_role(&state.core, &tenant)
        .await
        .expect("resolve_role");
    FrontDoor::new(state, mutator, lifecycle, cred.clone(), tenant, role)
}

/// Send one JSON-RPC request through the door; parse the response.
async fn rpc(door: &FrontDoor, method: &str, id: i64, params: Value) -> Value {
    let raw = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
    .to_string();
    let resp = door
        .handle(&raw)
        .await
        .unwrap_or_else(|| panic!("expected a response for {method}"));
    serde_json::from_str(&resp).expect("response parses")
}

/// Call a tool; return the raw result object.
async fn call_tool(door: &FrontDoor, id: i64, name: &str, args: Value) -> Value {
    let resp = rpc(
        door,
        "tools/call",
        id,
        json!({ "name": name, "arguments": args }),
    )
    .await;
    assert!(
        resp.get("error").is_none(),
        "tools/call {name} was a protocol error: {resp}"
    );
    resp["result"].clone()
}

/// The text payload of a successful tool result (canonical JSON).
fn ok_text(result: &Value) -> String {
    assert!(
        result.get("isError").is_none(),
        "expected success, got tool error: {result}"
    );
    result["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_string()
}

/// The parsed error payload of a failed tool result.
fn err_payload(result: &Value) -> Value {
    assert_eq!(result["isError"], true, "expected isError tool result");
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("error payload parses")
}

fn values(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// Issue a key with full scopes for `org_id` and return a door over it.
async fn full_door(env: &Env, org_id: Uuid) -> FrontDoor {
    let (_, cred) = issue_key(
        env,
        org_id,
        "full",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    door(env, &cred).await
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_ok_and_protocol_negotiation() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (_, cred) = issue_key(
        &env,
        ctx.organization_id.0,
        "hs",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let door = door(&env, &cred).await;

    let resp = rpc(&door, "initialize", 1, json!({})).await;
    assert!(resp.get("error").is_none(), "initialize failed: {resp}");
    assert_eq!(resp["result"]["protocolVersion"], LATEST_PROTOCOL_VERSION);
    assert_eq!(resp["result"]["serverInfo"]["name"], SERVER_NAME);
    // Real server version: the client can pin and detect drift.
    assert_eq!(
        resp["result"]["serverInfo"]["version"],
        describe::tinker_version()
    );
    assert!(resp["result"]["capabilities"]["tools"].is_object());
    assert!(resp["result"]["capabilities"]["resources"].is_object());

    // Client asks for an older protocol version we support → honored.
    let resp = rpc(
        &door,
        "initialize",
        2,
        json!({ "protocolVersion": "2024-11-05" }),
    )
    .await;
    assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");

    // Unknown future version → we state the latest we speak.
    let resp = rpc(
        &door,
        "initialize",
        3,
        json!({ "protocolVersion": "2099-01-01" }),
    )
    .await;
    assert_eq!(resp["result"]["protocolVersion"], LATEST_PROTOCOL_VERSION);

    // notifications/initialized produces no response (never echoed).
    let raw = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }).to_string();
    assert!(door.handle(&raw).await.is_none());

    // ping answers pong.
    let resp = rpc(&door, "ping", 4, json!({})).await;
    assert!(resp.get("error").is_none());
}

#[tokio::test]
async fn handshake_version_mismatch_fails_loudly() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (_, cred) = issue_key(
        &env,
        ctx.organization_id.0,
        "hs2",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let door = door(&env, &cred).await;

    let resp = rpc(
        &door,
        "initialize",
        1,
        json!({ "client_tinker_version": "0.0.0-stale" }),
    )
    .await;
    let err = &resp["error"];
    assert_eq!(err["code"], -32000);
    let msg = err["message"].as_str().unwrap();
    // The failure names both sides — the client can act on it.
    assert!(msg.contains("0.0.0-stale"), "client version named: {msg}");
    assert!(
        msg.contains(describe::tinker_version()),
        "server version named: {msg}"
    );
    assert!(msg.contains("tinker describe"), "teaching pointer: {msg}");
}

#[tokio::test]
async fn handshake_malformed_requests_fail_closed() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let door = full_door(&env, ctx.organization_id.0).await;

    // Not JSON at all.
    let resp: Value = serde_json::from_str(&door.handle("{nope").await.unwrap()).unwrap();
    assert_eq!(resp["error"]["code"], -32700);

    // Batch arrays are rejected (not supported).
    let resp: Value = serde_json::from_str(&door.handle("[]").await.unwrap()).unwrap();
    assert_eq!(resp["error"]["code"], -32600);

    // Wrong jsonrpc marker.
    let resp = rpc(&door, "ping", 1, json!({})).await;
    assert!(resp.get("error").is_none());
    let raw = r#"{"jsonrpc":"1.0","id":9,"method":"ping"}"#;
    let resp: Value = serde_json::from_str(&door.handle(raw).await.unwrap()).unwrap();
    assert_eq!(resp["error"]["code"], -32600);

    // Unknown method.
    let resp = rpc(&door, "tools/delete", 2, json!({})).await;
    assert_eq!(resp["error"]["code"], -32601);

    // Response echoes the request id, even for parse-level errors.
    let resp: Value = serde_json::from_str(
        &door
            .handle(r#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resp["id"], "abc");
    assert!(resp.get("error").is_none());
}

// ---------------------------------------------------------------------------
// Scope gating
// ---------------------------------------------------------------------------

#[tokio::test]
async fn scope_gating_tools_vs_resources() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;

    // Resources-only key: tools are denied, resources work.
    let (_, cred) = issue_key(&env, org_id, "res-only", "member", &["mcp:resources"]).await;
    let d = door(&env, &cred).await;
    let resp = rpc(&d, "tools/list", 1, json!({})).await;
    assert_eq!(resp["error"]["code"], -32001);
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("mcp:tools"));
    let resp = rpc(
        &d,
        "tools/call",
        2,
        json!({ "name": "describe", "arguments": {} }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32001);
    let resp = rpc(&d, "resources/list", 3, json!({})).await;
    assert!(resp.get("error").is_none());

    // Tools-only key: mirror image.
    let (_, cred) = issue_key(&env, org_id, "tool-only", "member", &["mcp:tools"]).await;
    let d = door(&env, &cred).await;
    let resp = rpc(&d, "resources/list", 4, json!({})).await;
    assert_eq!(resp["error"]["code"], -32001);
    let resp = rpc(&d, "tools/list", 5, json!({})).await;
    assert!(resp.get("error").is_none());

    // Per-tool scope: only describe may be called.
    let (_, cred) = issue_key(
        &env,
        org_id,
        "describe-only",
        "member",
        &["mcp:tool:describe"],
    )
    .await;
    let d = door(&env, &cred).await;
    let ok = call_tool(&d, 6, "describe", json!({})).await;
    assert!(ok.get("isError").is_none());
    let resp = rpc(
        &d,
        "tools/call",
        7,
        json!({ "name": "query", "arguments": { "object": "x", "intent": {} } }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32001);
    assert!(resp["error"]["message"]
        .as_str()
        .unwrap()
        .contains("mcp:tools"));
}

#[tokio::test]
async fn no_membership_fails_closed_with_fix() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;

    // Key issued but never granted a membership role: the door cannot
    // be built, and the error tells the operator exactly what to run.
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));
    let issued = store
        .issue(org_id, "roleless", &["mcp:tools".into()], None, None)
        .await
        .unwrap();
    let cred = store.verify(&issued.secret).await.unwrap();
    let (state, _, _) = build_services(env.core.0.clone(), env.core_owner.clone()).unwrap();
    let tenant = TenantContext::new(
        OrganizationId(org_id),
        cred.actor_id,
        "mcp-test".to_string(),
    );
    let err = FrontDoor::resolve_role(&state.core, &tenant)
        .await
        .expect_err("must fail closed");
    assert!(matches!(err, TinkerError::Forbidden(_)));
    let msg = err.to_string();
    assert!(
        msg.contains("tinker-cli mcp key issue --role"),
        "fix spelled out: {msg}"
    );
    assert!(!msg.contains(&issued.secret), "secret never echoed");
}

#[tokio::test]
async fn grant_machine_role_roundtrip() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));

    assert!(store
        .grant_machine_role(org_id, Uuid::now_v7(), "")
        .await
        .is_err());
    let actor = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
    )
    .bind(actor)
    .bind(org_id)
    .bind("mcp-role-test")
    .execute(&env.core_owner)
    .await
    .unwrap();
    store
        .grant_machine_role(org_id, actor, "analyst")
        .await
        .unwrap();
    let (state, _, _) = build_services(env.core.0.clone(), env.core_owner.clone()).unwrap();
    let tenant = TenantContext::new(OrganizationId(org_id), actor, "mcp-test".to_string());
    let role = FrontDoor::resolve_role(&state.core, &tenant).await.unwrap();
    assert_eq!(role, "analyst");
    // Re-grant replaces the role.
    store
        .grant_machine_role(org_id, actor, "auditor")
        .await
        .unwrap();
    let role = FrontDoor::resolve_role(&state.core, &tenant).await.unwrap();
    assert_eq!(role, "auditor");
}

// ---------------------------------------------------------------------------
// tools/list, describe, resources
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tools_list_advertises_the_nine_tools() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let door = full_door(&env, ctx.organization_id.0).await;
    let resp = rpc(&door, "tools/list", 1, json!({})).await;
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for want in [
        "describe",
        "query",
        "get_record",
        "create_record",
        "update_record",
        "transition",
        "render_dashboard",
        // Sensitive fields: the explicit-scope plaintext and erasure paths.
        "reveal",
        "erase",
    ] {
        assert!(names.contains(&want), "tool {want} advertised: {names:?}");
    }
    assert_eq!(names.len(), 9);
    for t in tools {
        assert!(t["inputSchema"].is_object(), "{} has schema", t["name"]);
    }
}

#[tokio::test]
async fn describe_tool_and_resources() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("gadget");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let door = full_door(&env, ctx.organization_id.0).await;

    // Catalog.
    let catalog: Value =
        serde_json::from_str(&ok_text(&call_tool(&door, 1, "describe", json!({})).await)).unwrap();
    assert_eq!(catalog["tinker_version"], describe::tinker_version());
    assert_eq!(catalog["ontology_version"], describe::ontology_version());
    let slugs: Vec<&str> = catalog["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["api_slug"].as_str().unwrap())
        .collect();
    assert!(slugs.contains(&slug.as_str()));

    // Object doc.
    let doc: Value = serde_json::from_str(&ok_text(
        &call_tool(&door, 2, "describe", json!({"object": slug})).await,
    ))
    .unwrap();
    let fields: Vec<&str> = doc["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["api_name"].as_str().unwrap())
        .collect();
    assert!(fields.contains(&"name"));

    // Unknown tool arguments fail closed (not silently ignored).
    let resp = rpc(
        &door,
        "tools/call",
        3,
        json!({ "name": "describe", "arguments": { "object": slug, "bogus": 1 } }),
    )
    .await;
    assert!(resp.get("error").is_none(), "protocol-level fine");
    let payload = err_payload(&resp["result"]);
    assert_eq!(payload["error"], "invalid");
    assert!(payload["message"].as_str().unwrap().contains("bogus"));

    // Unknown tool name → -32602.
    let resp = rpc(
        &door,
        "tools/call",
        4,
        json!({ "name": "apply_snapshot", "arguments": {} }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
}

#[tokio::test]
async fn describe_hides_other_org_slugs_without_oracle() {
    let env = setup().await;
    let ctx_a = new_org(&env).await;
    let ctx_b = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("secret");
    ont.define_object(&ctx_a, &object_def(&slug)).await.unwrap();
    let door_b = full_door(&env, ctx_b.organization_id.0).await;

    // A slug that exists in another org looks exactly like one that
    // exists nowhere: not_found, and the message is a pure function of
    // the *request* (it echoes the slug the caller asked about — which
    // the caller already knows), never of existence.
    let payload_b = err_payload(&call_tool(&door_b, 1, "describe", json!({"object": slug})).await);
    let payload_none = err_payload(
        &call_tool(
            &door_b,
            2,
            "describe",
            json!({"object": "definitely-not-here"}),
        )
        .await,
    );
    assert_eq!(payload_b["error"], "not_found");
    assert_eq!(payload_none["error"], "not_found");
    assert_eq!(
        payload_b["message"].as_str().unwrap(),
        format!("object {slug} (see describe)"),
    );
    assert_eq!(
        payload_none["message"].as_str().unwrap(),
        "object definitely-not-here (see describe)",
    );
}

#[tokio::test]
async fn resources_read_ontology_payloads() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("widget");
    ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    let door = full_door(&env, ctx.organization_id.0).await;

    let resp = rpc(&door, "resources/list", 1, json!({})).await;
    let uris: Vec<&str> = resp["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert!(uris.contains(&"tinker://ontology"));
    assert!(uris.iter().any(|u| u.ends_with(&slug)), "{uris:?}");

    let resp = rpc(
        &door,
        "resources/read",
        2,
        json!({ "uri": format!("tinker://ontology/{slug}") }),
    )
    .await;
    let body = resp["result"]["contents"][0]["text"].as_str().unwrap();
    let doc: Value = serde_json::from_str(body).unwrap();
    assert_eq!(doc["tinker_version"], describe::tinker_version());

    let resp = rpc(
        &door,
        "resources/read",
        3,
        json!({ "uri": "tinker://ontology/nope" }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32002);
    let resp = rpc(
        &door,
        "resources/read",
        4,
        json!({ "uri": "tinker://elsewhere" }),
    )
    .await;
    assert_eq!(resp["error"]["code"], -32602);
}

// ---------------------------------------------------------------------------
// Governed reads: query, get_record
// ---------------------------------------------------------------------------

/// Org with a `gadget` object (name/owner/price). `policy_role`
/// carries a row policy `owner = '<role>'` so records tagged with the
/// caller's role are visible to that caller only. Returns the door's
/// org id, both roles' doors, and (slug, object id).
async fn governed_world(env: &Env) -> (Uuid, FrontDoor, FrontDoor, String, Uuid) {
    let ctx = new_org(env).await;
    let org_id = ctx.organization_id.0;
    let ont = ontology(env);
    let slug = uniq("gadget");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    ont.add_field(&ctx, obj.id, &text_field("owner", false))
        .await
        .unwrap();
    // Two callers, two roles; the policy shows each only its own rows.
    for role in ["rep", "manager"] {
        RowFilters::new(env.core.clone())
            .set_filters(
                &ctx,
                &ont.describe_object(&ctx, obj.id).await.unwrap(),
                role,
                &[RowFilterDef {
                    field: "owner".into(),
                    op: "eq".into(),
                    value: Some(json!(role)),
                }],
            )
            .await
            .unwrap();
    }
    let mutator = MutationConnector::new(env.core.clone(), ont);
    for (name, owner) in [("alpha", "rep"), ("beta", "manager"), ("gamma", "rep")] {
        mutator
            .create(
                &ctx,
                &CreateRequest {
                    object_id: obj.id,
                    values: values(&[("name", json!(name)), ("owner", json!(owner))]),
                    require_approval: false,
                    approval_request_id: None,
                },
                &NoHooks,
            )
            .await
            .unwrap();
    }
    let (_, cred_rep) = issue_key(env, org_id, "rep-key", "rep", &["mcp:tools"]).await;
    let (_, cred_mgr) = issue_key(env, org_id, "mgr-key", "manager", &["mcp:tools"]).await;
    (
        org_id,
        door(env, &cred_rep).await,
        door(env, &cred_mgr).await,
        slug,
        obj.id,
    )
}

#[tokio::test]
async fn query_and_get_record_respect_row_policy() {
    let env = setup().await;
    let (_, rep, mgr, slug, _obj) = governed_world(&env).await;

    let intent = json!({ "select": ["name", "owner"], "limit": 10 });
    let rep_rows: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &rep,
            1,
            "query",
            json!({ "object": slug, "intent": intent }),
        )
        .await,
    ))
    .unwrap();
    let mut names: Vec<String> = rep_rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["alpha".to_string(), "gamma".to_string()]);

    let mgr_rows: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &mgr,
            2,
            "query",
            json!({ "object": slug, "intent": intent }),
        )
        .await,
    ))
    .unwrap();
    let names: Vec<String> = mgr_rows["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["beta".to_string()]);

    // get_record on a hidden row: identical shape to a missing one —
    // same error class, and the message is a pure function of the
    // REQUESTED id, so nothing about the hidden row leaks. The hidden
    // row is "beta" (manager's); rep must not learn it exists.
    let hidden_id = mgr_rows["rows"][0]["__id"].as_str().unwrap().to_string();
    let missing_id = Uuid::now_v7().to_string();
    let payload_hidden = err_payload(
        &call_tool(
            &rep,
            3,
            "get_record",
            json!({ "object": slug, "record_id": hidden_id.clone() }),
        )
        .await,
    );
    let payload_missing = err_payload(
        &call_tool(
            &rep,
            4,
            "get_record",
            json!({ "object": slug, "record_id": missing_id.clone() }),
        )
        .await,
    );
    assert_eq!(payload_hidden["error"], "not_found");
    assert_eq!(payload_missing["error"], "not_found");
    assert!(payload_hidden["message"]
        .as_str()
        .unwrap()
        .contains(&hidden_id));
    assert!(payload_missing["message"]
        .as_str()
        .unwrap()
        .contains(&missing_id));
    assert!(!payload_hidden.to_string().contains("beta"));

    // ...while the manager can read its own row.
    let doc: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &mgr,
            5,
            "get_record",
            json!({ "object": slug, "record_id": hidden_id }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(doc["record"]["name"], json!("beta"));
}

#[tokio::test]
async fn query_unknown_object_and_bad_intent_fail_closed() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("intent");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let door = full_door(&env, ctx.organization_id.0).await;

    // Unknown object slug.
    let payload = err_payload(
        &call_tool(
            &door,
            1,
            "query",
            json!({ "object": "nope", "intent": { "select": [] } }),
        )
        .await,
    );
    assert_eq!(payload["error"], "not_found");

    // A structurally invalid intent (select not an array) fails
    // closed with a validation error, not a panic.
    let payload = err_payload(
        &call_tool(
            &door,
            2,
            "query",
            json!({ "object": slug, "intent": { "select": "name" } }),
        )
        .await,
    );
    assert_eq!(payload["error"], "invalid");
    assert!(payload["message"]
        .as_str()
        .unwrap()
        .contains("invalid intent"));

    // create_record on a lifecycle object teaches the transition tool.
    let ont = ontology(&env);
    let slug = uniq("article");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("title", true))
        .await
        .unwrap();
    ont.set_lifecycle_enabled(&ctx, obj.id, true).await.unwrap();
    let payload = err_payload(
        &call_tool(
            &door,
            3,
            "create_record",
            json!({ "object": slug, "values": { "title": "x" } }),
        )
        .await,
    );
    assert_eq!(payload["error"], "forbidden");
    let msg = payload["message"].as_str().unwrap();
    assert!(msg.contains("`transition`"), "teaches transition: {msg}");
    assert!(msg.contains("describe"), "points at describe: {msg}");
}

// ---------------------------------------------------------------------------
// Governed writes: create_record, update_record
// ---------------------------------------------------------------------------

#[tokio::test]
async fn create_and_update_record_apply_validation_and_presets() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("gadget");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    // A field with a write preset: the agent must not supply it.
    let mut status = text_field("status", false);
    status.preset = Some(WritePreset {
        mode: PresetMode::Always,
        value: PresetValue::Static {
            value: json!("new"),
        },
    });
    ont.add_field(&ctx, obj.id, &status).await.unwrap();
    let door = full_door(&env, ctx.organization_id.0).await;

    // Missing required field → invalid, naming the rule and the doc.
    let payload = err_payload(
        &call_tool(
            &door,
            1,
            "create_record",
            json!({ "object": slug, "values": {} }),
        )
        .await,
    );
    assert_eq!(payload["error"], "invalid");
    let msg = payload["message"].as_str().unwrap();
    assert!(msg.contains("name"), "names the rule: {msg}");
    assert!(msg.contains("describe"), "points at describe: {msg}");

    // An Always preset is a forced default: a supplied value is
    // overwritten by the preset (which describe documents), not
    // rejected. The agent sees the applied value on read.
    let created: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &door,
            2,
            "create_record",
            json!({ "object": slug, "values": { "name": "n", "status": "shipped" } }),
        )
        .await,
    ))
    .unwrap();
    let preset_id = created["record_id"].as_str().unwrap().to_string();
    let doc: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &door,
            3,
            "get_record",
            json!({ "object": slug, "record_id": preset_id }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(doc["record"]["status"], json!("new"));
    assert_eq!(doc["record"]["name"], json!("n"));

    // Happy path: preset applied, record created.
    let created: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &door,
            4,
            "create_record",
            json!({ "object": slug, "values": { "name": "widget" } }),
        )
        .await,
    ))
    .unwrap();
    let record_id = created["record_id"].as_str().unwrap().to_string();

    // update_record applies changes with optimistic locking.
    let updated: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &door,
            5,
            "update_record",
            json!({
                "object": slug,
                "record_id": record_id,
                "values": { "name": "widget-v2" },
                "expected_version": created["version"].as_i64().unwrap(),
            }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(updated["version"], created["version"].as_i64().unwrap() + 1);
    let doc: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &door,
            6,
            "get_record",
            json!({ "object": slug, "record_id": record_id }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(doc["record"]["name"], json!("widget-v2"));

    // Stale expected_version → conflict naming the versions.
    let payload = err_payload(
        &call_tool(
            &door,
            7,
            "update_record",
            json!({
                "object": slug,
                "record_id": record_id,
                "values": { "name": "widget-v3" },
                "expected_version": created["version"].as_i64().unwrap(),
            }),
        )
        .await,
    );
    assert_eq!(payload["error"], "conflict");
    assert!(payload["message"].as_str().unwrap().contains("version"));

    // Unknown keys in the arguments envelope fail closed.
    let resp = rpc(
        &door,
        "tools/call",
        8,
        json!({
            "name": "update_record",
            "arguments": {
                "object": slug, "record_id": record_id, "values": {}, "expected_version": 1,
                "force": true,
            }
        }),
    )
    .await;
    let payload = err_payload(&resp["result"]);
    assert_eq!(payload["error"], "invalid");
    assert!(payload["message"].as_str().unwrap().contains("force"));
}

// ---------------------------------------------------------------------------
// transition: the item-40 engine through the front door
// ---------------------------------------------------------------------------

/// Lifecycle-enabled `article` object with a draft in it, plus an M7
/// approval fixture for the reviewer's sign-off (same pattern as the
/// item-44 skill tests).
/// Lifecycle world: an `article` object with lifecycle enabled, a
/// machine-key door, a reviewer actor, and a helper that mints an
/// approved M7 approval bound to (action, draft_id) decided by the
/// reviewer. The draft itself is created *through the tool* so the
/// machine-key actor is its author (the engine enforces author-only
/// edits).
struct LifecycleWorld {
    door: FrontDoor,
    slug: String,
    reviewer: Uuid,
    attachment: Uuid,
    ctx_owner: TenantContext,
}

async fn lifecycle_world(env: &Env) -> LifecycleWorld {
    let ctx = new_org(env).await;
    let org_id = ctx.organization_id.0;
    for (actor, name) in [(ctx.actor_id, "mcp-lifecycle-owner")] {
        sqlx::query(
            "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
        )
        .bind(actor)
        .bind(org_id)
        .bind(name)
        .execute(&env.core_owner)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,'member')",
        )
        .bind(actor)
        .bind(org_id)
        .execute(&env.core_owner)
        .await
        .unwrap();
    }
    let ont = ontology(env);
    let slug = uniq("article");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("title", true))
        .await
        .unwrap();
    ont.add_field(&ctx, obj.id, &text_field("body", false))
        .await
        .unwrap();
    ont.set_lifecycle_enabled(&ctx, obj.id, true).await.unwrap();

    let (_, cred) = issue_key(env, org_id, "lifecycle", "member", &["mcp:tools"]).await;
    let door = door(env, &cred).await;

    // The reviewer: a second human whose sign-off the engine requires.
    let reviewer = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
    )
    .bind(reviewer)
    .bind(org_id)
    .bind(format!("reviewer-{reviewer}"))
    .execute(&env.core_owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,'member')",
    )
    .bind(reviewer)
    .bind(org_id)
    .execute(&env.core_owner)
    .await
    .unwrap();

    // Scratch agent attachment backing the M7 approval rows (the
    // attachment_id FK needs a real row; the engine binds on
    // action_name + payload, not the attachment).
    let mut att_tx = env.core.tenant_tx(&ctx).await.unwrap();
    let attachment: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_attachments \
         (organization_id, actor_id, name, kind, scope, action_grants, \
          approval_policy, budgets, status) \
         VALUES ($1,$2,'mcp-test','test','{}','[]','{}','{}','active') \
         RETURNING id",
    )
    .bind(org_id)
    .bind(ctx.actor_id)
    .fetch_one(&mut *att_tx)
    .await
    .unwrap();
    att_tx.commit().await.unwrap();

    LifecycleWorld {
        door,
        slug,
        reviewer,
        attachment,
        ctx_owner: ctx,
    }
}

/// Mint an already-approved M7 approval bound to (action, draft_id),
/// decided by the reviewer. The engine only reads status/action/
/// payload/decided_by — this is the fixture, not a second path.
async fn mint_approval(env: &Env, w: &LifecycleWorld, action: &str, draft_id: Uuid) -> String {
    let org_id = w.ctx_owner.organization_id.0;
    let id = Uuid::now_v7();
    let mut tx = env.core.tenant_tx(&w.ctx_owner).await.unwrap();
    sqlx::query(
        "INSERT INTO approval_requests \
         (id, organization_id, attachment_id, action_name, payload, \
          idempotency_key, status, decided_by, decided_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'approved',$7,now())",
    )
    .bind(id)
    .bind(org_id)
    .bind(w.attachment)
    .bind(action)
    .bind(serde_json::json!({ "draft_id": draft_id.to_string() }))
    .bind(format!("mcp-{action}-{id}"))
    .bind(w.reviewer)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id.to_string()
}

#[tokio::test]
async fn transition_flow_with_approvals() {
    let env = setup().await;
    let w = lifecycle_world(&env).await;
    let slug = w.slug.clone();

    // create_draft through the tool: the machine-key actor is the author.
    let created: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            1,
            "transition",
            json!({ "object": slug, "action": "create_draft", "values": { "title": "hello" } }),
        )
        .await,
    ))
    .unwrap();
    let draft = created["draft_id"].as_str().unwrap().to_string();
    assert_eq!(created["state"], "draft");

    // submit_for_review with NO approval → invalid, teaching the path.
    let payload = err_payload(
        &call_tool(
            &w.door,
            2,
            "transition",
            json!({ "object": slug, "draft_id": draft, "action": "submit_for_review" }),
        )
        .await,
    );
    assert_eq!(payload["error"], "invalid");
    assert!(payload["message"].as_str().unwrap().contains("approval"));

    // submit_for_review with a reviewer-bound approval → in_review.
    let submit_appr = mint_approval(
        &env,
        &w,
        "submit_for_review",
        Uuid::parse_str(&draft).unwrap(),
    )
    .await;
    let out: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            3,
            "transition",
            json!({
                "object": slug, "draft_id": draft,
                "action": "submit_for_review", "approval_id": submit_appr,
            }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(out["state"], "in_review");

    // publish: a reviewer-decided approval bound to THIS draft.
    let publish_appr = mint_approval(&env, &w, "publish", Uuid::parse_str(&draft).unwrap()).await;
    let out: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            4,
            "transition",
            json!({
                "object": slug, "draft_id": draft,
                "action": "publish", "approval_id": publish_appr,
            }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(out["state"], "published");

    // A different draft cannot reuse this draft's approval → denied.
    let other: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            5,
            "transition",
            json!({ "object": slug, "action": "create_draft", "values": { "title": "two" } }),
        )
        .await,
    ))
    .unwrap();
    let other_draft = other["draft_id"].as_str().unwrap();
    let payload = err_payload(
        &call_tool(
            &w.door,
            6,
            "transition",
            json!({
                "object": slug, "draft_id": other_draft,
                "action": "publish", "approval_id": publish_appr,
            }),
        )
        .await,
    );
    assert!(
        payload["error"] == "invalid" || payload["error"] == "forbidden",
        "approval bound to one draft: {payload}"
    );

    // Unknown action names fail closed.
    let payload = err_payload(
        &call_tool(
            &w.door,
            7,
            "transition",
            json!({ "object": slug, "draft_id": draft, "action": "shred" }),
        )
        .await,
    );
    assert_eq!(payload["error"], "invalid");
    assert!(payload["message"].as_str().unwrap().contains("shred"));
}

#[tokio::test]
async fn render_dashboard_respects_viewer_policy() {
    let env = setup().await;
    let (org_id, rep, mgr, _slug, obj_id) = governed_world(&env).await;

    // A dashboard with one table panel over the governed object.
    // Created as a real member: dashboard creation requires an
    // org membership.
    let creator = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
    )
    .bind(creator)
    .bind(org_id)
    .bind("mcp-dash-creator")
    .execute(&env.core_owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,'member')",
    )
    .bind(creator)
    .bind(org_id)
    .execute(&env.core_owner)
    .await
    .unwrap();
    let svc = tinker_query::dashboard::DashboardService::new(env.core.clone(), ontology(&env));
    let ctx = TenantContext::new(OrganizationId(org_id), creator, "mcp-test".to_string());
    let dash = svc
        .create(
            &ctx,
            DashboardInput {
                name: "mcp".into(),
                description: None,
                panels: vec![PanelDef {
                    id: "p1".into(),
                    query: QueryIntent {
                        from: obj_id,
                        select: vec!["name".into(), "owner".into()],
                        filters: vec![],
                        order: vec![],
                        limit: Some(100),
                        schema_version: None,
                    },
                    visualization: VisualizationKind::Table,
                    x: 0,
                    y: 0,
                    w: 12,
                    h: 6,
                }],
            },
        )
        .await
        .unwrap();

    let rep_dash: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &rep,
            1,
            "render_dashboard",
            json!({ "dashboard_id": dash.id.to_string() }),
        )
        .await,
    ))
    .unwrap();
    let mut names: Vec<String> = rep_dash["panels"][0]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(names, vec!["alpha".to_string(), "gamma".to_string()]);

    // The manager's render of the SAME dashboard shows only its rows:
    // the shared artifact cannot launder the other caller's visibility.
    let mgr_dash: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &mgr,
            2,
            "render_dashboard",
            json!({ "dashboard_id": dash.id.to_string() }),
        )
        .await,
    ))
    .unwrap();
    let names: Vec<String> = mgr_dash["panels"][0]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["beta".to_string()]);

    // An unknown dashboard is not_found — no oracle against other
    // orgs' dashboards either.
    let payload = err_payload(
        &call_tool(
            &rep,
            3,
            "render_dashboard",
            json!({ "dashboard_id": Uuid::now_v7().to_string() }),
        )
        .await,
    );
    assert_eq!(payload["error"], "not_found");
}

// ---------------------------------------------------------------------------
// The real binary over a pipe
// ---------------------------------------------------------------------------

struct Pipe {
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    child: std::process::Child,
}

fn spawn_binary(secret: &str) -> Pipe {
    let bin = env!("CARGO_BIN_EXE_tinker-mcp");
    let mut cmd = Command::new(bin);
    cmd.env("TINKER_API_KEY", secret)
        .env(
            "TINKER_FILE_ROOT",
            std::env::temp_dir().join("tinker-mcp-bin-test"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn tinker-mcp");
    let stdin = child.stdin.take().expect("child stdin");
    let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    Pipe {
        stdin,
        stdout,
        child,
    }
}

fn pipe_send(pipe: &mut Pipe, method: &str, id: i64, params: Value) -> Value {
    let raw = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
    writeln!(pipe.stdin, "{raw}").expect("write to child");
    pipe.stdin.flush().expect("flush");
    let mut line = String::new();
    pipe.stdout.read_line(&mut line).expect("read from child");
    assert!(!line.trim().is_empty(), "child went quiet on {method}");
    serde_json::from_str(&line).expect("child response parses")
}

#[tokio::test]
async fn pipe_full_conversation() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;
    let ont = ontology(&env);
    let slug = uniq("pipeobj");
    ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    let (secret, _) = issue_key(
        &env,
        org_id,
        "pipe",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;

    let mut pipe = spawn_binary(&secret);
    // Give the binary a moment to finish startup (migrations +
    // key verification) before the first request.
    std::thread::sleep(std::time::Duration::from_secs(3));

    // initialize → the real server identifies itself.
    let resp = pipe_send(&mut pipe, "initialize", 1, json!({}));
    assert!(resp.get("error").is_none(), "initialize failed: {resp}");
    assert_eq!(resp["result"]["serverInfo"]["name"], "tinker-mcp");

    // initialized notification → no response (never echo it).
    writeln!(
        pipe.stdin,
        "{}",
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
    )
    .unwrap();
    pipe.stdin.flush().unwrap();

    // tools/list → nine tools (seven + `reveal` + `erase`).
    let resp = pipe_send(&mut pipe, "tools/list", 2, json!({}));
    assert_eq!(resp["result"]["tools"].as_array().unwrap().len(), 9);

    // tools/call describe → the catalog carries this org's object.
    let resp = pipe_send(
        &mut pipe,
        "tools/call",
        3,
        json!({ "name": "describe", "arguments": {} }),
    );
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    let catalog: Value = serde_json::from_str(text).unwrap();
    let slugs: Vec<&str> = catalog["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["api_slug"].as_str().unwrap())
        .collect();
    assert!(slugs.contains(&slug.as_str()), "{slugs:?}");

    // resources/read → the object document over the wire.
    let resp = pipe_send(
        &mut pipe,
        "resources/read",
        4,
        json!({ "uri": format!("tinker://ontology/{slug}") }),
    );
    let text = resp["result"]["contents"][0]["text"].as_str().unwrap();
    let doc: Value = serde_json::from_str(text).unwrap();
    assert_eq!(doc["tinker_version"], describe::tinker_version());

    // Clean shutdown: close stdin, the child exits on EOF.
    drop(pipe.stdin);
    let status = pipe.child.wait().expect("child exits");
    assert!(status.success(), "clean exit on EOF");
    let mut err = String::new();
    use std::io::Read;
    pipe.child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    // stderr carried startup logging; the key itself never appears.
    assert!(!err.contains(&secret), "secret never on stderr");
    assert!(!err.contains("tk_"), "key material never on stderr");
}

#[tokio::test]
async fn pipe_bad_key_exits_no_oracle() {
    let mut pipe = spawn_binary("tk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    std::thread::sleep(std::time::Duration::from_secs(3));

    // The binary should have exited on its own: nothing valid on
    // stdout, no protocol output at all.
    match pipe.child.try_wait().expect("try_wait") {
        Some(status) => assert!(!status.success(), "bad key exits non-zero"),
        None => panic!("binary with a bad key must exit, not hang"),
    }
    let mut out = String::new();
    use std::io::Read;
    pipe.stdout
        .read_to_string(&mut out)
        .expect("read child stdout");
    assert!(out.trim().is_empty(), "no protocol output on auth failure");
    let mut err = String::new();
    pipe.child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(err.contains("auth failed"), "clear failure: {err}");
    assert!(!err.contains("tk_"), "key material never echoed");
}

#[tokio::test]
async fn update_record_rejects_nonintegral_expected_version() {
    // A non-integral expected_version must fail closed — silently
    // dropping it would disable optimistic locking.
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("verlock");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let door = full_door(&env, ctx.organization_id.0).await;
    let created: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &door,
            1,
            "create_record",
            json!({ "object": slug, "values": { "name": "v" } }),
        )
        .await,
    ))
    .unwrap();
    let record_id = created["record_id"].as_str().unwrap();
    for bad in [json!(1.5), json!("3"), json!(true)] {
        let payload = err_payload(
            &call_tool(
                &door,
                2,
                "update_record",
                json!({
                    "object": slug, "record_id": record_id,
                    "values": { "name": "v2" }, "expected_version": bad,
                }),
            )
            .await,
        );
        assert_eq!(payload["error"], "invalid", "bad version {bad}");
        assert!(payload["message"]
            .as_str()
            .unwrap()
            .contains("expected_version"));
    }
}

#[tokio::test]
async fn mutation_tools_accept_the_documented_approval_arguments() {
    // The tool schemas advertise require_approval/approval_request_id;
    // the argument envelopes must accept them (not reject as unknown).
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("apprargs");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let door = full_door(&env, ctx.organization_id.0).await;
    let payload = err_payload(
        &call_tool(
            &door,
            1,
            "create_record",
            json!({ "object": slug, "values": { "name": "n" }, "require_approval": true }),
        )
        .await,
    );
    assert_eq!(payload["error"], "invalid");
    assert!(
        payload["message"]
            .as_str()
            .unwrap()
            .contains("approval_request_id"),
        "asks for the approval id, not unknown-argument: {}",
        payload["message"]
    );
}

// ---------------------------------------------------------------------------
// Query-cache invalidation on mutation (stale-read regression)
// ---------------------------------------------------------------------------

/// Parse a successful `query` tool result into (rows, cached).
fn query_rows(result: &Value) -> (Vec<Value>, bool) {
    let doc: Value = serde_json::from_str(&ok_text(result)).unwrap();
    let rows = doc["rows"].as_array().expect("rows array").clone();
    let cached = doc["cached"].as_bool().expect("cached flag");
    (rows, cached)
}

async fn query_names(door: &FrontDoor, id: i64, slug: &str) -> (Vec<String>, bool) {
    let result = call_tool(
        door,
        id,
        "query",
        json!({ "object": slug, "intent": { "select": ["name"] } }),
    )
    .await;
    let (rows, cached) = query_rows(&result);
    let names: Vec<String> = rows
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect();
    (names, cached)
}

#[tokio::test]
async fn query_cache_invalidated_on_create_and_update() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("cacheinv");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let door = full_door(&env, ctx.organization_id.0).await;

    // Prime the cache: empty result, served fresh.
    let (names, cached) = query_names(&door, 1, &slug).await;
    assert!(names.is_empty());
    assert!(!cached, "first query is a cache miss");

    // create_record, then query inside the 30s TTL: the new row must be
    // visible. Before the fix this returned the stale empty result with
    // cached=true.
    let created: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &door,
            2,
            "create_record",
            json!({ "object": slug, "values": { "name": "alpha" } }),
        )
        .await,
    ))
    .unwrap();
    let record_id = created["record_id"].as_str().unwrap().to_string();
    let (names, cached) = query_names(&door, 3, &slug).await;
    assert_eq!(
        names,
        vec!["alpha".to_string()],
        "query after create_record served stale rows"
    );
    assert!(!cached, "create_record must invalidate the query cache");

    // update_record, then query: the update must be visible.
    let ok = ok_text(
        &call_tool(
            &door,
            4,
            "update_record",
            json!({ "object": slug, "record_id": record_id, "values": { "name": "beta" } }),
        )
        .await,
    );
    assert!(ok.contains(&record_id));
    let (names, cached) = query_names(&door, 5, &slug).await;
    assert_eq!(
        names,
        vec!["beta".to_string()],
        "query after update_record served stale rows"
    );
    assert!(!cached, "update_record must invalidate the query cache");

    // A repeat query with no intervening write IS served from cache —
    // the fix invalidates on mutation, it does not disable caching.
    let (names, cached) = query_names(&door, 6, &slug).await;
    assert_eq!(names, vec!["beta".to_string()]);
    assert!(cached, "quiet query should still hit the cache");
}

#[tokio::test]
async fn query_cache_invalidated_on_publish() {
    let env = setup().await;
    let w = lifecycle_world(&env).await;
    let slug = w.slug.clone();

    // Prime the cache: no published rows yet. (The lifecycle object has
    // title/body fields, so select title here, not name.)
    let result = call_tool(
        &w.door,
        1,
        "query",
        json!({ "object": slug, "intent": { "select": ["title"] } }),
    )
    .await;
    let (rows, cached) = query_rows(&result);
    assert!(rows.is_empty());
    assert!(!cached, "first query is a cache miss");

    // Drive a draft to published through the tool, with approvals.
    let created: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            2,
            "transition",
            json!({ "object": slug, "action": "create_draft", "values": { "title": "hello" } }),
        )
        .await,
    ))
    .unwrap();
    let draft = created["draft_id"].as_str().unwrap().to_string();
    let draft_id = Uuid::parse_str(&draft).unwrap();
    let submit_appr = mint_approval(&env, &w, "submit_for_review", draft_id).await;
    let out: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            3,
            "transition",
            json!({ "object": slug, "draft_id": draft, "action": "submit_for_review", "approval_id": submit_appr }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(out["state"], "in_review");
    let publish_appr = mint_approval(&env, &w, "publish", draft_id).await;
    let out: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            4,
            "transition",
            json!({ "object": slug, "draft_id": draft, "action": "publish", "approval_id": publish_appr }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(out["state"], "published");

    // The published row must be visible to query inside the TTL.
    // The lifecycle object has fields title/body; select title here.
    let result = call_tool(
        &w.door,
        5,
        "query",
        json!({ "object": slug, "intent": { "select": ["title"] } }),
    )
    .await;
    let (rows, cached) = query_rows(&result);
    assert_eq!(rows.len(), 1, "query after publish served stale rows");
    assert_eq!(rows[0]["title"], "hello");
    assert!(!cached, "publish must invalidate the query cache");
}

/// Mint an already-approved M7 approval bound to (action, record_id),
/// for record-level transitions (archive/unarchive). The engine binds
/// on action_name + payload record_id, decided by the reviewer.
async fn mint_record_approval(
    env: &Env,
    w: &LifecycleWorld,
    action: &str,
    record_id: Uuid,
) -> String {
    let org_id = w.ctx_owner.organization_id.0;
    let id = Uuid::now_v7();
    let mut tx = env.core.tenant_tx(&w.ctx_owner).await.unwrap();
    sqlx::query(
        "INSERT INTO approval_requests \
         (id, organization_id, attachment_id, action_name, payload, \
          idempotency_key, status, decided_by, decided_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'approved',$7,now())",
    )
    .bind(id)
    .bind(org_id)
    .bind(w.attachment)
    .bind(action)
    .bind(serde_json::json!({ "record_id": record_id.to_string() }))
    .bind(format!("mcp-{action}-rec-{id}"))
    .bind(w.reviewer)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id.to_string()
}

#[tokio::test]
async fn query_cache_invalidated_on_archive() {
    let env = setup().await;
    let w = lifecycle_world(&env).await;
    let slug = w.slug.clone();

    // Drive a draft to published through the tool, with approvals.
    let created: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            1,
            "transition",
            json!({ "object": slug, "action": "create_draft", "values": { "title": "hello" } }),
        )
        .await,
    ))
    .unwrap();
    let draft = created["draft_id"].as_str().unwrap().to_string();
    let draft_id = Uuid::parse_str(&draft).unwrap();
    let submit_appr = mint_approval(&env, &w, "submit_for_review", draft_id).await;
    let out: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            2,
            "transition",
            json!({ "object": slug, "draft_id": draft, "action": "submit_for_review", "approval_id": submit_appr }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(out["state"], "in_review");
    let publish_appr = mint_approval(&env, &w, "publish", draft_id).await;
    let out: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            3,
            "transition",
            json!({ "object": slug, "draft_id": draft, "action": "publish", "approval_id": publish_appr }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(out["state"], "published");
    let record_id = Uuid::parse_str(out["record_id"].as_str().unwrap()).unwrap();

    // Prime the cache: the published row is visible (miss), then the
    // repeat query hits the cache — proving the entry exists.
    let result = call_tool(
        &w.door,
        4,
        "query",
        json!({ "object": slug, "intent": { "select": ["title"] } }),
    )
    .await;
    let (rows, cached) = query_rows(&result);
    assert_eq!(rows.len(), 1);
    assert!(!cached, "first query is a cache miss");
    let result = call_tool(
        &w.door,
        5,
        "query",
        json!({ "object": slug, "intent": { "select": ["title"] } }),
    )
    .await;
    let (_, cached) = query_rows(&result);
    assert!(cached, "repeat query should hit the cache");

    // Archive through the tool with a record-bound approval.
    let arch_appr = mint_record_approval(&env, &w, "archive", record_id).await;
    let out: Value = serde_json::from_str(&ok_text(
        &call_tool(
            &w.door,
            6,
            "transition",
            json!({ "object": slug, "record_id": record_id.to_string(), "action": "archive", "approval_id": arch_appr }),
        )
        .await,
    ))
    .unwrap();
    assert_eq!(out["state"], "archived");

    // The archived row must disappear from default (published-only)
    // queries inside the TTL. Before the fix this returned the stale
    // published row with cached=true.
    let result = call_tool(
        &w.door,
        7,
        "query",
        json!({ "object": slug, "intent": { "select": ["title"] } }),
    )
    .await;
    let (rows, cached) = query_rows(&result);
    assert!(rows.is_empty(), "query after archive served stale rows");
    assert!(!cached, "archive must invalidate the query cache");
}
