//! Item 46: MCP over HTTP/SSE (`tinker-mcp serve`), tested end-to-end.
//!
//! The contract under test:
//! - Auth: no key → 401, invalid key → 401, and two different invalid
//!   keys produce byte-identical bodies (no oracle). Key material is
//!   never echoed.
//! - Sessions: `initialize` mints a `Mcp-Session-Id`; non-initialize
//!   methods need it; a different key on the same session is rejected;
//!   `DELETE /mcp` tears the session down.
//! - Behavior parity with stdio: the same tool calls through HTTP and
//!   through `FrontDoor::handle` produce byte-identical `result`
//!   payloads; even the `-32700` parse-error envelope is byte-identical.
//! - Tenant isolation: key B sees key A's records as `not_found`, never
//!   `forbidden` (no existence oracle).
//! - SSE: `GET /mcp/stream` yields `text/event-stream` with an
//!   `event: ready` greeting; `POST /mcp` with
//!   `Accept: text/event-stream` delivers the response as one SSE
//!   `data:` event.
//!
//! Each test spawns the real binary (`tinker-mcp serve --bind
//! 127.0.0.1:0`) and parses the listening address from its stderr.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tinker_auth::apikey::{MachineCredentialStore, VerifiedCredential};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_mcp::{build_services, FrontDoor};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope, ValidationRules};
use tokio::sync::OnceCell;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness (mirrors mcp_front_door.rs)
// ---------------------------------------------------------------------------

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
    std::env::set_var(
        "TINKER_FILE_ROOT",
        std::env::temp_dir().join(format!("tinker-mcp-http-test-{}", std::process::id())),
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
    let slug = format!("mcphttporg{}", &s[24..32]);
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
        "mcp-http-test".to_string(),
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
/// plaintext secret (for HTTP auth) and the verified credential (for
/// the stdio parity door).
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

/// One authenticated stdio front door for `cred` — the parity oracle.
async fn door(env: &Env, cred: &VerifiedCredential) -> FrontDoor {
    let (state, mutator, lifecycle) =
        build_services(env.core.0.clone(), env.core_owner.clone()).expect("build_services");
    let tenant = TenantContext::new(
        OrganizationId(cred.organization_id),
        cred.actor_id,
        "mcp-http-test".to_string(),
    );
    let role = FrontDoor::resolve_role(&state.core, &tenant)
        .await
        .expect("resolve_role");
    FrontDoor::new(state, mutator, lifecycle, cred.clone(), tenant, role)
}

// ---------------------------------------------------------------------------
// The server under test
// ---------------------------------------------------------------------------

struct HttpServer {
    child: Child,
    base: String,
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn `tinker-mcp serve --bind 127.0.0.1:0`; parse the listening
/// address from stderr ("tinker-mcp: listening on <addr> (http)"); wait
/// until it accepts connections. A drain thread keeps stderr flowing
/// until the child exits.
async fn spawn_server() -> HttpServer {
    let bin = env("CARGO_BIN_EXE_tinker-mcp");
    let mut child = Command::new(&bin)
        .arg("serve")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .env("TINKER_CORE_OWNER_URL", env("TINKER_CORE_OWNER_URL"))
        .env("TINKER_CORE_URL", env("TINKER_CORE_URL"))
        .env(
            "TINKER_FILE_ROOT",
            std::env::temp_dir().join(format!("tinker-mcp-http-test-{}", std::process::id())),
        )
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn tinker-mcp serve");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut sent = false;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if !sent {
                        if let Some(rest) = line.split("listening on ").nth(1) {
                            if let Some(addr) = rest.split_whitespace().next() {
                                let _ = tx.send(addr.to_string());
                                sent = true;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("server did not print its listening address");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(s) => {
                drop(s);
                break;
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("server at {addr} never accepted connections: {e}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    HttpServer {
        child,
        base: format!("http://{addr}"),
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

struct HttpResp {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

fn rpc_body(id: i64, method: &str, params: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
}

async fn post_raw(
    server: &HttpServer,
    key: Option<&str>,
    session: Option<&str>,
    raw: &str,
    accept_sse: bool,
) -> HttpResp {
    let mut req = client()
        .post(format!("{}/mcp", server.base))
        .header(CONTENT_TYPE, "application/json")
        .body(raw.to_string());
    if let Some(k) = key {
        req = req.header(AUTHORIZATION, format!("Bearer {k}"));
    }
    if let Some(s) = session {
        req = req.header("mcp-session-id", s);
    }
    if accept_sse {
        req = req.header(ACCEPT, "text/event-stream");
    }
    let resp = req.send().await.expect("POST /mcp");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.text().await.expect("response body");
    HttpResp {
        status,
        headers,
        body,
    }
}

async fn post_rpc(
    server: &HttpServer,
    key: &str,
    session: Option<&str>,
    id: i64,
    method: &str,
    params: Value,
) -> HttpResp {
    post_raw(
        server,
        Some(key),
        session,
        &rpc_body(id, method, params),
        false,
    )
    .await
}

fn session_id_of(resp: &HttpResp) -> String {
    resp.headers
        .get("mcp-session-id")
        .expect("Mcp-Session-Id response header")
        .to_str()
        .expect("header value")
        .to_string()
}

/// Open a session; return (session_id, initialize result payload).
async fn initialize(server: &HttpServer, key: &str) -> (String, Value) {
    let resp = post_rpc(
        server,
        key,
        None,
        1,
        "initialize",
        json!({ "protocolVersion": "2025-06-18" }),
    )
    .await;
    assert_eq!(resp.status, StatusCode::OK, "initialize: {}", resp.body);
    let body: Value = serde_json::from_str(&resp.body).expect("initialize parses");
    assert!(
        body.get("error").is_none(),
        "initialize was a protocol error: {body}"
    );
    (session_id_of(&resp), body["result"].clone())
}

/// The `result` payload of a successful JSON-RPC response.
fn ok_result(resp: &HttpResp) -> Value {
    assert_eq!(resp.status, StatusCode::OK, "expected 200: {}", resp.body);
    let body: Value = serde_json::from_str(&resp.body).expect("response parses");
    assert!(
        body.get("error").is_none(),
        "expected result, got protocol error: {body}"
    );
    body["result"].clone()
}

/// The text payload of a successful tool result (canonical JSON).
fn tool_text(result: &Value) -> String {
    assert!(
        result.get("isError").is_none(),
        "expected success, got tool error: {result}"
    );
    result["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_string()
}

/// The parsed payload of an `isError` tool result.
fn tool_err(result: &Value) -> Value {
    assert_eq!(result["isError"], true, "expected isError tool result");
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("error payload parses")
}

async fn call_tool(
    server: &HttpServer,
    key: &str,
    session: &str,
    id: i64,
    name: &str,
    args: Value,
) -> Value {
    let resp = post_rpc(
        server,
        key,
        Some(session),
        id,
        "tools/call",
        json!({ "name": name, "arguments": args }),
    )
    .await;
    ok_result(&resp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn http_rejects_missing_key() {
    let _env = setup().await;
    let server = spawn_server().await;

    // No Authorization header at all.
    let resp = post_raw(&server, None, None, &rpc_body(1, "ping", json!({})), false).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.body);
    let body: Value = serde_json::from_str(&resp.body).expect("body parses");
    assert_eq!(body["error"], "unauthorized");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("Authorization: Bearer"),
        "teaches the header: {body}"
    );
    assert!(body["hint"]
        .as_str()
        .unwrap()
        .contains("tinker-cli mcp key issue"));

    // Malformed scheme.
    let resp = client()
        .post(format!("{}/mcp", server.base))
        .header(AUTHORIZATION, "Basic dG86eA==")
        .body(rpc_body(1, "ping", json!({})))
        .send()
        .await
        .expect("POST");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // The stream and delete routes reject too.
    for (method, url) in [
        ("GET", format!("{}/mcp/stream", server.base)),
        ("DELETE", format!("{}/mcp", server.base)),
    ] {
        let resp = client()
            .request(method.parse().unwrap(), &url)
            .send()
            .await
            .expect("request");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {url}");
        let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
        assert_eq!(body["error"], "unauthorized");
    }
}

#[tokio::test]
async fn http_rejects_invalid_keys_identically() {
    let _env = setup().await;
    let server = spawn_server().await;
    let raw = rpc_body(1, "ping", json!({}));

    // Garbage, a well-formed-but-unknown tk_ key, and a truncated one:
    // every verification failure shares one identical body — no oracle.
    let bodies: Vec<String> = {
        let mut out = vec![];
        for key in [
            "not-a-key",
            "tk_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "tk_short",
        ] {
            let resp = post_raw(&server, Some(key), None, &raw, false).await;
            assert_eq!(
                resp.status,
                StatusCode::UNAUTHORIZED,
                "key {key}: {}",
                resp.body
            );
            let body: Value = serde_json::from_str(&resp.body).expect("body parses");
            assert_eq!(body["error"], "unauthorized");
            // The key itself is never echoed back.
            assert!(
                !resp.body.contains(key),
                "key material echoed: {}",
                resp.body
            );
            out.push(resp.body.clone());
        }
        out
    };
    assert_eq!(bodies[0], bodies[1], "no oracle: bodies must be identical");
    assert_eq!(bodies[1], bodies[2], "no oracle: bodies must be identical");
}

#[tokio::test]
async fn http_end_to_end_describe_create_query() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("widget");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let (secret, _) = issue_key(
        &env,
        ctx.organization_id.0,
        "http-e2e",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let server = spawn_server().await;
    let (session, init) = initialize(&server, &secret).await;
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert_eq!(init["serverInfo"]["name"], "tinker-mcp");

    // describe the catalog: our object is listed.
    let result = call_tool(&server, &secret, &session, 2, "describe", json!({})).await;
    let catalog: Value = serde_json::from_str(&tool_text(&result)).unwrap();
    assert!(
        catalog["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["api_slug"] == slug),
        "catalog lists {slug}"
    );

    // create_record → query → get_record, the item-45 flow over HTTP.
    let result = call_tool(
        &server,
        &secret,
        &session,
        3,
        "create_record",
        json!({ "object": slug, "values": { "name": "alpha" } }),
    )
    .await;
    let created: Value = serde_json::from_str(&tool_text(&result)).unwrap();
    let record_id = created["record_id"]
        .as_str()
        .expect("record_id")
        .to_string();

    let result = call_tool(
        &server,
        &secret,
        &session,
        4,
        "query",
        json!({ "object": slug, "intent": { "select": ["name"] } }),
    )
    .await;
    let queried: Value = serde_json::from_str(&tool_text(&result)).unwrap();
    let rows = queried["rows"].as_array().expect("rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "alpha");

    let result = call_tool(
        &server,
        &secret,
        &session,
        5,
        "get_record",
        json!({ "object": slug, "record_id": record_id }),
    )
    .await;
    let doc: Value = serde_json::from_str(&tool_text(&result)).unwrap();
    assert_eq!(doc["record"]["name"], "alpha");

    // Ontology resources ride the same session.
    let resp = post_rpc(
        &server,
        &secret,
        Some(&session),
        6,
        "resources/list",
        json!({}),
    )
    .await;
    let listed = ok_result(&resp);
    assert!(
        listed["resources"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["uri"] == format!("tinker://ontology/{slug}")),
        "resources list the object"
    );
    let resp = post_rpc(
        &server,
        &secret,
        Some(&session),
        7,
        "resources/read",
        json!({ "uri": format!("tinker://ontology/{slug}") }),
    )
    .await;
    let read = ok_result(&resp);
    assert_eq!(
        read["contents"][0]["uri"],
        format!("tinker://ontology/{slug}")
    );
}

#[tokio::test]
async fn http_error_shapes_match_stdio() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("parity");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let (secret, verified) = issue_key(
        &env,
        ctx.organization_id.0,
        "http-parity",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let server = spawn_server().await;
    let (session, _) = initialize(&server, &secret).await;
    // The stdio oracle: the same credential through FrontDoor::handle.
    let stdio = door(&env, &verified).await;

    // A governance error: unknown tool argument fails closed.
    let args = json!({ "object": slug, "values": { "name": "x" }, "bogus": 1 });
    let http_result = call_tool(&server, &secret, &session, 2, "create_record", args.clone()).await;
    let raw = json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": { "name": "create_record", "arguments": args },
    })
    .to_string();
    let stdio_resp: Value =
        serde_json::from_str(&stdio.handle(&raw).await.expect("stdio responds")).unwrap();
    assert_eq!(
        http_result, stdio_resp["result"],
        "tool error payloads are byte-identical"
    );
    assert_eq!(tool_err(&http_result)["error"], "invalid");

    // not_found: missing, hidden, and foreign records share the shape.
    // Here: a well-formed uuid that names nothing.
    let missing = Uuid::now_v7().to_string();
    let args = json!({ "object": slug, "record_id": missing });
    let http_result = call_tool(&server, &secret, &session, 3, "get_record", args.clone()).await;
    let raw = json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": { "name": "get_record", "arguments": args },
    })
    .to_string();
    let stdio_resp: Value =
        serde_json::from_str(&stdio.handle(&raw).await.expect("stdio responds")).unwrap();
    assert_eq!(
        http_result, stdio_resp["result"],
        "not_found payloads are byte-identical"
    );
    assert_eq!(tool_err(&http_result)["error"], "not_found");

    // Even the -32700 parse-error envelope is byte-identical to stdio.
    let stdio_raw = stdio.handle("{not json").await.expect("stdio responds");
    let http_resp = post_raw(&server, Some(&secret), Some(&session), "{not json", false).await;
    assert_eq!(http_resp.status, StatusCode::OK);
    assert_eq!(
        http_resp.body, stdio_raw,
        "parse error envelopes match byte-for-byte"
    );
}

#[tokio::test]
async fn http_tenant_isolation_is_not_found_not_forbidden() {
    let env = setup().await;
    // Org A with a record.
    let ctx_a = new_org(&env).await;
    let ont = ontology(&env);
    let slug = uniq("secret");
    let obj = ont.define_object(&ctx_a, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx_a, obj.id, &text_field("name", true))
        .await
        .unwrap();
    let (secret_a, _) = issue_key(
        &env,
        ctx_a.organization_id.0,
        "http-iso-a",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    // Org B, same role, same scopes.
    let ctx_b = new_org(&env).await;
    let (secret_b, _) = issue_key(
        &env,
        ctx_b.organization_id.0,
        "http-iso-b",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;

    let server = spawn_server().await;
    let (session_a, _) = initialize(&server, &secret_a).await;
    let result = call_tool(
        &server,
        &secret_a,
        &session_a,
        2,
        "create_record",
        json!({ "object": slug, "values": { "name": "a-secret" } }),
    )
    .await;
    let record_id = serde_json::from_str::<Value>(&tool_text(&result)).unwrap()["record_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Key B cannot see it: get_record says not_found — never forbidden.
    let (session_b, _) = initialize(&server, &secret_b).await;
    let result = call_tool(
        &server,
        &secret_b,
        &session_b,
        3,
        "get_record",
        json!({ "object": slug, "record_id": record_id }),
    )
    .await;
    let payload = tool_err(&result);
    assert_eq!(payload["error"], "not_found", "no oracle: {payload}");

    // B's query over the same slug also finds nothing (the object is
    // org-scoped; unknown and foreign slugs share the shape).
    let result = call_tool(
        &server,
        &secret_b,
        &session_b,
        4,
        "query",
        json!({ "object": slug, "intent": { "select": ["name"] } }),
    )
    .await;
    assert_eq!(tool_err(&result)["error"], "not_found", "no oracle");
}

#[tokio::test]
async fn http_scope_gating_applies_per_session() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    // Resources-only scope: tools/list must be -32001, exactly like stdio.
    let (secret, _) = issue_key(
        &env,
        ctx.organization_id.0,
        "http-scope",
        "member",
        &["mcp:resources"],
    )
    .await;
    let server = spawn_server().await;
    let (session, _) = initialize(&server, &secret).await;

    let resp = post_rpc(&server, &secret, Some(&session), 2, "tools/list", json!({})).await;
    assert_eq!(resp.status, StatusCode::OK);
    let body: Value = serde_json::from_str(&resp.body).unwrap();
    assert_eq!(body["error"]["code"], -32001, "scope denial: {body}");

    // resources/list passes with the same credential.
    let resp = post_rpc(
        &server,
        &secret,
        Some(&session),
        3,
        "resources/list",
        json!({}),
    )
    .await;
    assert!(ok_result(&resp)["resources"].is_array());
}

#[tokio::test]
async fn http_sessions_are_per_connection() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (secret_a, _) = issue_key(
        &env,
        ctx.organization_id.0,
        "http-sess-a",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let ctx_b = new_org(&env).await;
    let (secret_b, _) = issue_key(
        &env,
        ctx_b.organization_id.0,
        "http-sess-b",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let server = spawn_server().await;

    // Two initializes → two distinct sessions.
    let (session_a, _) = initialize(&server, &secret_a).await;
    let (session_b, _) = initialize(&server, &secret_b).await;
    assert_ne!(session_a, session_b, "sessions are distinct");

    // A method without a session id fails closed, teaching initialize.
    let resp = post_rpc(&server, &secret_a, None, 9, "ping", json!({})).await;
    assert_eq!(resp.status, StatusCode::BAD_REQUEST, "{}", resp.body);
    let body: Value = serde_json::from_str(&resp.body).unwrap();
    assert!(body["message"].as_str().unwrap().contains("Mcp-Session-Id"));

    // Key B on session A's id: the key is valid, but it is not the
    // session's credential → 401.
    let resp = post_rpc(&server, &secret_b, Some(&session_a), 10, "ping", json!({})).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.body);

    // Both sessions work independently.
    for (key, session) in [(&secret_a, &session_a), (&secret_b, &session_b)] {
        let resp = post_rpc(&server, key, Some(session.as_str()), 11, "ping", json!({})).await;
        assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
    }

    // DELETE tears session A down; its methods 404, session B survives.
    let resp = client()
        .delete(format!("{}/mcp", server.base))
        .header(AUTHORIZATION, format!("Bearer {secret_a}"))
        .header("mcp-session-id", &session_a)
        .send()
        .await
        .expect("DELETE");
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let resp = post_rpc(&server, &secret_a, Some(&session_a), 12, "ping", json!({})).await;
    assert_eq!(resp.status, StatusCode::NOT_FOUND, "{}", resp.body);
    let resp = post_rpc(&server, &secret_b, Some(&session_b), 13, "ping", json!({})).await;
    assert_eq!(resp.status, StatusCode::OK, "{}", resp.body);
}

#[tokio::test]
async fn http_sse_stream_and_sse_post() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (secret, _) = issue_key(
        &env,
        ctx.organization_id.0,
        "http-sse",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let server = spawn_server().await;
    let (session, _) = initialize(&server, &secret).await;

    // GET /mcp/stream: text/event-stream with an `event: ready` greeting.
    let mut resp = client()
        .get(format!("{}/mcp/stream", server.base))
        .header(AUTHORIZATION, format!("Bearer {secret}"))
        .header("mcp-session-id", &session)
        .header(ACCEPT, "text/event-stream")
        .send()
        .await
        .expect("GET /mcp/stream");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.headers()["content-type"]
            .to_str()
            .unwrap()
            .contains("text/event-stream"),
        "SSE content type"
    );
    let chunk = tokio::time::timeout(Duration::from_secs(10), resp.chunk())
        .await
        .expect("first SSE chunk in time")
        .expect("chunk ok")
        .expect("non-empty chunk");
    let text = String::from_utf8_lossy(&chunk);
    assert!(text.contains("event: ready"), "ready greeting: {text}");
    assert!(text.contains(&session), "greeting names the session");

    // The stream needs a session too.
    let resp = client()
        .get(format!("{}/mcp/stream", server.base))
        .header(AUTHORIZATION, format!("Bearer {secret}"))
        .header(ACCEPT, "text/event-stream")
        .send()
        .await
        .expect("GET /mcp/stream without session");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // POST with Accept: text/event-stream → one SSE `data:` event whose
    // data is the identical JSON-RPC response.
    let sse_resp = post_raw(
        &server,
        Some(&secret),
        Some(&session),
        &rpc_body(20, "tools/list", json!({})),
        true,
    )
    .await;
    assert_eq!(sse_resp.status, StatusCode::OK);
    assert!(
        sse_resp
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream"),
        "SSE content type on POST"
    );
    let data = sse_resp
        .body
        .strip_prefix("data: ")
        .expect("single data event");
    let sse_json: Value = serde_json::from_str(data.trim()).expect("SSE data parses");

    let json_resp = post_rpc(
        &server,
        &secret,
        Some(&session),
        21,
        "tools/list",
        json!({}),
    )
    .await;
    let json_result = ok_result(&json_resp);
    assert_eq!(sse_json["result"], json_result, "SSE and JSON modes agree");
    assert!(sse_json["result"]["tools"].as_array().unwrap().len() >= 7);
}

#[tokio::test]
async fn http_unknown_route_teaches() {
    let _env = setup().await;
    let server = spawn_server().await;
    let resp = client()
        .get(format!("{}/nope", server.base))
        .send()
        .await
        .expect("GET /nope");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(body["error"], "not_found");
    assert!(body["hint"].as_str().unwrap().contains("POST /mcp"));
}

#[tokio::test]
async fn http_healthz_is_unauthenticated_and_minimal() {
    let _env = setup().await;
    let server = spawn_server().await;
    // No Authorization header: the probe must work without one.
    let resp = client()
        .get(format!("{}/healthz", server.base))
        .send()
        .await
        .expect("GET /healthz");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let body: Value = serde_json::from_str(&resp.text().await.unwrap()).unwrap();
    assert_eq!(body["status"], "ok");
    // Version pins the build; the body carries nothing else (no db
    // state, sessions, tenants, config).
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        body.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["status", "version"]
    );
}

/// The role is re-read per request: changing or removing the key actor's
/// membership ends the live session instead of letting the role frozen
/// at `initialize` ride for as long as the client stays active.
#[tokio::test]
async fn http_session_ends_when_membership_changes() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (secret, cred) = issue_key(
        &env,
        ctx.organization_id.0,
        "http-role-change",
        "member",
        &["mcp:tools", "mcp:resources"],
    )
    .await;
    let server = spawn_server().await;
    let (session, _) = initialize(&server, &secret).await;
    let resp = post_rpc(&server, &secret, Some(&session), 2, "tools/list", json!({})).await;
    ok_result(&resp);

    sqlx::query(
        "UPDATE memberships SET role = 'viewer' WHERE actor_id = $1 AND organization_id = $2",
    )
    .bind(cred.actor_id)
    .bind(ctx.organization_id.0)
    .execute(&env.core_owner)
    .await
    .unwrap();
    let resp = post_rpc(&server, &secret, Some(&session), 3, "tools/list", json!({})).await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.body);
    assert!(resp.body.contains("membership changed"), "{}", resp.body);
    // The old session is gone for good, even if the role flips back.
    let resp = post_rpc(&server, &secret, Some(&session), 4, "tools/list", json!({})).await;
    assert_ne!(resp.status, StatusCode::OK);

    // A fresh initialize picks up the current role.
    let (session2, _) = initialize(&server, &secret).await;
    ok_result(
        &post_rpc(
            &server,
            &secret,
            Some(&session2),
            5,
            "tools/list",
            json!({}),
        )
        .await,
    );

    // Membership removed: the live session ends.
    sqlx::query("DELETE FROM memberships WHERE actor_id = $1 AND organization_id = $2")
        .bind(cred.actor_id)
        .bind(ctx.organization_id.0)
        .execute(&env.core_owner)
        .await
        .unwrap();
    let resp = post_rpc(
        &server,
        &secret,
        Some(&session2),
        6,
        "tools/list",
        json!({}),
    )
    .await;
    assert_eq!(resp.status, StatusCode::UNAUTHORIZED, "{}", resp.body);
}
