//! Item 22: MCP wire transport (Directus C6) — JSON-RPC 2.0 over stdio.
//!
//! - Protocol engine: initialize handshake, tools/list+call,
//!   resources/list+read, ping, notifications, error codes.
//! - Tool execution errors surface as MCP isError results; unknown
//!   methods/params are JSON-RPC protocol errors.
//! - End-to-end: the real `tinker-cli mcp serve` binary spawned with piped
//!   stdio, driven through a full session.

mod common;

use common::*;
use serde_json::{json, Value};
use tinker_agents::mcp_stdio::{StdioMcpServer, MCP_PROTOCOL_VERSION};
use tinker_agents::profiles::ProfileEngine;
use tinker_agents::{AuditWriter, TransformCache, TransformEngine};

fn server(env: &AgentEnv) -> StdioMcpServer {
    let audit = AuditWriter::new(env.core.clone(), env.owner.clone());
    let engine = TransformEngine::new(
        env.core.clone(),
        env.owner.clone(),
        env.ontology.clone(),
        env.gateway.clone(),
        audit,
    );
    let cache = TransformCache::new(env.core.clone(), env.owner.clone());
    let profiles = ProfileEngine::new(env.core.clone(), env.owner.clone());
    StdioMcpServer::new(
        env.exec_ctx.clone(),
        env.core.clone(),
        env.owner.clone(),
        env.ontology.clone(),
        engine,
        cache,
        profiles,
        None,
    )
}

fn req(id: i64, method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

fn deal_path(env: &AgentEnv) -> String {
    format!("/tinker/crm_deal/{}/index.md", env.deal_d1)
}

// ---------------------------------------------------------------------------
// Protocol engine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn initialize_negotiates_protocol_version() {
    let env = setup().await;
    let s = server(&env);

    let resp = s
        .handle(req(
            1,
            "initialize",
            json!({"protocolVersion": MCP_PROTOCOL_VERSION}),
        ))
        .await
        .expect("initialize gets a response");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    assert_eq!(resp["result"]["serverInfo"]["name"], "tinker");
    assert!(resp["result"]["capabilities"]["tools"].is_object());

    // Unknown client version → server answers with its own.
    let resp = s
        .handle(req(
            2,
            "initialize",
            json!({"protocolVersion": "1999-01-01"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
}

#[tokio::test]
async fn ping_and_notifications() {
    let env = setup().await;
    let s = server(&env);

    let resp = s.handle(req(1, "ping", json!({}))).await.unwrap();
    assert_eq!(resp["result"], json!({}));

    // Notifications (no id) never get a response.
    let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
    assert!(s.handle(notif).await.is_none());

    // Non-2.0 messages are ignored.
    let bad = json!({"jsonrpc": "1.0", "id": 9, "method": "ping"});
    assert!(s.handle(bad).await.is_none());
}

#[tokio::test]
async fn unknown_method_is_protocol_error() {
    let env = setup().await;
    let s = server(&env);
    let resp = s.handle(req(1, "tools/destroy", json!({}))).await.unwrap();
    assert_eq!(resp["error"]["code"], -32601);
}

#[tokio::test]
async fn tools_list_has_input_schemas() {
    let env = setup().await;
    let s = server(&env);
    let resp = s.handle(req(1, "tools/list", json!({}))).await.unwrap();
    let tools = resp["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 3);
    for t in tools {
        let schema = &t["inputSchema"];
        assert_eq!(schema["type"], "object");
        assert!(
            schema["required"].is_array(),
            "every tool needs required params: {t}"
        );
    }
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"read_virtual_file"));
    assert!(names.contains(&"expand_context"));
    assert!(names.contains(&"describe_profile"));
}

#[tokio::test]
async fn tools_call_read_virtual_file() {
    let env = setup().await;
    let s = server(&env);
    let resp = s
        .handle(req(
            1,
            "tools/call",
            json!({"name": "read_virtual_file", "arguments": {"path": deal_path(&env)}}),
        ))
        .await
        .unwrap();
    let content = &resp["result"]["content"];
    assert!(resp["result"].get("isError").is_none(), "call must succeed");
    let text = content[0]["text"].as_str().unwrap();
    assert!(
        text.contains("Acme Expansion"),
        "authorized projection: {text}"
    );
}

#[tokio::test]
async fn tools_call_unknown_tool_is_error_result_not_protocol_error() {
    let env = setup().await;
    let s = server(&env);
    let resp = s
        .handle(req(
            1,
            "tools/call",
            json!({"name": "wipe_everything", "arguments": {}}),
        ))
        .await
        .unwrap();
    // MCP-idiomatic: execution failure → isError result, still a 2.0 response.
    assert_eq!(resp["result"]["isError"], true);
    assert!(resp.get("error").is_none());
}

#[tokio::test]
async fn tools_call_missing_name_is_invalid_params() {
    let env = setup().await;
    let s = server(&env);
    let resp = s
        .handle(req(1, "tools/call", json!({"arguments": {}})))
        .await
        .unwrap();
    assert_eq!(resp["error"]["code"], -32602);
}

#[tokio::test]
async fn resources_list_and_read() {
    let env = setup().await;
    let s = server(&env);
    let resp = s.handle(req(1, "resources/list", json!({}))).await.unwrap();
    let resources = resp["result"]["resources"].as_array().unwrap();
    assert!(!resources.is_empty());

    let uri = format!("tinker://crm_deal/{}/index.md", env.deal_d1);
    let resp = s
        .handle(req(2, "resources/read", json!({"uri": uri})))
        .await
        .unwrap();
    let contents = resp["result"]["contents"].as_array().unwrap();
    assert_eq!(contents[0]["uri"], uri);
    assert_eq!(contents[0]["mimeType"], "text/markdown");
    assert!(contents[0]["text"]
        .as_str()
        .unwrap()
        .contains("Acme Expansion"));

    // Bad URI → protocol error, not a crash.
    let resp = s
        .handle(req(3, "resources/read", json!({"uri": "http://evil/x"})))
        .await
        .unwrap();
    assert!(resp.get("error").is_some());
}

#[tokio::test]
async fn expand_context_without_attachment_fails_closed() {
    let env = setup().await;
    let s = server(&env);
    let resp = s
        .handle(req(
            1,
            "tools/call",
            json!({
                "name": "expand_context",
                "arguments": {
                    "profile": env.profile_key,
                    "root_object": "crm_deal",
                    "root_record": env.deal_d1.to_string(),
                },
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp["result"]["isError"], true);
    let text = resp["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("attachment"),
        "must demand attachment: {text}"
    );
}

// ---------------------------------------------------------------------------
// End-to-end: spawned binary over piped stdio
// ---------------------------------------------------------------------------

#[tokio::test]
async fn spawned_binary_serves_full_mcp_session() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::process::Command;

    let env = setup().await;
    let org_slug = format!("m7-{}", env.org_id.simple());
    // Item 35: the CLI binary is `tinker-cli` (its own target path, so it
    // can never collide with the `tinker` web server binary again).
    let bin = env!("CARGO_BIN_EXE_tinker-cli");

    let mut child = Command::new(bin)
        .args(["mcp", "serve", "--org", &org_slug, "--actor", "exec"])
        // The tinker binary reads TINKER_CORE_URL as the OWNER url and
        // TINKER_APP_URL as the app-role url; the harness's ambient
        // TINKER_CORE_URL is the app-role url, so map explicitly.
        .env(
            "TINKER_CORE_URL",
            std::env::var("TINKER_CORE_OWNER_URL").unwrap(),
        )
        .env("TINKER_APP_URL", std::env::var("TINKER_CORE_URL").unwrap())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn tinker-cli mcp serve");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();

    async fn rpc(
        stdin: &mut tokio::process::ChildStdin,
        lines: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
        id: i64,
        method: &str,
        params: Value,
    ) -> Value {
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        stdin
            .write_all(format!("{msg}\n").as_bytes())
            .await
            .unwrap();
        stdin.flush().await.unwrap();
        let line = tokio::time::timeout(std::time::Duration::from_secs(30), lines.next_line())
            .await
            .expect("response timeout")
            .unwrap()
            .expect("stdout closed");
        serde_json::from_str(&line).unwrap()
    }

    // initialize → tools/list → tools/call → done.
    let init = rpc(
        &mut stdin,
        &mut lines,
        1,
        "initialize",
        json!({"protocolVersion": MCP_PROTOCOL_VERSION}),
    )
    .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "tinker");

    // notifications/initialized → no response expected; just continue.
    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
        .await
        .unwrap();

    let list = rpc(&mut stdin, &mut lines, 2, "tools/list", json!({})).await;
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 3);

    let call = rpc(
        &mut stdin,
        &mut lines,
        3,
        "tools/call",
        json!({"name": "read_virtual_file", "arguments": {"path": deal_path(&env)}}),
    )
    .await;
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("Acme Expansion"),
        "binary served the authorized projection"
    );

    // EOF on stdin → clean shutdown.
    drop(stdin);
    let status = tokio::time::timeout(std::time::Duration::from_secs(15), child.wait())
        .await
        .expect("shutdown timeout")
        .unwrap();
    assert!(status.success(), "clean exit on EOF: {status}");
}
