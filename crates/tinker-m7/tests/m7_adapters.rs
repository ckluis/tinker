//! Item 24: real model-provider adapters.
//!
//! - HTTP transport speaks OpenAI-compatible /v1/chat/completions.
//! - Token accounting comes from the live `usage` block; a response
//!   without usage fails closed.
//! - Retries: 429/5xx (honoring Retry-After) and transport errors;
//!   4xx never retried; 401/403 -> Forbidden without leaking the key.
//! - Placement is enforced at the transport: an adapter whose declared
//!   boundary mismatches the provider row is rejected before any prompt
//!   bytes leave the process (mock sees zero requests).
//! - Timeouts are typed and bounded.

mod common;

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use common::*;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;
use tinker_agents::adapters::HttpModelAdapter;
use tinker_agents::gateway::{ModelAdapter, ModelGateway, Placement};
use tinker_core::TinkerError;

struct Behavior {
    status: u16,
    body: serde_json::Value,
    retry_after_secs: Option<u64>,
    delay: Duration,
}

struct Seen {
    auth: Option<String>,
    path: String,
    body: serde_json::Value,
}

struct Mock {
    behaviors: tokio::sync::Mutex<VecDeque<Behavior>>,
    seen: tokio::sync::Mutex<Vec<Seen>>,
}

async fn spawn_mock(behaviors: Vec<Behavior>) -> (String, Arc<Mock>) {
    let mock = Arc::new(Mock {
        behaviors: tokio::sync::Mutex::new(behaviors.into()),
        seen: tokio::sync::Mutex::new(Vec::new()),
    });
    let state = mock.clone();
    let app = Router::new()
        .route(
            "/chat/completions",
            post(
                move |State(m): State<Arc<Mock>>, headers: HeaderMap, body: Bytes| async move {
                    let seen = Seen {
                        auth: headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_string),
                        path: "/chat/completions".to_string(),
                        body: serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null),
                    };
                    m.seen.lock().await.push(seen);
                    let b = m.behaviors.lock().await.pop_front().unwrap_or(Behavior {
                        status: 500,
                        body: serde_json::json!({"error": "mock behavior queue exhausted"}),
                        retry_after_secs: None,
                        delay: Duration::ZERO,
                    });
                    if !b.delay.is_zero() {
                        tokio::time::sleep(b.delay).await;
                    }
                    let mut resp: Response =
                        (StatusCode::from_u16(b.status).unwrap(), Json(b.body)).into_response();
                    if let Some(ra) = b.retry_after_secs {
                        resp.headers_mut()
                            .insert("retry-after", ra.to_string().parse().unwrap());
                    }
                    resp
                },
            ),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), mock)
}

fn ok_body() -> serde_json::Value {
    serde_json::json!({
        "model": "gpt-4o-mini",
        "choices": [{"message": {"role": "assistant", "content": "summary text"}}],
        "usage": {"prompt_tokens": 41, "completion_tokens": 7, "total_tokens": 48}
    })
}

fn ok_behavior() -> Behavior {
    Behavior {
        status: 200,
        body: ok_body(),
        retry_after_secs: None,
        delay: Duration::ZERO,
    }
}

fn adapter_for(url: &str, placement: Placement) -> HttpModelAdapter {
    HttpModelAdapter::new(
        "test-provider",
        placement,
        url,
        "test-model",
        "sk-test-key-123",
        Duration::from_secs(5),
        2,
    )
    .unwrap()
}

#[tokio::test]
async fn http_adapter_success_uses_live_usage() {
    let (url, mock) = spawn_mock(vec![ok_behavior()]).await;
    let adapter = adapter_for(&url, Placement::Public);

    let c = adapter.complete("some record notes", "test").await.unwrap();
    assert_eq!(c.text, "summary text");
    assert_eq!(
        c.tokens_in, 41,
        "tokens must come from the provider usage block"
    );
    assert_eq!(c.tokens_out, 7);
    assert_eq!(c.model_ref, "test-provider/gpt-4o-mini");

    let seen = mock.seen.lock().await;
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].auth.as_deref(), Some("Bearer sk-test-key-123"));
    assert_eq!(seen[0].path, "/chat/completions");
    assert_eq!(seen[0].body["model"], "test-model");
    let system_msg = seen[0].body["messages"][0]["content"].as_str().unwrap();
    assert!(system_msg.contains("untrusted content"));
    let user_msg = seen[0].body["messages"][1]["content"].as_str().unwrap();
    assert!(user_msg.contains("some record notes"));
}

#[tokio::test]
async fn http_adapter_retries_transient_then_succeeds() {
    let (url, mock) = spawn_mock(vec![
        Behavior {
            status: 503,
            body: serde_json::json!({"error": "overloaded"}),
            retry_after_secs: None,
            delay: Duration::ZERO,
        },
        ok_behavior(),
    ])
    .await;
    let adapter = adapter_for(&url, Placement::Public);
    let c = adapter.complete("notes", "test").await.unwrap();
    assert_eq!(c.text, "summary text");
    assert_eq!(
        mock.seen.lock().await.len(),
        2,
        "transient 503 retried once"
    );
}

#[tokio::test]
async fn http_adapter_honors_retry_after() {
    let (url, _mock) = spawn_mock(vec![
        Behavior {
            status: 429,
            body: serde_json::json!({"error": "rate limited"}),
            retry_after_secs: Some(1),
            delay: Duration::ZERO,
        },
        ok_behavior(),
    ])
    .await;
    let adapter = adapter_for(&url, Placement::Public);
    let start = std::time::Instant::now();
    adapter.complete("notes", "test").await.unwrap();
    assert!(
        start.elapsed() >= Duration::from_secs(1),
        "Retry-After: 1 must be honored"
    );
}

#[tokio::test]
async fn http_adapter_does_not_retry_client_errors() {
    let (url, mock) = spawn_mock(vec![Behavior {
        status: 400,
        body: serde_json::json!({"error": "bad request"}),
        retry_after_secs: None,
        delay: Duration::ZERO,
    }])
    .await;
    let adapter = adapter_for(&url, Placement::Public);
    let err = adapter.complete("notes", "test").await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Internal(_)),
        "400 -> Internal, not retried: {err:?}"
    );
    assert_eq!(mock.seen.lock().await.len(), 1, "4xx must not be retried");
}

#[tokio::test]
async fn http_adapter_rejects_bad_credentials_without_leak() {
    let (url, _mock) = spawn_mock(vec![Behavior {
        status: 401,
        body: serde_json::json!({"error": "invalid api key"}),
        retry_after_secs: None,
        delay: Duration::ZERO,
    }])
    .await;
    let adapter = adapter_for(&url, Placement::Public);
    let err = adapter.complete("notes", "test").await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "401 -> Forbidden: {err:?}"
    );
    let msg = format!("{err:?}");
    assert!(
        !msg.contains("sk-test-key-123"),
        "key must not leak into errors"
    );
    let dbg = format!("{adapter:?}");
    assert!(
        !dbg.contains("sk-test-key-123"),
        "key must not leak via Debug"
    );
}

#[tokio::test]
async fn http_adapter_fails_closed_without_usage_block() {
    let (url, _mock) = spawn_mock(vec![Behavior {
        status: 200,
        body: serde_json::json!({
            "model": "gpt-4o-mini",
            "choices": [{"message": {"role": "assistant", "content": "text"}}]
        }),
        retry_after_secs: None,
        delay: Duration::ZERO,
    }])
    .await;
    let adapter = adapter_for(&url, Placement::Public);
    let err = adapter.complete("notes", "test").await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Internal(_)),
        "missing usage block must fail closed, not invent tokens: {err:?}"
    );
}

#[tokio::test]
async fn http_adapter_times_out() {
    let (url, _mock) = spawn_mock(vec![Behavior {
        status: 200,
        body: ok_body(),
        retry_after_secs: None,
        delay: Duration::from_secs(5),
    }])
    .await;
    let adapter = HttpModelAdapter::new(
        "slow-provider",
        Placement::Public,
        &url,
        "test-model",
        "sk-test-key-123",
        Duration::from_secs(1),
        0,
    )
    .unwrap();
    let start = std::time::Instant::now();
    let err = adapter.complete("notes", "test").await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Internal(_)),
        "timeout -> typed Internal: {err:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "client timeout must bound the call"
    );
}

#[tokio::test]
async fn http_adapter_rejects_non_http_base_url() {
    let err = HttpModelAdapter::new(
        "bad",
        Placement::Public,
        "ftp://example.com/v1",
        "m",
        "k",
        Duration::from_secs(5),
        0,
    )
    .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
}

#[tokio::test]
async fn from_env_reads_provider_config() {
    // Unique var names: no other test touches these.
    let prefix = "TINKER_PROVIDER_ITEM24ENVTEST";
    std::env::set_var(
        format!("{prefix}_BASE_URL"),
        "https://llm.internal.example/v1",
    );
    std::env::set_var(format!("{prefix}_API_KEY"), "sk-env-key");
    std::env::set_var(format!("{prefix}_MODEL"), "private-7b");
    std::env::set_var(format!("{prefix}_PLACEMENT"), "org-controlled");
    let adapter = HttpModelAdapter::from_env("item24envtest").unwrap();
    assert_eq!(adapter.name(), "item24envtest");
    assert_eq!(adapter.placement(), Placement::OrgControlled);
    assert!(adapter.available());
    for suffix in ["BASE_URL", "API_KEY", "MODEL", "PLACEMENT"] {
        std::env::remove_var(format!("{prefix}_{suffix}"));
    }
    let err = HttpModelAdapter::from_env("item24envtest").unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "missing env config must fail: {err:?}"
    );
    assert!(format!("{err:?}").contains("BASE_URL"));
}

async fn register_provider(env: &AgentEnv, name: &str, kind: &str, boundary: &str) {
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO model_providers (organization_id, name, kind, placement_boundary, status)
         VALUES ($1, $2, $3, $4, 'available')
         ON CONFLICT (organization_id, name) DO UPDATE SET kind=EXCLUDED.kind, placement_boundary=EXCLUDED.placement_boundary",
    )
    .bind(env.org_id)
    .bind(name)
    .bind(kind)
    .bind(boundary)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn gateway_transport_check_rejects_placement_mismatch_before_any_bytes() {
    let env = setup().await;
    let (url, mock) = spawn_mock(vec![ok_behavior()]).await;
    // Row says org-controlled, but the adapter declares public transport.
    register_provider(&env, "mixed-llm", "private", "org-controlled").await;

    let mut gw = ModelGateway::new(env.core.clone(), env.owner.clone());
    gw.register("mixed-llm", Arc::new(adapter_for(&url, Placement::Public)));
    let err = gw
        .transform_richtext(&env.exec_ctx, "mixed-llm", "substance", "secret notes")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "transport placement mismatch must fail closed: {err:?}"
    );
    assert_eq!(
        mock.seen.lock().await.len(),
        0,
        "no prompt bytes may leave the process on mismatch"
    );
}

#[tokio::test]
async fn gateway_transport_check_allows_matching_private_endpoint() {
    let env = setup().await;
    let (url, mock) = spawn_mock(vec![ok_behavior()]).await;
    register_provider(&env, "private-llm", "private", "org-controlled").await;

    let mut gw = ModelGateway::new(env.core.clone(), env.owner.clone());
    gw.register(
        "private-llm",
        Arc::new(adapter_for(&url, Placement::OrgControlled)),
    );
    let c = gw
        .transform_richtext(&env.exec_ctx, "private-llm", "substance", "notes here")
        .await
        .unwrap();
    assert_eq!(c.text, "summary text");
    assert_eq!(c.tokens_in, 41);
    assert_eq!(mock.seen.lock().await.len(), 1);
}
