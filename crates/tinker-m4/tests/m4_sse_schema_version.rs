//! Post-M8 item 18: open SSE streams re-evaluate schema version
//! changes. Promotion/rollback publish a distinct `schema_version` event
//! and drop cached plans compiled against the old version, so a client
//! with an open stream re-resolves the schema instead of waiting for a
//! row invalidation that might never come.

mod common;

use std::time::Duration;

use axum::http::{header, Request, StatusCode};
use tokio_stream::StreamExt;
use tower::ServiceExt;
use uuid::Uuid;

use common::{insert_ext_row, post_json, setup, ActorCtx};

fn contact_query(contact_id: Uuid, select: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "from": contact_id,
        "select": select,
        "filters": [],
        "order": [],
        "limit": 10,
        "schema_version": null,
    })
}

/// Draft → add `nickname` → preview → promote, seeding one ext row. The
/// governed HTTP path, end to end.
async fn evolve_and_promote(
    router: &axum::Router,
    actor: &ActorCtx,
    system_pool: &sqlx::PgPool,
    contact_id: Uuid,
) -> String {
    let (status, body) = post_json(
        router,
        actor,
        &format!("/api/schema/objects/{contact_id}/drafts"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create draft: {body}");
    let v = body["id"].as_str().unwrap().to_string();

    let (status, body) = post_json(
        router,
        actor,
        &format!("/api/schema/versions/{v}/fields"),
        &serde_json::json!({
            "name": "Nickname", "api_name": "nickname", "label": "Nickname",
            "field_type": "text", "options": {}, "required": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add field: {body}");
    let physical = body["physical_column"].as_str().unwrap().to_string();

    let amy: (Uuid,) = sqlx::query_as("SELECT id FROM data.crm_contact WHERE organization_id=$1")
        .bind(actor.tenant.organization_id.0)
        .fetch_one(system_pool)
        .await
        .unwrap();
    insert_ext_row(
        system_pool,
        actor.tenant.organization_id.0,
        contact_id,
        amy.0,
        &physical,
        "Ames",
    )
    .await;

    let (status, _) = post_json(
        router,
        actor,
        &format!("/api/schema/versions/{v}/preview"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "preview");

    let (status, body) = post_json(
        router,
        actor,
        &format!("/api/schema/versions/{v}/promote"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "promote: {body}");
    v
}

/// Open `GET /api/sse?object=...` and read until a `schema_version` event
/// arrives (10s timeout so a stuck stream fails instead of hanging).
async fn await_schema_version_event(
    router: &axum::Router,
    cookie: &str,
    object_id: Uuid,
) -> serde_json::Value {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/sse?object={object_id}"))
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("text/event-stream"),
        "SSE content type"
    );
    let mut stream = res.into_body().into_data_stream();

    let mut buf: Vec<u8> = Vec::new();
    let mut current_event = String::from("message");
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            buf.extend_from_slice(&chunk);
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line);
                let text = text.trim_end();
                if let Some(name) = text.strip_prefix("event:") {
                    current_event = name.trim().to_string();
                } else if let Some(payload) = text.strip_prefix("data:") {
                    let payload = payload.trim();
                    if payload.is_empty() {
                        continue;
                    }
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(payload) {
                        if current_event == "schema_version" {
                            return msg;
                        }
                        // Skip invalidate/resync/keep-alive events.
                    }
                }
                // Comment lines (":...") and blanks: ignored.
            }
        }
        panic!("stream ended without a schema_version event")
    })
    .await
    .expect("schema_version event arrives")
}

#[tokio::test]
async fn promote_emits_schema_version_event_and_drops_cached_plans() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    // Warm the query cache: the second identical query is served cached.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false);
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], true, "second identical query is cached");

    // Open the SSE stream, then promote from a spawned task.
    let router = env.router.clone();
    let cookie = env.builder_a.cookie.clone();
    let sse =
        tokio::spawn(async move { await_schema_version_event(&router, &cookie, contact_id).await });

    let router2 = env.router.clone();
    let builder2 = ActorCtx {
        actor_id: env.builder_a.actor_id,
        tenant: env.builder_a.tenant.clone(),
        cookie: env.builder_a.cookie.clone(),
    };
    let pool2 = env.system_pool.clone();
    let promoter = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        evolve_and_promote(&router2, &builder2, &pool2, contact_id).await
    });

    let msg = sse.await.unwrap();
    promoter.await.unwrap();

    // The schema_version envelope is id-only: seq + object id, no rows,
    // no record ids.
    assert_eq!(
        msg["object_id"].as_str().unwrap(),
        contact_id.to_string(),
        "event names the object"
    );
    assert!(msg["seq"].as_u64().is_some(), "event carries a seq");
    assert!(
        msg.get("record_ids").is_none(),
        "no record ids on a schema event"
    );
    assert!(msg.get("rows").is_none(), "no row contents leak");

    // The cached plan compiled against the pre-promotion schema is gone:
    // the same query recompiles (cached=false), and the evolved field
    // now resolves.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false, "promote drops cached plans");

    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "evolved field serves: {body}");
    assert_eq!(body["rows"][0]["nickname"], "Ames");
}

#[tokio::test]
async fn rollback_emits_schema_version_event() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    // Promote synchronously first; the evolved field serves.
    let v = evolve_and_promote(&env.router, &env.builder_a, &env.system_pool, contact_id).await;
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["rows"][0]["nickname"], "Ames");

    // Open the stream, then roll back from a spawned task.
    let router = env.router.clone();
    let cookie = env.builder_a.cookie.clone();
    let sse =
        tokio::spawn(async move { await_schema_version_event(&router, &cookie, contact_id).await });

    let router2 = env.router.clone();
    let builder2 = ActorCtx {
        actor_id: env.builder_a.actor_id,
        tenant: env.builder_a.tenant.clone(),
        cookie: env.builder_a.cookie.clone(),
    };
    let rollback = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (status, body) = post_json(
            &router2,
            &builder2,
            &format!("/api/schema/versions/{v}/rollback"),
            &serde_json::json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "rollback: {body}");
    });

    let msg = sse.await.unwrap();
    rollback.await.unwrap();
    assert_eq!(msg["object_id"].as_str().unwrap(), contact_id.to_string());
    assert!(msg["seq"].as_u64().is_some());

    // The rollback restored the pack base: the evolved field no longer
    // resolves, and the plan cache was dropped (no stale cached=true).
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "nickname is gone: {body}");

    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false, "rollback drops cached plans");
    assert_eq!(body["rows"][0]["name"], "Amy");
}

// --- Post-M8 item 33: form entry points go through shared governance ---
//
// The form-driven promote/rollback used to call the evolver with no
// plan-cache invalidation and no schema_version signal, leaving stale
// cached plans and unaware SSE streams. Both paths now go through the
// same promote_and_broadcast / rollback_and_broadcast helpers as the
// JSON endpoints.

/// POST a urlencoded form; returns (status, location header).
async fn post_form(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
    body: &str,
) -> (StatusCode, String) {
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, &actor.cookie)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let loc = res
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    (status, loc)
}

/// Draft → add `nickname` → preview → promote entirely through the FORM
/// endpoints (303 redirects). Returns the version id.
async fn form_evolve_and_promote(
    router: &axum::Router,
    actor: &ActorCtx,
    contact_id: Uuid,
) -> String {
    let (status, loc) = post_form(
        router,
        actor,
        &format!("/schema/objects/{contact_id}/drafts"),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "form draft: {loc}");
    let v = loc.split("version=").nth(1).unwrap().to_string();

    let (status, _) = post_form(
        router,
        actor,
        &format!("/schema/versions/{v}/fields"),
        "name=Nickname&api_name=nickname&label=Nickname&field_type=text",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "form add field");

    let (status, _) = post_form(router, actor, &format!("/schema/versions/{v}/preview"), "").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "form preview");

    let (status, _) = post_form(router, actor, &format!("/schema/versions/{v}/promote"), "").await;
    assert_eq!(status, StatusCode::SEE_OTHER, "form promote");
    v
}

/// Item 33: a form-driven promote invalidates the object's cached plans
/// AND publishes a schema_version signal — previously only the JSON
/// path did both.
#[tokio::test]
async fn form_promote_drops_cache_and_emits_schema_version() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    // Warm the query cache: the second identical query is served cached.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false);
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], true, "second identical query is cached");

    // Open the SSE stream, then promote via the FORM endpoint.
    let router = env.router.clone();
    let cookie = env.builder_a.cookie.clone();
    let sse =
        tokio::spawn(async move { await_schema_version_event(&router, &cookie, contact_id).await });

    let router2 = env.router.clone();
    let builder2 = ActorCtx {
        actor_id: env.builder_a.actor_id,
        tenant: env.builder_a.tenant.clone(),
        cookie: env.builder_a.cookie.clone(),
    };
    let promoter = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        form_evolve_and_promote(&router2, &builder2, contact_id).await
    });

    let msg = sse.await.unwrap();
    promoter.await.unwrap();
    assert_eq!(
        msg["object_id"].as_str().unwrap(),
        contact_id.to_string(),
        "event names the object"
    );
    assert!(msg["seq"].as_u64().is_some(), "event carries a seq");

    // The cached plan compiled against the pre-promotion schema is gone:
    // the same query recompiles (cached=false)...
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false, "form promote drops cached plans");

    // ...and the evolved field resolves against the new schema.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "evolved field serves: {body}");
    assert!(body["rows"][0]["nickname"].is_null());
}

/// Item 33: a form-driven rollback invalidates the object's cached plans
/// AND publishes a schema_version signal.
#[tokio::test]
async fn form_rollback_drops_cache_and_emits_schema_version() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    // Promote through the form endpoints; the evolved field resolves and
    // the second identical query is cached.
    let v = form_evolve_and_promote(&env.router, &env.builder_a, contact_id).await;
    let query = || contact_query(contact_id, &["name", "nickname"]);
    let (status, body) = post_json(&env.router, &env.builder_a, "/api/query", &query()).await;
    assert_eq!(status, StatusCode::OK, "evolved field serves: {body}");
    let (status, body) = post_json(&env.router, &env.builder_a, "/api/query", &query()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], true, "second identical query is cached");

    // Open the stream, then roll back via the FORM endpoint.
    let router = env.router.clone();
    let cookie = env.builder_a.cookie.clone();
    let sse =
        tokio::spawn(async move { await_schema_version_event(&router, &cookie, contact_id).await });

    let router2 = env.router.clone();
    let builder2 = ActorCtx {
        actor_id: env.builder_a.actor_id,
        tenant: env.builder_a.tenant.clone(),
        cookie: env.builder_a.cookie.clone(),
    };
    let rollback = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (status, _) = post_form(
            &router2,
            &builder2,
            &format!("/schema/versions/{v}/rollback"),
            "",
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER, "form rollback");
    });

    let msg = sse.await.unwrap();
    rollback.await.unwrap();
    assert_eq!(msg["object_id"].as_str().unwrap(), contact_id.to_string());
    assert!(msg["seq"].as_u64().is_some());

    // The rollback restored the pack base: the evolved field no longer
    // resolves, and the plan cache was dropped (no stale cached=true).
    let (status, body) = post_json(&env.router, &env.builder_a, "/api/query", &query()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "nickname is gone: {body}");

    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(contact_id, &["name"]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false, "form rollback drops cached plans");
}

/// Collect every schema_version event for `object_id` that arrives on a
/// fresh SSE stream within `window`. Subscribers only see signals
/// published after subscribing, so events before the window are not
/// replayed.
async fn collect_schema_version_events(
    router: axum::Router,
    cookie: String,
    object_id: Uuid,
    window: Duration,
) -> Vec<serde_json::Value> {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/sse?object={object_id}"))
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let res = router.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let mut stream = res.into_body().into_data_stream();

    let mut buf: Vec<u8> = Vec::new();
    let mut current_event = String::from("message");
    let mut out: Vec<serde_json::Value> = Vec::new();
    let _ = tokio::time::timeout(window, async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            buf.extend_from_slice(&chunk);
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line);
                let text = text.trim_end();
                if let Some(name) = text.strip_prefix("event:") {
                    current_event = name.trim().to_string();
                } else if let Some(payload) = text.strip_prefix("data:") {
                    let payload = payload.trim();
                    if payload.is_empty() {
                        continue;
                    }
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(payload) {
                        if current_event == "schema_version"
                            && msg["object_id"].as_str() == Some(&object_id.to_string())
                        {
                            out.push(msg);
                        }
                    }
                }
            }
        }
    })
    .await;
    out
}

/// Draft → add `nickname` → preview through the JSON endpoints, stopping
/// short of promote. Returns the version id.
async fn json_evolve_to_preview(
    router: &axum::Router,
    actor: &ActorCtx,
    contact_id: Uuid,
) -> String {
    let (status, body) = post_json(
        router,
        actor,
        &format!("/api/schema/objects/{contact_id}/drafts"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create draft: {body}");
    let v = body["id"].as_str().unwrap().to_string();

    let (status, body) = post_json(
        router,
        actor,
        &format!("/api/schema/versions/{v}/fields"),
        &serde_json::json!({
            "name": "Nickname", "api_name": "nickname", "label": "Nickname",
            "field_type": "text", "options": {}, "required": false,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "add field: {body}");

    let (status, _) = post_json(
        router,
        actor,
        &format!("/api/schema/versions/{v}/preview"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "preview");
    v
}

/// Item 33: the shared helpers publish exactly one schema_version
/// signal per operation — the JSON path must not double-broadcast after
/// the refactor (the form path inherits the same helper).
#[tokio::test]
async fn promote_and_rollback_emit_exactly_one_schema_version_event() {
    // --- JSON promote ---
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let v = json_evolve_to_preview(&env.router, &env.builder_a, contact_id).await;

    let router = env.router.clone();
    let cookie = env.builder_a.cookie.clone();
    let collector = tokio::spawn(async move {
        collect_schema_version_events(router, cookie, contact_id, Duration::from_secs(3)).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v}/promote"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "promote: {body}");

    let events = collector.await.unwrap();
    assert_eq!(events.len(), 1, "promote publishes exactly one signal");

    // --- JSON rollback (fresh env; promote before the stream opens) ---
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let v = json_evolve_to_preview(&env.router, &env.builder_a, contact_id).await;
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v}/promote"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "promote: {body}");

    let router = env.router.clone();
    let cookie = env.builder_a.cookie.clone();
    let collector = tokio::spawn(async move {
        collect_schema_version_events(router, cookie, contact_id, Duration::from_secs(3)).await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v}/rollback"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "rollback: {body}");

    let events = collector.await.unwrap();
    assert_eq!(events.len(), 1, "rollback publishes exactly one signal");
}
