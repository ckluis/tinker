//! M2 reactivity properties: timeout, audit, ordered id-only SSE over
//! HTTP, cache invalidation on write, and the rt-grid connector.

mod common;

use std::time::Duration;

use axum::http::{header, Request, StatusCode};
use tinker_query::QueryIntent;
use tokio_stream::StreamExt;
use tower::ServiceExt;

use common::{colliding_id, post_query, setup};

fn widget_intent(object_id: uuid::Uuid) -> QueryIntent {
    QueryIntent {
        from: object_id,
        select: vec!["name".into(), "score".into()],
        filters: vec![],
        order: vec![],
        limit: Some(50),
        schema_version: None,
    }
}

/// Every executed query is audited in its own tenant context: the audit
/// row attributes the query to the right org, actor, and object.
#[tokio::test]
async fn executed_queries_are_audited_per_tenant() {
    let env = setup().await;
    let intent = widget_intent(env.object_id);

    for org in [&env.org_a, &env.org_b] {
        let plan = env
            .state
            .compiler
            .compile(&org.tenant, &intent)
            .await
            .unwrap();
        env.state
            .executor
            .execute(&org.tenant, &plan)
            .await
            .unwrap();
    }

    // Read the audit log as each org: each sees exactly its own row.
    for (org, want_rows) in [(&env.org_a, 1), (&env.org_b, 1)] {
        let core = tinker_db::CoreDb(env.tenant_pool.clone());
        let mut tx = core.tenant_tx(&org.tenant).await.unwrap();
        let rows: Vec<(uuid::Uuid, uuid::Uuid, i32)> = sqlx::query_as(
            "SELECT actor_id, object_id, row_count FROM query_audit \
             WHERE object_id = $1 ORDER BY created_at",
        )
        .bind(env.object_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(rows.len(), want_rows, "each org sees its own audit rows");
        assert_eq!(rows[0].0, org.actor_id, "audit attributes the actor");
        assert_eq!(rows[0].1, env.object_id, "audit attributes the object");
        assert_eq!(rows[0].2, 1, "one row returned");
    }
}

/// The executor pins a statement timeout: a runaway query fails instead
/// of hanging the grid.
#[tokio::test]
async fn executor_enforces_statement_timeout() {
    let env = setup().await;
    // pg_sleep(10) exceeds the 5s governed timeout.
    let plan = tinker_query::CompiledPlan {
        sql: "SELECT pg_sleep(10)".into(),
        params: vec![],
        output_fields: vec![],
        object_id: env.object_id,
    };
    let res = tokio::time::timeout(
        Duration::from_secs(15),
        env.state.executor.execute(&env.org_a.tenant, &plan),
    )
    .await
    .expect("executor returns");
    assert!(
        res.is_err(),
        "a 10s query must fail under the 5s statement timeout"
    );
}

/// HTTP SSE: org A's stream receives org A's invalidation as an id-only,
/// sequenced event — and nothing for org B's writes.
#[tokio::test]
async fn http_sse_streams_ordered_id_only_invalidations() {
    let env = setup().await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/sse?object={}", env.object_id))
        .header(header::COOKIE, &env.org_a.cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let res = env.router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.headers()[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .contains("text/event-stream"),
        "SSE content type"
    );
    let mut stream = res.into_body().into_data_stream();

    // Publish org B's change first: A's stream must stay silent.
    let signals = env.state.signals.clone();
    let object_id = env.object_id;
    let cid = colliding_id();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        signals
            .publish(env.org_b.org_id, object_id, vec![cid])
            .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        signals
            .publish(env.org_a.org_id, object_id, vec![cid])
            .await;
    });

    // Read until the first invalidate event (with an overall timeout so a
    // stuck stream fails the test instead of hanging it).
    let mut buf = Vec::new();
    let mut seqs = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            buf.extend_from_slice(&chunk);
            // Drain complete `data:` lines.
            while let Some(pos) = find_subslice(&buf, b"\n") {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line);
                if let Some(payload) = text.strip_prefix("data:") {
                    let payload = payload.trim();
                    if payload == "ping" || payload.is_empty() {
                        continue;
                    }
                    if let Ok(msg) = serde_json::from_str::<serde_json::Value>(payload) {
                        // Id-only: record ids, never row contents.
                        assert!(
                            msg.get("record_ids").is_some(),
                            "envelope carries record ids"
                        );
                        assert!(msg.get("name").is_none(), "no row contents leak");
                        assert!(msg.get("rows").is_none(), "no row contents leak");
                        assert_eq!(msg["record_ids"][0].as_str().unwrap(), cid.to_string());
                        seqs.push(msg["seq"].as_u64().unwrap());
                        return;
                    }
                }
            }
        }
    })
    .await
    .expect("invalidate arrives");

    assert_eq!(
        seqs.len(),
        1,
        "exactly one invalidation: B's write was silent"
    );
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Publishing a write invalidates the tenant's cached plans for that
/// object — the next /api/query re-executes and the grid sees new data.
#[tokio::test]
async fn write_invalidates_tenant_cache() {
    let env = setup().await;
    let intent = serde_json::to_value(widget_intent(env.object_id)).unwrap();

    let (status, body) = post_query(&env.router, &env.org_a.cookie, &intent).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false);
    assert_eq!(body["rows"].as_array().unwrap().len(), 1);

    // Simulate the write path: insert a row, publish the signal, drop the
    // tenant's cached plans for the object (what the production writer does).
    let desc = env
        .state
        .ontology
        .describe_object(&env.org_a.tenant, env.object_id)
        .await
        .unwrap();
    let slug = desc.api_slug.clone();
    let name_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let new_id = uuid::Uuid::now_v7();
    let core = tinker_db::CoreDb(env.tenant_pool.clone());
    let mut tx = core.tenant_tx(&env.org_a.tenant).await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO data.{slug} (organization_id, id, \"{name_col}\") VALUES ($1, $2, 'Gamma')"
    ))
    .bind(env.org_a.org_id)
    .bind(new_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    env.state
        .signals
        .publish(env.org_a.org_id, env.object_id, vec![new_id])
        .await;
    let dropped = env
        .state
        .cache
        .invalidate(env.org_a.org_id, env.object_id)
        .await;
    assert_eq!(dropped, 1, "the cached plan is dropped on write");

    let (status, body) = post_query(&env.router, &env.org_a.cookie, &intent).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["cached"], false, "re-executes after invalidation");
    assert_eq!(
        body["rows"].as_array().unwrap().len(),
        2,
        "grid sees the new row"
    );

    // Org B's cache was never populated and its data is untouched.
    let (status, body_b) = post_query(&env.router, &env.org_b.cookie, &intent).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body_b["rows"].as_array().unwrap().len(), 1);
    assert_eq!(body_b["rows"][0]["name"].as_str().unwrap(), "Beta");
}

/// The rt-grid renderer embeds the query intent as data-query so the
/// client connector can fetch + subscribe without server round-trips.
#[tokio::test]
async fn grid_renderer_embeds_live_query_connector() {
    let env = setup().await;
    let intent = widget_intent(env.object_id);
    let def: tinker_apps::AppDefinition = serde_json::from_value(serde_json::json!({
        "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
        "components": [{
            "id": "w", "type": "rt-grid",
            "props": {
                "columns": [
                    { "label": "Name", "field": "name" },
                    { "label": "Score", "field": "score" },
                ],
                "query": serde_json::to_value(&intent).unwrap(),
            },
            "layout": { "x": 0, "y": 0, "w": 12, "h": 4 },
        }],
    }))
    .unwrap();
    let html = tinker_apps::render_app(
        &tinker_apps::PublishedApp {
            app_id: uuid::Uuid::now_v7(),
            slug: "m2grid".into(),
            name: "M2 Grid".into(),
            version_number: 1,
            definition: def,
            tokens: serde_json::from_value(serde_json::json!({})).unwrap(),
        },
        "acme",
        "tinker.test",
    )
    .unwrap();
    assert!(
        html.contains("data-query="),
        "grid carries the query intent"
    );
    assert!(
        html.contains("data-fields="),
        "grid carries the column fields"
    );
    // The intent round-trips: the client can POST it verbatim.
    let attr = html
        .split("data-query=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let decoded = html_escape_decode(attr);
    let back: QueryIntent = serde_json::from_str(&decoded).unwrap();
    assert_eq!(back.from, env.object_id);
    assert_eq!(back.select, vec!["name".to_string(), "score".to_string()]);

    // And the intent the grid carries actually executes through the API.
    let (status, body) = post_query(
        &env.router,
        &env.org_a.cookie,
        &serde_json::to_value(&back).unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["rows"][0]["name"].as_str().unwrap(), "Alpha");
}

/// Unknown fields and bad intents fail at the API with 400, never with a
/// partial render or a leaked error.
#[tokio::test]
async fn bad_intents_fail_closed_at_the_api() {
    let env = setup().await;
    let bad = serde_json::json!({
        "from": env.object_id,
        "select": ["nope_not_a_field"],
        "filters": [], "order": [], "limit": 10,
    });
    let (status, _) = post_query(&env.router, &env.org_a.cookie, &bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Empty select: also 400.
    let bad = serde_json::json!({
        "from": env.object_id,
        "select": [],
        "filters": [], "order": [], "limit": 10,
    });
    let (status, _) = post_query(&env.router, &env.org_a.cookie, &bad).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

fn html_escape_decode(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}
