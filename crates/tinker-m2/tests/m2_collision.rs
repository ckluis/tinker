//! M2 exit test: colliding IDs cannot cross query, cache, job, search,
//! virtual-file, or SSE paths.
//!
//! One platform object, one physical table, ONE record UUID inserted under
//! org A ("Alpha") and org B ("Beta"). Every path below runs as each org
//! and must return only that org's row — the sibling's identically-keyed
//! row must never appear.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use tinker_core::{OrganizationId, TenantContext};
use tinker_durable::RunDef;
use tinker_live::{resolve_vpath, QueryExecutor};
use tinker_query::QueryIntent;
use tinker_search::{IndexChange, SearchBackend, SearchPlan};

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

fn names_of(rows: &[serde_json::Value]) -> Vec<String> {
    rows.iter()
        .map(|r| r["name"].as_str().unwrap_or("?").to_string())
        .collect()
}

/// PATH 1 — query: the compiled plan's tenant predicate isolates the
/// colliding row at the SQL level.
#[tokio::test]
async fn query_path_isolates_colliding_ids() {
    let env = setup().await;
    let intent = widget_intent(env.object_id);

    for (org, want) in [(&env.org_a, "Alpha"), (&env.org_b, "Beta")] {
        let plan = env
            .state
            .compiler
            .compile(&org.tenant, &intent)
            .await
            .unwrap();
        // The tenant predicate is the FIRST bind.
        assert!(
            plan.sql.contains("t0.organization_id = $1"),
            "tenant predicate must lead the plan"
        );
        let rows = env
            .state
            .executor
            .execute(&org.tenant, &plan)
            .await
            .unwrap();
        assert_eq!(names_of(&rows), vec![want.to_string()]);
        // The colliding id resolves to this org's content, never the sibling's.
        assert_eq!(
            rows[0]["__id"].as_str().unwrap(),
            colliding_id().to_string()
        );
    }
}

/// PATH 2 — cache: keys are (org, plan_hash). Priming org A's entry must
/// not serve org B, and invalidating org A must not drop org B's entry.
#[tokio::test]
async fn cache_path_isolates_colliding_ids() {
    let env = setup().await;
    let intent = widget_intent(env.object_id);

    let plan_a = env
        .state
        .compiler
        .compile(&env.org_a.tenant, &intent)
        .await
        .unwrap();
    let hash_a = QueryExecutor::plan_hash(&plan_a);
    let rows_a = env
        .state
        .executor
        .execute(&env.org_a.tenant, &plan_a)
        .await
        .unwrap();

    // Same SQL text, same binds except $1 — but the plan hash alone is
    // never a cache key.
    let plan_b = env
        .state
        .compiler
        .compile(&env.org_b.tenant, &intent)
        .await
        .unwrap();
    let hash_b = QueryExecutor::plan_hash(&plan_b);

    env.state
        .cache
        .put(env.org_a.org_id, &hash_a, env.object_id, rows_a.clone())
        .await;

    // Org B misses despite the identical plan shape...
    assert!(
        env.state
            .cache
            .get(env.org_b.org_id, &hash_b)
            .await
            .is_none(),
        "org B must not hit org A's cache entry"
    );
    // ...and even probing A's hash under B's org misses.
    assert!(
        env.state
            .cache
            .get(env.org_b.org_id, &hash_a)
            .await
            .is_none(),
        "plan hash alone must never resolve"
    );
    // Org A hits its own entry.
    let hit = env
        .state
        .cache
        .get(env.org_a.org_id, &hash_a)
        .await
        .unwrap();
    assert_eq!(names_of(&hit), vec!["Alpha".to_string()]);

    // Invalidation is per-org: dropping A's entry leaves B's alone.
    let rows_b = env
        .state
        .executor
        .execute(&env.org_b.tenant, &plan_b)
        .await
        .unwrap();
    env.state
        .cache
        .put(env.org_b.org_id, &hash_b, env.object_id, rows_b)
        .await;
    let dropped = env
        .state
        .cache
        .invalidate(env.org_a.org_id, env.object_id)
        .await;
    assert_eq!(dropped, 1);
    assert!(
        env.state
            .cache
            .get(env.org_a.org_id, &hash_a)
            .await
            .is_none(),
        "A's entry is gone"
    );
    let b_hit = env
        .state
        .cache
        .get(env.org_b.org_id, &hash_b)
        .await
        .unwrap();
    assert_eq!(
        names_of(&b_hit),
        vec!["Beta".to_string()],
        "B's entry survives"
    );
}

/// PATH 3 — job: a durable run carries its organization's id; the worker
/// rebuilds the tenant context from the RUN, never from caller input, so
/// the colliding id resolves inside the run's org only.
#[tokio::test]
async fn job_path_isolates_colliding_ids() {
    let env = setup().await;
    let intent = widget_intent(env.object_id);

    // Enqueue one refresh job per org. The input names the colliding
    // record id explicitly — the worker must still resolve it per-org.
    for org in [&env.org_a, &env.org_b] {
        env.durable
            .start_run(
                &org.tenant,
                &RunDef {
                    definition_id: "grid-refresh".into(),
                    definition_version: "1".into(),
                    input: serde_json::json!({
                        "intent": serde_json::to_value(&intent).unwrap(),
                        "record_id": colliding_id().to_string(),
                    }),
                    queue: "m2-test".into(),
                    partition_key: org.org_id.to_string(),
                    priority: 0,
                    wake_at: None,
                },
            )
            .await
            .unwrap();
    }

    // The worker claims per-org (tenant-scoped claim) and executes the
    // input intent under the RUN's organization.
    for (org, want) in [(&env.org_a, "Alpha"), (&env.org_b, "Beta")] {
        let claimed = env
            .durable
            .claim_next(
                &org.tenant,
                "m2-test",
                "worker-1",
                Duration::from_secs(60),
                10,
            )
            .await
            .unwrap();
        assert_eq!(claimed.len(), 1, "each org's worker claims its own run");
        let run = &claimed[0];
        assert_eq!(run.organization_id, org.org_id);

        // Tenant context comes from the run's stored org — never from the
        // (caller-influenced) input.
        let job_ctx = TenantContext::new(
            OrganizationId(run.organization_id),
            org.actor_id,
            "job-worker",
        );
        let job_intent: QueryIntent =
            serde_json::from_value(run.input_ref["intent"].clone()).unwrap();
        let plan = env
            .state
            .compiler
            .compile(&job_ctx, &job_intent)
            .await
            .unwrap();
        let rows = env.state.executor.execute(&job_ctx, &plan).await.unwrap();
        assert_eq!(names_of(&rows), vec![want.to_string()]);
        // The colliding record id in the input resolves to this org's row.
        assert_eq!(rows[0]["name"].as_str().unwrap(), want);
    }
}

/// PATH 4 — search: the index is keyed by (org, object, record); a search
/// as org A never returns org B's identically-keyed document.
#[tokio::test]
async fn search_path_isolates_colliding_ids() {
    let env = setup().await;
    let cid = colliding_id();

    for (org, text) in [
        (&env.org_a, "Alpha widget bravo"),
        (&env.org_b, "Beta widget bravo"),
    ] {
        env.search
            .index_change(
                &org.tenant,
                &IndexChange {
                    object_id: env.object_id,
                    record_id: cid,
                    text: text.into(),
                    field_versions: serde_json::json!({"name": 1}),
                    storage_classes: vec!["text".into()],
                },
            )
            .await
            .unwrap();
    }

    for (org, want_id, want_text) in [(&env.org_a, cid, "Alpha"), (&env.org_b, cid, "Beta")] {
        let page = env
            .search
            .search(
                &org.tenant,
                &SearchPlan {
                    text_query: "bravo".into(),
                    object_id: Some(env.object_id),
                    limit: 10,
                    row_policies: vec![],
                },
            )
            .await
            .unwrap();
        assert_eq!(page.hits.len(), 1, "exactly one org's doc matches");
        assert_eq!(page.hits[0].record_id, want_id);
        assert!(
            page.hits[0].snippet.contains(want_text),
            "hit is this org's document"
        );
    }
}

/// PATH 5 — virtual file: the path carries no org; the caller's tenant
/// context scopes it. Same path, two orgs, different rows.
#[tokio::test]
async fn vfile_path_isolates_colliding_ids() {
    let env = setup().await;
    let slug = format!("m2_widget_{}", env.run).replace('-', "_");
    let path = format!("/objects/{slug}/{}", colliding_id());

    for (org, want) in [(&env.org_a, "Alpha"), (&env.org_b, "Beta")] {
        let intent = resolve_vpath(&env.state.ontology, &org.tenant, &path)
            .await
            .unwrap();
        let plan = env
            .state
            .compiler
            .compile(&org.tenant, &intent)
            .await
            .unwrap();
        let rows = env
            .state
            .executor
            .execute(&org.tenant, &plan)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["name"].as_str().unwrap(), want);
    }

    // Unknown paths fail loudly, never with another org's data.
    assert!(resolve_vpath(
        &env.state.ontology,
        &env.org_a.tenant,
        "/objects/nope_xyz/123"
    )
    .await
    .is_err());
}

/// PATH 6 — SSE: the signal bus is per-org. Publishing org B's change
/// emits nothing on org A's subscription; org A's own change arrives as
/// an id-only envelope with a strictly increasing sequence.
#[tokio::test]
async fn sse_path_isolates_colliding_ids() {
    let env = setup().await;
    let cid = colliding_id();

    let mut rx_a = env.state.signals.subscribe(env.org_a.org_id).await;
    let mut rx_b = env.state.signals.subscribe(env.org_b.org_id).await;

    // Org B's write: org A's subscriber must see NOTHING.
    env.state
        .signals
        .publish(env.org_b.org_id, env.object_id, vec![cid])
        .await;
    let res = tokio::time::timeout(Duration::from_millis(150), rx_a.recv()).await;
    assert!(
        res.is_err(),
        "org A's SSE stream must not see org B's signal"
    );
    // Org B's own subscriber does.
    let sig_b = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .expect("B's signal arrives")
        .unwrap();
    assert_eq!(sig_b.seq, 1);
    assert_eq!(sig_b.record_ids, vec![cid]);

    // Org A's write: id-only envelope, per-org sequence.
    let seq1 = env
        .state
        .signals
        .publish(env.org_a.org_id, env.object_id, vec![cid])
        .await;
    let seq2 = env
        .state
        .signals
        .publish(env.org_a.org_id, env.object_id, vec![cid])
        .await;
    assert!(seq2 > seq1, "sequences strictly increase per org");
    let sig_a = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
        .await
        .expect("A's signal arrives")
        .unwrap();
    assert_eq!(sig_a.organization_id, env.org_a.org_id);
    assert_eq!(sig_a.object_id, env.object_id);
    assert_eq!(sig_a.record_ids, vec![cid]);
    // Id-only: the envelope carries no row contents.
    let wire = serde_json::to_value(&sig_a).unwrap_or(serde_json::json!({}));
    assert!(
        wire.get("name").is_none(),
        "no row contents in the envelope"
    );
}

/// HTTP: POST /api/query through the real router isolates the colliding
/// row per session, and the second identical call is served from cache.
#[tokio::test]
async fn http_query_path_isolates_and_caches() {
    let env = setup().await;
    let intent = serde_json::to_value(widget_intent(env.object_id)).unwrap();

    for (org, want) in [(&env.org_a, "Alpha"), (&env.org_b, "Beta")] {
        let (status, body) = post_query(&env.router, &org.cookie, &intent).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["cached"], false);
        assert_eq!(body["rows"][0]["name"].as_str().unwrap(), want);
        assert_eq!(
            body["rows"][0]["__id"].as_str().unwrap(),
            colliding_id().to_string()
        );

        let (status2, body2) = post_query(&env.router, &org.cookie, &intent).await;
        assert_eq!(status2, StatusCode::OK);
        assert_eq!(body2["cached"], true, "second call hits the tenant cache");
        assert_eq!(body2["rows"][0]["name"].as_str().unwrap(), want);
    }
}

/// HTTP: /api/sse rejects a sibling org's object id — fail closed, no
/// existence oracle beyond the 404 the tenant-scoped ontology already gives.
#[tokio::test]
async fn http_sse_rejects_unresolvable_object() {
    let env = setup().await;
    use axum::http::{header, Request};
    use tower::ServiceExt;

    // A random object id resolves to nothing in either org: 404, and the
    // SSE stream never opens.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/sse?object={}", uuid::Uuid::now_v7()))
        .header(header::COOKIE, &env.org_a.cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let res = env.router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // No session at all: the extractor redirects to login, never streams.
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/sse?object={}", env.object_id))
        .body(axum::body::Body::empty())
        .unwrap();
    let res = env.router.clone().oneshot(req).await.unwrap();
    assert!(
        res.status() == StatusCode::SEE_OTHER || res.status() == StatusCode::TEMPORARY_REDIRECT,
        "anonymous SSE must not stream, got {}",
        res.status()
    );
}
