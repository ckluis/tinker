//! M2 performance baselines (local Postgres 16, debug build).
//!
//! Regression tripwires, not SLAs: the numbers document what this machine
//! does today so a future change that doubles them gets caught. Gates use
//! p50 (robust to noisy neighbors on a shared VM); p95 is reported.

mod common;

use std::time::Instant;

use common::{post_query, setup};
use tinker_live::QueryExecutor;
use tinker_query::QueryIntent;

fn percentile(mut samples: Vec<u128>, pct: f64) -> u128 {
    samples.sort_unstable();
    let idx = ((samples.len() as f64 * pct).ceil() as usize).saturating_sub(1);
    samples[idx.min(samples.len() - 1)]
}

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

/// Compile + execute a typed query end to end (with audit write).
#[tokio::test]
async fn query_execute_tripwire() {
    let env = setup().await;
    let intent = widget_intent(env.object_id);

    let mut samples = Vec::new();
    for _ in 0..30 {
        let t = Instant::now();
        let plan = env
            .state
            .compiler
            .compile(&env.org_a.tenant, &intent)
            .await
            .unwrap();
        let rows = env
            .state
            .executor
            .execute(&env.org_a.tenant, &plan)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        samples.push(t.elapsed().as_micros());
    }
    let p50 = percentile(samples.clone(), 0.5);
    let p95 = percentile(samples, 0.95);
    println!("query execute: p50={p50}µs p95={p95}µs");
    assert!(p50 < 50_000, "query execute p50 tripwire: {p50}µs");
}

/// Cached query over HTTP: session → cache hit → JSON.
#[tokio::test]
async fn cached_query_http_tripwire() {
    let env = setup().await;
    let intent = serde_json::to_value(widget_intent(env.object_id)).unwrap();
    // Prime the cache.
    let (_, body) = post_query(&env.router, &env.org_a.cookie, &intent).await;
    assert_eq!(body["cached"], false);

    let mut samples = Vec::new();
    for _ in 0..30 {
        let t = Instant::now();
        let (status, body) = post_query(&env.router, &env.org_a.cookie, &intent).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(body["cached"], true);
        samples.push(t.elapsed().as_micros());
    }
    let p50 = percentile(samples.clone(), 0.5);
    let p95 = percentile(samples, 0.95);
    println!("cached query http: p50={p50}µs p95={p95}µs");
    assert!(p50 < 50_000, "cached query p50 tripwire: {p50}µs");
}

/// Plan hashing cost (cache-key computation).
#[tokio::test]
async fn plan_hash_tripwire() {
    let env = setup().await;
    let intent = widget_intent(env.object_id);
    let plan = env
        .state
        .compiler
        .compile(&env.org_a.tenant, &intent)
        .await
        .unwrap();

    let mut samples = Vec::new();
    for _ in 0..1000 {
        let t = Instant::now();
        let _ = QueryExecutor::plan_hash(&plan);
        samples.push(t.elapsed().as_nanos());
    }
    let p50 = percentile(samples.clone(), 0.5);
    let p95 = percentile(samples, 0.95);
    println!("plan hash: p50={p50}ns p95={p95}ns");
    assert!(p50 < 50_000, "plan hash p50 tripwire: {p50}ns");
}
