//! M0 performance baselines: measured on local dev hardware (single node,
//! PostgreSQL 16, debug build). These are NOT tuning targets — they are
//! the first ledger entries in the performance loop (build → test →
//! harden → secure → performance → backlog). Bounds are generous
//! regression tripwires, not SLAs.

mod common;

use std::time::Instant;
use tinker_db::OwnerDb;
use tinker_durable::{DurableRuntime, RunDef};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use tinker_search::{IndexChange, NativeSearchBackend, SearchBackend, SearchPlan};
use uuid::Uuid;

fn percentile(mut samples: Vec<f64>, p: f64) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let i = ((p / 100.0) * (samples.len() - 1) as f64).round() as usize;
    samples[i]
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

fn field(api_name: &str) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        sensitive: false,
        validation: Default::default(),
        preset: None,
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type: FieldType::Text,
        options: serde_json::json!({}),
        required: false,
    }
}

#[tokio::test]
async fn perf_object_and_field_ddl_latency() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));

    let run_tag: String = Uuid::now_v7().simple().to_string()[24..32].to_string();
    let mut samples = Vec::new();
    for i in 0..20 {
        let t = Instant::now();
        let meta = ont
            .define_object(&ctx, &object_def(&format!("perf_obj_{run_tag}_{i}")))
            .await
            .unwrap();
        ont.add_field(&ctx, meta.id, &field("perf_field"))
            .await
            .unwrap();
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let p50 = percentile(samples.clone(), 50.0);
    let p95 = percentile(samples.clone(), 95.0);
    println!("DDL define_object+add_field: n=20 p50={p50:.1}ms p95={p95:.1}ms");
    assert!(
        p95 < 500.0,
        "DDL p95 {p95:.1}ms exceeds regression tripwire 500ms"
    );
}

#[tokio::test]
async fn perf_queue_claim_latency() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());
    let queue = format!("perfq-{}", Uuid::now_v7().simple());

    for i in 0..200 {
        d.start_run(
            &ctx,
            &RunDef {
                definition_id: "perf".into(),
                definition_version: "1".into(),
                input: serde_json::json!({ "i": i }),
                queue: queue.clone(),
                partition_key: String::new(),
                priority: 0,
                wake_at: None,
            },
        )
        .await
        .unwrap();
    }

    let mut samples = Vec::new();
    for _ in 0..20 {
        let t = Instant::now();
        let claimed = d
            .claim_next(
                &ctx,
                &queue,
                "perf-worker",
                std::time::Duration::from_secs(60),
                10,
            )
            .await
            .unwrap();
        assert_eq!(claimed.len(), 10);
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let p50 = percentile(samples.clone(), 50.0);
    let p95 = percentile(samples.clone(), 95.0);
    println!("queue claim_next(batch=10): n=20 p50={p50:.1}ms p95={p95:.1}ms");
    assert!(
        p95 < 250.0,
        "claim p95 {p95:.1}ms exceeds regression tripwire 250ms"
    );
}

#[tokio::test]
async fn perf_native_search_throughput() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let backend = NativeSearchBackend::new(env.core.clone());
    let object_id = Uuid::now_v7();

    for i in 0..1000u32 {
        backend
            .index_change(
                &ctx,
                &IndexChange {
                    object_id,
                    record_id: Uuid::now_v7(),
                    text: format!("quarterly renewal contract for vendor {i} services agreement"),
                    field_versions: serde_json::json!({}),
                    storage_classes: vec!["text".into()],
                },
            )
            .await
            .unwrap();
    }

    let plan = SearchPlan {
        text_query: "renewal contract".into(),
        object_id: None,
        limit: 10,
        row_policies: vec![],
    };
    let mut samples = Vec::new();
    for _ in 0..100 {
        let t = Instant::now();
        let page = backend.search(&ctx, &plan).await.unwrap();
        assert_eq!(page.hits.len(), 10);
        samples.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    let p50 = percentile(samples.clone(), 50.0);
    let p95 = percentile(samples.clone(), 95.0);
    let qps = 100.0 / (samples.iter().sum::<f64>() / 1000.0);
    println!("native search(1000 docs): n=100 p50={p50:.1}ms p95={p95:.1}ms qps={qps:.0}");
    assert!(
        p95 < 250.0,
        "search p95 {p95:.1}ms exceeds regression tripwire 250ms"
    );
}
