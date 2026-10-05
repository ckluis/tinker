//! M4 performance tripwires (local debug cluster — tripwires, not SLAs).

mod common;

use common::*;
use std::time::Instant;
use tinker_evolve::VersionSel;
use tinker_query::QueryIntent;

fn contact_intent(contact_id: uuid::Uuid, version: &str) -> QueryIntent {
    QueryIntent {
        from: contact_id,
        select: vec!["name".into(), "nickname".into()],
        filters: vec![],
        order: vec![],
        limit: Some(1000),
        schema_version: Some(version.into()),
    }
}

/// Evolution DDL stays interactive: draft + field + canary + promote for
/// one object completes far below a 5s tripwire on the local cluster.
#[tokio::test]
async fn evolution_lifecycle_tripwire() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let ctx = &env.builder_a.tenant;

    let t = Instant::now();
    let v = evolver.create_draft(ctx, contact_id).await.unwrap();
    let draft_ms = t.elapsed().as_millis();

    let t = Instant::now();
    evolver
        .add_field(ctx, v.id, &text_field("nickname"))
        .await
        .unwrap();
    let add_field_ms = t.elapsed().as_millis();

    let t = Instant::now();
    evolver.mark_canary(ctx, v.id, None).await.unwrap();
    let canary_ms = t.elapsed().as_millis();

    let t = Instant::now();
    evolver.promote(ctx, v.id).await.unwrap();
    let promote_ms = t.elapsed().as_millis();

    println!(
        "m4 lifecycle: draft={draft_ms}ms add_field={add_field_ms}ms canary={canary_ms}ms promote={promote_ms}ms"
    );
    assert!(draft_ms < 2000, "draft tripwire");
    assert!(add_field_ms < 2000, "add_field tripwire (includes ext DDL)");
    assert!(canary_ms < 2000, "canary tripwire");
    assert!(promote_ms < 2000, "promote tripwire");
}

/// Versioned queries (ext join) stay on the fast path: compile + execute
/// over 1k contacts with an ext join, p50-style assertion over 21 runs.
#[tokio::test]
async fn versioned_query_tripwire() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let compiler = compiler_of(&env);
    let ctx = &env.builder_a.tenant;

    let v = evolver.create_draft(ctx, contact_id).await.unwrap();
    let sf = evolver
        .add_field(ctx, v.id, &text_field("nickname"))
        .await
        .unwrap();
    evolver.mark_canary(ctx, v.id, None).await.unwrap();
    evolver.promote(ctx, v.id).await.unwrap();

    // Seed 1k contacts + ext rows through the owner pool.
    let slug: (String,) = sqlx::query_as("SELECT api_slug FROM ontology_objects WHERE id=$1")
        .bind(contact_id)
        .fetch_one(&env.system_pool)
        .await
        .unwrap();
    let name_col: (String,) = sqlx::query_as(
        "SELECT physical_column FROM ontology_fields WHERE object_id=$1 AND api_name='name'",
    )
    .bind(contact_id)
    .fetch_one(&env.system_pool)
    .await
    .unwrap();
    let table = tinker_evolve::ext_table_name(env.org_a_id, contact_id);
    for i in 0..1000 {
        let (rid,): (uuid::Uuid,) = sqlx::query_as(&format!(
            "INSERT INTO data.{} (organization_id, \"{}\") VALUES ($1,$2) RETURNING id",
            slug.0, name_col.0
        ))
        .bind(env.org_a_id)
        .bind(format!("perf-{i}"))
        .fetch_one(&env.system_pool)
        .await
        .unwrap();
        sqlx::query(&format!(
            "INSERT INTO {table} (organization_id, record_id, \"{}\") VALUES ($1,$2,$3)",
            sf.physical_column
        ))
        .bind(env.org_a_id)
        .bind(rid)
        .bind(format!("nick-{i}"))
        .execute(&env.system_pool)
        .await
        .unwrap();
    }

    let intent = contact_intent(contact_id, "active");
    // Warmup.
    let _ = compiler.compile(ctx, &intent).await.unwrap();
    // Execute via a tenant tx (RLS on).
    let mut times = vec![];
    for _ in 0..21 {
        let t = Instant::now();
        let plan = compiler.compile(ctx, &intent).await.unwrap();
        let mut tx = env.tenant_pool.begin().await.unwrap();
        sqlx::query(&format!(
            "SET LOCAL app.organization_id = '{}'",
            env.org_a_id
        ))
        .execute(&mut *tx)
        .await
        .unwrap();
        let mut q = sqlx::query(&plan.sql);
        for p in &plan.params {
            q = tinker_live::bind_param(q, p);
        }
        let rows = q.fetch_all(&mut *tx).await.unwrap();
        assert_eq!(rows.len(), 1000, "full page of 1k seeded contacts");
        tx.commit().await.unwrap();
        times.push(t.elapsed().as_micros());
    }
    times.sort_unstable();
    let p50 = times[times.len() / 2];
    println!("m4 versioned query over 1k rows: p50={p50}us");
    assert!(
        p50 < 50_000,
        "versioned query p50 tripwire 50ms, got {p50}us"
    );
}

/// Version resolution itself is cheap: resolve() p50 over 21 runs.
#[tokio::test]
async fn resolve_tripwire() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let ctx = &env.builder_a.tenant;
    let v = evolver.create_draft(ctx, contact_id).await.unwrap();
    evolver
        .add_field(ctx, v.id, &text_field("nickname"))
        .await
        .unwrap();
    evolver.mark_canary(ctx, v.id, None).await.unwrap();
    evolver.promote(ctx, v.id).await.unwrap();

    let mut times = vec![];
    for _ in 0..21 {
        let t = Instant::now();
        let r = evolver
            .resolve(ctx, contact_id, VersionSel::Active)
            .await
            .unwrap();
        assert_eq!(r.ext_fields.len(), 1);
        times.push(t.elapsed().as_micros());
    }
    times.sort_unstable();
    let p50 = times[times.len() / 2];
    println!("m4 resolve p50={p50}us");
    assert!(p50 < 20_000, "resolve p50 tripwire 20ms, got {p50}us");
}
