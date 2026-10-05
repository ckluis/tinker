//! M4 hardening: concurrent lifecycle transitions, hostile inputs.

mod common;

use common::*;
use tinker_core::TinkerError;
use uuid::Uuid;

/// Concurrent draft creation serializes: every creator gets a distinct,
/// gapless version number (advisory lock), none dies on the unique index.
#[tokio::test]
async fn concurrent_drafts_serialize() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = std::sync::Arc::new(evolver_of(&env));

    let mut handles = vec![];
    for _ in 0..8 {
        let ev = evolver.clone();
        let ctx = env.builder_a.tenant.clone();
        handles.push(tokio::spawn(async move {
            ev.create_draft(&ctx, contact_id).await
        }));
    }
    let mut numbers = vec![];
    for h in handles {
        let v = h.await.unwrap().unwrap();
        numbers.push(v.version_number);
    }
    numbers.sort_unstable();
    assert_eq!(
        numbers,
        (1..=8).collect::<Vec<_>>(),
        "gapless serialized version numbers"
    );
}

/// Two promotable versions race: exactly one becomes active; the loser
/// gets a clean Validation error, never a raw 500, and double-active is
/// impossible. Deterministic: the rival's activation is held uncommitted
/// in a raw transaction, so promote()'s final UPDATE blocks on the
/// partial unique index and must lose the race when the rival commits.
/// (A barrier/spawn race was tried first — on a loaded VM the two
/// promotes can serialize, and sequential promotes legitimately
/// supersede, so the "exactly one wins" assertion was timing luck.)
#[tokio::test]
async fn concurrent_promote_single_winner() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = std::sync::Arc::new(evolver_of(&env));
    let ctx = env.builder_a.tenant.clone();

    // One canary + one preview: the only way two promotable versions can
    // coexist (the schema allows at most one of each per org/object).
    let v1 = evolver.create_draft(&ctx, contact_id).await.unwrap();
    evolver
        .add_field(&ctx, v1.id, &text_field("race_a"))
        .await
        .unwrap();
    evolver.mark_canary(&ctx, v1.id, None).await.unwrap();
    let v2 = evolver.create_draft(&ctx, contact_id).await.unwrap();
    evolver
        .add_field(&ctx, v2.id, &text_field("race_b"))
        .await
        .unwrap();
    evolver.mark_preview(&ctx, v2.id).await.unwrap();

    // Rival activation, held uncommitted: v2 becomes active in a raw
    // transaction we control (owner pool bypasses RLS; same org/object).
    let mut rival = env.system_pool.begin().await.unwrap();
    sqlx::query("UPDATE schema_versions SET status='active' WHERE id=$1")
        .bind(v2.id)
        .execute(&mut *rival)
        .await
        .unwrap();

    // promote(v1) now: its supersede sweep can't see the rival's
    // uncommitted row, and its final UPDATE must block on the partial
    // unique index until the rival commits — then lose with 23505.
    let ev = evolver.clone();
    let c = ctx.clone();
    let racer = tokio::spawn(async move { ev.promote(&c, v1.id).await });
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    rival.commit().await.unwrap();
    let outcome = racer.await.unwrap();
    let err = outcome.unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "loser gets a clean Validation error, got: {err:?}"
    );

    let versions = evolver.list_versions(&ctx, contact_id).await.unwrap();
    let active: Vec<_> = versions.iter().filter(|v| v.status == "active").collect();
    assert_eq!(active.len(), 1, "exactly one active version survives");
    assert_eq!(active[0].id, v2.id, "the committed rival is the survivor");
}

/// Promoting the same version twice: the second fails closed.
#[tokio::test]
async fn double_promote_fails_closed() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let ctx = &env.builder_a.tenant;
    let v = evolver.create_draft(ctx, contact_id).await.unwrap();
    evolver.mark_preview(ctx, v.id).await.unwrap();
    evolver.promote(ctx, v.id).await.unwrap();
    let err = evolver.promote(ctx, v.id).await.unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
}

/// Hostile version ids: random UUIDs and sibling-org versions surface as
/// NotFound — no existence oracle, no cross-org reads.
#[tokio::test]
async fn hostile_version_ids_fail_closed() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);

    // A's version is invisible to B.
    let va = evolver
        .create_draft(&env.builder_a.tenant, contact_id)
        .await
        .unwrap();
    for bad in [
        Uuid::now_v7(), // random: may or may not exist
        Uuid::nil(),    // degenerate
    ] {
        let r = evolver.get_version(&env.builder_b.tenant, bad).await;
        assert!(
            matches!(r, Err(TinkerError::NotFound(_))),
            "random id: {r:?}"
        );
    }
    let r = evolver.get_version(&env.builder_b.tenant, va.id).await;
    assert!(
        matches!(r, Err(TinkerError::NotFound(_))),
        "sibling version is NotFound, not Forbidden: {r:?}"
    );
    // B cannot mutate A's version through any transition.
    for op in ["preview", "canary", "promote", "rollback"] {
        let uri = format!("/api/schema/versions/{}/{}", va.id, op);
        let body = serde_json::json!({});
        let (status, _) = post_json(&env.router, &env.builder_b, &uri, &body).await;
        // builder_b has no schema:evolve grant at all -> 403 before it even
        // reaches the version lookup; either way it cannot touch A's chain.
        assert!(status == 403 || status == 404, "cross-org {op}: {status}");
    }
    // B cannot add a field to A's version through the HTTP fields
    // endpoint either (service-level NotFound is pinned by
    // sibling_add_field_is_rejected; this pins the route's ctx wiring).
    let (status, _) = post_json(
        &env.router,
        &env.builder_b,
        &format!("/api/schema/versions/{}/fields", va.id),
        &serde_json::json!({
            "name": "Hostile", "api_name": "hostile", "label": "Hostile",
            "field_type": "text", "options": {}, "required": false,
        }),
    )
    .await;
    assert!(status == 403 || status == 404, "cross-org fields: {status}");
}

/// A sibling org's actor cannot add fields to another org's draft
/// version. The version lookup's explicit organization predicate fails
/// closed with NotFound — no existence oracle — and no physical column
/// is materialized on the victim's extension table.
#[tokio::test]
async fn sibling_add_field_is_rejected() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);

    // A's draft version.
    let va = evolver
        .create_draft(&env.builder_a.tenant, contact_id)
        .await
        .unwrap();

    // Snapshot A's extension-table columns before the hostile attempt.
    let ext = tinker_evolve::ext_table_name(env.org_a_id, contact_id);
    let ext_bare = ext.strip_prefix("data.").unwrap();
    let cols_before: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema='data' AND table_name=$1 ORDER BY 1",
    )
    .bind(ext_bare)
    .fetch_all(&env.system_pool)
    .await
    .unwrap();

    // B's hostile add_field must fail closed with NotFound — never
    // Forbidden, which would confirm the version exists in another org.
    let err = evolver
        .add_field(&env.builder_b.tenant, va.id, &text_field("hostile"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_)),
        "sibling add_field must be NotFound, got {err:?}"
    );

    // Nothing materialized: A's extension table is column-identical,
    // and A can still evolve its own draft normally afterwards.
    let cols_after: Vec<String> = sqlx::query_scalar(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema='data' AND table_name=$1 ORDER BY 1",
    )
    .bind(ext_bare)
    .fetch_all(&env.system_pool)
    .await
    .unwrap();
    assert_eq!(
        cols_before, cols_after,
        "hostile add_field must not add columns"
    );

    let f = evolver
        .add_field(&env.builder_a.tenant, va.id, &text_field("nickname"))
        .await
        .unwrap();
    assert_eq!(f.api_name, "nickname");
}

/// A draft for a sibling org's object fails closed at describe time.
#[tokio::test]
async fn cross_org_object_draft_fails() {
    let env = setup().await;
    // There are no per-org objects in M4 (pack objects are platform), so
    // the hostile input here is a nonexistent object id: NotFound, and the
    // draft endpoint must not leak whether the id is valid.
    let evolver = evolver_of(&env);
    let err = evolver
        .create_draft(&env.builder_a.tenant, Uuid::now_v7())
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));
    let (status, _) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/objects/{}/drafts", Uuid::now_v7()),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 404, "unknown object -> 404, not 500");
}

/// Hostile field definitions: SQL injection in api_name, hostile types.
#[tokio::test]
async fn hostile_field_defs_rejected() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let ctx = &env.builder_a.tenant;
    let v = evolver.create_draft(ctx, contact_id).await.unwrap();

    for api_name in [
        "x\"; DROP TABLE data.crm_contact; --",
        "a'b",
        "../escape",
        "",
        "with space",
    ] {
        let err = evolver
            .add_field(ctx, v.id, &text_field(api_name))
            .await
            .unwrap_err();
        assert!(
            matches!(err, TinkerError::Validation(_)),
            "api_name {api_name:?} rejected: {err:?}"
        );
    }
    // Malformed field_type over HTTP.
    let (status, _) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{}/fields", v.id),
        &serde_json::json!({
            "name": "X", "api_name": "x", "label": "X",
            "field_type": "supertext", "options": {}, "required": false,
        }),
    )
    .await;
    assert_eq!(status, 400, "unknown field_type rejected");
}

/// Malformed canary cohorts over HTTP fail closed (400), never half-apply.
#[tokio::test]
async fn malformed_cohort_rejected() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/objects/{contact_id}/drafts"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200);
    let v = body["id"].as_str().unwrap();
    for cohort in [
        serde_json::json!({"cohort": ["not-a-uuid"]}),
        serde_json::json!({"cohort": "everyone"}),
        serde_json::json!({"cohort": [1, 2, 3]}),
    ] {
        let (status, _) = post_json(
            &env.router,
            &env.builder_a,
            &format!("/api/schema/versions/{v}/canary"),
            &cohort,
        )
        .await;
        // 400 (validation) or 422 (axum JSON rejection): both fail closed.
        assert!(
            status == 400 || status == 422,
            "cohort {cohort} rejected, got {status}"
        );
    }
    // The version is still a draft: the failed canary left no trace.
    let (status, body) = get_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/objects/{contact_id}/versions"),
    )
    .await;
    assert_eq!(status, 200);
    let versions = body.as_array().unwrap();
    assert_eq!(versions[0]["status"], "draft");
}

/// mark_canary validates the cohort against the org roster: unknown,
/// foreign-org, and empty cohorts fail fast instead of silently
/// producing a canary nobody can see.
#[tokio::test]
async fn mark_canary_validates_cohort_roster() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let ctx = &env.builder_a.tenant;

    // Unknown UUID.
    let v1 = evolver.create_draft(ctx, contact_id).await.unwrap();
    let err = evolver
        .mark_canary(ctx, v1.id, Some(vec![Uuid::now_v7()]))
        .await
        .expect_err("unknown cohort member must be rejected");
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "expected Validation, got {err:?}"
    );

    // Foreign-org actor: the roster check is org-scoped, so this is
    // "unknown" from org A's perspective. The error must not reveal
    // whether the UUID exists in another org.
    let err = evolver
        .mark_canary(ctx, v1.id, Some(vec![env.builder_b.actor_id]))
        .await
        .expect_err("foreign-org cohort member must be rejected");
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "expected Validation, got {err:?}"
    );
    assert!(
        !err.to_string().contains(&env.org_b_id.to_string()),
        "rejection must not leak foreign-org details: {err}"
    );

    // Empty cohort.
    let err = evolver
        .mark_canary(ctx, v1.id, Some(vec![]))
        .await
        .expect_err("empty cohort must be rejected");
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "expected Validation, got {err:?}"
    );

    // The rejections left the version untouched: still draft, and a
    // valid cohort transitions it to canary.
    let v = evolver
        .mark_canary(
            ctx,
            v1.id,
            Some(vec![env.builder_a.actor_id, env.member_a.actor_id]),
        )
        .await
        .unwrap();
    assert_eq!(v.status, "canary");
    assert_eq!(
        v.canary_cohort.as_ref().map(|c| c.len()),
        Some(2),
        "both org members must be stored"
    );
}

/// A duplicated cohort member is deduped, not rejected.
#[tokio::test]
async fn mark_canary_dedupes_cohort() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let ctx = &env.builder_a.tenant;
    let v1 = evolver.create_draft(ctx, contact_id).await.unwrap();
    let v = evolver
        .mark_canary(
            ctx,
            v1.id,
            Some(vec![env.builder_a.actor_id, env.builder_a.actor_id]),
        )
        .await
        .unwrap();
    assert_eq!(v.status, "canary");
    assert_eq!(
        v.canary_cohort.as_ref().map(|c| c.len()),
        Some(1),
        "duplicate cohort member must be stored once"
    );
}

/// Concurrent `add_field` on one draft serializes on the version row lock
/// (FOR UPDATE held across the owner-pool DDL): both fields land, the
/// spec holds both, no lost update, no raw 500. Deterministic: the
/// loser's row lock simply waits for the winner's commit.
#[tokio::test]
async fn concurrent_add_field_on_one_draft() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = std::sync::Arc::new(evolver_of(&env));
    let ctx = env.builder_a.tenant.clone();

    let draft = evolver.create_draft(&ctx, contact_id).await.unwrap();

    let ev1 = evolver.clone();
    let ctx1 = ctx.clone();
    let h1 =
        tokio::spawn(async move { ev1.add_field(&ctx1, draft.id, &text_field("rival_a")).await });
    let ev2 = evolver.clone();
    let ctx2 = ctx.clone();
    let h2 =
        tokio::spawn(async move { ev2.add_field(&ctx2, draft.id, &text_field("rival_b")).await });
    let (r1, r2) = tokio::join!(h1, h2);
    r1.unwrap().unwrap();
    r2.unwrap().unwrap();

    let spec: serde_json::Value =
        sqlx::query_scalar("SELECT spec FROM schema_versions WHERE id=$1")
            .bind(draft.id)
            .fetch_one(&env.system_pool)
            .await
            .unwrap();
    let names: Vec<&str> = spec["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["api_name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"rival_a") && names.contains(&"rival_b"),
        "both concurrent fields must land in the draft spec: {names:?}"
    );
}

/// Relation-only join demand: the query selects base fields and filters
/// on nothing, but ORDERS BY a relation traversal while FILTERING on a
/// second relation. Every join must be resolved from filter/order
/// pre-resolution (not select), aliases must not collide, and the
/// executed order must reflect the joined values. This is the case the
/// M4 join-ordering fix did not cover with a test.
#[tokio::test]
async fn relation_only_filter_and_order_joins_execute() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let compiler = compiler_of(&env);
    let ctx = &env.builder_a.tenant;

    // Two self-relations on contact. add_relation returns the SpecField,
    // which carries the physical ext-table column for each relation.
    let v1 = evolver.create_draft(ctx, contact_id).await.unwrap();
    let referred_by_field = evolver
        .add_relation(
            ctx,
            v1.id,
            &common::relation_field("referred_by", contact_id),
        )
        .await
        .unwrap();
    let manager_field = evolver
        .add_relation(ctx, v1.id, &common::relation_field("manager", contact_id))
        .await
        .unwrap();
    evolver.mark_canary(ctx, v1.id, None).await.unwrap();
    evolver.promote(ctx, v1.id).await.unwrap();
    let referred_col = referred_by_field.physical_column.clone();
    let manager_col = manager_field.physical_column.clone();

    // Physical column for the base name field.
    let slug: (String,) = sqlx::query_as("SELECT api_slug FROM ontology_objects WHERE id=$1")
        .bind(contact_id)
        .fetch_one(&env.system_pool)
        .await
        .unwrap();
    async fn physical_col(pool: &sqlx::PgPool, object_id: Uuid, api_name: &str) -> String {
        sqlx::query_scalar::<_, String>(
            "SELECT physical_column FROM ontology_fields WHERE object_id=$1 AND api_name=$2",
        )
        .bind(object_id)
        .bind(api_name)
        .fetch_one(pool)
        .await
        .unwrap()
    }
    let name_col = physical_col(&env.system_pool, contact_id, "name").await;
    let ext_table = tinker_evolve::ext_table_name(env.org_a_id, contact_id);

    // Alice <- Bob <- Carol chain; Dave managed by Bob, referred by Alice.
    async fn insert_contact(
        pool: &sqlx::PgPool,
        slug: &str,
        name_col: &str,
        org: Uuid,
        name: &str,
    ) -> Uuid {
        sqlx::query_scalar(&format!(
            "INSERT INTO data.{slug} (organization_id, \"{name_col}\") VALUES ($1,$2) RETURNING id"
        ))
        .bind(org)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
    }
    let alice = insert_contact(&env.system_pool, &slug.0, &name_col, env.org_a_id, "Alice").await;
    let bob = insert_contact(&env.system_pool, &slug.0, &name_col, env.org_a_id, "Bob").await;
    let carol = insert_contact(&env.system_pool, &slug.0, &name_col, env.org_a_id, "Carol").await;
    let dave = insert_contact(&env.system_pool, &slug.0, &name_col, env.org_a_id, "Dave").await;
    for (record, referred, manager) in [
        (bob, Some(alice), Some(alice)),
        (carol, Some(bob), Some(alice)),
        (dave, Some(alice), Some(bob)),
    ] {
        sqlx::query(&format!(
            "INSERT INTO {ext_table} (organization_id, record_id, \"{referred_col}\", \"{manager_col}\") \
             VALUES ($1,$2,$3,$4)"
        ))
        .bind(env.org_a_id)
        .bind(record)
        .bind(referred)
        .bind(manager)
        .execute(&env.system_pool)
        .await
        .unwrap();
    }

    // Filter on manager (relation 1), order by referred_by.name (relation 2),
    // select only base fields: all join demand is relation-only.
    let intent_value = serde_json::json!({
        "from": contact_id,
        "select": ["name"],
        "filters": [{"field": "manager.name", "op": "eq", "value": "Alice"}],
        "order": [{"field": "referred_by.name", "descending": false}],
        "limit": 10,
        "schema_version": "active",
    });
    let intent: tinker_query::QueryIntent = serde_json::from_value(intent_value).unwrap();
    let plan = compiler.compile(ctx, &intent).await.unwrap();
    assert_eq!(
        plan.sql.matches("LEFT JOIN").count(),
        3,
        "two relation joins + one ext join expected: {}",
        plan.sql
    );
    let join_pos = plan.sql.find("LEFT JOIN").expect("has joins");
    let where_pos = plan.sql.find("WHERE").expect("has a where");
    let order_pos = plan.sql.find("ORDER BY").expect("has order by");
    assert!(
        join_pos < where_pos && where_pos < order_pos,
        "joins render before WHERE before ORDER BY: {}",
        plan.sql
    );

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
    tx.commit().await.unwrap();
    let names: Vec<String> = rows
        .iter()
        .map(|r| {
            use sqlx::Row;
            // Select cols are raw expressions without aliases; the name
            // is the single selected column.
            r.try_get::<String, _>(0).unwrap()
        })
        .collect();
    // Managed by Alice: Bob (referred by Alice) and Carol (referred by Bob);
    // ordered by referrer name ascending: Bob before Carol.
    assert_eq!(names, vec!["Bob".to_string(), "Carol".to_string()]);
}
