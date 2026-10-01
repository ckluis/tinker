//! M4: one company adds a field and a relation, canaries the change,
//! promotes it, and rolls it back — without changing a sibling company.

mod common;

use common::*;
use tinker_core::TinkerError;
use tinker_evolve::{VersionRef, VersionSel};
use tinker_ontology::{PresetMode, PresetValue};
use tinker_query::QueryIntent;
use uuid::Uuid;

fn contact_query(
    contact_id: Uuid,
    select: &[&str],
    schema_version: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "from": contact_id,
        "select": select,
        "filters": [],
        "order": [],
        "limit": 10,
        "schema_version": schema_version,
    })
}

/// The M4 exit, end to end over HTTP: org A adds a field + relation,
/// canaries (cohort-gated), promotes, rolls back. Org B never changes.
#[tokio::test]
async fn full_lifecycle_via_http() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    // 1. Draft.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/objects/{contact_id}/drafts"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "create draft: {body}");
    let v1 = body["id"].as_str().unwrap().to_string();

    // 2. Add a text field and a relation on the draft.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/fields"),
        &serde_json::json!({
            "name": "Nickname", "api_name": "nickname", "label": "Nickname",
            "field_type": "text", "options": {}, "required": false,
        }),
    )
    .await;
    assert_eq!(status, 200, "add field: {body}");
    assert_eq!(body["api_name"], "nickname");
    let physical = body["physical_column"].as_str().unwrap().to_string();
    assert!(physical.starts_with("f_"), "stable physical column naming");

    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/relations"),
        &serde_json::json!({
            "name": "Referred by", "api_name": "referred_by", "label": "Referred by",
            "field_type": "relation", "options": {}, "required": false,
            "target_object_id": contact_id,
        }),
    )
    .await;
    assert_eq!(status, 200, "add relation: {body}");

    // Seed an ext row for Amy's contact: nickname + self-referral.
    let amy: (Uuid,) = sqlx::query_as("SELECT id FROM data.crm_contact WHERE organization_id=$1")
        .bind(env.org_a_id)
        .fetch_one(&env.system_pool)
        .await
        .unwrap();
    insert_ext_row(
        &env.system_pool,
        env.org_a_id,
        contact_id,
        amy.0,
        &physical,
        "Ames",
    )
    .await;

    // 3. Canary, cohort = builder only.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/canary"),
        &serde_json::json!({"cohort": [env.builder_a.actor_id]}),
    )
    .await;
    assert_eq!(status, 200, "mark canary: {body}");
    assert_eq!(body["status"], "canary");

    // Builder resolves the canary: nickname is there, relation traverses.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        "/api/query",
        &contact_query(
            contact_id,
            &["name", "nickname", "referred_by.name"],
            Some("canary"),
        ),
    )
    .await;
    assert_eq!(status, 200, "builder canary query: {body}");
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["nickname"], "Ames");

    // A non-cohort member asking for the canary fails closed.
    let (status, _) = post_json(
        &env.router,
        &env.member_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"], Some("canary")),
    )
    .await;
    assert_eq!(status, 403, "canary is cohort-gated");

    // Active schema is untouched by the canary: the new field is unknown.
    let (status, _) = post_json(
        &env.router,
        &env.member_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"], None),
    )
    .await;
    assert_eq!(status, 400, "active schema has no nickname yet");
    let (status, body) = post_json(
        &env.router,
        &env.member_a,
        "/api/query",
        &contact_query(contact_id, &["name"], None),
    )
    .await;
    assert_eq!(status, 200, "active query still works: {body}");
    assert_eq!(body["rows"].as_array().unwrap()[0]["name"], "Amy");

    // 4. Promote: one atomic flip; everyone sees the new schema.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/promote"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "promote: {body}");
    assert_eq!(body["status"], "active");

    let (status, body) = post_json(
        &env.router,
        &env.member_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"], None),
    )
    .await;
    assert_eq!(status, 200, "member sees promoted schema: {body}");
    assert_eq!(body["rows"].as_array().unwrap()[0]["nickname"], "Ames");

    // 5. Roll back: the pointer flips to the pack base (no parent version).
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/rollback"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "rollback: {body}");
    assert!(body["restored"].is_null(), "rolled back to the pack base");

    let (status, _) = post_json(
        &env.router,
        &env.member_a,
        "/api/query",
        &contact_query(contact_id, &["name", "nickname"], None),
    )
    .await;
    assert_eq!(status, 400, "nickname is gone after rollback");

    // 6. Sibling org B: no versions, no ext table, data intact.
    let (status, body) = get_json(
        &env.router,
        &env.builder_b,
        &format!("/api/schema/objects/{contact_id}/versions"),
    )
    .await;
    // builder_b has no schema:evolve grant -> 403; that's fine, check via
    // the evolver directly that B has zero versions.
    assert_eq!(status, 403, "org B builder has no evolve grant: {body}");
    let evolver = evolver_of(&env);
    let b_versions = evolver
        .list_versions(&env.builder_b.tenant, contact_id)
        .await
        .unwrap();
    assert!(b_versions.is_empty(), "org B never evolved");
    let ext_b = tinker_evolve::ext_table_name(env.org_b_id, contact_id);
    let exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='data' AND table_name=$1)",
    )
    .bind(ext_b.trim_start_matches("data."))
    .fetch_one(&env.system_pool)
    .await
    .unwrap();
    assert!(!exists.0, "no extension table was ever created for org B");
    // Org B's data still queries fine on the base schema.
    let (status, body) = post_json(
        &env.router,
        &env.builder_b,
        "/api/query",
        &contact_query(contact_id, &["name"], None),
    )
    .await;
    assert_eq!(status, 200, "org B queries unaffected: {body}");
    assert_eq!(body["rows"].as_array().unwrap()[0]["name"], "Brian");
}

/// Schema DDL without the grant is 403 — on every endpoint.
#[tokio::test]
async fn grant_gate_blocks_member() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let (status, _) = post_json(
        &env.router,
        &env.member_a,
        &format!("/api/schema/objects/{contact_id}/drafts"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 403, "member cannot create drafts");
    let (status, _) = post_json(
        &env.router,
        &env.member_a,
        &format!("/api/schema/versions/{}/promote", Uuid::now_v7()),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 403, "member cannot promote");
}

/// Versions are immutable once they leave draft; a newer version never
/// rewrites an older version's spec.
#[tokio::test]
async fn versions_are_immutable() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let ctx = &env.builder_a.tenant;

    let v1 = evolver.create_draft(ctx, contact_id).await.unwrap();
    evolver
        .add_field(ctx, v1.id, &text_field("nickname"))
        .await
        .unwrap();
    evolver.mark_canary(ctx, v1.id, None).await.unwrap();

    // Non-draft versions refuse new fields.
    let err = evolver
        .add_field(ctx, v1.id, &text_field("sneaky"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "canary is immutable: {err:?}"
    );

    evolver.promote(ctx, v1.id).await.unwrap();
    let err = evolver
        .add_field(ctx, v1.id, &text_field("sneaky2"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "active is immutable: {err:?}"
    );

    // v2 forks from v1; v1's spec is untouched.
    let v2 = evolver.create_draft(ctx, contact_id).await.unwrap();
    assert_eq!(v2.parent_version_id, Some(v1.id), "lineage is chained");
    evolver
        .add_field(ctx, v2.id, &text_field("v2_only"))
        .await
        .unwrap();
    let diff = evolver
        .diff(
            ctx,
            contact_id,
            VersionRef::Version(v1.id),
            VersionRef::Version(v2.id),
        )
        .await
        .unwrap();
    assert_eq!(
        diff.added,
        vec!["v2_only"],
        "v1 spec unchanged by v2: {diff:?}"
    );
    assert!(diff.removed.is_empty() && diff.changed.is_empty());
}

/// Cohort gating also holds at the compiler level (no HTTP involved).
#[tokio::test]
async fn cohort_enforced_at_compiler() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let compiler = compiler_of(&env);

    let v1 = evolver
        .create_draft(&env.builder_a.tenant, contact_id)
        .await
        .unwrap();
    evolver
        .add_field(&env.builder_a.tenant, v1.id, &text_field("nickname"))
        .await
        .unwrap();
    evolver
        .mark_canary(
            &env.builder_a.tenant,
            v1.id,
            Some(vec![env.builder_a.actor_id]),
        )
        .await
        .unwrap();

    let mut intent = QueryIntent {
        from: contact_id,
        select: vec!["name".into(), "nickname".into()],
        filters: vec![],
        order: vec![],
        limit: Some(10),
        schema_version: Some("canary".into()),
    };
    // Builder (in cohort) compiles fine.
    let plan = compiler
        .compile(&env.builder_a.tenant, &intent)
        .await
        .unwrap();
    assert!(
        plan.sql.contains("data.ext_"),
        "canary plan joins the extension table"
    );
    // Outsider fails closed.
    let err = compiler
        .compile(&env.member_a.tenant, &intent)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "non-cohort compile is forbidden: {err:?}"
    );
    // Unknown version names fail loudly, never silently active.
    intent.schema_version = Some("banana".into());
    let err = compiler
        .compile(&env.builder_a.tenant, &intent)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
}

/// Filters on relation fields (base and evolved) produce valid SQL: the
/// M4 join-ordering fix — joins are rendered before WHERE references them.
#[tokio::test]
async fn filter_on_relation_field_executes() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let compiler = compiler_of(&env);
    let ctx = &env.builder_a.tenant;

    let v1 = evolver.create_draft(ctx, contact_id).await.unwrap();
    evolver
        .add_relation(
            ctx,
            v1.id,
            &common::relation_field("referred_by", contact_id),
        )
        .await
        .unwrap();
    evolver.mark_canary(ctx, v1.id, None).await.unwrap();
    evolver.promote(ctx, v1.id).await.unwrap();

    let intent_value = serde_json::json!({
        "from": contact_id,
        "select": ["name"],
        "filters": [{"field": "referred_by.name", "op": "eq", "value": "Nobody"}],
        "order": [],
        "limit": 10,
        "schema_version": "active",
    });
    let intent: QueryIntent = serde_json::from_value(intent_value).unwrap();
    let plan = compiler.compile(ctx, &intent).await.unwrap();
    let join_pos = plan.sql.find("LEFT JOIN").expect("has a join");
    let where_pos = plan.sql.find("WHERE").expect("has a where");
    assert!(
        join_pos < where_pos,
        "joins render before WHERE: {}",
        plan.sql
    );
    // And the SQL actually runs (0 rows, no error).
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
    assert!(rows.is_empty(), "no contact is referred by Nobody");
    tx.commit().await.unwrap();
}

/// Pack diff between the base schema and a version, via HTTP.
#[tokio::test]
async fn diff_base_to_version() {
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
    let v1 = body["id"].as_str().unwrap();
    for (kind, payload) in [
        (
            "fields",
            serde_json::json!({
                "name": "Nickname", "api_name": "nickname", "label": "Nickname",
                "field_type": "text", "options": {}, "required": false,
            }),
        ),
        (
            "relations",
            serde_json::json!({
                "name": "Referred by", "api_name": "referred_by", "label": "Referred by",
                "field_type": "relation", "options": {}, "required": false,
                "target_object_id": contact_id,
            }),
        ),
    ] {
        let (status, _) = post_json(
            &env.router,
            &env.builder_a,
            &format!("/api/schema/versions/{v1}/{kind}"),
            &payload,
        )
        .await;
        assert_eq!(status, 200, "add {kind}");
    }
    let (status, body) = get_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/objects/{contact_id}/diff?from=base&to={v1}"),
    )
    .await;
    assert_eq!(status, 200, "diff: {body}");
    let mut added: Vec<String> = body["added"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    added.sort();
    assert_eq!(added, vec!["nickname", "referred_by"]);
    assert!(body["removed"].as_array().unwrap().is_empty());
}

/// Sibling orgs evolve independently: org B can run its own chain while
/// org A is mid-canary, and neither sees the other's versions.
#[tokio::test]
async fn sibling_evolution_is_independent() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);

    // Org A starts a canary.
    let va = evolver
        .create_draft(&env.builder_a.tenant, contact_id)
        .await
        .unwrap();
    evolver
        .add_field(&env.builder_a.tenant, va.id, &text_field("a_field"))
        .await
        .unwrap();
    evolver
        .mark_canary(&env.builder_a.tenant, va.id, None)
        .await
        .unwrap();

    // Org B cannot see A's versions (RLS + explicit org predicate).
    let b_list = evolver
        .list_versions(&env.builder_b.tenant, contact_id)
        .await
        .unwrap();
    assert!(b_list.is_empty());
    let missing = evolver.get_version(&env.builder_b.tenant, va.id).await;
    assert!(
        matches!(missing, Err(TinkerError::NotFound(_))),
        "B cannot fetch A's version: {missing:?}"
    );

    // Org B runs its own full chain concurrently.
    let ctx_b = &env.builder_b.tenant;
    let vb = evolver.create_draft(ctx_b, contact_id).await.unwrap();
    assert_eq!(vb.version_number, 1, "B's chain starts at 1");
    evolver
        .add_field(ctx_b, vb.id, &text_field("b_field"))
        .await
        .unwrap();
    evolver.mark_preview(ctx_b, vb.id).await.unwrap();
    evolver.promote(ctx_b, vb.id).await.unwrap();

    // A still resolves its canary; B resolves its active. Neither leaks.
    let ra = evolver
        .resolve(&env.builder_a.tenant, contact_id, VersionSel::Canary)
        .await
        .unwrap();
    assert_eq!(ra.version_id, Some(va.id));
    assert!(ra.ext_fields.iter().any(|f| f.api_name == "a_field"));
    assert!(!ra.ext_fields.iter().any(|f| f.api_name == "b_field"));
    let rb = evolver
        .resolve(&env.builder_b.tenant, contact_id, VersionSel::Active)
        .await
        .unwrap();
    assert_eq!(rb.version_id, Some(vb.id));
    assert!(rb.ext_fields.iter().any(|f| f.api_name == "b_field"));
    assert!(!rb.ext_fields.iter().any(|f| f.api_name == "a_field"));
}

/// M3 projections compose with M4 evolution: a role whose allowlist
/// predates the new field does not see it (fail-closed for new fields).
#[tokio::test]
async fn projections_apply_to_evolved_fields() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let evolver = evolver_of(&env);
    let compiler = compiler_of(&env);
    let ctx = &env.builder_a.tenant;

    let v1 = evolver.create_draft(ctx, contact_id).await.unwrap();
    evolver
        .add_field(ctx, v1.id, &text_field("nickname"))
        .await
        .unwrap();
    evolver.mark_canary(ctx, v1.id, None).await.unwrap();
    evolver.promote(ctx, v1.id).await.unwrap();

    // A projection written before the evolution: name only.
    let projection = tinker_query::FieldProjection::allowlist(
        [(contact_id, ["name".to_string()].into_iter().collect())]
            .into_iter()
            .collect(),
    );
    let intent_value = serde_json::json!({
        "from": contact_id,
        "select": ["name", "nickname"],
        "filters": [],
        "order": [],
        "limit": 10,
        "schema_version": "active",
    });
    let intent: QueryIntent = serde_json::from_value(intent_value).unwrap();
    let plan = compiler
        .compile_with_projection(ctx, &intent, &projection)
        .await
        .unwrap();
    assert_eq!(
        plan.output_fields,
        vec!["name", "__id"],
        "new field is hidden by the pre-existing allowlist"
    );
    assert!(
        !plan.sql.contains("data.ext_"),
        "hidden field is not even joined: {}",
        plan.sql
    );

    // Filtering on the hidden new field is forbidden (no oracle).
    let intent_value = serde_json::json!({
        "from": contact_id,
        "select": ["name"],
        "filters": [{"field": "nickname", "op": "eq", "value": "x"}],
        "order": [],
        "limit": 10,
        "schema_version": "active",
    });
    let intent: QueryIntent = serde_json::from_value(intent_value).unwrap();
    let err = compiler
        .compile_with_projection(ctx, &intent, &projection)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)));
}

/// Item 37 (C3): governance metadata — validation rules, write presets,
/// required — survives M4 evolution. The client-supplied rules travel
/// draft -> version spec -> resolved description, and the evolved field's
/// definition-time validation rejects incoherent rules just like base
/// fields do.
#[tokio::test]
async fn evolution_carries_validation_and_presets() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    // 1. Draft.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/objects/{contact_id}/drafts"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "create draft: {body}");
    let v1 = body["id"].as_str().unwrap().to_string();

    // 2. Add a field carrying governance metadata through the web input.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/fields"),
        &serde_json::json!({
            "name": "Loyalty tier", "api_name": "loyalty_tier", "label": "Loyalty tier",
            "field_type": "text", "options": {}, "required": true,
            "validation": {"min": 2.0, "max": 12.0},
            "preset": {"mode": "when_missing", "value": {"kind": "static", "value": "bronze"}},
        }),
    )
    .await;
    assert_eq!(status, 200, "add field with governance: {body}");

    // 2b. Incoherent rules are rejected at definition time, like base fields.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/fields"),
        &serde_json::json!({
            "name": "Bad", "api_name": "bad_rules", "label": "Bad",
            "field_type": "number", "options": {}, "required": false,
            "validation": {"pattern": "^[0-9]+$"},
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "regex on a number field must be rejected: {body}"
    );

    // 3. Canary, then promote.
    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/canary"),
        &serde_json::json!({"cohort": [env.builder_a.actor_id]}),
    )
    .await;
    assert_eq!(status, 200, "mark canary: {body}");

    let (status, body) = post_json(
        &env.router,
        &env.builder_a,
        &format!("/api/schema/versions/{v1}/promote"),
        &serde_json::json!({}),
    )
    .await;
    assert_eq!(status, 200, "promote: {body}");

    // 4. The resolved description carries the governance metadata.
    let evolver = evolver_of(&env);
    let resolved = evolver
        .resolve(&env.builder_a.tenant, contact_id, VersionSel::Active)
        .await
        .unwrap();
    let ont = ontology_of(&env);
    let desc = ont
        .describe_object_with_ext(&env.builder_a.tenant, contact_id, &resolved.ext_fields)
        .await
        .unwrap();
    let f = desc
        .fields
        .iter()
        .find(|f| f.api_name == "loyalty_tier")
        .expect("evolved field present");
    assert!(f.required, "required travels through evolution");
    assert_eq!(f.validation.min, Some(2.0));
    assert_eq!(f.validation.max, Some(12.0));
    let preset = f.preset.as_ref().expect("preset travels through evolution");
    assert!(
        matches!(preset.mode, PresetMode::WhenMissing),
        "preset mode preserved"
    );
    match &preset.value {
        PresetValue::Static { value } => assert_eq!(value, &serde_json::json!("bronze")),
        PresetValue::ActorId => panic!("preset value mismatch"),
    }
}
