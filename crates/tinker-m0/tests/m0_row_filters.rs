//! Item 38 (C2) exits: row-level permission filters.
//!
//! The contract under test:
//! - Filters are data (field, operator, value) per (org, object, role) —
//!   never raw SQL; they compile into the query alongside the tenant
//!   predicate ("policy before ranking").
//! - No rows for (org, object, role) = default-open.
//! - A filter matching nothing returns nothing — no "forbidden vs absent"
//!   distinction anywhere (queries, direct reads, search).
//! - Values are tenant constants or `actor.*` references; everything is
//!   parameter-bound, so injection-shaped values stay inert.
//! - Search applies the policy in the SAME statement as matching and
//!   ranking: hidden rows never influence rank, snippets, or counts.

mod common;

use std::collections::HashSet;

use tinker_agents::audit::AuditWriter;
use tinker_agents::gateway::ModelGateway;
use tinker_agents::transforms::TransformEngine;
use tinker_core::{OrganizationId, Param, TenantContext, TinkerError};
use tinker_db::OwnerDb;
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use tinker_query::{
    bind_param_as, FieldProjection, QueryCompiler, QueryIntent, RowFilterDef, RowFilters,
};
use tinker_search::{IndexChange, NativeSearchBackend, SearchBackend, SearchPlan};
use uuid::Uuid;

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

fn field(api_name: &str, field_type: FieldType) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        validation: Default::default(),
        preset: None,
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type,
        options: serde_json::json!({}),
        required: false,
    }
}

/// One org with a `deal` object: name/region/owner/amount plus a `person`
/// target for the relation. Returns the contexts (each with a membership
/// row for its role), the deal object id, and the seeded record ids.
struct World {
    deal: Uuid,
    deal_b: Uuid,
    deal_slug: String,
    ctx_owner: TenantContext,
    ctx_sales: TenantContext,
    ctx_viewer: TenantContext,
    ctx_b_sales: TenantContext,
    d1: Uuid,
    d2: Uuid,
    d3: Uuid,
    _d4: Uuid,
    _b1: Uuid,
}

async fn member(env: &common::Env, org_id: Uuid, role: &str) -> TenantContext {
    let actor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
    )
    .bind(actor_id)
    .bind(org_id)
    .bind(format!("{role}-{actor_id}"))
    .execute(&env.core_owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,$3)")
        .bind(actor_id)
        .bind(org_id)
        .bind(role)
        .execute(&env.core_owner)
        .await
        .unwrap();
    TenantContext::new(OrganizationId(org_id), actor_id, "m0-rowfilter-test")
}

async fn setup_world(env: &common::Env) -> World {
    let ctx_a = common::new_org(env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(env, &common::uniq("orgb")).await;
    let org_a = ctx_a.organization_id.0;
    let org_b = ctx_b.organization_id.0;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));

    let deal_slug = common::uniq("deal");
    let person_slug = common::uniq("person");
    let person = ont
        .define_object(&ctx_a, &object_def(&person_slug))
        .await
        .unwrap();
    ont.add_field(&ctx_a, person.id, &field("name", FieldType::Text))
        .await
        .unwrap();
    let deal = ont
        .define_object(&ctx_a, &object_def(&deal_slug))
        .await
        .unwrap();
    ont.add_field(&ctx_a, deal.id, &field("name", FieldType::Text))
        .await
        .unwrap();
    ont.add_field(&ctx_a, deal.id, &field("region", FieldType::Text))
        .await
        .unwrap();
    ont.add_field(
        &ctx_a,
        deal.id,
        &field(
            "owner",
            FieldType::Relation {
                target_object_id: person.id,
            },
        ),
    )
    .await
    .unwrap();
    ont.add_field(&ctx_a, deal.id, &field("amount", FieldType::Number))
        .await
        .unwrap();

    let desc = ont.describe_object(&ctx_a, deal.id).await.unwrap();
    let col = |api: &str| {
        desc.fields
            .iter()
            .find(|f| f.api_name == api)
            .unwrap()
            .physical_column
            .clone()
    };
    let (c_name, c_region, c_owner, c_amount) =
        (col("name"), col("region"), col("owner"), col("amount"));

    // Same object shape in org B (separate ontology rows, separate table).
    let deal_b = ont
        .define_object(&ctx_b, &object_def(&common::uniq("deal")))
        .await
        .unwrap();
    for (api, ft) in [
        ("name", FieldType::Text),
        ("region", FieldType::Text),
        ("amount", FieldType::Number),
    ] {
        ont.add_field(&ctx_b, deal_b.id, &field(api, ft))
            .await
            .unwrap();
    }
    let desc_b = ont.describe_object(&ctx_b, deal_b.id).await.unwrap();
    let col_b = |api: &str| {
        desc_b
            .fields
            .iter()
            .find(|f| f.api_name == api)
            .unwrap()
            .physical_column
            .clone()
    };

    let ctx_owner = member(env, org_a, "owner").await;
    let ctx_sales = member(env, org_a, "sales").await;
    let ctx_viewer = member(env, org_a, "viewer").await;
    let ctx_b_sales = member(env, org_b, "sales").await;

    // Person rows keyed by actor id: the relation FK is real, and
    // `owner = actor.id` is then both FK-valid and meaningful.
    let person_name_col = ont
        .describe_object(&ctx_a, person.id)
        .await
        .unwrap()
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let mut tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    for (pid, pname) in [(ctx_owner.actor_id, "Owner"), (ctx_sales.actor_id, "Sales")] {
        sqlx::query(&format!(
            "INSERT INTO data.\"{person_slug}\" (organization_id, id, version, \"{person_name_col}\") VALUES ($1,$2,1,$3)"
        ))
        .bind(org_a)
        .bind(pid)
        .bind(pname)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    // Seed org A: (name, region, owner, amount).
    let d1 = Uuid::now_v7();
    let d2 = Uuid::now_v7();
    let d3 = Uuid::now_v7();
    let d4 = Uuid::now_v7();
    let b1 = Uuid::now_v7();
    let mut tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    for (id, name, region, owner, amount) in [
        (d1, "Alpha", Some("emea"), Some(ctx_owner.actor_id), 100i64),
        (d2, "Beta", Some("amer"), Some(ctx_sales.actor_id), 200i64),
        (d3, "Gamma", Some("emea"), Some(ctx_sales.actor_id), 300i64),
        (d4, "Delta", None, None, 400i64),
    ] {
        sqlx::query(&format!(
            "INSERT INTO data.\"{deal_slug}\" (organization_id, id, version, \"{c_name}\", \"{c_region}\", \"{c_owner}\", \"{c_amount}\") VALUES ($1,$2,1,$3,$4,$5,$6)"
        ))
        .bind(org_a)
        .bind(id)
        .bind(name)
        .bind(region)
        .bind(owner)
        .bind(amount)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    // Seed org B: same region value as org A's restricted set — the
    // tenant predicate, not the policy, keeps it out of org A's reads.
    let mut tx = env.core.tenant_tx(&ctx_b).await.unwrap();
    let (bn, br, ba) = (col_b("name"), col_b("region"), col_b("amount"));
    sqlx::query(&format!(
        "INSERT INTO data.\"{}\" (organization_id, id, version, \"{bn}\", \"{br}\", \"{ba}\") VALUES ($1,$2,1,'Epsilon','emea',500)",
        desc_b.api_slug
    ))
    .bind(org_b)
    .bind(b1)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    World {
        deal: deal.id,
        deal_b: deal_b.id,
        deal_slug,
        ctx_owner,
        ctx_sales,
        ctx_viewer,
        ctx_b_sales,
        d1,
        d2,
        d3,
        _d4: d4,
        _b1: b1,
    }
}

fn def(field: &str, op: &str, value: serde_json::Value) -> RowFilterDef {
    RowFilterDef {
        field: field.into(),
        op: op.into(),
        value: Some(value),
    }
}

/// Compile a name-select query under a role's policy and return the
/// returned record names. Executes the real SQL: the policy is part of
/// the statement, not a post-filter. Returns the compile error for
/// adversarial cases (e.g. a tenant compiling against a foreign object).
async fn try_query_names(
    env: &common::Env,
    ctx: &TenantContext,
    deal_id: Uuid,
    role: &str,
) -> Result<Vec<String>, TinkerError> {
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let qc = QueryCompiler::new(ont.clone());
    let rf = RowFilters::new(env.core.clone());
    let policy = rf.load_policy(ctx, deal_id, role).await?;
    let plan = qc
        .compile_with_policy(
            ctx,
            &QueryIntent {
                from: deal_id,
                select: vec!["name".into()],
                filters: vec![],
                order: vec![],
                limit: Some(100),
                schema_version: None,
            },
            &FieldProjection::unrestricted(),
            &policy,
        )
        .await?;
    // Policy first: the tenant predicate is $1 and policy predicates
    // follow, before any caller filter.
    assert!(
        plan.sql.contains("t0.organization_id = $1"),
        "tenant predicate must stay first: {}",
        plan.sql
    );
    assert!(
        matches!(&plan.params[0], Param::Uuid(u) if *u == ctx.organization_id.0),
        "first bind must be the caller's organization_id"
    );
    let mut tx = env.core.tenant_tx(ctx).await.unwrap();
    let mut q = sqlx::query_as::<_, (String,)>(&plan.sql);
    for p in &plan.params {
        q = bind_param_as(q, p);
    }
    let rows: Vec<(String,)> = q.fetch_all(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let mut names: Vec<String> = rows.into_iter().map(|(n,)| n).collect();
    names.sort();
    Ok(names)
}

async fn query_names(
    env: &common::Env,
    ctx: &TenantContext,
    world: &World,
    role: &str,
) -> Vec<String> {
    try_query_names(env, ctx, world.deal, role).await.unwrap()
}

#[tokio::test]
async fn exact_role_filtered_results() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let rf = RowFilters::new(env.core.clone());

    rf.set_filters(
        &w.ctx_sales,
        &Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
            .describe_object(&w.ctx_sales, w.deal)
            .await
            .unwrap(),
        "sales",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();

    // Exact set: the two emea rows, nothing else.
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "sales").await,
        ["Alpha", "Gamma"]
    );
    // A role with no filter rows is default-open: all four org-A rows.
    assert_eq!(
        query_names(&env, &w.ctx_viewer, &w, "viewer").await,
        ["Alpha", "Beta", "Delta", "Gamma"]
    );
}

#[tokio::test]
async fn tenant_isolation_still_applies() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();
    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "sales",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();

    // Org B querying org A's object id fails closed at compile time —
    // the object is invisible to the foreign tenant (no oracle: the
    // error is the same NotFound the compiler gives for any unknown
    // object).
    let err = try_query_names(&env, &w.ctx_b_sales, w.deal, "sales")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_) | TinkerError::Forbidden(_)),
        "foreign object must fail closed, got {err:?}"
    );
    // Org B's own object: its own emea row, and only its own row.
    assert_eq!(
        try_query_names(&env, &w.ctx_b_sales, w.deal_b, "sales")
            .await
            .unwrap(),
        ["Epsilon"]
    );
    // Org A's restricted read never sees org B's emea row.
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "sales").await,
        ["Alpha", "Gamma"]
    );
}

#[tokio::test]
async fn actor_reference_resolves_per_caller() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_owner, w.deal).await.unwrap();

    // owner = actor.id: the classic per-caller row ownership filter.
    rf.set_filters(
        &w.ctx_owner,
        &desc,
        "owneronly",
        &[def("owner", "eq", serde_json::json!({"actor": "id"}))],
    )
    .await
    .unwrap();

    // Same role, same org, different actors → different rows. The actor
    // id is a bind, resolved from the trusted context at compile time.
    assert_eq!(
        query_names(&env, &w.ctx_owner, &w, "owneronly").await,
        ["Alpha"]
    );
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "owneronly").await,
        ["Beta", "Gamma"]
    );
}

#[tokio::test]
async fn injection_shaped_values_stay_inert() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();

    // A tautology-shaped constant is a literal string compare — it matches
    // nothing and breaks no SQL.
    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "sales",
        &[def("region", "eq", serde_json::json!("emea' OR '1'='1"))],
    )
    .await
    .unwrap();
    assert!(query_names(&env, &w.ctx_sales, &w, "sales")
        .await
        .is_empty());

    // Operator injection is rejected at the write boundary.
    for bad_op in ["eq\" OR 1=1 --", "eq; DROP TABLE row_filters; --", "like"] {
        let err = rf
            .set_filters(
                &w.ctx_sales,
                &desc,
                "sales",
                &[def("region", bad_op, serde_json::json!("emea"))],
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, TinkerError::Validation(_)),
            "bad operator must be Validation, got {err:?}"
        );
    }
    // Malformed actor references fail closed — never silently a constant.
    for bad_val in [
        serde_json::json!({"actor": "root"}),
        serde_json::json!({"actor": "id", "extra": 1}),
        serde_json::json!({"actor": ["id"]}),
    ] {
        let err = rf
            .set_filters(&w.ctx_sales, &desc, "sales", &[def("owner", "eq", bad_val)])
            .await
            .unwrap_err();
        assert!(
            matches!(err, TinkerError::Validation(_)),
            "bad actor ref must be Validation, got {err:?}"
        );
    }
    // Hostile field names are unknown fields, rejected — and the table
    // the injection targeted still answers afterwards.
    let err = rf
        .set_filters(
            &w.ctx_sales,
            &desc,
            "sales",
            &[def(
                "region\"; DROP TABLE row_filters; --",
                "eq",
                serde_json::json!("emea"),
            )],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
    let policy = rf.load_policy(&w.ctx_sales, w.deal, "sales").await.unwrap();
    assert_eq!(
        policy.filters.len(),
        1,
        "row_filters table survived; prior policy intact"
    );
}

#[tokio::test]
async fn ranking_only_reorders_the_authorized_set() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();
    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "sales",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();

    let backend = NativeSearchBackend::new(env.core.clone());
    // d2 repeats the query term, so it ranks FIRST without a policy —
    // the adversarial case: the globally-best match is unauthorized.
    for (id, text) in [
        (w.d1, "alpha deal one"),
        (w.d2, "alpha alpha alpha deal two"),
        (w.d3, "alpha deal three"),
    ] {
        backend
            .index_change(
                &w.ctx_sales,
                &IndexChange {
                    object_id: w.deal,
                    record_id: id,
                    text: text.into(),
                    field_versions: serde_json::json!({}),
                    storage_classes: vec!["text".into()],
                },
            )
            .await
            .unwrap();
    }

    // No policy: the unauthorized row wins the top rank.
    let open = backend
        .search(
            &w.ctx_viewer,
            &SearchPlan {
                text_query: "alpha deal".into(),
                object_id: Some(w.deal),
                limit: 1,
                row_policies: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(open.hits.len(), 1);
    assert_eq!(
        open.hits[0].record_id, w.d2,
        "unrestricted top rank is the amer row"
    );

    // With the policy compiled into the match/rank statement: the top hit
    // is authorized, and the hidden row appears NOWHERE — not demoted,
    // not in snippets, not in counts.
    let policy = rf.load_policy(&w.ctx_sales, w.deal, "sales").await.unwrap();
    let compiled = policy
        .compile_for_search(&w.ctx_sales, &desc)
        .unwrap()
        .unwrap();
    let limited = backend
        .search(
            &w.ctx_sales,
            &SearchPlan {
                text_query: "alpha deal".into(),
                object_id: Some(w.deal),
                limit: 1,
                row_policies: vec![compiled.clone()],
            },
        )
        .await
        .unwrap();
    assert_eq!(limited.hits.len(), 1);
    assert!(
        limited.hits[0].record_id == w.d1 || limited.hits[0].record_id == w.d3,
        "top rank under policy must be authorized, got {}",
        limited.hits[0].record_id
    );
    let all = backend
        .search(
            &w.ctx_sales,
            &SearchPlan {
                text_query: "alpha deal".into(),
                object_id: Some(w.deal),
                limit: 10,
                row_policies: vec![compiled],
            },
        )
        .await
        .unwrap();
    let ids: HashSet<Uuid> = all.hits.iter().map(|h| h.record_id).collect();
    assert_eq!(
        ids,
        HashSet::from([w.d1, w.d3]),
        "hidden row must not appear at any rank"
    );
}

#[tokio::test]
async fn in_range_and_null_operators() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();

    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "r_in",
        &[def("region", "in", serde_json::json!(["emea", "amer"]))],
    )
    .await
    .unwrap();
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "r_in").await,
        ["Alpha", "Beta", "Gamma"]
    );

    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "r_gte",
        &[def("amount", "gte", serde_json::json!(300))],
    )
    .await
    .unwrap();
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "r_gte").await,
        ["Delta", "Gamma"]
    );

    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "r_lt",
        &[def("amount", "lt", serde_json::json!(200))],
    )
    .await
    .unwrap();
    assert_eq!(query_names(&env, &w.ctx_sales, &w, "r_lt").await, ["Alpha"]);

    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "r_null",
        &[def("region", "is_null", serde_json::Value::Null)],
    )
    .await
    .unwrap();
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "r_null").await,
        ["Delta"]
    );

    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "r_neq",
        // "neq" is the BACKLOG.md spelling; "ne" is also accepted.
        &[def("region", "neq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();
    assert_eq!(query_names(&env, &w.ctx_sales, &w, "r_neq").await, ["Beta"]);
    // (SQL three-valued logic: Delta's NULL region does not satisfy <>.)

    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "r_notnull",
        &[def("region", "is_not_null", serde_json::Value::Null)],
    )
    .await
    .unwrap();
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "r_notnull").await,
        ["Alpha", "Beta", "Gamma"]
    );
}

#[tokio::test]
async fn set_filters_replaces_atomically_and_validates() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();

    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "sales",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();
    // Replacement, not accumulation.
    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "sales",
        &[def("region", "eq", serde_json::json!("amer"))],
    )
    .await
    .unwrap();
    let policy = rf.load_policy(&w.ctx_sales, w.deal, "sales").await.unwrap();
    assert_eq!(policy.filters.len(), 1);
    assert_eq!(query_names(&env, &w.ctx_sales, &w, "sales").await, ["Beta"]);

    // A failed write leaves the previous policy intact — never
    // half-applied, never silently opened.
    let err = rf
        .set_filters(
            &w.ctx_sales,
            &desc,
            "sales",
            &[
                def("region", "eq", serde_json::json!("amer")),
                def("nope", "eq", serde_json::json!("x")),
            ],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
    assert_eq!(query_names(&env, &w.ctx_sales, &w, "sales").await, ["Beta"]);

    // Empty defs return the role to default-open.
    rf.set_filters(&w.ctx_sales, &desc, "sales", &[])
        .await
        .unwrap();
    let policy = rf.load_policy(&w.ctx_sales, w.deal, "sales").await.unwrap();
    assert!(policy.is_open());
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "sales").await,
        ["Alpha", "Beta", "Delta", "Gamma"]
    );
}

#[tokio::test]
async fn cross_tenant_writes_cannot_touch_another_orgs_policy() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc_a = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();

    // Org A locks sales down to emea.
    rf.set_filters(
        &w.ctx_sales,
        &desc_a,
        "sales",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();

    // Org B's actor tries to overwrite the policy for org A's OBJECT id.
    // RLS scopes the write to org B, so org A's policy is untouched.
    rf.set_filters(
        &w.ctx_b_sales,
        &desc_a,
        "sales",
        &[def("region", "eq", serde_json::json!("amer"))],
    )
    .await
    .unwrap();
    let policy_a = rf.load_policy(&w.ctx_sales, w.deal, "sales").await.unwrap();
    assert_eq!(policy_a.filters.len(), 1);
    assert_eq!(
        query_names(&env, &w.ctx_sales, &w, "sales").await,
        ["Alpha", "Gamma"]
    );

    // And org B's actor cannot even compile against org A's object id.
    assert!(try_query_names(&env, &w.ctx_b_sales, w.deal, "sales")
        .await
        .is_err());
}

#[tokio::test]
async fn search_fragment_is_parameterized() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();
    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "sales",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();

    let policy = rf.load_policy(&w.ctx_sales, w.deal, "sales").await.unwrap();
    let compiled = policy
        .compile_for_search(&w.ctx_sales, &desc)
        .unwrap()
        .unwrap();
    // The literal value is a bind, not interpolated text.
    assert!(
        !compiled.sql.contains("emea"),
        "filter value must be bound, not interpolated: {}",
        compiled.sql
    );
    assert!(compiled.sql.contains("{{p1}}") && compiled.sql.contains("{{p2}}"));
    assert!(matches!(&compiled.params[0], Param::Uuid(u) if *u == w.deal));
    assert!(matches!(&compiled.params[1], Param::Text(s) if s == "emea"));
    let subbed = compiled.substitute(5);
    assert!(subbed.contains("$5") && subbed.contains("$6"), "{subbed}");
    assert!(!subbed.contains("{{p"), "all markers substituted: {subbed}");

    // Open policy compiles to just the C1 lifecycle guard (item 40):
    // archived rows must not surface in search even with no row
    // filters. The backends always splice the fragment.
    let open = rf
        .load_policy(&w.ctx_viewer, w.deal, "viewer")
        .await
        .unwrap();
    assert!(open.is_open());
    let open_compiled = open
        .compile_for_search(&w.ctx_viewer, &desc)
        .unwrap()
        .unwrap();
    assert!(
        open_compiled.sql.contains("\"lifecycle_state\""),
        "open policy fragment must carry the lifecycle guard: {}",
        open_compiled.sql
    );
    assert!(matches!(
        &open_compiled.params[1],
        Param::Text(s) if s == "published"
    ));
}

#[tokio::test]
async fn render_record_returns_not_found_for_hidden_rows() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_sales, w.deal).await.unwrap();
    rf.set_filters(
        &w.ctx_sales,
        &desc,
        "sales",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();

    let owner_db = OwnerDb(env.core_owner.clone());
    let engine = TransformEngine::new(
        env.core.clone(),
        owner_db.clone(),
        ont.clone(),
        ModelGateway::new(env.core.clone(), owner_db.clone()),
        AuditWriter::new(env.core.clone(), owner_db),
    );

    // Hidden row: NotFound — identical to a genuinely absent row, so no
    // existence oracle.
    let err = engine
        .render_record(&w.ctx_sales, &w.deal_slug, w.d2, None, "/")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_)),
        "hidden row must be NotFound, got {err:?}"
    );
    let err_absent = engine
        .render_record(&w.ctx_sales, &w.deal_slug, Uuid::now_v7(), None, "/")
        .await
        .unwrap_err();
    assert!(
        matches!(err_absent, TinkerError::NotFound(_)),
        "absent row must also be NotFound, got {err_absent:?}"
    );
    // Authorized row renders.
    let (fields, _) = engine
        .render_record(&w.ctx_sales, &w.deal_slug, w.d1, None, "/")
        .await
        .unwrap();
    assert!(
        fields.iter().any(|(k, v)| k == "name" && v == "Alpha"),
        "authorized row renders: {fields:?}"
    );
    // Cross-tenant: org B cannot render org A's rows either.
    let err_x = engine
        .render_record(&w.ctx_b_sales, &w.deal_slug, w.d1, None, "/")
        .await
        .unwrap_err();
    assert!(
        matches!(err_x, TinkerError::NotFound(_)),
        "cross-tenant must be NotFound, got {err_x:?}"
    );
}
