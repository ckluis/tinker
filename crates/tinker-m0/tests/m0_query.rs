//! M0 query exits: the compiler injects the tenant predicate, unknown
//! fields fail closed, relations join only through declared relations, and
//! the emitted SQL actually executes.

mod common;

use tinker_core::{Param, TinkerError};
use tinker_db::OwnerDb;
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use tinker_query::{Filter, FilterOp, QueryCompiler, QueryIntent};
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

fn text_field(api_name: &str) -> FieldDef {
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

fn ontology(env: &common::Env) -> Ontology {
    Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
}

fn bind_params<'q>(
    sql: &'q str,
    params: &'q [Param],
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, (String, String), sqlx::postgres::PgArguments> {
    let mut q = sqlx::query_as::<_, (String, String)>(sql);
    for p in params {
        q = match p {
            Param::Text(s) => q.bind(s),
            Param::Int(n) => q.bind(n),
            Param::Float(f) => q.bind(f),
            Param::Bool(b) => q.bind(b),
            Param::Uuid(u) => q.bind(u),
            Param::Date(d) => q.bind(d),
            Param::Timestamp(t) => q.bind(t),
            Param::Json(j) => q.bind(j),
            Param::Null => q.bind(Option::<String>::None),
        };
    }
    q
}

#[tokio::test]
async fn compiler_injects_tenant_predicate_first() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);
    let qc = QueryCompiler::new(ont.clone());

    let slug = common::uniq("company");
    let meta = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, meta.id, &text_field("name"))
        .await
        .unwrap();

    let plan = qc
        .compile(
            &ctx,
            &QueryIntent {
                from: meta.id,
                select: vec!["name".into()],
                filters: vec![],
                order: vec![],
                limit: Some(10),
                schema_version: None,
            },
        )
        .await
        .unwrap();

    assert!(
        plan.sql.contains("t0.organization_id = $1"),
        "tenant predicate must be in the SQL: {}",
        plan.sql
    );
    assert!(
        matches!(&plan.params[0], Param::Uuid(u) if *u == ctx.organization_id.0),
        "first bind must be the caller's organization_id"
    );
}

#[tokio::test]
async fn unknown_field_fails_closed() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);
    let qc = QueryCompiler::new(ont.clone());

    let slug = common::uniq("company");
    let meta = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, meta.id, &text_field("name"))
        .await
        .unwrap();

    let err = qc
        .compile(
            &ctx,
            &QueryIntent {
                from: meta.id,
                select: vec!["nope".into()],
                filters: vec![],
                order: vec![],
                limit: None,
                schema_version: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));

    // Undeclared relation traversal in a filter also fails.
    let err = qc
        .compile(
            &ctx,
            &QueryIntent {
                from: meta.id,
                select: vec!["name".into()],
                filters: vec![Filter {
                    field: "company.name".into(),
                    op: FilterOp::Eq,
                    value: serde_json::json!("x"),
                }],
                order: vec![],
                limit: None,
                schema_version: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));

    // Querying another org's object id fails closed (RLS: not found).
    let ctx_b = common::new_org(&env, &common::uniq("orgb")).await;
    let err = qc
        .compile(
            &ctx_b,
            &QueryIntent {
                from: meta.id,
                select: vec!["name".into()],
                filters: vec![],
                order: vec![],
                limit: None,
                schema_version: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));
}

#[tokio::test]
async fn relation_join_compiles_and_executes() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);
    let qc = QueryCompiler::new(ont.clone());

    let cslug = common::uniq("company");
    let dslug = common::uniq("deal");
    let company = ont.define_object(&ctx, &object_def(&cslug)).await.unwrap();
    ont.add_field(&ctx, company.id, &text_field("name"))
        .await
        .unwrap();
    let deal = ont.define_object(&ctx, &object_def(&dslug)).await.unwrap();
    ont.add_field(&ctx, deal.id, &text_field("name"))
        .await
        .unwrap();
    ont.add_field(
        &ctx,
        deal.id,
        &FieldDef {
            max_pii_class: "restricted".to_string(),
            sensitive: false,
            validation: Default::default(),
            preset: None,
            name: "company".into(),
            api_name: "company".into(),
            label: "company".into(),
            field_type: FieldType::Relation {
                target_object_id: company.id,
            },
            options: serde_json::json!({}),
            required: false,
        },
    )
    .await
    .unwrap();

    // Resolve physical columns through the tenant's metadata view.
    let co_desc = ont.describe_object(&ctx, company.id).await.unwrap();
    let co_name = co_desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let deal_desc = ont.describe_object(&ctx, deal.id).await.unwrap();
    let deal_name = deal_desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let deal_co = deal_desc
        .fields
        .iter()
        .find(|f| f.api_name == "company")
        .unwrap()
        .physical_column
        .clone();

    // Seed: Acme/Globex companies, one deal each.
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let acme = Uuid::now_v7();
    let globex = Uuid::now_v7();
    for (id, name) in [(acme, "Acme"), (globex, "Globex")] {
        sqlx::query(&format!(
            "INSERT INTO data.\"{cslug}\" (organization_id, id, version, \"{co_name}\") VALUES ($1,$2,1,$3)"
        ))
        .bind(ctx.organization_id.0)
        .bind(id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    for (id, co, name) in [
        (Uuid::now_v7(), acme, "Acme deal"),
        (Uuid::now_v7(), globex, "Globex deal"),
    ] {
        sqlx::query(&format!(
            "INSERT INTO data.\"{dslug}\" (organization_id, id, version, \"{deal_name}\", \"{deal_co}\") \
             VALUES ($1,$2,1,$3,$4)"
        ))
        .bind(ctx.organization_id.0)
        .bind(id)
        .bind(name)
        .bind(co)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    let plan = qc
        .compile(
            &ctx,
            &QueryIntent {
                from: deal.id,
                select: vec!["name".into(), "company.name".into()],
                filters: vec![Filter {
                    field: "company.name".into(),
                    op: FilterOp::Eq,
                    value: serde_json::json!("Acme"),
                }],
                order: vec![],
                limit: Some(10),
                schema_version: None,
            },
        )
        .await
        .unwrap();

    assert!(plan.sql.contains("LEFT JOIN"), "SQL: {}", plan.sql);

    // The emitted SQL executes against the real database and returns the
    // authorized projection: only the Acme deal, with the company name.
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let rows: Vec<(String, String)> = bind_params(&plan.sql, &plan.params)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "Acme deal");
    assert_eq!(rows[0].1, "Acme");
    assert_eq!(plan.output_fields, vec!["name", "company.name", "__id"]);
}

#[tokio::test]
async fn like_wildcards_in_user_input_are_escaped() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);
    let qc = QueryCompiler::new(ont.clone());

    let slug = common::uniq("company");
    let meta = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, meta.id, &text_field("name"))
        .await
        .unwrap();

    let plan = qc
        .compile(
            &ctx,
            &QueryIntent {
                from: meta.id,
                select: vec!["name".into()],
                filters: vec![Filter {
                    field: "name".into(),
                    op: FilterOp::Contains,
                    value: serde_json::json!("100%_sure"),
                }],
                order: vec![],
                limit: None,
                schema_version: None,
            },
        )
        .await
        .unwrap();

    assert!(plan.sql.contains("ESCAPE"), "SQL: {}", plan.sql);
    match &plan.params[1] {
        Param::Text(p) => assert_eq!(p, "%100\\%\\_sure%"),
        other => panic!("expected text pattern, got {other:?}"),
    }
}
