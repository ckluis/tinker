//! M0 headline exit: define an object through the schema builder and prove
//! a REAL table with REAL typed columns exists. Plus multi-tenant row
//! isolation, rename semantics, and name validation.

mod common;

use std::collections::HashMap;
use tinker_core::TinkerError;
use tinker_db::OwnerDb;
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use uuid::Uuid;

fn object_def(slug: &str, label: &str) -> ObjectDef {
    ObjectDef {
        name: label.into(),
        api_slug: slug.into(),
        label: label.into(),
        scope: Scope::Organization,
        pack_id: None,
        pack_version: None,
    }
}

fn field(name: &str, api_name: &str, ft: FieldType) -> FieldDef {
    let options = match &ft {
        FieldType::Select => serde_json::json!({"options": ["seed", "series_a"]}),
        _ => serde_json::json!({}),
    };
    FieldDef {
        max_pii_class: "restricted".to_string(),
        validation: Default::default(),
        preset: None,
        name: name.into(),
        api_name: api_name.into(),
        label: name.into(),
        field_type: ft,
        options,
        required: false,
    }
}

fn ontology(env: &common::Env) -> Ontology {
    Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
}

#[tokio::test]
async fn define_object_creates_real_table_with_typed_columns() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);

    let slug = common::uniq("company");
    let meta = ont
        .define_object(&ctx, &object_def(&slug, "Company"))
        .await
        .unwrap();
    assert_eq!(meta.api_slug, slug);
    assert_eq!(meta.table, format!("data.{slug}"));

    // Add one field of each representative type.
    let fields = vec![
        ("Name", "name", FieldType::Text, "text"),
        ("Revenue", "revenue", FieldType::Currency, "numeric"),
        ("Founded", "founded", FieldType::Date, "date"),
        ("Active", "active", FieldType::Boolean, "boolean"),
        ("Stage", "stage", FieldType::Select, "text"),
        ("Website", "website", FieldType::Url, "text"),
        ("Notes", "notes", FieldType::RichText, "jsonb"),
        ("Headcount", "headcount", FieldType::Number, "numeric"),
    ];
    for (name, api, ft, _pg) in &fields {
        ont.add_field(&ctx, meta.id, &field(name, api, ft.clone()))
            .await
            .unwrap();
    }

    // Proof, straight from the catalog: map api_name -> physical column via
    // the tenant's own metadata view, then check real Postgres types.
    let desc = ont.describe_object(&ctx, meta.id).await.unwrap();
    let phys: HashMap<&str, &str> = desc
        .fields
        .iter()
        .map(|f| (f.api_name.as_str(), f.physical_column.as_str()))
        .collect();
    let cols = ont.physical_columns(&meta.table).await.unwrap();
    let types: HashMap<&str, &str> = cols
        .iter()
        .map(|(n, t, _)| (n.as_str(), t.as_str()))
        .collect();

    // Base columns are real.
    assert_eq!(types.get("organization_id"), Some(&"uuid"));
    assert_eq!(types.get("id"), Some(&"uuid"));
    assert_eq!(types.get("version"), Some(&"bigint"));

    // Every field is a real typed column (physical names are stable random
    // ids, never derived from display names — so resolve via metadata).
    for (_name, api, _ft, pg) in &fields {
        let col = phys
            .get(api)
            .unwrap_or_else(|| panic!("no metadata for {api}"));
        assert_eq!(
            types.get(col),
            Some(pg),
            "field {api} should be {pg}, table columns: {types:?}"
        );
    }

    // RLS is enabled on the generated table.
    let rls: bool = sqlx::query_scalar(
        "SELECT relrowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
         WHERE n.nspname='data' AND c.relname=$1",
    )
    .bind(&slug)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert!(rls, "generated table must have RLS enabled");

    // The select field got a real CHECK constraint (Postgres owns it).
    let chk: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid \
         JOIN pg_namespace n ON n.oid=t.relnamespace \
         WHERE n.nspname='data' AND t.relname=$1 AND c.contype='c'",
    )
    .bind(&slug)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert!(chk >= 1, "select field must have a CHECK constraint");
}

#[tokio::test]
async fn cross_tenant_rows_are_invisible() {
    let env = common::setup().await;
    let ctx_a = common::new_org(&env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(&env, &common::uniq("orgb")).await;
    let ont = ontology(&env);

    // The object namespace is portfolio-shared in M0: the second org cannot
    // redefine the same slug — it fails closed instead of forking the table.
    let slug = common::uniq("company");
    let meta_a = ont
        .define_object(&ctx_a, &object_def(&slug, "Company"))
        .await
        .unwrap();
    let dup = ont
        .define_object(&ctx_b, &object_def(&slug, "Company"))
        .await;
    assert!(dup.is_err(), "duplicate slug must fail closed");

    ont.add_field(&ctx_a, meta_a.id, &field("Name", "name", FieldType::Text))
        .await
        .unwrap();
    let desc = ont.describe_object(&ctx_a, meta_a.id).await.unwrap();
    let name_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();

    // Org A inserts a row through its tenant context.
    let row_id = Uuid::now_v7();
    let mut tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO data.\"{slug}\" (organization_id, id, version, \"{name_col}\") VALUES ($1,$2,1,'Acme')"
    ))
    .bind(ctx_a.organization_id.0)
    .bind(row_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Org B sees nothing in the shared table.
    let mut tx = env.core.tenant_tx(&ctx_b).await.unwrap();
    let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM data.\"{slug}\""))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(count, 0);

    // Org B cannot see org A's object metadata row either: the app role,
    // under org B's tenant context, finds no such object.
    let mut tx = env.core.tenant_tx(&ctx_b).await.unwrap();
    let found: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM ontology_objects WHERE api_slug=$1 AND state='active'")
            .bind(&slug)
            .fetch_optional(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert!(found.is_none(), "org B must not see org A's metadata");
}

#[tokio::test]
async fn rename_changes_metadata_not_storage() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);

    let slug = common::uniq("company");
    let meta = ont
        .define_object(&ctx, &object_def(&slug, "Company"))
        .await
        .unwrap();
    ont.add_field(&ctx, meta.id, &field("Name", "name", FieldType::Text))
        .await
        .unwrap();
    let before = ont.physical_columns(&meta.table).await.unwrap();

    ont.rename_object(&ctx, meta.id, "Renamed Company", "Renamed Company")
        .await
        .unwrap();

    let name: String = sqlx::query_scalar("SELECT name FROM ontology_objects WHERE id=$1")
        .bind(meta.id)
        .fetch_one(&env.core_owner)
        .await
        .unwrap();
    assert_eq!(name, "Renamed Company");

    // Physical storage is untouched by the rename.
    let after = ont.physical_columns(&meta.table).await.unwrap();
    assert_eq!(before, after);

    // Field addition still works after rename.
    ont.add_field(&ctx, meta.id, &field("Extra", "extra", FieldType::Number))
        .await
        .unwrap();
    let desc = ont.describe_object(&ctx, meta.id).await.unwrap();
    assert!(desc.fields.iter().any(|f| f.api_name == "extra"));
}

#[tokio::test]
async fn relation_creates_real_foreign_key() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);

    let cslug = common::uniq("company");
    let pslug = common::uniq("person");
    let company = ont
        .define_object(&ctx, &object_def(&cslug, "Company"))
        .await
        .unwrap();
    let person = ont
        .define_object(&ctx, &object_def(&pslug, "Person"))
        .await
        .unwrap();
    ont.add_field(
        &ctx,
        person.id,
        &field(
            "Company",
            "company",
            FieldType::Relation {
                target_object_id: company.id,
            },
        ),
    )
    .await
    .unwrap();

    // A real composite FK references data.company(organization_id, id).
    let fk: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_constraint c \
         JOIN pg_class t ON t.oid=c.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace \
         WHERE n.nspname='data' AND t.relname=$1 AND c.contype='f'",
    )
    .bind(&pslug)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert!(fk >= 1, "relation must create a real foreign key");

    // And the FK actually enforces: inserting a bogus company id fails.
    let desc = ont.describe_object(&ctx, person.id).await.unwrap();
    let co_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "company")
        .unwrap()
        .physical_column
        .clone();
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let bad = sqlx::query(&format!(
        "INSERT INTO data.\"{pslug}\" (organization_id, id, version, \"{co_col}\") \
         VALUES ($1,$2,1,$3)"
    ))
    .bind(ctx.organization_id.0)
    .bind(Uuid::now_v7())
    .bind(Uuid::now_v7())
    .execute(&mut *tx)
    .await;
    assert!(bad.is_err(), "FK must reject dangling relation ids");
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn reserved_and_malicious_names_are_rejected() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = ontology(&env);

    let mut def = object_def("select", "Select");
    assert!(ont.define_object(&ctx, &def).await.is_err());

    def = object_def("x\"; DROP TABLE hosts;--", "X");
    assert!(ont.define_object(&ctx, &def).await.is_err());

    // api_names can never become physical column names: storage uses stable
    // random ids, so even a hostile api_name cannot shadow base columns.
    let slug = common::uniq("ok");
    let meta = ont
        .define_object(&ctx, &object_def(&slug, "Ok"))
        .await
        .unwrap();
    ont.add_field(
        &ctx,
        meta.id,
        &field("Org", "organization_id", FieldType::Text),
    )
    .await
    .unwrap();
    let desc = ont.describe_object(&ctx, meta.id).await.unwrap();
    let fcol = &desc
        .fields
        .iter()
        .find(|f| f.api_name == "organization_id")
        .unwrap()
        .physical_column;
    assert!(
        fcol.starts_with("f_") && fcol != "organization_id",
        "field storage must use a stable random column, got {fcol}"
    );
}

#[tokio::test]
async fn platform_scope_is_rejected_for_tenant_callers() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));

    // Platform scope writes rows visible to every tenant; a tenant caller
    // must not be able to create them.
    let mut def = object_def(&common::uniq("plat"), "Plat");
    def.scope = Scope::Platform;
    let err = ont.define_object(&ctx, &def).await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "platform scope must be forbidden, got {err:?}"
    );
}

#[tokio::test]
async fn sibling_object_mutation_is_rejected() {
    let env = common::setup().await;
    let ctx_a = common::new_org(&env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(&env, &common::uniq("orgb")).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));

    // Org A owns this object.
    let meta_a = ont
        .define_object(&ctx_a, &object_def(&common::uniq("a"), "A"))
        .await
        .unwrap();

    // Org B cannot add a field to it: no existence oracle, just NotFound.
    // (The api_name is valid so validation passes and the ownership
    // check is what rejects it.)
    let err = ont
        .add_field(
            &ctx_b,
            meta_a.id,
            &field("Sib", "sibling_field", FieldType::Text),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_)),
        "sibling mutation must be NotFound, got {err:?}"
    );

    // Org B cannot rename it either (RLS hides it from the tenant tx).
    let err = ont
        .rename_object(&ctx_b, meta_a.id, "Hijacked", "Hijacked")
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));

    // And a relation from B's object to A's object is refused: a
    // cross-tenant foreign key would bridge two tenants' tables.
    let meta_b = ont
        .define_object(&ctx_b, &object_def(&common::uniq("b"), "B"))
        .await
        .unwrap();
    let err = ont
        .add_field(
            &ctx_b,
            meta_b.id,
            &field(
                "Target",
                "target",
                FieldType::Relation {
                    target_object_id: meta_a.id,
                },
            ),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_)),
        "cross-tenant relation must be NotFound, got {err:?}"
    );
}
