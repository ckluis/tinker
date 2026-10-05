//! Post-M8 item 20: shared-object adoption.
//!
//! A second organization adopts an existing shared object (metadata-only
//! row pointing at the existing table) instead of failing on the
//! duplicate table. Proves: base fields resolve live for the adopter,
//! the adopter's own fields stay namespaced, adoption is idempotent and
//! flattens to the root definer, shadowing a base field fails closed,
//! and data isolation (RLS) is unchanged.

mod common;

use tinker_core::{TenantContext, TinkerError};
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

fn field(name: &str, api_name: &str) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        sensitive: false,
        validation: Default::default(),
        preset: None,
        name: name.into(),
        api_name: api_name.into(),
        label: name.into(),
        field_type: FieldType::Text,
        options: serde_json::json!({}),
        required: false,
    }
}

fn ontology(env: &common::Env) -> Ontology {
    Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
}

/// Org A defines `slug` with one base field; returns (ctx_a, object_id).
async fn define_shared(env: &common::Env, ont: &Ontology, slug: &str) -> (TenantContext, Uuid) {
    let ctx_a = common::new_org(env, &common::uniq("org")).await;
    let meta = ont
        .define_object(&ctx_a, &object_def(slug, "Shared"))
        .await
        .unwrap();
    ont.add_field(&ctx_a, meta.id, &field("Name", "name"))
        .await
        .unwrap();
    (ctx_a, meta.id)
}

#[tokio::test]
async fn adopt_sees_shared_base_fields() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    let (_ctx_a, root_id) = define_shared(&env, &ont, &slug).await;

    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    let adopted = ont.adopt_object(&ctx_b, &slug).await.unwrap();
    // Metadata-only: same table, new row, points at the root definer.
    assert_eq!(adopted.table, format!("data.{slug}"));
    assert_ne!(adopted.id, root_id);

    let desc = ont.describe_object(&ctx_b, adopted.id).await.unwrap();
    let names: Vec<_> = desc.fields.iter().map(|f| f.api_name.as_str()).collect();
    assert_eq!(names, vec!["name"], "adopter sees the shared base field");

    // adopted_from is stored on the row (owner-visible).
    let from: Option<Uuid> =
        sqlx::query_scalar("SELECT adopted_from FROM ontology_objects WHERE id=$1")
            .bind(adopted.id)
            .fetch_one(&env.core_owner)
            .await
            .unwrap();
    assert_eq!(from, Some(root_id));
}

#[tokio::test]
async fn adopt_is_idempotent() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    define_shared(&env, &ont, &slug).await;

    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    let first = ont.adopt_object(&ctx_b, &slug).await.unwrap();
    let second = ont.adopt_object(&ctx_b, &slug).await.unwrap();
    assert_eq!(first.id, second.id, "repeat adoption converges on one row");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM ontology_objects WHERE api_slug=$1 AND organization_id=$2",
    )
    .bind(&slug)
    .bind(ctx_b.organization_id.0)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn adopter_fields_are_namespaced() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    let (ctx_a, root_id) = define_shared(&env, &ont, &slug).await;

    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    let adopted = ont.adopt_object(&ctx_b, &slug).await.unwrap();
    // The adopter's own post-adoption field lands in the shared table but
    // is namespaced to the adopted row.
    ont.add_field(&ctx_b, adopted.id, &field("Nickname", "nickname"))
        .await
        .unwrap();

    let desc_b = ont.describe_object(&ctx_b, adopted.id).await.unwrap();
    let names_b: Vec<_> = desc_b.fields.iter().map(|f| f.api_name.as_str()).collect();
    assert_eq!(names_b, vec!["name", "nickname"]);

    // The definer never sees the adopter's field.
    let desc_a = ont.describe_object(&ctx_a, root_id).await.unwrap();
    let names_a: Vec<_> = desc_a.fields.iter().map(|f| f.api_name.as_str()).collect();
    assert_eq!(names_a, vec!["name"]);
}

#[tokio::test]
async fn base_field_added_after_adoption_is_visible() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    let (ctx_a, _root_id) = define_shared(&env, &ont, &slug).await;

    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    let adopted = ont.adopt_object(&ctx_b, &slug).await.unwrap();

    // The definer extends the shared base AFTER the adoption: the link is
    // live, not a snapshot.
    ont.add_field(&ctx_a, _root_id, &field("Email", "email"))
        .await
        .unwrap();
    let desc = ont.describe_object(&ctx_b, adopted.id).await.unwrap();
    let names: Vec<_> = desc.fields.iter().map(|f| f.api_name.as_str()).collect();
    assert_eq!(names, vec!["name", "email"]);
}

#[tokio::test]
async fn adopter_cannot_shadow_a_base_field() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    define_shared(&env, &ont, &slug).await;

    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    let adopted = ont.adopt_object(&ctx_b, &slug).await.unwrap();
    let err = ont
        .add_field(&ctx_b, adopted.id, &field("Name clone", "name"))
        .await
        .unwrap_err();
    match err {
        TinkerError::Validation(m) => assert!(m.contains("shadows a shared base field"), "{m}"),
        e => panic!("expected Validation, got {e:?}"),
    }
}

#[tokio::test]
async fn adopt_missing_slug_is_not_found() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let err = ont
        .adopt_object(&ctx, &common::uniq("nosuchobject"))
        .await
        .unwrap_err();
    match err {
        TinkerError::NotFound(m) => assert!(m.contains("no shared object to adopt"), "{m}"),
        e => panic!("expected NotFound, got {e:?}"),
    }
}

#[tokio::test]
async fn adopt_invalid_slug_is_rejected() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let err = ont.adopt_object(&ctx, "Has Space").await.unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "{err:?}");
}

#[tokio::test]
async fn define_still_fails_closed_and_points_to_adopt() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    define_shared(&env, &ont, &slug).await;

    // A fresh org defining the shared slug fails closed...
    let ctx_c = common::new_org(&env, &common::uniq("org")).await;
    let err = ont
        .define_object(&ctx_c, &object_def(&slug, "Contact"))
        .await
        .unwrap_err();
    match err {
        TinkerError::Validation(m) => {
            assert!(m.contains("object slug already exists"), "{m}");
            assert!(
                m.contains("adopt_object"),
                "error must guide to adoption: {m}"
            );
        }
        e => panic!("expected Validation, got {e:?}"),
    }
    // ...and the guided path works.
    let adopted = ont.adopt_object(&ctx_c, &slug).await.unwrap();
    assert_eq!(adopted.table, format!("data.{slug}"));
}

#[tokio::test]
async fn adopt_flattens_to_the_root_definer() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    let (_ctx_a, root_id) = define_shared(&env, &ont, &slug).await;

    // Org B adopts, then adds its own customization.
    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    let adopted_b = ont.adopt_object(&ctx_b, &slug).await.unwrap();
    ont.add_field(&ctx_b, adopted_b.id, &field("Nickname", "nickname"))
        .await
        .unwrap();

    // Org C adopts the same slug: it must link to the ROOT (org A), not
    // to org B's adopted row — C gets the shared base, not B's extras.
    let ctx_c = common::new_org(&env, &common::uniq("org")).await;
    let adopted_c = ont.adopt_object(&ctx_c, &slug).await.unwrap();
    let from: Option<Uuid> =
        sqlx::query_scalar("SELECT adopted_from FROM ontology_objects WHERE id=$1")
            .bind(adopted_c.id)
            .fetch_one(&env.core_owner)
            .await
            .unwrap();
    assert_eq!(from, Some(root_id), "adoption flattens to the root definer");

    let desc = ont.describe_object(&ctx_c, adopted_c.id).await.unwrap();
    let names: Vec<_> = desc.fields.iter().map(|f| f.api_name.as_str()).collect();
    assert_eq!(
        names,
        vec!["name"],
        "C sees the base, not B's customization"
    );
}

#[tokio::test]
async fn adopted_rows_keep_rls_data_isolation() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    let (ctx_a, _root_id) = define_shared(&env, &ont, &slug).await;

    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    let adopted = ont.adopt_object(&ctx_b, &slug).await.unwrap();

    // Physical column of the shared base field, via the adopter's view.
    let desc = ont.describe_object(&ctx_b, adopted.id).await.unwrap();
    let name_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();

    // Org A writes a row; org B (adopter) sees zero rows in the table.
    let mut tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO data.\"{slug}\" (organization_id, id, version, \"{name_col}\") \
         VALUES ($1,$2,1,'Acme')"
    ))
    .bind(ctx_a.organization_id.0)
    .bind(Uuid::now_v7())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut tx = env.core.tenant_tx(&ctx_b).await.unwrap();
    let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM data.\"{slug}\""))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(count, 0, "adopter sees only its own rows via RLS");
}

/// Migration 0045: visibility is not writability. Through the app role
/// (tenant tx), an adopter can READ the definer's base field rows and
/// every tenant can READ platform objects, but neither may be written.
/// Before 0045 the FOR ALL / USING-only policies let both UPDATEs land.
#[tokio::test]
async fn visible_shared_and_platform_rows_are_not_writable_by_tenants() {
    let env = common::setup().await;
    let ont = ontology(&env);
    let slug = common::uniq("contact");
    let (_ctx_a, root_id) = define_shared(&env, &ont, &slug).await;
    let ctx_b = common::new_org(&env, &common::uniq("org")).await;
    ont.adopt_object(&ctx_b, &slug).await.unwrap();

    // A platform object (owner-inserted, as the pack installer would).
    let platform_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO ontology_objects (id, scope_kind, name, api_slug, label) \
         VALUES ($1, 'platform', 'Base', $2, 'Base')",
    )
    .bind(platform_id)
    .bind(common::uniq("base"))
    .execute(&env.core_owner)
    .await
    .unwrap();

    let mut tx = env.core.tenant_tx(&ctx_b).await.unwrap();
    let visible_fields: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ontology_fields WHERE object_id=$1")
            .bind(root_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(
        visible_fields, 1,
        "adopter still sees the shared base field"
    );
    let visible_platform: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ontology_objects WHERE id=$1")
            .bind(platform_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(visible_platform, 1, "platform objects stay visible");

    for (sql, id) in [
        (
            "UPDATE ontology_fields SET label='pwned' WHERE object_id=$1",
            root_id,
        ),
        ("DELETE FROM ontology_fields WHERE object_id=$1", root_id),
        (
            "UPDATE ontology_objects SET label='pwned' WHERE id=$1",
            platform_id,
        ),
        ("DELETE FROM ontology_objects WHERE id=$1", platform_id),
    ] {
        let n = sqlx::query(sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .unwrap()
            .rows_affected();
        assert_eq!(n, 0, "tenant write must not reach a foreign row: {sql}");
    }
    tx.commit().await.unwrap();

    // The library path fails closed the same way (no existence oracle).
    let err = ont
        .rename_object(&ctx_b, platform_id, "Hijacked", "Hijacked")
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "got {err:?}");

    let label: String = sqlx::query_scalar("SELECT label FROM ontology_objects WHERE id=$1")
        .bind(platform_id)
        .fetch_one(&env.core_owner)
        .await
        .unwrap();
    assert_eq!(label, "Base");
}
