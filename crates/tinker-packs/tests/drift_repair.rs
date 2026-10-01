//! Pack drift / reinstall idempotence proof (post-M8 item 17).
//!
//! - `reinstall_repairs_drifted_pack`: an operator drifts a pack out of
//!   band (drops a field, relabels another, rewrites select options);
//!   reinstall restores the declared schema, leaves operator-added extra
//!   fields alone, and preserves row data.
//! - `reinstall_fails_closed_on_type_drift`: a type-drifted pack field
//!   fails the reinstall with a named error — reinstall never rewrites a
//!   physical column.
//! - `concurrent_duplicate_installs_converge`: N concurrent installs of
//!   the same pack all succeed on identical object ids with no duplicate
//!   fields.
//! - `concurrent_cross_pack_slug_collision_converges`: two different packs
//!   declaring the same slug converge through the 23505 retry path.
//! - `reinstall_does_not_clobber_evolved_fields`: reinstall over an org
//!   with an active evolved schema leaves the extension table, its rows,
//!   and the resolved ExtFields intact.

use std::sync::Arc;

use tinker_apps::AppRegistry;
use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_evolve::{SchemaEvolver, VersionSel};
use tinker_ontology::{FieldDef, FieldType, Ontology};
use tinker_packs::{PackDefinition, PackInstaller};
use uuid::Uuid;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

async fn setup() -> (PackInstaller, Ontology, sqlx::PgPool, sqlx::PgPool) {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let ontology = Ontology::new(CoreDb(tenant_pool.clone()), OwnerDb(owner_pool.clone()));
    let installer = PackInstaller::new(ontology.clone(), AppRegistry::new(tenant_pool.clone()));
    (installer, ontology, owner_pool, tenant_pool)
}

/// The LAST 12 hex chars: the first 12 of a v7 UUID are the millisecond
/// timestamp, so parallel tests started in the same ms shared a tag (and
/// a pack slug) and flaked.
fn rand_tag() -> String {
    Uuid::now_v7().simple().to_string()[20..32].to_string()
}

/// Two-object pack: widget (text + two selects + relation) and gadget.
fn drift_pack(tag: &str) -> PackDefinition {
    let toml = format!(
        "[pack]\nid = \"drift-{tag}\"\nversion = \"1.0.0\"\nname = \"Drift\"\n\n\
         [[objects]]\nname = \"Widget\"\napi_slug = \"drift_widget_{tag}\"\nlabel = \"Widget\"\n\n\
         [[objects.fields]]\nname = \"name\"\napi_name = \"name\"\nlabel = \"Name\"\nfield_type = \"text\"\n\n\
         [[objects.fields]]\nname = \"status\"\napi_name = \"status\"\nlabel = \"Status\"\nfield_type = \"select\"\noptions = [\"new\", \"active\"]\n\n\
         [[objects.fields]]\nname = \"priority\"\napi_name = \"priority\"\nlabel = \"Priority\"\nfield_type = \"select\"\noptions = [\"low\", \"high\"]\n\n\
         [[objects.fields]]\nname = \"owner_ref\"\napi_name = \"owner_ref\"\nlabel = \"Owner\"\nfield_type = \"relation\"\nrelation_target = \"drift_gadget_{tag}\"\n\n\
         [[objects]]\nname = \"Gadget\"\napi_slug = \"drift_gadget_{tag}\"\nlabel = \"Gadget\"\n\n\
         [[objects.fields]]\nname = \"title\"\napi_name = \"title\"\nlabel = \"Title\"\nfield_type = \"text\"\n"
    );
    PackDefinition::from_toml(&toml).unwrap()
}

async fn physical_column(owner: &sqlx::PgPool, object_id: Uuid, api_name: &str) -> String {
    let (col,): (String,) = sqlx::query_as(
        "SELECT physical_column FROM ontology_fields WHERE object_id=$1 AND api_name=$2",
    )
    .bind(object_id)
    .bind(api_name)
    .fetch_one(owner)
    .await
    .unwrap();
    col
}

async fn field_row(
    owner: &sqlx::PgPool,
    object_id: Uuid,
    api_name: &str,
) -> (String, String, bool, serde_json::Value) {
    let row = sqlx::query(
        "SELECT field_type, label, required, options_json FROM ontology_fields \
         WHERE object_id=$1 AND api_name=$2 AND state='active'",
    )
    .bind(object_id)
    .bind(api_name)
    .fetch_one(owner)
    .await
    .unwrap();
    use sqlx::Row;
    (
        row.get("field_type"),
        row.get("label"),
        row.get("required"),
        row.get("options_json"),
    )
}

async fn column_exists(owner: &sqlx::PgPool, slug: &str, column: &str) -> bool {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema='data' AND table_name=$1 AND column_name=$2",
    )
    .bind(slug)
    .bind(column)
    .fetch_one(owner)
    .await
    .unwrap();
    n == 1
}

#[tokio::test]
async fn reinstall_repairs_drifted_pack() {
    let (installer, ontology, owner, _) = setup().await;
    let tag = rand_tag();
    let pack = drift_pack(&tag);
    let installed = installer.install_objects(&pack).await.unwrap();
    let widget_id = installed.objects[&format!("drift_widget_{tag}")];
    let gadget_id = installed.objects[&format!("drift_gadget_{tag}")];
    let widget_slug = format!("drift_widget_{tag}");

    // Seed a data row through the owner pool; its data must survive.
    let org = Uuid::now_v7();
    let name_col = physical_column(&owner, widget_id, "name").await;
    let (record_id,): (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.{widget_slug} (organization_id, \"{name_col}\") \
         VALUES ($1, 'gizmo') RETURNING id"
    ))
    .bind(org)
    .fetch_one(&owner)
    .await
    .unwrap();

    // --- Drift, out of band, like a careless operator migration. ---
    // 1. Drop the `status` field entirely (metadata row + physical column).
    let status_col = physical_column(&owner, widget_id, "status").await;
    sqlx::query("DELETE FROM ontology_fields WHERE object_id=$1 AND api_name='status'")
        .bind(widget_id)
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query(&format!(
        "ALTER TABLE data.{widget_slug} DROP COLUMN \"{status_col}\""
    ))
    .execute(&owner)
    .await
    .unwrap();
    // 2. Relabel `name` and flip its required flag.
    sqlx::query(
        "UPDATE ontology_fields SET label='HACKED', required=true \
         WHERE object_id=$1 AND api_name='name'",
    )
    .bind(widget_id)
    .execute(&owner)
    .await
    .unwrap();
    // 3. Rewrite `priority` select options.
    sqlx::query(
        "UPDATE ontology_fields SET options_json='{\"options\":[\"bogus\"]}' \
         WHERE object_id=$1 AND api_name='priority'",
    )
    .bind(widget_id)
    .execute(&owner)
    .await
    .unwrap();
    // 4. An operator-added field the pack never declared.
    ontology
        .add_platform_field(
            widget_id,
            &FieldDef {
                max_pii_class: "restricted".to_string(),
                sensitive: false,
                validation: Default::default(),
                preset: None,
                name: "extra".into(),
                api_name: "extra_note".into(),
                label: "Extra".into(),
                field_type: FieldType::Text,
                options: serde_json::Value::Null,
                required: false,
            },
        )
        .await
        .unwrap();

    // --- Reinstall: the declared schema must come back. ---
    let reinstalled = installer.install_objects(&pack).await.unwrap();
    assert_eq!(
        reinstalled.objects[&format!("drift_widget_{tag}")],
        widget_id,
        "reinstall resolves the same platform objects"
    );

    // Dropped field re-added with its declared type and options.
    let (ft, label, _, options) = field_row(&owner, widget_id, "status").await;
    assert_eq!(ft, "select");
    assert_eq!(label, "Status");
    assert_eq!(options, serde_json::json!({"options": ["new", "active"]}));
    let new_status_col = physical_column(&owner, widget_id, "status").await;
    assert!(
        column_exists(&owner, &widget_slug, &new_status_col).await,
        "re-added field has a real physical column"
    );
    // Relabel + required flag restored.
    let (_, label, required, _) = field_row(&owner, widget_id, "name").await;
    assert_eq!(label, "Name");
    assert!(!required, "declared required=false is restored");
    // Options restored.
    let (_, _, _, options) = field_row(&owner, widget_id, "priority").await;
    assert_eq!(options, serde_json::json!({"options": ["low", "high"]}));
    // Operator-added extra field untouched.
    let (ft, _, _, _) = field_row(&owner, widget_id, "extra_note").await;
    assert_eq!(ft, "text", "undeclared fields are left alone");
    // Relation still targets the gadget.
    let (ft, _, _, _): (String, String, bool, serde_json::Value) =
        field_row(&owner, widget_id, "owner_ref").await;
    assert_eq!(ft, "relation");
    let (target,): (Option<Uuid>,) = sqlx::query_as(
        "SELECT relation_target_id FROM ontology_fields \
         WHERE object_id=$1 AND api_name='owner_ref'",
    )
    .bind(widget_id)
    .fetch_one(&owner)
    .await
    .unwrap();
    assert_eq!(target, Some(gadget_id));
    // Seeded row data intact.
    let (name_val,): (Option<String>,) = sqlx::query_as(&format!(
        "SELECT \"{name_col}\" FROM data.{widget_slug} WHERE id=$1"
    ))
    .bind(record_id)
    .fetch_one(&owner)
    .await
    .unwrap();
    assert_eq!(name_val.as_deref(), Some("gizmo"));
}

#[tokio::test]
async fn reinstall_fails_closed_on_type_drift() {
    let (installer, _, owner, _) = setup().await;
    let tag = rand_tag();
    let pack = drift_pack(&tag);
    let installed = installer.install_objects(&pack).await.unwrap();
    let widget_id = installed.objects[&format!("drift_widget_{tag}")];

    // Catalog drift: the metadata says number, the column is still text.
    sqlx::query(
        "UPDATE ontology_fields SET field_type='number' \
         WHERE object_id=$1 AND api_name='name'",
    )
    .bind(widget_id)
    .execute(&owner)
    .await
    .unwrap();

    let err = installer
        .install_objects(&pack)
        .await
        .expect_err("type drift must fail the reinstall");
    let msg = match &err {
        TinkerError::Validation(m) => m.clone(),
        other => panic!("expected Validation, got {other:?}"),
    };
    assert!(msg.contains("'name'"), "names the field: {msg}");
    assert!(msg.contains("text"), "names the declared type: {msg}");
    assert!(msg.contains("number"), "names the drifted type: {msg}");

    // The failed reinstall wrote nothing: the drifted row is untouched.
    let (ft, label, _, _) = field_row(&owner, widget_id, "name").await;
    assert_eq!(ft, "number", "reinstall never rewrites the column");
    assert_eq!(label, "Name");
}

#[tokio::test]
async fn concurrent_duplicate_installs_converge() {
    let (installer, _, owner, _) = setup().await;
    let installer = Arc::new(installer);
    let tag = rand_tag();
    let pack = drift_pack(&tag);
    let widget_slug = format!("drift_widget_{tag}");
    let gadget_slug = format!("drift_gadget_{tag}");

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let inst = installer.clone();
        let p = pack.clone();
        set.spawn(async move { inst.install_objects(&p).await });
    }
    let mut runs = Vec::new();
    while let Some(r) = set.join_next().await {
        runs.push(r.expect("install task survived").expect("install succeeds"));
    }
    assert_eq!(runs.len(), 8);
    assert!(
        runs.iter()
            .all(|done| done.objects[&widget_slug] == runs[0].objects[&widget_slug]),
        "8 concurrent installs converge on one object id"
    );
    // No duplicate fields: exactly the declared count per object.
    for (slug, expect) in [(widget_slug.as_str(), 4i64), (gadget_slug.as_str(), 1i64)] {
        let object_id = runs[0].objects[slug];
        let (n,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM ontology_fields WHERE object_id=$1 AND state='active'",
        )
        .bind(object_id)
        .fetch_one(&owner)
        .await
        .unwrap();
        assert_eq!(
            n, expect,
            "{slug} has exactly its declared fields, no duplicates"
        );
    }
}

#[tokio::test]
async fn concurrent_cross_pack_slug_collision_converges() {
    let (installer, _, owner, _) = setup().await;
    let installer = Arc::new(installer);
    let tag = rand_tag();
    // Two different packs declaring the same slug: the loser of the race
    // hits 23505 and converges through the single retry.
    let mut pack_a = drift_pack(&tag);
    pack_a.pack.id = format!("collide-a-{tag}");
    let mut pack_b = drift_pack(&tag);
    pack_b.pack.id = format!("collide-b-{tag}");
    let slug = format!("drift_widget_{tag}");

    let ia = installer.clone();
    let ib = installer.clone();
    let (ra, rb) = tokio::join!(ia.install_objects(&pack_a), ib.install_objects(&pack_b));
    let a = ra.expect("pack A installs");
    let b = rb.expect("pack B installs");
    assert_eq!(
        a.objects[&slug], b.objects[&slug],
        "cross-pack slug collision converges on one object"
    );
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM ontology_objects WHERE api_slug=$1 AND state='active'",
    )
    .bind(&slug)
    .fetch_one(&owner)
    .await
    .unwrap();
    assert_eq!(n, 1, "exactly one platform object carries the slug");
}

fn evo_text_field(api_name: &str) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        sensitive: false,
        validation: Default::default(),
        preset: None,
        name: api_name.to_string(),
        api_name: api_name.to_string(),
        label: api_name.to_string(),
        field_type: FieldType::Text,
        options: serde_json::json!({}),
        required: false,
    }
}

#[tokio::test]
async fn reinstall_does_not_clobber_evolved_fields() {
    let (installer, ontology, owner, tenant_pool) = setup().await;
    let tag = rand_tag();
    let pack = drift_pack(&tag);
    let installed = installer.install_objects(&pack).await.unwrap();
    let widget_id = installed.objects[&format!("drift_widget_{tag}")];
    let widget_slug = format!("drift_widget_{tag}");

    // Org A with an active evolved schema: draft -> add nickname ->
    // preview -> promote. Extension table + ExtField, base schema untouched.
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, 'drift-host')")
        .bind(host_id)
        .execute(&owner)
        .await
        .unwrap();
    let org_a = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1,$2,$3,$4)")
        .bind(org_a)
        .bind(host_id)
        .bind(format!("driftorg-{tag}"))
        .bind("drift org")
        .execute(&owner)
        .await
        .unwrap();
    let ctx = TenantContext::new(OrganizationId(org_a), Uuid::now_v7(), "drift-test");
    let evolver = SchemaEvolver::new(
        CoreDb(tenant_pool),
        OwnerDb(owner.clone()),
        ontology.clone(),
    );
    let draft = evolver.create_draft(&ctx, widget_id).await.unwrap();
    let spec = evolver
        .add_field(&ctx, draft.id, &evo_text_field("nickname"))
        .await
        .unwrap();
    evolver.mark_preview(&ctx, draft.id).await.unwrap();
    evolver.promote(&ctx, draft.id).await.unwrap();

    // Seed a base row and its evolved extension row.
    let name_col = physical_column(&owner, widget_id, "name").await;
    let (record_id,): (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.{widget_slug} (organization_id, \"{name_col}\") \
         VALUES ($1, 'Amy') RETURNING id"
    ))
    .bind(org_a)
    .fetch_one(&owner)
    .await
    .unwrap();
    let ext_table = tinker_evolve::ext_table_name(org_a, widget_id);
    sqlx::query(&format!(
        "INSERT INTO {ext_table} (organization_id, record_id, \"{}\") VALUES ($1,$2,'Ames')",
        spec.physical_column
    ))
    .bind(org_a)
    .bind(record_id)
    .execute(&owner)
    .await
    .unwrap();

    // --- Reinstall the pack over the evolved org. ---
    installer.install_objects(&pack).await.unwrap();

    // Base schema converged: pack fields intact.
    let (ft, _, _, _) = field_row(&owner, widget_id, "name").await;
    assert_eq!(ft, "text");
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM ontology_fields WHERE object_id=$1 AND state='active'",
    )
    .bind(widget_id)
    .fetch_one(&owner)
    .await
    .unwrap();
    assert_eq!(n, 4, "reinstall did not touch the base field set");
    // Evolved field still resolves on the active version...
    let resolved = evolver
        .resolve(&ctx, widget_id, VersionSel::Active)
        .await
        .unwrap();
    assert!(
        resolved.ext_fields.iter().any(|f| f.api_name == "nickname"),
        "evolved field still resolves after reinstall"
    );
    // ...its extension table and row survived...
    let (n,): (i64,) = sqlx::query_as(&format!(
        "SELECT count(*) FROM {ext_table} WHERE record_id=$1"
    ))
    .bind(record_id)
    .fetch_one(&owner)
    .await
    .unwrap();
    assert_eq!(n, 1, "extension row survived the reinstall");
    // ...and the unified description still carries it as an extension field.
    let desc = ontology
        .describe_object_with_ext(&ctx, widget_id, &resolved.ext_fields)
        .await
        .unwrap();
    let nick = desc
        .fields
        .iter()
        .find(|f| f.api_name == "nickname")
        .expect("nickname in unified description");
    assert!(
        nick.extension_table.is_some(),
        "evolved field still lives on its extension table"
    );
}

/// A pack can declare a sensitive field (docs/pii-sensitive-fields.md):
/// it installs as a vault-ref UUID column + blind index, and a reinstall
/// that flips the flag is drift — never a silent column rewrite.
#[tokio::test]
async fn pack_sensitive_field_installs_sealed_and_flip_is_drift() {
    let (installer, _ontology, owner, _) = setup().await;
    let tag = rand_tag();
    let pack = |sensitive: bool| {
        PackDefinition::from_toml(&format!(
            "[pack]\nid = \"pii-{tag}\"\nversion = \"1.0.0\"\nname = \"Pii\"\n\n\
             [[objects]]\nname = \"Person\"\napi_slug = \"pii_person_{tag}\"\nlabel = \"Person\"\n\n\
             [[objects.fields]]\nname = \"email\"\napi_name = \"email\"\nlabel = \"Email\"\n\
             field_type = \"email\"\nsensitive = {sensitive}\n"
        ))
        .unwrap()
    };
    let installed = installer.install_objects(&pack(true)).await.unwrap();
    let id = installed.objects[&format!("pii_person_{tag}")];
    let col = physical_column(&owner, id, "email").await;
    let types: Vec<(String, String)> = sqlx::query_as(
        "SELECT column_name::text, data_type::text FROM information_schema.columns \
         WHERE table_schema = 'data' AND table_name = $1 AND column_name LIKE $2 ORDER BY 1",
    )
    .bind(format!("pii_person_{tag}"))
    .bind(format!("{col}%"))
    .fetch_all(&owner)
    .await
    .unwrap();
    assert_eq!(
        types,
        vec![
            (col.clone(), "uuid".to_string()),
            (format!("{col}__bidx"), "text".to_string())
        ]
    );
    // Same declaration: idempotent. Flipped flag: named drift error.
    installer.install_objects(&pack(true)).await.unwrap();
    let err = installer.install_objects(&pack(false)).await.unwrap_err();
    assert!(
        matches!(&err, TinkerError::Validation(m) if m.contains("sensitive")),
        "{err:?}"
    );
}
