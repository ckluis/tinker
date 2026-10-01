//! R2 disaster-recovery drill fixtures (prodread workstream R2).
//!
//! Idempotent seeder: creates org `drorg_1` with an `drorg_article`
//! object (title required, body optional) and ~300 article records via
//! the governed `MutationConnector` write path. Re-runs are no-ops once
//! the target record count is reached. Slug prefix `drorg_` per
//! ~/workspace/prodread/PROTOCOL.md — never touches soakorg_* fixtures.
//!
//! Run: cargo test --test dr_seed -- --nocapture
//! Env: TINKER_CORE_OWNER_URL, TINKER_CORE_URL, TINKER_PII_OWNER_URL,
//!      TINKER_PII_URL, DATABASE_URL (as for the M0 exit tests).

mod common;

use std::collections::HashMap;

use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::OwnerDb;
use tinker_ontology::mutate::{CreateRequest, MutationConnector, NoHooks};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, ObjectMeta, Ontology, Scope};
use uuid::Uuid;

const ORG_SLUG: &str = "drorg_1";
const ARTICLE_SLUG: &str = "drorg_article";
const TARGET_RECORDS: i64 = 300;

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

fn field(api_name: &str, field_type: FieldType, required: bool) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        validation: Default::default(),
        preset: None,
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type,
        options: serde_json::json!({}),
        required,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn seed_drorg_1() {
    let env = common::setup().await;

    // Org: fixed slug, insert-if-missing (host fixed to test host).
    let org_id: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3) \
         ON CONFLICT (host_id, slug) DO UPDATE SET name=EXCLUDED.name \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(env.host_id)
    .bind(ORG_SLUG)
    .fetch_one(&env.core_owner)
    .await
    .expect("org upsert");
    println!("org {ORG_SLUG} id={org_id}");

    // Actor + membership for the tenant write path.
    let actor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
    )
    .bind(actor_id)
    .bind(org_id)
    .bind(format!("dr-seeder-{actor_id}"))
    .execute(&env.core_owner)
    .await
    .expect("actor insert");
    sqlx::query("INSERT INTO memberships (organization_id, actor_id, role) VALUES ($1,$2,'owner')")
        .bind(org_id)
        .bind(actor_id)
        .execute(&env.core_owner)
        .await
        .expect("membership insert");
    let ctx = TenantContext::new(OrganizationId(org_id), actor_id, "dr-seed".to_string());

    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));

    // Article object: define_or_adopt adopts across orgs, but a same-org
    // re-run hits "object slug already exists" — so reuse the existing row.
    let (meta, adopted) = match ont.define_or_adopt(&ctx, &object_def(ARTICLE_SLUG)).await {
        Ok(ok) => ok,
        Err(TinkerError::Validation(msg)) if msg.contains("already exists") => {
            let id: Uuid = sqlx::query_scalar(
                "SELECT id FROM ontology_objects WHERE organization_id=$1 AND api_slug=$2 \
                 AND state='active' ORDER BY created_at LIMIT 1",
            )
            .bind(org_id)
            .bind(ARTICLE_SLUG)
            .fetch_one(&env.core_owner)
            .await
            .expect("existing article object");
            (
                ObjectMeta {
                    id,
                    api_slug: ARTICLE_SLUG.into(),
                    table: format!("data.{ARTICLE_SLUG}"),
                },
                true,
            )
        }
        Err(e) => panic!("define_or_adopt article: {e:?}"),
    };
    println!("article object id={} adopted={adopted}", meta.id);

    // Fields idempotent: add only if the api_name is absent.
    let desc = ont
        .describe_object(&ctx, meta.id)
        .await
        .expect("describe article");
    let have: std::collections::HashSet<String> =
        desc.fields.iter().map(|f| f.api_name.clone()).collect();
    for (api_name, ft, required) in [
        ("title", FieldType::Text, true),
        ("body", FieldType::Text, false),
    ] {
        if !have.contains(api_name) {
            ont.add_field(&ctx, meta.id, &field(api_name, ft, required))
                .await
                .expect("add_field");
            println!("added field {api_name}");
        }
    }

    // Count existing records; top up to TARGET_RECORDS.
    let desc = ont
        .describe_object(&ctx, meta.id)
        .await
        .expect("describe article (fresh)");
    let mut tx = env.core.tenant_tx(&ctx).await.expect("tenant tx");
    let have_records: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM data.{} WHERE organization_id=$1",
        desc.api_slug
    ))
    .bind(org_id)
    .fetch_one(&mut *tx)
    .await
    .expect("count records");
    tx.commit().await.expect("commit");
    println!("article records present: {have_records}");

    let mc = MutationConnector::new(env.core.clone(), ont.clone());
    let hooks = NoHooks;
    let mut created = 0i64;
    let mut i = have_records as usize;
    while have_records + created < TARGET_RECORDS {
        let mut values: HashMap<String, serde_json::Value> = HashMap::new();
        values.insert(
            "title".into(),
            serde_json::json!(format!("DR drill article #{i}")),
        );
        values.insert(
            "body".into(),
            serde_json::json!(format!(
                "Fixture body for disaster-recovery drill record {i}. \
                 Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
                 sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
            )),
        );
        let out = mc
            .create(
                &ctx,
                &CreateRequest {
                    object_id: meta.id,
                    values,
                    require_approval: false,
                    approval_request_id: None,
                },
                &hooks,
            )
            .await
            .expect("create article record");
        assert!(out.version >= 1);
        created += 1;
        i += 1;
    }
    println!("created {created} article records (total {have_records} pre-existing)");
}
