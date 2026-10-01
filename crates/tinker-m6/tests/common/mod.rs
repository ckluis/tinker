//! M6 test harness: managed ingestion into the typed CRM ontology.
//!
//! The canonical targets are the M3 CRM pack's platform objects
//! (`crm_company`, `crm_contact`, `crm_deal`) — real typed tables installed
//! through the pack installer. No test DDL, no JSONB catch-alls: every
//! ordinary field is a typed column.

#![allow(dead_code)]

use tinker_apps::AppRegistry;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ingest::connector::{FakeSalesforce, SourceField, SourceRecord};
use tinker_ingest::IngestPipeline;
use tinker_ontology::Ontology;
use tinker_packs::{PackDefinition, PackInstaller};
use uuid::Uuid;

pub struct IngestEnv {
    pub org_id: Uuid,
    pub actor_id: Uuid,
    pub ctx: TenantContext,
    pub core: CoreDb,
    pub owner: OwnerDb,
    pub pipeline: IngestPipeline,
    pub salesforce: FakeSalesforce,
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

fn sf_field(name: &str, ty: &str) -> SourceField {
    SourceField {
        name: name.to_string(),
        type_name: ty.to_string(),
    }
}

fn sf_record(id: &str, updated_at: &str, fields: Vec<(&str, serde_json::Value)>) -> SourceRecord {
    SourceRecord {
        source_id: id.to_string(),
        updated_at: updated_at.parse().unwrap(),
        deleted: false,
        fields: fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    }
}

/// Fresh pools per call: each #[tokio::test] runs on its own
/// current-thread runtime, and pools must not be shared across runtimes.
pub async fn setup() -> IngestEnv {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let core = CoreDb(tenant_pool.clone());
    let owner = OwnerDb(owner_pool.clone());

    // Install the CRM pack through the privileged installer: the pack TOML
    // is the entire interface, and the install is idempotent across tests.
    // This gives M6 real typed canonical tables (data.crm_company, ...).
    let pack_toml = include_str!("../../../../packs/crm/pack.toml");
    let pack = PackDefinition::from_toml(pack_toml).unwrap();
    let installer = PackInstaller::new(
        Ontology::new(core.clone(), owner.clone()),
        AppRegistry::new(tenant_pool.clone()),
    );
    let installed = installer.install_objects(&pack).await.unwrap();
    assert_eq!(installed.objects.len(), 3, "crm pack has 3 objects");

    let (org_id, actor_id) = create_org(&owner_pool).await;

    let ctx = TenantContext::new(OrganizationId(org_id), actor_id, "m6-test");
    let pipeline = IngestPipeline::new(core.clone(), owner.clone());

    IngestEnv {
        org_id,
        actor_id,
        ctx,
        core,
        owner,
        pipeline,
        salesforce: FakeSalesforce::new(),
    }
}

/// Owner-pool transaction scoped to one org: mirrors production's
/// `tenant_tx` but over the owner pool, for white-box fixtures on
/// FORCE-RLS tables. The owner no longer bypasses FORCE RLS since the
/// least-privilege hardening (post-M8 item 11), so fixtures must set
/// the tenant context explicitly instead of relying on superuser
/// bypass. Callers hold the returned transaction and run their
/// statements against `&mut *tx`.
pub async fn owner_scoped(
    owner_pool: &sqlx::PgPool,
    org_id: Uuid,
) -> sqlx::Transaction<'_, sqlx::Postgres> {
    let mut tx = owner_pool.begin().await.unwrap();
    sqlx::query(&format!("SET LOCAL app.organization_id = '{org_id}'"))
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}
/// Create a fresh org + actor (owner-backed). Used for the primary org and
/// for sibling-tenant isolation tests.
pub async fn create_org(owner_pool: &sqlx::PgPool) -> (Uuid, Uuid) {
    let org_id = Uuid::now_v7();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("m6-host")
        .execute(owner_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("m6-{}", org_id.simple()))
        .bind("m6 org")
        .execute(owner_pool)
        .await
        .unwrap();
    let actor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)",
    )
    .bind(actor_id)
    .bind(org_id)
    .bind("m6-operator")
    .bind("m6-operator")
    .execute(owner_pool)
    .await
    .unwrap();
    (org_id, actor_id)
}

/// Physical column for an api field on a pack object (resolved through the
/// ontology — no hardcoded column names).
pub async fn phys(env: &IngestEnv, object_slug: &str, api_name: &str) -> String {
    let row: (String,) = sqlx::query_as(
        "SELECT f.physical_column FROM ontology_fields f
         JOIN ontology_objects o ON o.id = f.object_id
         WHERE o.api_slug=$1 AND f.api_name=$2 AND f.state='active'",
    )
    .bind(object_slug)
    .bind(api_name)
    .fetch_one(&env.owner.0)
    .await
    .unwrap();
    row.0
}

/// Seed the three M6 source objects with deterministic records.
pub fn seed_salesforce(env: &IngestEnv) {
    let sf = &env.salesforce;
    sf.seed_object(
        "Account",
        vec![
            sf_field("Id", "id"),
            sf_field("Name", "string"),
            sf_field("Industry", "string"),
        ],
        vec![
            sf_record(
                "ACC-1",
                "2026-09-20T10:00:00Z",
                vec![
                    ("Id", serde_json::json!("ACC-1")),
                    ("Name", serde_json::json!("Acme Corp")),
                    ("Industry", serde_json::json!("Manufacturing")),
                ],
            ),
            sf_record(
                "ACC-2",
                "2026-09-21T10:00:00Z",
                vec![
                    ("Id", serde_json::json!("ACC-2")),
                    ("Name", serde_json::json!("Globex")),
                    ("Industry", serde_json::json!("Technology")),
                ],
            ),
        ],
    );
    sf.seed_object(
        "Contact",
        vec![
            sf_field("Id", "id"),
            sf_field("FullName", "string"),
            sf_field("Email", "string"),
            sf_field("AccountId", "reference"),
        ],
        vec![
            sf_record(
                "CON-1",
                "2026-09-20T11:00:00Z",
                vec![
                    ("Id", serde_json::json!("CON-1")),
                    ("FullName", serde_json::json!("Alice Anderson")),
                    ("Email", serde_json::json!("alice@acme.example")),
                    ("AccountId", serde_json::json!("ACC-1")),
                ],
            ),
            sf_record(
                "CON-2",
                "2026-09-21T11:00:00Z",
                vec![
                    ("Id", serde_json::json!("CON-2")),
                    ("Name", serde_json::json!("Bob Baker")),
                    ("Email", serde_json::json!("bob@globex.example")),
                    ("AccountId", serde_json::json!("ACC-2")),
                ],
            ),
        ],
    );
    // NOTE: the second record intentionally uses "Name" instead of
    // "FullName" — a ragged source schema the profiler must measure.
    sf.seed_object(
        "Opportunity",
        vec![
            sf_field("Id", "id"),
            sf_field("Name", "string"),
            sf_field("Amount", "currency"),
            sf_field("Stage", "string"),
            sf_field("AccountId", "reference"),
        ],
        vec![sf_record(
            "OPP-1",
            "2026-09-22T10:00:00Z",
            vec![
                ("Id", serde_json::json!("OPP-1")),
                ("Name", serde_json::json!("Acme Expansion")),
                ("Amount", serde_json::json!(50000)),
                ("Stage", serde_json::json!("proposal")),
                ("AccountId", serde_json::json!("ACC-1")),
            ],
        )],
    );
}

pub fn account_target() -> tinker_ingest::pipeline::CanonicalTarget {
    tinker_ingest::pipeline::CanonicalTarget {
        object_slug: "crm_company".to_string(),
        email_api_field: None,
    }
}

pub fn contact_target() -> tinker_ingest::pipeline::CanonicalTarget {
    tinker_ingest::pipeline::CanonicalTarget {
        object_slug: "crm_contact".to_string(),
        email_api_field: Some("email".to_string()),
    }
}

pub fn opportunity_target() -> tinker_ingest::pipeline::CanonicalTarget {
    tinker_ingest::pipeline::CanonicalTarget {
        object_slug: "crm_deal".to_string(),
        email_api_field: None,
    }
}

/// Standard mappings for the three objects (api field names — the
/// pipeline resolves them to physical typed columns).
pub async fn put_standard_mappings(env: &IngestEnv, stream_id: Uuid, object: &str) {
    let m = env.pipeline.mappings();
    let pairs: Vec<(&str, &str)> = match object {
        "Account" => vec![("Name", "name"), ("Industry", "industry")],
        "Contact" => vec![("FullName", "name"), ("Email", "email")],
        "Opportunity" => vec![("Name", "name"), ("Amount", "amount"), ("Stage", "stage")],
        _ => vec![],
    };
    let target_slug = match object {
        "Account" => "crm_company",
        "Contact" => "crm_contact",
        "Opportunity" => "crm_deal",
        _ => panic!("bad object"),
    };
    for (src, tgt) in pairs {
        m.put_mapping(&env.ctx, stream_id, src, target_slug, tgt)
            .await
            .unwrap();
    }
}
