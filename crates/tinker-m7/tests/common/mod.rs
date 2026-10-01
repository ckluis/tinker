//! M7 test harness: context and agents over the typed CRM ontology.
//!
//! Fixture: the M3 CRM pack's platform objects (crm_company, crm_contact,
//! crm_deal) with two companies (Acme in-scope, Globex out-of-scope),
//! contacts, and deals with amounts + richtext notes. Three roles:
//! executive (actual values), employee (bucketed/masked), contractor
//! (amount omitted entirely).

#![allow(dead_code)]

use std::str::FromStr;
use std::sync::Arc;
use tinker_agents::gateway::{FakeModelAdapter, ModelGateway, UnavailableModelAdapter};
use tinker_apps::AppRegistry;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::Ontology;
use tinker_packs::{PackDefinition, PackInstaller};
use uuid::Uuid;

pub struct AgentEnv {
    pub org_id: Uuid,
    pub exec_id: Uuid,
    pub employee_id: Uuid,
    pub contractor_id: Uuid,
    pub exec_ctx: TenantContext,
    pub employee_ctx: TenantContext,
    pub contractor_ctx: TenantContext,
    pub core: CoreDb,
    pub owner: OwnerDb,
    pub ontology: Ontology,
    pub gateway: ModelGateway,
    pub attachment_id: Uuid,
    pub profile_key: String,
    /// Seeded record ids.
    pub acme_id: Uuid,
    pub globex_id: Uuid,
    pub alice_id: Uuid,
    pub deal_d1: Uuid,
    pub deal_d2: Uuid,
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

/// Fresh pools per call: each #[tokio::test] runs on its own
/// current-thread runtime, and pools must not be shared across runtimes.
pub async fn setup() -> AgentEnv {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let core = CoreDb(tenant_pool.clone());
    let owner = OwnerDb(owner_pool.clone());
    let ontology = Ontology::new(core.clone(), owner.clone());

    // Install the CRM pack (idempotent across tests).
    let pack_toml = include_str!("../../../../packs/crm/pack.toml");
    let pack = PackDefinition::from_toml(pack_toml).unwrap();
    let installer = PackInstaller::new(
        Ontology::new(core.clone(), owner.clone()),
        AppRegistry::new(tenant_pool.clone()),
    );
    let installed = installer.install_objects(&pack).await.unwrap();
    assert_eq!(installed.objects.len(), 3, "crm pack has 3 objects");

    let org_id = Uuid::now_v7();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("m7-host")
        .execute(&owner_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("m7-{}", org_id.simple()))
        .bind("m7 org")
        .execute(&owner_pool)
        .await
        .unwrap();

    async fn mk_actor(
        owner_pool: &sqlx::PgPool,
        org_id: Uuid,
        name: &str,
        role: &str,
    ) -> (Uuid, TenantContext) {
        let actor_id = Uuid::now_v7();
        sqlx::query("INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)")
            .bind(actor_id)
            .bind(org_id)
            .bind(name)
            .bind(name)
            .execute(owner_pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, $3)",
        )
        .bind(actor_id)
        .bind(org_id)
        .bind(role)
        .execute(owner_pool)
        .await
        .unwrap();
        (
            actor_id,
            TenantContext::new(OrganizationId(org_id), actor_id, "m7-test"),
        )
    }

    let (exec_id, exec_ctx) = mk_actor(&owner_pool, org_id, "exec", "executive").await;
    let (employee_id, employee_ctx) = mk_actor(&owner_pool, org_id, "emp", "employee").await;
    let (contractor_id, contractor_ctx) = mk_actor(&owner_pool, org_id, "con", "contractor").await;

    let mut e = AgentEnv {
        org_id,
        exec_id,
        employee_id,
        contractor_id,
        exec_ctx,
        employee_ctx,
        contractor_ctx,
        core: core.clone(),
        owner: owner.clone(),
        ontology,
        gateway: ModelGateway::new(core.clone(), owner.clone()),
        attachment_id: Uuid::nil(),
        profile_key: "renewal".to_string(),
        acme_id: Uuid::nil(),
        globex_id: Uuid::nil(),
        alice_id: Uuid::nil(),
        deal_d1: Uuid::nil(),
        deal_d2: Uuid::nil(),
    };

    seed_data(&mut e).await;
    seed_policies(&mut e).await;
    seed_gateway(&mut e).await;

    e
}

/// Physical column for an api field on a pack object.
async fn phys(env: &AgentEnv, object_slug: &str, api_name: &str) -> String {
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

async fn insert_company(env: &AgentEnv, name: &str, industry: &str, size: &str) -> Uuid {
    let c_name = phys(env, "crm_company", "name").await;
    let c_ind = phys(env, "crm_company", "industry").await;
    let c_size = phys(env, "crm_company", "size").await;
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let (id,): (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.crm_company (organization_id, \"{c_name}\", \"{c_ind}\", \"{c_size}\")
         VALUES ($1, $2, $3, $4) RETURNING id"
    ))
    .bind(env.org_id)
    .bind(name)
    .bind(industry)
    .bind(size)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

async fn insert_contact(env: &AgentEnv, name: &str, email: &str, company_id: Uuid) -> Uuid {
    let c_name = phys(env, "crm_contact", "name").await;
    let c_email = phys(env, "crm_contact", "email").await;
    let c_company = phys(env, "crm_contact", "company").await;
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let (id,): (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.crm_contact (organization_id, \"{c_name}\", \"{c_email}\", \"{c_company}\")
         VALUES ($1, $2, $3, $4) RETURNING id"
    ))
    .bind(env.org_id)
    .bind(name)
    .bind(email)
    .bind(company_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

async fn insert_deal(
    env: &AgentEnv,
    name: &str,
    amount: &str,
    stage: &str,
    contact_id: Uuid,
    company_id: Uuid,
    notes: &str,
) -> Uuid {
    use sqlx::types::BigDecimal;
    let c_name = phys(env, "crm_deal", "name").await;
    let c_amount = phys(env, "crm_deal", "amount").await;
    let c_stage = phys(env, "crm_deal", "stage").await;
    let c_contact = phys(env, "crm_deal", "contact").await;
    let c_company = phys(env, "crm_deal", "company").await;
    let c_notes = phys(env, "crm_deal", "notes").await;
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let (id,): (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.crm_deal
           (organization_id, \"{c_name}\", \"{c_amount}\", \"{c_stage}\",
            \"{c_contact}\", \"{c_company}\", \"{c_notes}\")
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id"
    ))
    .bind(env.org_id)
    .bind(name)
    .bind(BigDecimal::from_str(amount).unwrap())
    .bind(stage)
    .bind(contact_id)
    .bind(company_id)
    .bind(serde_json::Value::String(notes.to_string()))
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

async fn seed_data(env: &mut AgentEnv) {
    let acme = insert_company(env, "Acme Corp", "Manufacturing", "enterprise").await;
    let globex = insert_company(env, "Globex", "Technology", "smb").await;
    let alice = insert_contact(env, "Alice Anderson", "alice@acme.example", acme).await;
    let _bob = insert_contact(env, "Bob Baker", "bob@acme.example", acme).await;
    let carol = insert_contact(env, "Carol Cole", "carol@globex.example", globex).await;
    let d1 = insert_deal(
        env,
        "Acme Expansion",
        "50000",
        "proposal",
        alice,
        acme,
        "Acme wants 200 more seats. Champion is Alice; economic buyer is the CFO.",
    )
    .await;
    let d2 = insert_deal(
        env,
        "Globex Pilot",
        "200000",
        "qualified",
        carol,
        globex,
        "Globex pilot for the EU division. Sensitive: internal discount approved.",
    )
    .await;
    env.acme_id = acme;
    env.globex_id = globex;
    env.alice_id = alice;
    env.deal_d1 = d1;
    env.deal_d2 = d2;
}

async fn object_id(env: &AgentEnv, slug: &str) -> Uuid {
    let row: (Uuid,) =
        sqlx::query_as("SELECT id FROM ontology_objects WHERE api_slug=$1 AND state='active'")
            .bind(slug)
            .fetch_one(&env.owner.0)
            .await
            .unwrap();
    row.0
}

async fn grant_fields(env: &AgentEnv, object_slug: &str, role: &str, fields: &[&str]) {
    let oid = object_id(env, object_slug).await;
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    for f in fields {
        sqlx::query(
            "INSERT INTO field_grants (organization_id, object_id, role, field_api_name)
             VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
        )
        .bind(env.org_id)
        .bind(oid)
        .bind(role)
        .bind(*f)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

async fn put_transform(
    env: &AgentEnv,
    object_slug: &str,
    role: &str,
    field: &str,
    transform: serde_json::Value,
) {
    let oid = object_id(env, object_slug).await;
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO field_transforms
             (organization_id, object_id, role, field_api_name, transform)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (organization_id, object_id, role, field_api_name)
         DO UPDATE SET transform = EXCLUDED.transform",
    )
    .bind(env.org_id)
    .bind(oid)
    .bind(role)
    .bind(field)
    .bind(transform)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Per-role policies: the PRD §15 field-policy sketch, on real columns.
/// deal.amount: executive → actual, employee → bucket, contractor → omit
/// (not in the allowlist at all). contact.email: executive → actual,
/// employee → mask. deal.notes: executive → llm_transform (richtext).
async fn seed_policies(env: &mut AgentEnv) {
    let deal_all = ["name", "amount", "stage", "contact", "company", "notes"];
    let deal_emp = ["name", "amount", "stage"];
    let deal_con = ["name", "stage"];
    let company_all = ["name", "industry", "size"];
    let contact_exec = ["name", "email", "phone", "title", "company"];
    let contact_emp = ["name", "email", "company"];

    grant_fields(env, "crm_deal", "executive", &deal_all).await;
    grant_fields(env, "crm_deal", "employee", &deal_emp).await;
    grant_fields(env, "crm_deal", "contractor", &deal_con).await;
    grant_fields(env, "crm_company", "executive", &company_all).await;
    grant_fields(env, "crm_company", "employee", &company_all).await;
    grant_fields(env, "crm_company", "contractor", &company_all).await;
    grant_fields(env, "crm_contact", "executive", &contact_exec).await;
    grant_fields(env, "crm_contact", "employee", &contact_emp).await;

    put_transform(
        env,
        "crm_deal",
        "executive",
        "amount",
        serde_json::json!({"kind": "actual"}),
    )
    .await;
    put_transform(
        env,
        "crm_deal",
        "employee",
        "amount",
        serde_json::json!({
            "kind": "bucket",
            "labels": ["Low", "Medium", "High"],
            "thresholds": [10000, 100000],
        }),
    )
    .await;
    put_transform(
        env,
        "crm_deal",
        "executive",
        "notes",
        serde_json::json!({
            "kind": "llm_transform",
            "provider": "notes-llm",
            "profile": "substance",
        }),
    )
    .await;
    put_transform(
        env,
        "crm_contact",
        "employee",
        "email",
        serde_json::json!({"kind": "mask", "keep_last": 12}),
    )
    .await;
    put_transform(
        env,
        "crm_contact",
        "executive",
        "email",
        serde_json::json!({"kind": "actual"}),
    )
    .await;

    // Model providers: one live fake, one down (degradation test).
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    for (name, kind, status) in [
        ("notes-llm", "fake", "available"),
        ("notes-llm-down", "fake", "unavailable"),
    ] {
        sqlx::query(
            "INSERT INTO model_providers
                 (organization_id, name, kind, placement_boundary, status)
             VALUES ($1, $2, $3, 'org-controlled', $4)
             ON CONFLICT (organization_id, name) DO UPDATE SET status = EXCLUDED.status",
        )
        .bind(env.org_id)
        .bind(name)
        .bind(kind)
        .bind(status)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    // Renewal copilot attachment (PRD budgets: 50 runs/hr, 12 tool steps).
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let (attachment_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO agent_attachments
             (organization_id, actor_id, name, kind, scope,
              action_grants, approval_policy, budgets, status)
         VALUES ($1, $2, 'renewal-copilot', 'renewal_copilot', $3, $4, $5, $6, 'active')
         RETURNING id",
    )
    .bind(env.org_id)
    .bind(env.exec_id)
    .bind(serde_json::json!({
        "root_objects": ["crm_deal"],
        "allowed_relation_types": ["crm_deal.company", "crm_deal.contact", "crm_contact.company"],
        "max_depth": 2,
    }))
    .bind(serde_json::json!([
        "deal.add_note",
        "task.create",
        "email.create_draft"
    ]))
    .bind(serde_json::json!({"human_before_external_send": true}))
    .bind(serde_json::json!({"max_runs_per_hour": 50, "max_tool_steps": 12}))
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    env.attachment_id = attachment_id;

    // Context profile: draft -> released -> active.
    let engine = tinker_agents::profiles::ProfileEngine::new(env.core.clone(), env.owner.clone());
    let draft = engine
        .draft(
            &env.exec_ctx,
            &env.profile_key,
            serde_json::json!({
                "root_objects": ["crm_deal"],
                "relation_depth": 2,
                "permitted_fields": {
                    "crm_deal": ["name", "amount", "stage", "contact", "company", "notes"],
                    "crm_contact": ["name", "email", "company"],
                    "crm_company": ["name", "industry", "size"],
                },
                "token_budget": 12000,
                "ranking_policy": "task_fit_then_freshness",
                "freshness_threshold": "7d",
            }),
        )
        .await
        .unwrap();
    engine.release(&env.exec_ctx, draft.id).await.unwrap();
}

/// Gateway adapters: deterministic fake + always-down.
async fn seed_gateway(env: &mut AgentEnv) {
    let fake = FakeModelAdapter::new("notes-llm").with_response(
        "substance",
        "Seats expansion; champion Alice; CFO economic buyer.",
    );
    env.gateway.register("notes-llm", Arc::new(fake));
    env.gateway.register(
        "notes-llm-down",
        Arc::new(UnavailableModelAdapter::new("notes-llm-down")),
    );
}

/// The hostile gateway used by the prompt-injection tests: a model that
/// returns tool-granting / scope-changing / approval-suppressing payloads.
pub fn hostile_gateway(env: &AgentEnv, payload: &str) -> ModelGateway {
    use tinker_agents::gateway::HostileModelAdapter;
    let mut gw = ModelGateway::new(env.core.clone(), env.owner.clone());
    gw.register(
        "notes-llm",
        Arc::new(HostileModelAdapter::new("notes-llm", payload)),
    );
    gw
}

/// Read the raw (untransformed) deal amount for assertions.
pub async fn raw_amount(env: &AgentEnv, deal_id: Uuid) -> String {
    let c = phys(env, "crm_deal", "amount").await;
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let (v,): (sqlx::types::BigDecimal,) = sqlx::query_as(&format!(
        "SELECT \"{c}\" FROM data.crm_deal WHERE organization_id = $1 AND id = $2"
    ))
    .bind(env.org_id)
    .bind(deal_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    v.to_string()
}

/// Count disclosure audit rows for a virtual path.
pub async fn audit_count(env: &AgentEnv, path: &str) -> i64 {
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM disclosure_audit WHERE organization_id = $1 AND virtual_path = $2",
    )
    .bind(env.org_id)
    .bind(path)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    n
}
