//! M8 test harness: authority transfer and hardening.
//!
//! Fixture: one org with an operator actor, a support actor, and a second
//! approver actor; the CRM pack's platform objects installed (so the
//! authority matrix has tenant-visible objects to govern); a synthetic
//! `salesforce` system registered in `connected` state.

#![allow(dead_code)]

use tinker_apps::AppRegistry;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb, PiiDb};
use tinker_ontology::Ontology;
use tinker_packs::{PackDefinition, PackInstaller};
use uuid::Uuid;

pub struct TransferEnv {
    pub org_id: Uuid,
    pub host_id: Uuid,
    pub operator_id: Uuid,
    pub support_id: Uuid,
    pub approver_id: Uuid,
    /// A second support actor in the same org (adversarial coverage).
    pub support2_id: Uuid,
    pub operator_ctx: TenantContext,
    /// Context whose actor is the support actor (for reveal requests).
    pub support_ctx: TenantContext,
    /// Context for the second support actor (must NOT use the first's sessions).
    pub support2_ctx: TenantContext,
    /// Context whose actor is the approver (second party).
    pub approver_ctx: TenantContext,
    pub core: CoreDb,
    pub owner: OwnerDb,
    pub pii: PiiDb,
    pub ontology: Ontology,
    /// A tenant-visible ontology object to govern.
    pub deal_object_id: Uuid,
    pub system_id: Uuid,
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

/// Fresh pools per call: each #[tokio::test] runs on its own
/// current-thread runtime, and pools must not be shared across runtimes.
pub async fn setup() -> TransferEnv {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let pii_pool = sqlx::PgPool::connect(&env("TINKER_PII_URL")).await.unwrap();
    let core = CoreDb(tenant_pool.clone());
    let owner = OwnerDb(owner_pool.clone());
    let pii = PiiDb(pii_pool);
    let ontology = Ontology::new(core.clone(), owner.clone());

    // Install the CRM pack for tenant-visible ontology objects.
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
        .bind("m8-host")
        .execute(&owner_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("m8-{}", org_id.simple()))
        .bind("m8 org")
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
            TenantContext::new(OrganizationId(org_id), actor_id, "m8-test"),
        )
    }

    let (operator_id, operator_ctx) = mk_actor(&owner_pool, org_id, "operator", "admin").await;
    let (support_id, support_ctx) = mk_actor(&owner_pool, org_id, "support", "support").await;
    let (support2_id, support2_ctx) = mk_actor(&owner_pool, org_id, "support2", "support").await;
    let (approver_id, approver_ctx) = mk_actor(&owner_pool, org_id, "approver", "admin").await;

    // Look up the CRM deal object (platform object, visible to all orgs).
    let deal_object_id: Uuid =
        sqlx::query_as("SELECT id FROM ontology_objects WHERE api_slug='crm_deal'")
            .fetch_one(&owner_pool)
            .await
            .map(|(id,): (Uuid,)| id)
            .unwrap();

    // Register the synthetic Salesforce slice; it starts `connected`.
    let system_id = tinker_transfer::TransferEngine::new(core.clone())
        .register_system(&operator_ctx, "salesforce", "Salesforce (mirror)")
        .await
        .unwrap();

    TransferEnv {
        org_id,
        host_id,
        operator_id,
        support_id,
        approver_id,
        support2_id,
        operator_ctx,
        support_ctx,
        support2_ctx,
        approver_ctx,
        core,
        owner,
        pii,
        ontology,
        deal_object_id,
        system_id,
    }
}

/// Drive a system from `connected` to `controlled` (no gates on these
/// forward steps).
pub async fn to_controlled(env: &TransferEnv) {
    let eng = tinker_transfer::TransferEngine::new(env.core.clone());
    for _ in 0..3 {
        eng.advance(
            &env.operator_ctx,
            env.system_id,
            env.operator_id,
            "test advance",
        )
        .await
        .unwrap();
    }
    let (state, _) = eng
        .state_of(&env.operator_ctx, env.system_id)
        .await
        .unwrap();
    assert_eq!(state, tinker_transfer::TransferState::Controlled);
}

/// Complete a run of `kind`, verifying every gate item with evidence.
pub async fn complete_run_with_evidence(
    env: &TransferEnv,
    kind: tinker_transfer::CutoverKind,
) -> Uuid {
    let eng = tinker_transfer::TransferEngine::new(env.core.clone());
    let run_id = eng
        .start_run(&env.operator_ctx, env.system_id, kind)
        .await
        .unwrap();
    let items: &[&str] = match kind {
        tinker_transfer::CutoverKind::Rollback => &["rollback_procedure", "owner_signoff"],
        _ => &[
            "export_verified",
            "rollback_procedure",
            "owner_signoff",
            "dependency_scan",
            "reconciliation_clean",
        ],
    };
    for item in items {
        eng.verify_checklist_item(
            &env.operator_ctx,
            run_id,
            item,
            env.operator_id,
            &format!("test evidence for {item}: harness-generated artifact #42"),
        )
        .await
        .unwrap();
    }
    eng.complete_run(&env.operator_ctx, run_id).await.unwrap();
    run_id
}

/// Seed one PII value row (dummy ciphertext is fine: the rehearsal only
/// resolves presence). Returns the value id.
pub async fn seed_pii_value(env: &TransferEnv) -> Uuid {
    let dek_id = Uuid::now_v7();
    let val_id = Uuid::now_v7();
    let mut tx = env.pii.tenant_tx(&env.operator_ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO wrapped_deks (id, organization_id, kek_id, wrapped_key, version)
         VALUES ($1, $2, 'test-kek', $3, 1)
         ON CONFLICT ON CONSTRAINT wrapped_deks_org_subject_version DO NOTHING",
    )
    .bind(dek_id)
    .bind(env.org_id)
    .bind(vec![0u8; 32])
    .execute(&mut *tx)
    .await
    .unwrap();
    // Re-read the DEK id in case the conflict branch hit.
    let dek_id: Uuid =
        sqlx::query_as(
            "SELECT id FROM wrapped_deks WHERE organization_id = $1 AND subject_id IS NULL AND version = 1",
        )
            .bind(env.org_id)
            .fetch_one(&mut *tx)
            .await
            .map(|(id,): (Uuid,)| id)
            .unwrap();
    sqlx::query(
        "INSERT INTO pii_values
             (id, organization_id, subject_id, storage_class, ciphertext, nonce, wrapped_dek_id)
         VALUES ($1, $2, $3, 'field', $4, $5, $6)",
    )
    .bind(val_id)
    .bind(env.org_id)
    .bind(Uuid::now_v7())
    .bind(vec![1u8; 32])
    .bind(vec![2u8; 12])
    .bind(dek_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    val_id
}
