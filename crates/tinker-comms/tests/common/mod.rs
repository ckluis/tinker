//! Item 36 test harness: inbound email + templates.
//!
//! Light fixture (two orgs, one actor each, comms objects installed,
//! FileStore on a temp dir). Each #[tokio::test] gets fresh pools —
//! pools must not be shared across runtimes.

#![allow(dead_code)]

use std::sync::Arc;
use tinker_agents::files::{FileStore, FsFileBackend};
use tinker_comms::{Comms, InboundConfig, InboundDeps, InstalledComms};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_live::SignalBus;
use tinker_ontology::Ontology;
use uuid::Uuid;

pub const MASTER_SECRET: &str = "test-master-secret-0123456789abcdef";

pub struct Item36Env {
    pub org_a: Uuid,
    pub org_b: Uuid,
    pub actor_a: Uuid,
    pub actor_b: Uuid,
    pub ctx_a: TenantContext,
    pub ctx_b: TenantContext,
    pub core: CoreDb,
    pub owner: OwnerDb,
    pub ontology: Ontology,
    pub signals: SignalBus,
    pub installed: InstalledComms,
    pub file_root: std::path::PathBuf,
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

pub async fn setup() -> Item36Env {
    // Webhook master secret (process-global; same value every time, so
    // parallel tests within one binary are safe).
    std::env::set_var("TINKER_INBOUND_WEBHOOK_SECRET", MASTER_SECRET);

    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let core = CoreDb(tenant_pool.clone());
    let owner = OwnerDb(owner_pool.clone());
    let ontology = Ontology::new(core.clone(), owner.clone());
    let signals = SignalBus::new();
    let comms = Comms::new(core.clone(), ontology.clone(), signals.clone());
    comms.install().await.unwrap();
    let installed = comms.installed().await.unwrap().clone();

    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("item36-host")
        .execute(&owner_pool)
        .await
        .unwrap();

    async fn mk_org(owner_pool: &sqlx::PgPool, host_id: Uuid, tag: &str) -> Uuid {
        let org_id = Uuid::now_v7();
        sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
            .bind(org_id)
            .bind(host_id)
            .bind(format!("i36-{tag}-{}", org_id.simple()))
            .bind("item36 org")
            .execute(owner_pool)
            .await
            .unwrap();
        org_id
    }

    async fn mk_actor(
        owner_pool: &sqlx::PgPool,
        org_id: Uuid,
        name: &str,
    ) -> (Uuid, TenantContext) {
        let actor_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO actors (id, organization_id, display_name, handle)
             VALUES ($1, $2, $3, $4)",
        )
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
        .bind("member")
        .execute(owner_pool)
        .await
        .unwrap();
        (
            actor_id,
            TenantContext::new(OrganizationId(org_id), actor_id, "item36-test"),
        )
    }

    let org_a = mk_org(&owner_pool, host_id, "a").await;
    let org_b = mk_org(&owner_pool, host_id, "b").await;
    let (actor_a, ctx_a) = mk_actor(&owner_pool, org_a, "i36-alice").await;
    let (actor_b, ctx_b) = mk_actor(&owner_pool, org_b, "i36-bob").await;

    let file_root = std::env::temp_dir().join(format!(
        "tinker-i36-{}-{}",
        std::process::id(),
        Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&file_root).unwrap();

    Item36Env {
        org_a,
        org_b,
        actor_a,
        actor_b,
        ctx_a,
        ctx_b,
        core,
        owner,
        ontology,
        signals,
        installed,
        file_root,
    }
}

/// Tight caps so cap tests don't need megabytes.
pub fn test_config() -> InboundConfig {
    InboundConfig {
        master_secret: MASTER_SECRET.as_bytes().to_vec(),
        max_attachments: 3,
        max_attachment_bytes: 1024,
        max_total_attachment_bytes: 2048,
        replay_window: std::time::Duration::from_secs(300),
    }
}

pub fn file_store_for(e: &Item36Env) -> FileStore {
    FileStore::new(
        e.core.clone(),
        Arc::new(FsFileBackend::new(e.file_root.clone())),
    )
}

pub fn deps_for(e: &Item36Env, with_search: bool) -> InboundDeps {
    let search_backend: Option<Arc<dyn tinker_search::SearchBackend>> = if with_search {
        Some(Arc::new(tinker_search::NativeSearchBackend::new(
            e.core.clone(),
        )))
    } else {
        None
    };
    InboundDeps {
        owner: e.owner.clone(),
        core: e.core.clone(),
        ontology: e.ontology.clone(),
        signals: e.signals.clone(),
        installed: e.installed.clone(),
        file_store: file_store_for(e),
        search_backend,
    }
}

/// `X-Tinker-Signature` value for `raw` as the provider would compute it.
pub fn sign(config: &InboundConfig, org_id: Uuid, raw: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let key = tinker_comms::derive_org_key(&config.master_secret, org_id);
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).unwrap();
    mac.update(raw);
    let hex: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256={hex}")
}

pub fn email_payload(
    provider_id: &str,
    to: &str,
    ts: i64,
    attachments: serde_json::Value,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "provider_id": provider_id,
        "to": to,
        "from": "sender@example.com",
        "subject": "Hello",
        "text_body": "body text",
        "timestamp": ts,
        "attachments": attachments,
    }))
    .unwrap()
}

pub fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

pub async fn register(e: &Item36Env, ctx: &TenantContext, address: &str) {
    tinker_comms::register_inbound_address(
        &e.core,
        &e.ontology,
        &e.signals,
        &e.installed,
        ctx,
        address,
        "Support inbox",
    )
    .await
    .unwrap();
}

pub async fn message_count(e: &Item36Env, ctx: &TenantContext) -> i64 {
    let mut tx = e.core.tenant_tx(ctx).await.unwrap();
    let n: i64 = sqlx::query_scalar(&format!(
        "SELECT COUNT(*) FROM {} WHERE organization_id = $1",
        e.installed.message_table
    ))
    .bind(ctx.organization_id.0)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    n
}

pub async fn stored_file_count(e: &Item36Env, org_id: Uuid) -> i64 {
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM stored_files WHERE organization_id = $1")
        .bind(org_id)
        .fetch_one(&e.owner.0)
        .await
        .unwrap();
    n
}

/// Globally-unique recipient address (the registry is global).
pub fn unique_addr(tag: &str) -> String {
    format!("i36-{tag}-{}@example.com", Uuid::now_v7().simple())
}
