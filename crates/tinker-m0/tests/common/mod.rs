//! Shared M0 exit-test setup. Not shipped (dev-only).
//!
//! Different test binaries use different subsets of this scaffolding;
//! dead-code warnings are noise here, not signal.
#![allow(dead_code)]

use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, PiiDb};
use tokio::sync::OnceCell;
use uuid::Uuid;

/// Shared M0 exit-test setup. Not shipped (dev-only).
pub struct Env {
    pub core: CoreDb,
    pub core_owner: sqlx::PgPool,
    pub pii: PiiDb,
    pub pii_owner: sqlx::PgPool,
    pub host_id: Uuid,
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// Connect, run migrations once per test binary, return handles.
/// Owner pools connect first: migrations create the app roles, so the
/// app-role pools can only connect after migrations have run.
pub async fn setup() -> Env {
    let core_owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("core owner connect");
    let pii_owner = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
        .await
        .expect("pii owner connect");

    // Migrations run once per test binary, asynchronously: no nested
    // runtime, no blocked worker threads. They run as the OWNER role
    // (creating roles, extensions, RLS policies); the app role could not.
    MIGRATED
        .get_or_init(|| async {
            tinker_db::MIGRATOR_CORE
                .run(&core_owner)
                .await
                .expect("core migrations");
            tinker_db::MIGRATOR_PII
                .run(&pii_owner)
                .await
                .expect("pii migrations");
        })
        .await;

    // App roles are created by the migrations above.
    let core = CoreDb::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("core app-role connect");
    let pii = PiiDb::connect(&env("TINKER_PII_URL"))
        .await
        .expect("pii app-role connect");

    // Fixed test host (owner bypasses RLS for platform rows).
    let host_id = Uuid::from_u128(0x0);
    sqlx::query(
        "INSERT INTO hosts (id, name) VALUES ($1,'test') \
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(host_id)
    .execute(&core_owner)
    .await
    .expect("host upsert");

    Env {
        core,
        core_owner,
        pii,
        pii_owner,
        host_id,
    }
}

/// A fresh organization per test: parallel tests never share tenant rows.
pub async fn new_org(env: &Env, slug: &str) -> TenantContext {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "m0-test".to_string(),
    )
}

/// Unique slug per test: parallel tests must not collide on object names.
/// NOTE: takes the LAST 8 hex chars of the v7 UUID — the first 8 are the
/// timestamp and identical for tests started in the same millisecond.
pub fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{}_{}", prefix, &s[24..32])
}
