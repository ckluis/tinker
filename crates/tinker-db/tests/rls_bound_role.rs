//! `CoreDb::connect` is the tenant pool: it must refuse a role that
//! row-level security does not bind. The owner role (which owns every
//! RLS table and is exempt from non-FORCE policies) is the realistic
//! mis-wiring — `tinker` and `tinker-mcp` once read `TINKER_CORE_URL`
//! with opposite meanings.

use tinker_core::TinkerError;
use tinker_db::CoreDb;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

#[tokio::test]
async fn tenant_pool_refuses_owner_role_and_accepts_app_role() {
    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("owner connect");
    tinker_db::MIGRATOR_CORE.run(&owner).await.expect("migrate");

    let err = CoreDb::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect_err("owner URL must not become a tenant pool");
    match err {
        TinkerError::Validation(msg) => {
            assert!(msg.contains("owns RLS-protected tables"), "{msg}")
        }
        other => panic!("expected Validation, got {other:?}"),
    }

    CoreDb::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("app role is RLS-bound and must connect");
}
