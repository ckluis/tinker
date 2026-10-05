//! M0 bootstrap gate: every migration applies from scratch into fresh
//! schemas, and the app roles can use the fresh tables. This caught three
//! real bugs: an unqualified gin_trgm_ops that broke under a custom
//! search_path, a missing pg_trgm/pgcrypto CREATE EXTENSION (masked by
//! manual installs in the dev DB), and grants hardcoded to SCHEMA public
//! that left the app role without USAGE on a fresh schema.
//!
//! The privileged bootstrap may install into a fresh database or a
//! dedicated schema; this test proves the migrations follow wherever
//! they run.

mod common;

use sqlx::postgres::PgPoolOptions;
use sqlx::Executor;
use uuid::Uuid;

/// Owner pool with a pinned search_path, so the migrator installs into a
/// fresh schema instead of the shared one.
async fn schema_pool(owner_url: &str, schema: &str) -> sqlx::PgPool {
    let schema = schema.to_string();
    PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |conn, _| {
            let schema = schema.clone();
            Box::pin(async move {
                conn.execute(format!("SET search_path = {schema}").as_str())
                    .await?;
                Ok(())
            })
        })
        .connect(owner_url)
        .await
        .unwrap()
}

#[tokio::test]
async fn bootstrap_applies_cleanly_from_scratch() {
    let env = common::setup().await;
    let tag: String = Uuid::now_v7().simple().to_string()[24..32].to_string();
    let core_schema = format!("clean_core_{tag}");
    let pii_schema = format!("clean_pii_{tag}");

    sqlx::query(&format!("CREATE SCHEMA {core_schema}"))
        .execute(&env.core_owner)
        .await
        .unwrap();
    sqlx::query(&format!("CREATE SCHEMA {pii_schema}"))
        .execute(&env.pii_owner)
        .await
        .unwrap();

    let core_owner_url = std::env::var("TINKER_CORE_OWNER_URL").unwrap();
    let pii_owner_url = std::env::var("TINKER_PII_OWNER_URL").unwrap();

    let core_pool = schema_pool(&core_owner_url, &core_schema).await;
    tinker_db::MIGRATOR_CORE.run(&core_pool).await.unwrap();
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&core_pool)
            .await
            .unwrap();
    // Expect exactly the migrations shipped in the binary — the set grows
    // with each milestone, so derive it from the migrator, never hardcode.
    let expected: Vec<i64> = tinker_db::MIGRATOR_CORE
        .migrations
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(versions, expected);

    let pii_pool = schema_pool(&pii_owner_url, &pii_schema).await;
    tinker_db::MIGRATOR_PII.run(&pii_pool).await.unwrap();
    let pii_versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&pii_pool)
            .await
            .unwrap();
    let pii_expected: Vec<i64> = tinker_db::MIGRATOR_PII
        .migrations
        .iter()
        .map(|m| m.version)
        .collect();
    assert_eq!(pii_versions, pii_expected);

    // The app roles (created idempotently by the 0001 migrations) can reach
    // the fresh tables: USAGE on the schema plus table privileges.
    let app_pool = PgPoolOptions::new()
        .max_connections(1)
        .after_connect({
            let s = core_schema.clone();
            move |conn, _| {
                let s = s.clone();
                Box::pin(async move {
                    conn.execute(format!("SET search_path = {s}").as_str())
                        .await?;
                    Ok(())
                })
            }
        })
        .connect(&std::env::var("TINKER_CORE_URL").unwrap())
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM organizations")
        .fetch_one(&app_pool)
        .await
        .unwrap();
    assert_eq!(n, 0);

    sqlx::query(&format!("DROP SCHEMA {core_schema} CASCADE"))
        .execute(&env.core_owner)
        .await
        .unwrap();
    sqlx::query(&format!("DROP SCHEMA {pii_schema} CASCADE"))
        .execute(&env.pii_owner)
        .await
        .unwrap();
}
