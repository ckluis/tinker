//! PII store RLS at the raw SQL level: the `tinker_pii_app` role must
//! see only the organization it declares, and nothing without a context.
//! This is the fail-closed backstop behind the audited projector.
//!
//! Note (post-M8 item 16): the `vault_items` table was dropped — it never
//! gained a consumer (no code path read or wrote it; the app role was
//! denied entirely via `USING (false)`). The assertion below pins its
//! absence so a future re-introduction is a deliberate, tested change.

use sqlx::Acquire;
use uuid::Uuid;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

async fn scoped_count(app: &sqlx::PgPool, org: Uuid, table: &str) -> i64 {
    let mut tx = app.begin().await.unwrap();
    sqlx::query(&format!("SET LOCAL app.organization_id = '{org}'"))
        .execute(&mut *tx)
        .await
        .unwrap();
    let (n,): (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM {table}"))
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    n
}

#[tokio::test]
async fn pii_app_role_rls_is_cross_tenant_fail_closed() {
    let owner = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
        .await
        .unwrap();
    let app = sqlx::PgPool::connect(&env("TINKER_PII_URL")).await.unwrap();

    // Seed two orgs through the owner (bypasses RLS, like the projector).
    let org_a = Uuid::now_v7();
    let org_b = Uuid::now_v7();
    for org in [org_a, org_b] {
        let dek: Uuid = sqlx::query_scalar(
            "INSERT INTO wrapped_deks (id, organization_id, kek_id, wrapped_key) \
             VALUES (gen_random_uuid(), $1, 'test-kek', '\\x00') RETURNING id",
        )
        .bind(org)
        .fetch_one(&owner)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO pii_values (id, organization_id, subject_id, storage_class, \
             ciphertext, nonce, wrapped_dek_id) \
             VALUES (gen_random_uuid(), $1, gen_random_uuid(), 'test', '\\x01', '\\x02', $2)",
        )
        .bind(org)
        .bind(dek)
        .execute(&owner)
        .await
        .unwrap();
    }
    // vault_items was dropped (post-M8 item 16): it never had a
    // consumer. Pin its absence — re-introducing a credentials-shaped
    // table must be a deliberate, tested change, not an accident.
    let gone: bool = sqlx::query_scalar("SELECT to_regclass('vault_items') IS NULL")
        .fetch_one(&owner)
        .await
        .unwrap();
    assert!(gone, "vault_items must not exist");

    // Scoped to org A: exactly org A's row, never org B's.
    assert_eq!(scoped_count(&app, org_a, "pii_values").await, 1);
    // Scoped to org B: exactly org B's row.
    assert_eq!(scoped_count(&app, org_b, "pii_values").await, 1);

    // No context on a virgin session: the policy compares against NULL,
    // which matches nothing — clean fail-closed empty.
    let fresh = sqlx::PgPool::connect(&env("TINKER_PII_URL")).await.unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM pii_values")
        .fetch_one(&fresh)
        .await
        .unwrap();
    assert_eq!(n, 0, "no context on a fresh session sees nothing");
    fresh.close().await;

    // Targeted cross-tenant read: scoped to A, org B's row id is invisible.
    let b_id: Uuid = sqlx::query_scalar("SELECT id FROM pii_values WHERE organization_id = $1")
        .bind(org_b)
        .fetch_one(&owner)
        .await
        .unwrap();
    let mut tx = app.begin().await.unwrap();
    sqlx::query(&format!("SET LOCAL app.organization_id = '{org_a}'"))
        .execute(&mut *tx)
        .await
        .unwrap();
    let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM pii_values WHERE id = $1")
        .bind(b_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert!(
        rows.is_empty(),
        "org B's pii row must be invisible to the app role scoped to org A"
    );

    // Unknown org sees nothing.
    let mut tx = app.begin().await.unwrap();
    sqlx::query("SET LOCAL app.organization_id = '00000000-0000-0000-0000-000000000000'")
        .execute(&mut *tx)
        .await
        .unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM pii_values")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(n, 0, "unknown org sees nothing");

    // Sharp edge, pinned as documentation: on a connection that previously
    // ran SET LOCAL inside a rolled-back transaction, PostgreSQL reports
    // the context as '' (not NULL) in the next transaction, and the
    // policy's ::uuid cast rejects it with 22P02. This fails LOUD — an
    // error, never leaked rows. Deterministic: one held connection.
    let mut conn = app.acquire().await.unwrap();
    {
        let mut tx = conn.begin().await.unwrap();
        sqlx::query(&format!("SET LOCAL app.organization_id = '{org_a}'"))
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
    }
    {
        let mut tx = conn.begin().await.unwrap();
        let err = sqlx::query_as::<_, (i64,)>("SELECT count(*) FROM pii_values")
            .fetch_one(&mut *tx)
            .await
            .unwrap_err();
        let db_err = err.as_database_error().expect("must be a db error");
        assert_eq!(
            db_err.code().as_deref(),
            Some("22P02"),
            "stale empty context must fail loud, never leak rows"
        );
        tx.rollback().await.unwrap();
    }

    // Sanity: both seeded rows really exist for the owner.
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM pii_values WHERE organization_id = ANY($1)")
            .bind(vec![org_a, org_b])
            .fetch_one(&owner)
            .await
            .unwrap();
    assert_eq!(n, 2, "owner sees both seeded rows");

    // Keep the shared PII database clean for other suites.
    for org in [org_a, org_b] {
        sqlx::query("DELETE FROM pii_values WHERE organization_id = $1")
            .bind(org)
            .execute(&owner)
            .await
            .unwrap();
        sqlx::query("DELETE FROM wrapped_deks WHERE organization_id = $1")
            .bind(org)
            .execute(&owner)
            .await
            .unwrap();
    }
}
