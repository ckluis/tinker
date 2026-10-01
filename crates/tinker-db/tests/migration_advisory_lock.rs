//! Post-M8 item 30 (scale-out spike): migration ownership across
//! instances.
//!
//! Every instance runs migrations at startup against the same database.
//! These tests pin the contract: [`tinker_db::MIGRATION_LOCK_CORE`] is a
//! cluster-wide Postgres advisory lock held for the whole migration, so
//!
//! - N concurrent `migrate()` calls all succeed and the schema is
//!   applied exactly once (no duplicate-DDL races);
//! - a `migrate()` that starts while another session holds the lock
//!   BLOCKS until the lock is released (proves serialization, not just
//!   idempotence).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tinker_db::{OwnerDb, MIGRATION_LOCK_CORE};

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

async fn owner_db() -> OwnerDb {
    let pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("owner connect");
    OwnerDb(pool)
}

#[tokio::test]
async fn concurrent_migrates_all_succeed_and_apply_once() {
    let db = owner_db().await;
    // Eight "instances" migrating at once: all must succeed.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let d = db.clone();
        handles.push(tokio::spawn(async move { d.migrate().await }));
    }
    for h in handles {
        h.await
            .expect("task panicked")
            .expect("concurrent migrate failed");
    }
    // Exactly one row per migration version: no double-apply.
    let (count, distinct): (i64, i64) =
        sqlx::query_as("SELECT COUNT(*), COUNT(DISTINCT version) FROM _sqlx_migrations")
            .fetch_one(&db.0)
            .await
            .expect("count applied migrations");
    assert!(count > 0, "migrations should be applied");
    assert_eq!(
        count, distinct,
        "every applied migration version must be unique"
    );
}

#[tokio::test]
async fn migrate_blocks_while_another_session_holds_the_lock() {
    let db = owner_db().await;
    // Hold the documented lock on a scratch session, simulating a
    // migrator on another host.
    let mut holder = db.0.acquire().await.expect("acquire holder");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATION_LOCK_CORE)
        .execute(&mut *holder)
        .await
        .expect("take advisory lock");

    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    let d = db.clone();
    tokio::spawn(async move {
        // Ignore the outcome; the assertion is about blocking.
        let _ = d.migrate().await;
        flag.store(true, Ordering::SeqCst);
    });

    // Generous margin: an uncontended migrate() finishes in
    // milliseconds. While the lock is held it must NOT finish.
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        !done.load(Ordering::SeqCst),
        "migrate() must block while another session holds MIGRATION_LOCK_CORE"
    );

    // Release: the blocked migrate() must now complete.
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_LOCK_CORE)
        .execute(&mut *holder)
        .await
        .expect("release advisory lock");
    drop(holder);
    let finished = tokio::time::timeout(Duration::from_secs(30), async {
        while !done.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        finished.is_ok(),
        "migrate() must complete after the lock is released"
    );
}
