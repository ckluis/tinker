//! Post-M8 item 14: migration source-checksum verification.
//!
//! `bin/pg-ensure.sh` used to compare migration *counts* after running the
//! migrator. These tests pin the stronger guarantee: the SHA-384 of every
//! `.sql` file on disk matches the checksum recorded in
//! `_sqlx_migrations`, the embedded migration set matches the source tree,
//! and the verifier fails closed on every drift shape — without ever
//! touching the real `_sqlx_migrations` table (drift is simulated with
//! copied directories).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

/// Copy a migrations dir to a scratch dir (so drift simulations never
/// touch the real source tree). The caller removes the scratch dir when
/// done.
fn copy_migrations_to_scratch(subdir: &str) -> PathBuf {
    let n = SCRATCH_SEQ.fetch_add(1, Ordering::SeqCst);
    let scratch = std::env::temp_dir().join(format!("tinker-migcheck-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    copy_dir(&crate_dir().join(subdir), &scratch);
    scratch
}

fn copy_dir(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).unwrap();
        }
    }
}

fn disk_versions(subdir: &str) -> Vec<i64> {
    let dir = crate_dir().join(subdir);
    let mut versions: Vec<i64> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let name = e.ok()?.file_name().to_str()?.to_string();
            if !name.ends_with(".sql") || name.ends_with(".down.sql") {
                return None;
            }
            name.split('_').next()?.parse::<i64>().ok()
        })
        .collect();
    versions.sort_unstable();
    versions
}

#[test]
fn disk_checksums_match_embedded() {
    // No database needed: proves the checksum algorithm is byte-identical
    // to sqlx::migrate!'s and that the compiled binary is in sync with the
    // source tree (build.rs rerun-if-changed is the mechanism; this is the
    // proof).
    for (migrator, subdir) in [
        (&tinker_db::MIGRATOR_CORE, "migrations/core"),
        (&tinker_db::MIGRATOR_PII, "migrations/pii"),
    ] {
        let dir = crate_dir().join(subdir);
        let mut files = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            if !name.ends_with(".sql") || name.ends_with(".down.sql") {
                continue;
            }
            let version: i64 = name.split('_').next().unwrap().parse().unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let embedded = migrator
                .migrations
                .iter()
                .find(|m| m.version == version)
                .unwrap_or_else(|| {
                    panic!("{subdir}: disk file {name} has no embedded migration — stale binary?")
                });
            assert_eq!(
                tinker_db::migration_checksum(&bytes).as_slice(),
                embedded.checksum.as_ref(),
                "{subdir}: checksum algorithm drift for {name}"
            );
            files += 1;
        }
        assert_eq!(
            files,
            migrator.migrations.len(),
            "{subdir}: disk/embedded migration count mismatch"
        );
        assert_eq!(
            files,
            disk_versions(subdir).len(),
            "{subdir}: internal consistency"
        );
    }
}

#[tokio::test]
async fn verify_passes_on_live_databases() {
    // The cluster is provisioned by pg-ensure (migrations run, then this
    // same verifier): source files must equal applied checksums.
    for (key, migrator, subdir) in [
        (
            "TINKER_CORE_OWNER_URL",
            &tinker_db::MIGRATOR_CORE,
            "migrations/core",
        ),
        (
            "TINKER_PII_OWNER_URL",
            &tinker_db::MIGRATOR_PII,
            "migrations/pii",
        ),
    ] {
        let pool = sqlx::PgPool::connect(&env(key)).await.unwrap();
        let n = tinker_db::verify_migration_checksums(&pool, migrator, &crate_dir().join(subdir))
            .await
            .unwrap_or_else(|e| {
                panic!("{key}: verification must pass on a pg-ensure provisioned cluster: {e}")
            });
        assert_eq!(n, migrator.migrations.len(), "{key}: verified count");
    }
}

#[tokio::test]
async fn verify_fails_closed_on_edited_file() {
    // Simulate the forbidden act: editing an applied migration. The
    // verifier must name the version, not just fail generically.
    let dir = copy_migrations_to_scratch("migrations/core");
    let victim = dir.join("0002_ontology.sql");
    let mut bytes = std::fs::read(&victim).unwrap();
    let i = bytes
        .iter()
        .position(|b| *b == b';')
        .expect("migration must contain a semicolon");
    bytes[i] = b',';
    std::fs::write(&victim, bytes).unwrap();

    let pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let err = tinker_db::verify_migration_checksums(&pool, &tinker_db::MIGRATOR_CORE, &dir)
        .await
        .expect_err("edited migration file must fail verification");
    match err {
        tinker_db::MigrationChecksumError::ChecksumMismatch { version, .. } => {
            assert_eq!(version, 2, "must name the edited version")
        }
        other => panic!("expected ChecksumMismatch, got {other}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn verify_fails_closed_on_unapplied_file() {
    // A migration file the database has never seen.
    let dir = copy_migrations_to_scratch("migrations/core");
    std::fs::write(dir.join("9999_future.sql"), "SELECT 1;").unwrap();

    let pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let err = tinker_db::verify_migration_checksums(&pool, &tinker_db::MIGRATOR_CORE, &dir)
        .await
        .expect_err("unapplied migration file must fail verification");
    match err {
        tinker_db::MigrationChecksumError::NotApplied { version, .. } => {
            assert_eq!(version, 9999, "must name the unapplied version")
        }
        other => panic!("expected NotApplied, got {other}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn verify_fails_closed_on_unknown_applied_row() {
    // The database applied something with no file on disk (e.g. a file
    // deleted from the tree after apply).
    let dir = copy_migrations_to_scratch("migrations/core");
    std::fs::remove_file(dir.join("0003_durable.sql")).unwrap();

    let pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let err = tinker_db::verify_migration_checksums(&pool, &tinker_db::MIGRATOR_CORE, &dir)
        .await
        .expect_err("applied row with no disk file must fail verification");
    match err {
        tinker_db::MigrationChecksumError::UnknownApplied { version } => {
            assert_eq!(version, 3, "must name the orphaned version")
        }
        other => panic!("expected UnknownApplied, got {other}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn core_migrations_start_at_one_and_are_dense() {
    // The verifier assumes a dense version sequence per store; pin it so a
    // gap can't silently weaken the "every file applied" check.
    let versions = disk_versions("migrations/core");
    assert!(!versions.is_empty());
    for (i, v) in versions.iter().enumerate() {
        assert_eq!(*v, i as i64 + 1, "core migrations must be dense from 1");
    }
    let pii = disk_versions("migrations/pii");
    for (i, v) in pii.iter().enumerate() {
        assert_eq!(*v, i as i64 + 1, "pii migrations must be dense from 1");
    }
}
