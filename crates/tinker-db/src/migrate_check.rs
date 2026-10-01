//! Source-checksum verification for migrations.
//!
//! `bin/pg-ensure.sh` used to compare migration *counts* (files on disk vs
//! rows in `_sqlx_migrations`) after running the migrator. Counts catch a
//! stale binary's missing migrations, but not a migration file edited after
//! it was applied — applied migrations are immutable, and a silent edit is
//! a schema-integrity hole. This module closes it: every `.sql` file on
//! disk gets a SHA-384 checksum computed with the exact algorithm
//! `sqlx::migrate!` uses at compile time (`Sha384::digest(sql.as_bytes())`
//! over the raw file bytes), and the whole set is compared against
//! `_sqlx_migrations`, failing closed on any drift.

use sha2::{Digest, Sha384};
use sqlx::migrate::Migrator;
use sqlx::postgres::PgPool;
use sqlx::Row;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// SHA-384 over the raw migration file bytes — byte-identical to the
/// checksum `sqlx::migrate!` embeds at compile time.
pub fn migration_checksum(sql: &[u8]) -> [u8; 48] {
    let digest = Sha384::digest(sql);
    let mut out = [0u8; 48];
    out.copy_from_slice(digest.as_slice());
    out
}

/// Every way the migration source tree can disagree with the database.
#[derive(Debug, thiserror::Error)]
pub enum MigrationChecksumError {
    #[error("cannot list migration dir {0}: {1}")]
    DirUnreadable(PathBuf, std::io::Error),
    #[error("cannot read migration file {0}: {1}")]
    FileUnreadable(PathBuf, std::io::Error),
    #[error("cannot parse migration filename {0:?}: expected <VERSION>_<description>.sql")]
    BadFilename(String),
    #[error("database error during checksum verification: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration {version:04} ({description}): on disk but not applied — run the migrator")]
    NotApplied { version: i64, description: String },
    #[error("migration version {version:04}: applied in the database but no file on disk — unknown migration")]
    UnknownApplied { version: i64 },
    #[error("migration {version:04} ({description}): CHECKSUM MISMATCH — the file was edited after it was applied; applied migrations are immutable")]
    ChecksumMismatch { version: i64, description: String },
    #[error("migration {version:04}: embedded checksum differs from the file on disk — stale binary, rebuild")]
    StaleBinary { version: i64 },
}

/// Verify the migration files in `dir` against the `_sqlx_migrations` table
/// in `pool`, and against the migrations embedded in `migrator`.
///
/// Returns the number of migrations verified. Fails closed on:
/// - a file on disk with no applied row ([`MigrationChecksumError::NotApplied`]),
/// - an applied row with no file on disk ([`MigrationChecksumError::UnknownApplied`]),
/// - a checksum mismatch between disk and database — the file was edited
///   after apply ([`MigrationChecksumError::ChecksumMismatch`]),
/// - an embedded migration whose checksum differs from the disk file, or
///   that has no disk file at all — the binary disagrees with the source
///   tree ([`MigrationChecksumError::StaleBinary`]).
///
/// A missing `_sqlx_migrations` table is treated as "nothing applied yet"
/// (fresh database), so every disk file reports [`MigrationChecksumError::NotApplied`].
pub async fn verify_migration_checksums(
    pool: &PgPool,
    migrator: &Migrator,
    dir: &Path,
) -> Result<usize, MigrationChecksumError> {
    // 1. Checksum every up-migration file on disk. Filename parsing mirrors
    // sqlx's own rules: `<VERSION>_<DESCRIPTION>.sql`, `.down.sql` skipped
    // (never applied in the up direction).
    let mut disk: BTreeMap<i64, (String, [u8; 48])> = BTreeMap::new();
    let entries =
        std::fs::read_dir(dir).map_err(|e| MigrationChecksumError::DirUnreadable(dir.into(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| MigrationChecksumError::DirUnreadable(dir.into(), e))?;
        let path = entry.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if !name.ends_with(".sql") || name.ends_with(".down.sql") {
            continue;
        }
        let mut parts = name.splitn(2, '_');
        let version: i64 = parts
            .next()
            .unwrap_or_default()
            .parse()
            .map_err(|_| MigrationChecksumError::BadFilename(name.clone()))?;
        let rest = parts
            .next()
            .ok_or_else(|| MigrationChecksumError::BadFilename(name.clone()))?;
        // Description mirrors sqlx: strip the suffix, underscores to spaces.
        let description = rest.trim_end_matches(".sql").replace('_', " ");
        let bytes = std::fs::read(&path)
            .map_err(|e| MigrationChecksumError::FileUnreadable(path.clone(), e))?;
        disk.insert(version, (description, migration_checksum(&bytes)));
    }

    // 2. Read the applied set. A missing table means a fresh database:
    // nothing applied yet, which the per-file check below reports honestly.
    let applied: BTreeMap<i64, Vec<u8>> =
        match sqlx::query("SELECT version, checksum FROM _sqlx_migrations")
            .fetch_all(pool)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|r| (r.get::<i64, _>("version"), r.get::<Vec<u8>, _>("checksum")))
                .collect(),
            Err(e) => {
                let missing_table = e
                    .as_database_error()
                    .and_then(|db| db.code())
                    .is_some_and(|code| code == "42P01");
                if missing_table {
                    BTreeMap::new()
                } else {
                    return Err(MigrationChecksumError::Db(e));
                }
            }
        };

    // 3. Every disk file must be applied with a matching checksum.
    for (version, (description, sum)) in &disk {
        match applied.get(version) {
            None => {
                return Err(MigrationChecksumError::NotApplied {
                    version: *version,
                    description: description.clone(),
                });
            }
            Some(applied_sum) if applied_sum.as_slice() != sum.as_slice() => {
                return Err(MigrationChecksumError::ChecksumMismatch {
                    version: *version,
                    description: description.clone(),
                });
            }
            Some(_) => {}
        }
    }

    // 4. Every applied row must have a file on disk.
    for version in applied.keys() {
        if !disk.contains_key(version) {
            return Err(MigrationChecksumError::UnknownApplied { version: *version });
        }
    }

    // 5. The embedded set must agree with the disk (stale-binary tripwire:
    // build.rs's rerun-if-changed normally prevents this, but a
    // hand-copied binary could disagree with the tree).
    for m in migrator.migrations.iter() {
        match disk.get(&m.version) {
            Some((_, sum)) if m.checksum.as_ref() == sum.as_slice() => {}
            _ => return Err(MigrationChecksumError::StaleBinary { version: m.version }),
        }
    }

    Ok(disk.len())
}
