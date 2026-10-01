//! Verify migration source checksums against the applied database state.
//!
//! Compares the SHA-384 of every `.sql` file on disk (the same algorithm
//! `sqlx::migrate!` uses at compile time) with the checksum recorded in
//! `_sqlx_migrations`, for the core and PII stores. Fails closed (exit 1)
//! on any drift: a file edited after apply, a file never applied, an
//! applied row with no file on disk, or an embedded migration set that
//! disagrees with the source tree (stale binary).
//!
//! `bin/pg-ensure.sh` runs this after the migrator: the old count check
//! caught a stale binary's *missing* migrations, but not a migration file
//! edited after it was applied.
//!
//! Usage: TINKER_CORE_OWNER_URL=... TINKER_PII_OWNER_URL=...
//!        cargo run -p tinker-db --example verify-migrations -- <core_dir> <pii_dir>

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let core_dir = args
        .next()
        .ok_or("usage: verify-migrations <core_dir> <pii_dir>")?;
    let pii_dir = args
        .next()
        .ok_or("usage: verify-migrations <core_dir> <pii_dir>")?;
    let core_url =
        std::env::var("TINKER_CORE_OWNER_URL").map_err(|_| "TINKER_CORE_OWNER_URL must be set")?;
    let pii_url =
        std::env::var("TINKER_PII_OWNER_URL").map_err(|_| "TINKER_PII_OWNER_URL must be set")?;

    let mut failed = false;
    let stores: [(&str, String, &sqlx::migrate::Migrator, String); 2] = [
        ("core", core_url, &tinker_db::MIGRATOR_CORE, core_dir),
        ("pii", pii_url, &tinker_db::MIGRATOR_PII, pii_dir),
    ];
    for (label, url, migrator, dir) in stores {
        let pool = sqlx::PgPool::connect(&url).await?;
        match tinker_db::verify_migration_checksums(&pool, migrator, std::path::Path::new(&dir))
            .await
        {
            Ok(n) => println!("{label}: {n} migration checksums verified against _sqlx_migrations"),
            Err(e) => {
                eprintln!("{label}: CHECKSUM VERIFICATION FAILED: {e}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
    Ok(())
}
