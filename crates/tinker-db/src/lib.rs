//! Database connectivity for Tinker's two physically separate stores.
//!
//! - [`CoreDb`]: operational facts, ontology metadata, durable runs, audit.
//!   Connects as `tinker_app` (owns nothing; RLS always applies).
//! - [`PiiDb`]: the PII vault. Separate database, credentials, and pool.
//!   There is intentionally no join path between the two stores.

use sqlx::migrate::Migrator;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Transaction;
use std::time::Duration;
use tinker_core::{Result, TenantContext};

mod migrate_check;
pub use migrate_check::{migration_checksum, verify_migration_checksums, MigrationChecksumError};

pub static MIGRATOR_CORE: Migrator = sqlx::migrate!("migrations/core");
pub static MIGRATOR_PII: Migrator = sqlx::migrate!("migrations/pii");

/// Cluster-wide advisory-lock keys serializing schema migrations.
///
/// Post-M8 item 30 (scale-out spike): two (or N) instances share one
/// database and all run migrations at startup. `Migrator::run` already
/// takes sqlx's own advisory lock (keyed opaquely by database name), but
/// that is an sqlx internal; these explicit keys are the documented,
/// testable contract: at most one migrator per store runs anywhere in
/// the fleet at a time. The keys embed `b"TINKER"` plus a store tag so
/// they can never collide with sqlx's CRC-derived ids or each other.
pub const MIGRATION_LOCK_CORE: i64 = 0x5449_4E4B_4552_0001;
pub const MIGRATION_LOCK_PII: i64 = 0x5449_4E4B_4552_0002;

/// Run `migrator` against `pool` holding the cluster-wide advisory lock
/// for the whole run. `pg_advisory_lock` is session-scoped, so the lock
/// is taken on a dedicated checked-out connection that stays checked
/// out until the migrator finishes — it cannot be silently released
/// (and re-acquired by a competitor) mid-migration. The migrator's own
/// internal lock nests inside ours; the keys differ, so there is no
/// deadlock: ours is always acquired first.
async fn migrate_with_lock(pool: &PgPool, migrator: &Migrator, lock_key: i64) -> Result<()> {
    let mut conn = pool.acquire().await.map_err(tinker_core::TinkerError::Db)?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_key)
        .execute(&mut *conn)
        .await
        .map_err(tinker_core::TinkerError::Db)?;
    let outcome = migrator.run(pool).await;
    // Release explicitly; the session lock would also die with `conn`,
    // but an explicit unlock keeps pg_locks honest when the pooled
    // connection is reused. A failed unlock must not mask the
    // migration outcome.
    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_key)
        .execute(&mut *conn)
        .await
    {
        tracing::warn!(lock_key, "migration advisory unlock failed: {e}");
    }
    drop(conn);
    outcome.map_err(|e| tinker_core::TinkerError::Internal(format!("migration failed: {e}")))?;
    Ok(())
}

/// Operational store handle.
#[derive(Debug, Clone)]
pub struct CoreDb(pub PgPool);

/// PII vault handle. Never mixed with [`CoreDb`] in a query.
#[derive(Debug, Clone)]
pub struct PiiDb(pub PgPool);

/// Owner-level handle used ONLY for migrations and the DDL runner.
/// The owner bypasses RLS; this handle must never serve tenant reads.
#[derive(Debug, Clone)]
pub struct OwnerDb(pub PgPool);

fn pool_options() -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(16)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
}

impl CoreDb {
    /// Tenant-facing pool: connect as the non-owner app role so RLS applies.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = pool_options()
            .connect(url)
            .await
            .map_err(tinker_core::TinkerError::Db)?;
        Ok(Self(pool))
    }

    pub async fn migrate(&self) -> Result<()> {
        migrate_with_lock(&self.0, &MIGRATOR_CORE, MIGRATION_LOCK_CORE).await
    }

    /// Open a transaction pinned to the tenant. Every statement inside sees
    /// exactly this organization through RLS; the settings die with the
    /// transaction and cannot leak back into the pool.
    pub async fn tenant_tx(
        &self,
        ctx: &TenantContext,
    ) -> Result<Transaction<'static, sqlx::Postgres>> {
        let mut tx = self.0.begin().await?;
        for stmt in ctx.set_local_statements() {
            sqlx::query(&stmt).execute(&mut *tx).await?;
        }
        Ok(tx)
    }
}

impl PiiDb {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = pool_options().connect(url).await?;
        Ok(Self(pool))
    }

    /// Transaction pinned to the caller's organization. The vault uses this
    /// for every access: RLS is the fail-closed backstop behind the
    /// projector's authorization.
    pub async fn tenant_tx(
        &self,
        ctx: &TenantContext,
    ) -> Result<Transaction<'static, sqlx::Postgres>> {
        let mut tx = self.0.begin().await?;
        for stmt in ctx.set_local_statements() {
            sqlx::query(&stmt).execute(&mut *tx).await?;
        }
        Ok(tx)
    }

    pub async fn migrate(&self) -> Result<()> {
        migrate_with_lock(&self.0, &MIGRATOR_PII, MIGRATION_LOCK_PII).await
    }
}

impl OwnerDb {
    /// Owner pool for migrations and DDL. Bypasses RLS by design.
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = pool_options().connect(url).await?;
        Ok(Self(pool))
    }

    /// Run core migrations under the cluster-wide advisory lock
    /// ([`MIGRATION_LOCK_CORE`]). Every instance calls this at startup;
    /// exactly one migrates while the rest wait, so a rolling deploy
    /// against one database can never run DDL twice.
    pub async fn migrate(&self) -> Result<()> {
        migrate_with_lock(&self.0, &MIGRATOR_CORE, MIGRATION_LOCK_CORE).await
    }
}

/// Extract the password from a Postgres URL's userinfo segment.
///
/// Mirrors `bin/pg-ensure.sh`'s `pw_of` exactly (raw substring between
/// `://user:` and the next `@` — no percent-decoding), so the password
/// this function yields is byte-identical to the one pg-ensure installs
/// on the role. Returns `None` when the URL has no password segment.
pub fn app_password_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let userinfo = after_scheme.split('@').next()?;
    let pw = userinfo.split_once(':')?.1;
    if pw.is_empty() {
        return None;
    }
    Some(pw.to_string())
}

/// Quote a value as a SQL string literal (single quotes doubled — the
/// complete escaping for a literal; no interpolation reaches the
/// statement any other way).
fn sql_literal(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Set the app-role passwords from environment-provided URLs.
///
/// The 0001 migrations create `tinker_app` / `tinker_pii_app` with
/// repo-embedded dev passwords when the roles do not already exist
/// (frozen migrations — that branch cannot be edited). Any deployment
/// that runs migrations without the env bootstrap would leave the
/// published defaults live. This function is the fail-closed fix: the
/// repo's own migration runner (`examples/migrate.rs`) and
/// `bin/pg-ensure.sh` both call it, so the embedded dev passwords never
/// survive a supported provisioning path.
///
/// Fails closed (`Internal`) when either URL carries no password —
///
/// silently keeping a default is worse than refusing to provision.
pub async fn rotate_app_role_passwords(
    core_owner: &PgPool,
    pii_owner: &PgPool,
    core_app_url: &str,
    pii_app_url: &str,
) -> Result<()> {
    let core_pw = app_password_from_url(core_app_url).ok_or_else(|| {
        tinker_core::TinkerError::Internal(
            "TINKER_CORE_URL has no password segment; refusing to leave the app role on a default"
                .to_string(),
        )
    })?;
    let pii_pw = app_password_from_url(pii_app_url).ok_or_else(|| {
        tinker_core::TinkerError::Internal(
            "TINKER_PII_URL has no password segment; refusing to leave the PII app role on a default"
                .to_string(),
        )
    })?;
    for (pool, role, pw) in [
        (core_owner, "tinker_app", core_pw),
        (pii_owner, "tinker_pii_app", pii_pw),
    ] {
        sqlx::query(&format!(
            "ALTER ROLE {} WITH PASSWORD {}",
            role,
            sql_literal(&pw)
        ))
        .execute(pool)
        .await
        .map_err(tinker_core::TinkerError::Db)?;
        tracing::info!(role = role, "app role password set from environment");
    }
    Ok(())
}
