//! The cross-plane grant bridge (PRD §10).
//!
//! A thread belongs to one organization. A host operator reaches it only
//! inside a time-boxed grant that names that organization and a purpose.
//! A grant for another organization resolves the thread to zero rows.
//! Expiry closes access automatically — the lookup filters
//! `expires_at > now()` — and the tenant can inspect the access record
//! (the rows live in the tenant's own schema, RLS-pinned to the org).
//!
//! This is deliberately separate from [`tinker_identity::Authorizer`]:
//! grants there never cross organizations by design. Cross-plane access
//! is the exceptional, audited path, not the normal one.

use chrono::{DateTime, Utc};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct CrossPlaneGrant {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub grantee_actor_id: Uuid,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
}

/// Issue a time-boxed cross-plane grant. Runs on the tenant pool with the
/// TENANT org's context (the rows are RLS-pinned to the accessed org);
/// authorizing the *issuer* is the caller's job (org admin path).
pub async fn grant_cross_plane_access(
    core: &CoreDb,
    ctx: &TenantContext,
    grantee_actor_id: Uuid,
    purpose: &str,
    expires_at: DateTime<Utc>,
    created_by: Uuid,
) -> Result<CrossPlaneGrant> {
    if purpose.trim().is_empty() || purpose.len() > 200 {
        return Err(TinkerError::Validation(
            "cross-plane grant needs a 1-200 char purpose".into(),
        ));
    }
    if expires_at <= Utc::now() {
        return Err(TinkerError::Validation(
            "cross-plane grant expiry must be in the future".into(),
        ));
    }
    let id = Uuid::now_v7();
    let mut tx = core.tenant_tx(ctx).await?;
    sqlx::query(
        "INSERT INTO cross_plane_grants
         (id, organization_id, grantee_actor_id, purpose, expires_at, created_by)
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(id)
    .bind(ctx.organization_id.0)
    .bind(grantee_actor_id)
    .bind(purpose)
    .bind(expires_at)
    .bind(created_by)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(CrossPlaneGrant {
        id,
        organization_id: ctx.organization_id.0,
        grantee_actor_id,
        purpose: purpose.to_string(),
        expires_at,
    })
}

/// The live grant for a grantee in the tenant org, if any. `ctx` carries
/// the ACCESSED org — RLS makes another org's grants invisible here, so a
/// grant for org B never authorizes reads in org A.
pub async fn find_valid_grant(
    core: &CoreDb,
    ctx: &TenantContext,
    grantee_actor_id: Uuid,
) -> Result<Option<CrossPlaneGrant>> {
    let mut tx = core.tenant_tx(ctx).await?;
    let row: Option<(Uuid, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT id, purpose, expires_at FROM cross_plane_grants
         WHERE organization_id=$1 AND grantee_actor_id=$2
           AND expires_at > now() AND revoked_at IS NULL
         ORDER BY expires_at DESC LIMIT 1",
    )
    .bind(ctx.organization_id.0)
    .bind(grantee_actor_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|(id, purpose, expires_at)| CrossPlaneGrant {
        id,
        organization_id: ctx.organization_id.0,
        grantee_actor_id,
        purpose,
        expires_at,
    }))
}

/// Revoke a live grant early. Only an unrevoked, unexpired grant in the
/// tenant org is affected; revoking twice is a no-op success.
pub async fn revoke_cross_plane_access(
    core: &CoreDb,
    ctx: &TenantContext,
    grant_id: Uuid,
) -> Result<()> {
    let mut tx = core.tenant_tx(ctx).await?;
    sqlx::query(
        "UPDATE cross_plane_grants SET revoked_at=now()
         WHERE id=$1 AND organization_id=$2 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .bind(ctx.organization_id.0)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record one cross-plane read performed under `grant_id`. `ctx` carries
/// the ACCESSED org, so the audit row is RLS-pinned exactly where the
/// grant row lives. Called on every successful cross-plane read — an
/// unaudited cross-plane read is a gap, not an optimization.
pub async fn log_grant_use(
    core: &CoreDb,
    ctx: &TenantContext,
    grant_id: Uuid,
    thread_id: Uuid,
) -> Result<()> {
    let mut tx = core.tenant_tx(ctx).await?;
    sqlx::query(
        "INSERT INTO cross_plane_grant_uses
         (organization_id, grant_id, grantee_actor_id, thread_id)
         VALUES ($1,$2,$3,$4)",
    )
    .bind(ctx.organization_id.0)
    .bind(grant_id)
    .bind(ctx.actor_id)
    .bind(thread_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// One grant plus how many audited reads it has served. The tenant's
/// audit surface: who was granted, why, by whom, and how often it was used.
#[derive(Debug, Clone)]
pub struct GrantSummary {
    pub id: Uuid,
    pub grantee_actor_id: Uuid,
    pub purpose: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub use_count: i64,
}

type GrantSummaryRow = (
    Uuid,
    Uuid,
    String,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Uuid,
    DateTime<Utc>,
    i64,
);

/// List every grant ever issued in the tenant org — live, expired, and
/// revoked — newest first. The tenant-auditable surface (PRD §10): the
/// rows live in the tenant's own schema, RLS-pinned to the org.
pub async fn list_grants(core: &CoreDb, ctx: &TenantContext) -> Result<Vec<GrantSummary>> {
    let mut tx = core.tenant_tx(ctx).await?;
    let rows: Vec<GrantSummaryRow> = sqlx::query_as(
        "SELECT g.id, g.grantee_actor_id, g.purpose, g.expires_at, g.revoked_at,
                g.created_by, g.created_at, COUNT(u.id)
         FROM cross_plane_grants g
         LEFT JOIN cross_plane_grant_uses u ON u.grant_id = g.id
         WHERE g.organization_id=$1
         GROUP BY g.id
         ORDER BY g.created_at DESC",
    )
    .bind(ctx.organization_id.0)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                grantee_actor_id,
                purpose,
                expires_at,
                revoked_at,
                created_by,
                created_at,
                use_count,
            )| {
                GrantSummary {
                    id,
                    grantee_actor_id,
                    purpose,
                    expires_at,
                    revoked_at,
                    created_by,
                    created_at,
                    use_count,
                }
            },
        )
        .collect())
}

/// One audited cross-plane read.
#[derive(Debug, Clone)]
pub struct GrantUse {
    pub id: Uuid,
    pub grant_id: Uuid,
    pub grantee_actor_id: Uuid,
    pub thread_id: Uuid,
    pub used_at: DateTime<Utc>,
}

/// The audited reads under one grant, newest first. The grant must live
/// in the tenant org — a foreign grant id yields an empty list, never a
/// cross-org peek.
pub async fn list_grant_uses(
    core: &CoreDb,
    ctx: &TenantContext,
    grant_id: Uuid,
) -> Result<Vec<GrantUse>> {
    let mut tx = core.tenant_tx(ctx).await?;
    let rows: Vec<(Uuid, Uuid, Uuid, Uuid, DateTime<Utc>)> = sqlx::query_as(
        "SELECT u.id, u.grant_id, u.grantee_actor_id, u.thread_id, u.used_at
         FROM cross_plane_grant_uses u
         JOIN cross_plane_grants g ON g.id = u.grant_id
         WHERE u.grant_id=$1 AND g.organization_id=$2
         ORDER BY u.used_at DESC",
    )
    .bind(grant_id)
    .bind(ctx.organization_id.0)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(rows
        .into_iter()
        .map(
            |(id, grant_id, grantee_actor_id, thread_id, used_at)| GrantUse {
                id,
                grant_id,
                grantee_actor_id,
                thread_id,
                used_at,
            },
        )
        .collect())
}
