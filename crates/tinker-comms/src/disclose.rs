//! Versioned, revocable identity disclosure.
//!
//! In cross-plane threads, tenant participants appear to outside viewers
//! by stable handle by default. A participant can opt in per conversation
//! (`thread_id = Some`), and an organization administrator can set a
//! broader override (`thread_id = None`). Every choice is a new version
//! row; the renderer reads the latest version. Revocation is another row
//! with `disclosed = false` — history is never rewritten.

use tinker_core::{Result, TenantContext};
use tinker_db::CoreDb;
use uuid::Uuid;

/// Record a disclosure choice as a new version. `thread_id = None` is the
/// org-wide admin override.
pub async fn set_disclosure(
    core: &CoreDb,
    ctx: &TenantContext,
    thread_id: Option<Uuid>,
    actor_id: Uuid,
    disclosed: bool,
    created_by: Uuid,
) -> Result<()> {
    let mut tx = core.tenant_tx(ctx).await?;
    // Serialize version allocation per (org, thread, actor): MAX(version)+1
    // without a lock lets two concurrent writers mint the same version.
    // The advisory lock is transaction-scoped, so it releases on commit.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(format!("disclosure:{}", ctx.organization_id.0))
        .bind(format!(
            "{}:{}",
            thread_id
                .map(|t| t.to_string())
                .unwrap_or_else(|| "-".into()),
            actor_id
        ))
        .execute(&mut *tx)
        .await?;
    let next: i32 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) + 1 FROM comm_identity_disclosures
         WHERE organization_id=$1 AND thread_id IS NOT DISTINCT FROM $2 AND actor_id=$3",
    )
    .bind(ctx.organization_id.0)
    .bind(thread_id)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO comm_identity_disclosures
         (id, organization_id, thread_id, actor_id, disclosed, version, created_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::now_v7())
    .bind(ctx.organization_id.0)
    .bind(thread_id)
    .bind(actor_id)
    .bind(disclosed)
    .bind(next)
    .bind(created_by)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// True iff the latest disclosure version for the actor discloses them —
/// either for this thread or via the org-wide override.
pub async fn is_disclosed(
    core: &CoreDb,
    ctx: &TenantContext,
    thread_id: Option<Uuid>,
    actor_id: Uuid,
) -> Result<bool> {
    let mut tx = core.tenant_tx(ctx).await?;
    // Latest per-thread version, if any.
    let thread_row: Option<(bool,)> = sqlx::query_as(
        "SELECT disclosed FROM comm_identity_disclosures
         WHERE organization_id=$1 AND thread_id IS NOT DISTINCT FROM $2 AND actor_id=$3
         ORDER BY version DESC LIMIT 1",
    )
    .bind(ctx.organization_id.0)
    .bind(thread_id)
    .bind(actor_id)
    .fetch_optional(&mut *tx)
    .await?;
    // Latest org-wide override, if any.
    let org_row: Option<(bool,)> = sqlx::query_as(
        "SELECT disclosed FROM comm_identity_disclosures
         WHERE organization_id=$1 AND thread_id IS NULL AND actor_id=$2
         ORDER BY version DESC LIMIT 1",
    )
    .bind(ctx.organization_id.0)
    .bind(actor_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    // Either a live per-thread opt-in or a live org-wide override
    // discloses. A newer `false` in either slot revokes that slot.
    Ok(thread_row.map(|(d,)| d).unwrap_or(false) || org_row.map(|(d,)| d).unwrap_or(false))
}
