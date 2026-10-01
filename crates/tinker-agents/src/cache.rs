//! Transform cache with no privileged entries.
//!
//! The cache key binds record version, ontology version, policy version,
//! actor entitlement set, purpose, and transform version. A broad output
//! can never satisfy a narrower request: different entitlement sets hash
//! to different keys. Revocation invalidates by policy version.

use sha2::{Digest, Sha256};
use std::time::Duration;
use tinker_core::{Result, TenantContext};
use tinker_db::{CoreDb, OwnerDb};

pub struct CacheKeyParts<'a> {
    pub record_version: i64,
    pub ontology_version: &'a str,
    pub policy_version: &'a str,
    pub entitlement_set: &'a str,
    pub purpose: &'a str,
    pub transform_version: &'a str,
    pub record_id: &'a str,
    pub object_slug: &'a str,
}

pub fn cache_key(parts: &CacheKeyParts<'_>) -> String {
    let mut h = Sha256::new();
    for s in [
        parts.object_slug,
        parts.record_id,
        &parts.record_version.to_string(),
        parts.ontology_version,
        parts.policy_version,
        parts.entitlement_set,
        parts.purpose,
        parts.transform_version,
    ] {
        h.update(s.as_bytes());
        h.update(b"\x00");
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub struct TransformCache {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
    ttl: Duration,
}

impl TransformCache {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self {
            core,
            owner,
            ttl: Duration::from_secs(300),
        }
    }

    pub async fn get(&self, ctx: &TenantContext, key: &str) -> Result<Option<serde_json::Value>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT value FROM transform_cache
             WHERE organization_id = $1 AND cache_key = $2 AND expires_at > now()",
        )
        .bind(ctx.organization_id.0)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|(v,)| v))
    }

    pub async fn put(
        &self,
        ctx: &TenantContext,
        key: &str,
        policy_version: &str,
        transform_version: &str,
        value: &serde_json::Value,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO transform_cache
                 (cache_key, organization_id, value, policy_version,
                  transform_version, expires_at)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
             ON CONFLICT (cache_key) DO UPDATE
             SET value = EXCLUDED.value,
                 policy_version = EXCLUDED.policy_version,
                 transform_version = EXCLUDED.transform_version,
                 expires_at = EXCLUDED.expires_at",
        )
        .bind(key)
        .bind(ctx.organization_id.0)
        .bind(value)
        .bind(policy_version)
        .bind(transform_version)
        .bind(self.ttl.as_secs() as f64)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Revocation invalidates every entry minted under the old policy
    /// version. Called when field_grants / field_transforms change.
    pub async fn invalidate_policy(
        &self,
        ctx: &TenantContext,
        policy_version: &str,
    ) -> Result<u64> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let r = sqlx::query(
            "DELETE FROM transform_cache
             WHERE organization_id = $1 AND policy_version = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(policy_version)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(r.rows_affected())
    }
}
