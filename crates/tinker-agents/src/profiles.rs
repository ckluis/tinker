//! Context profiles: versioned ontology artifacts.
//!
//! Each product/feature defines a profile: root objects, relation depth,
//! permitted fields, token budget, ranking policy, freshness threshold.
//! Profiles are immutable after release — change means a new version plus
//! an active-pointer flip; health gates can roll the pointer back.

use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ContextProfile {
    pub id: Uuid,
    pub profile_key: String,
    pub version: i64,
    pub status: String,
    pub definition: serde_json::Value,
    pub is_active: bool,
}

impl ContextProfile {
    pub fn relation_depth(&self) -> u32 {
        self.definition
            .get("relation_depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(2)
    }

    pub fn token_budget(&self) -> u64 {
        self.definition
            .get("token_budget")
            .and_then(|v| v.as_u64())
            .unwrap_or(12_000)
    }

    pub fn root_objects(&self) -> Vec<String> {
        self.definition
            .get("root_objects")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn permitted_fields(&self, object_slug: &str) -> Option<Vec<String>> {
        self.definition
            .get("permitted_fields")?
            .get(object_slug)?
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
    }
}

pub struct ProfileEngine {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
}

impl ProfileEngine {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    fn row(
        id: Uuid,
        profile_key: String,
        version: i64,
        status: String,
        definition: serde_json::Value,
        is_active: bool,
    ) -> ContextProfile {
        ContextProfile {
            id,
            profile_key,
            version,
            status,
            definition,
            is_active,
        }
    }

    /// Draft a new profile version (next version number for the key).
    pub async fn draft(
        &self,
        ctx: &TenantContext,
        profile_key: &str,
        definition: serde_json::Value,
    ) -> Result<ContextProfile> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (next,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM context_profiles
             WHERE organization_id = $1 AND profile_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(profile_key)
        .fetch_one(&mut *tx)
        .await?;
        let (id, version, status, def, is_active): (Uuid, i64, String, serde_json::Value, bool) =
            sqlx::query_as(
                "INSERT INTO context_profiles
                     (organization_id, profile_key, version, status, definition)
                 VALUES ($1, $2, $3, 'draft', $4)
                 RETURNING id, version, status, definition, is_active",
            )
            .bind(ctx.organization_id.0)
            .bind(profile_key)
            .bind(next)
            .bind(definition)
            .fetch_one(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Self::row(
            id,
            profile_key.to_string(),
            version,
            status,
            def,
            is_active,
        ))
    }

    /// Release a draft (draft -> released) and flip the active pointer to
    /// it, archiving the previous active version in the same transaction.
    pub async fn release(&self, ctx: &TenantContext, profile_id: Uuid) -> Result<ContextProfile> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(Uuid, String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT id, profile_key, status, definition FROM context_profiles
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(profile_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (id, key, status, def) =
            row.ok_or_else(|| TinkerError::NotFound(format!("profile {profile_id}")))?;
        if status != "draft" {
            return Err(TinkerError::Validation(format!(
                "only drafts can be released (status={status})"
            )));
        }
        sqlx::query(
            "UPDATE context_profiles SET is_active = false
             WHERE organization_id = $1 AND profile_key = $2 AND is_active",
        )
        .bind(ctx.organization_id.0)
        .bind(&key)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE context_profiles
             SET status = 'released', is_active = true, released_at = now()
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Self::row(id, key, 0, "released".into(), def, true))
    }

    /// Roll back: flip the active pointer to a previous released version.
    /// The bad version is marked rolled_back (history is preserved).
    pub async fn rollback(
        &self,
        ctx: &TenantContext,
        profile_key: &str,
        to_version: i64,
    ) -> Result<ContextProfile> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let target: Option<(Uuid, String, serde_json::Value, i64)> = sqlx::query_as(
            "SELECT id, status, definition, version FROM context_profiles
             WHERE organization_id = $1 AND profile_key = $2 AND version = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(profile_key)
        .bind(to_version)
        .fetch_optional(&mut *tx)
        .await?;
        let (id, status, def, version) = target
            .ok_or_else(|| TinkerError::NotFound(format!("profile {profile_key} v{to_version}")))?;
        if status != "released" && status != "rolled_back" {
            return Err(TinkerError::Validation(format!(
                "cannot roll back to a {status} version"
            )));
        }
        let current: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM context_profiles
             WHERE organization_id = $1 AND profile_key = $2 AND is_active",
        )
        .bind(ctx.organization_id.0)
        .bind(profile_key)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((cur_id,)) = current {
            sqlx::query(
                "UPDATE context_profiles SET is_active = false, status = 'rolled_back'
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(ctx.organization_id.0)
            .bind(cur_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "UPDATE context_profiles SET is_active = true, status = 'released'
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(Self::row(
            id,
            profile_key.to_string(),
            version,
            "released".into(),
            def,
            true,
        ))
    }

    /// The active version of a profile key (what agents actually use).
    pub async fn active(&self, ctx: &TenantContext, profile_key: &str) -> Result<ContextProfile> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(Uuid, i64, String, serde_json::Value, bool)> = sqlx::query_as(
            "SELECT id, version, status, definition, is_active FROM context_profiles
             WHERE organization_id = $1 AND profile_key = $2 AND is_active",
        )
        .bind(ctx.organization_id.0)
        .bind(profile_key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let (id, version, status, def, is_active) =
            row.ok_or_else(|| TinkerError::NotFound(format!("active profile {profile_key}")))?;
        Ok(Self::row(
            id,
            profile_key.to_string(),
            version,
            status,
            def,
            is_active,
        ))
    }
}
