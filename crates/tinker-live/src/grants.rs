//! Field-level projections (M3): which fields a role may see per object.
//!
//! `field_grants` is an allowlist. When rows exist for
//! (organization_id, object_id, role), that role sees ONLY the listed
//! fields. When no rows exist the role is unrestricted (default-open).
//! The compiler turns these rows into a [`FieldProjection`] and enforces
//! it: hidden selected fields are dropped, hidden filter/sort fields
//! are rejected, and the SQL never selects a hidden column.

use std::collections::{HashMap, HashSet};

use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_query::FieldProjection;
use uuid::Uuid;

/// Sentinel stored when a projection allows zero fields. `api_name`
/// values must start with a lowercase letter (`valid_slug`), so this can
/// never collide with a real field. Without it, "no fields" would be
/// stored as zero rows — indistinguishable from "no projection" — and an
/// admin clearing every checkbox would silently grant FULL access.
pub const DENY_ALL_FIELDS: &str = "__deny_all";

/// Owner-handle access to `field_grants`. Writes come from the pack
/// installer or an org admin path; reads serve the query endpoint.
pub struct FieldGrants {
    core: CoreDb,
}

impl FieldGrants {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Replace the projection for (org, object, role) with exactly
    /// `fields`. An empty set is an explicit deny-all (sees nothing but
    /// `__id`); it is stored as a sentinel row so it can never be confused
    /// with "no projection" (unrestricted). Delete-then-insert keeps it
    /// atomic per call.
    pub async fn set_projection(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        role: &str,
        fields: &[&str],
    ) -> Result<()> {
        if role.is_empty() || role.len() > 64 {
            return Err(TinkerError::Validation("bad role".into()));
        }
        for f in fields {
            if *f == DENY_ALL_FIELDS || f.is_empty() {
                return Err(TinkerError::Validation("bad field in projection".into()));
            }
        }
        let organization_id = ctx.organization_id.0;
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "DELETE FROM field_grants WHERE organization_id=$1 AND object_id=$2 AND role=$3",
        )
        .bind(organization_id)
        .bind(object_id)
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        // Empty projection: store the deny-all sentinel so the loader
        // sees an explicit entry instead of "no rows".
        let to_insert: Vec<&str> = if fields.is_empty() {
            vec![DENY_ALL_FIELDS]
        } else {
            fields.to_vec()
        };
        for f in to_insert {
            sqlx::query(
                "INSERT INTO field_grants (organization_id, object_id, role, field_api_name)
                 VALUES ($1,$2,$3,$4)",
            )
            .bind(organization_id)
            .bind(object_id)
            .bind(role)
            .bind(f)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        }
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Load the projection for a role over the objects a query may touch.
    /// Only objects WITH grant rows appear in the map; the rest are
    /// unrestricted.
    pub async fn load_projection(
        &self,
        ctx: &TenantContext,
        role: &str,
        object_ids: &[Uuid],
    ) -> Result<FieldProjection> {
        if object_ids.is_empty() {
            return Ok(FieldProjection::unrestricted());
        }
        let organization_id = ctx.organization_id.0;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT object_id, field_api_name FROM field_grants
             WHERE organization_id=$1 AND role=$2 AND object_id = ANY($3)",
        )
        .bind(organization_id)
        .bind(role)
        .bind(object_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let mut map: HashMap<Uuid, HashSet<String>> = HashMap::new();
        for (oid, field) in rows {
            if field == DENY_ALL_FIELDS {
                // Explicit deny-all: the entry exists but allows nothing.
                // (__id stays visible; the compiler always exposes it.)
                map.entry(oid).or_default();
            } else {
                map.entry(oid).or_default().insert(field);
            }
        }
        // An object with grant rows but zero fields listed is still a
        // projection (sees nothing); the entry must exist even if empty.
        // The query above only returns listed fields, so seed entries for
        // objects that have ANY row for this role.
        let with_rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT object_id FROM field_grants
             WHERE organization_id=$1 AND role=$2 AND object_id = ANY($3)",
        )
        .bind(organization_id)
        .bind(role)
        .bind(object_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        for (oid,) in with_rows {
            map.entry(oid).or_default();
        }
        Ok(FieldProjection::allowlist(map))
    }

    /// Load the projection for a role over the base object plus its
    /// one-level relation targets (the compiler only joins one level, so
    /// this is the full set of objects a query can touch).
    pub async fn load_projection_for_query(
        &self,
        ctx: &TenantContext,
        ontology: &tinker_ontology::Ontology,
        role: &str,
        base_object_id: Uuid,
    ) -> Result<FieldProjection> {
        let base = ontology.describe_object(ctx, base_object_id).await?;
        let mut ids = vec![base_object_id];
        let mut tx = self.core.tenant_tx(ctx).await?;
        for f in &base.fields {
            if f.field_type == "relation" {
                let row: Option<(Uuid,)> =
                    sqlx::query_as("SELECT relation_target_id FROM ontology_fields WHERE id=$1")
                        .bind(f.id)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(TinkerError::Db)?;
                if let Some((target,)) = row {
                    if !ids.contains(&target) {
                        ids.push(target);
                    }
                }
            }
        }
        tx.commit().await.map_err(TinkerError::Db)?;
        self.load_projection(ctx, role, &ids).await
    }
}
