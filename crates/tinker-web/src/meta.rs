//! Governed-metadata resolution with caching (item 47).
//!
//! The governed read path re-resolves slow-moving metadata on every
//! request — object description (with evolved fields), the caller's
//! field projection, and the caller's row policy — at a cost of dozens
//! of DB round trips per request, even when the query *result* cache
//! hits. This module is the single place that consults the shared
//! [`tinker_live::MetaCache`]: on a hit the caller gets cloneable
//! values with zero round trips; on a miss it performs exactly the
//! same resolutions the uncached path did, then populates the cache.
//!
//! Freshness parity with the query *result* cache is structural: every
//! site that invalidates the result cache also invalidates the
//! metadata cache (record writes, schema changes, remote
//! schema-version signals), and both share the same 30s TTL backstop,
//! so metadata can never be staler than the rows it governs.
//!
//! Error behavior is preserved exactly: on a miss the resolutions run
//! in the same order the uncached path used, with the version label
//! validated in the position the compiler validated it (fail closed,
//! with the compiler's error). Unknown labels never consult the cache,
//! so fail-closed behavior cannot depend on cache state.

use tinker_core::{Result, TenantContext, TinkerError};
use tinker_evolve::VersionSel;
use tinker_live::QueryInputs;
use uuid::Uuid;

use crate::describe::Describer;
use crate::SharedState;

/// Parse the version label exactly the way the compiler does, so an
/// unknown label fails closed with the same error on a cache hit as on
/// a miss (fail-closed behavior must not depend on cache state).
fn parse_version(label: Option<&str>) -> Result<VersionSel> {
    match label {
        None | Some("active") => Ok(VersionSel::Active),
        Some("canary") => Ok(VersionSel::Canary),
        Some("preview") => Ok(VersionSel::Preview),
        Some(other) => Err(TinkerError::Validation(format!(
            "unknown schema_version: {other}"
        ))),
    }
}

/// Resolve an object slug to its id, tenant-scoped, via the cached
/// slug mapping. Slugs are immutable and objects are never deleted,
/// so the mapping only grows; it is still invalidated with the rest
/// of the object's metadata on writes for hygiene.
pub async fn object_id_cached(
    state: &SharedState,
    tenant: &TenantContext,
    slug: &str,
) -> Result<Uuid> {
    let org = tenant.organization_id.0;
    if let Some(id) = state.meta.get_slug(org, slug).await {
        return Ok(id);
    }
    let desc = state.ontology.describe_object_by_slug(tenant, slug).await?;
    state.meta.put_slug(org, slug, desc.id).await;
    Ok(desc.id)
}

/// Load (or reuse cached) the governed inputs one query needs:
/// description with the resolved version's evolved fields, the
/// caller's field projection, and the caller's row policy.
///
/// Only the `active` schema version is cached: it changes solely via
/// promote/rollback, which invalidate this cache. `canary`/`preview`
/// labels can resolve to different version ids over time (a new
/// version marked canary, cohort edits) without any broadcast, so
/// they always resolve fresh — exactly the uncached behavior.
///
/// On a cache miss this performs exactly the same resolutions the
/// uncached path did (projection, policy, version-label validation,
/// version resolve, describe-with-ext), in the same order, so errors
/// surface identically; on a hit it performs zero DB round trips.
pub async fn query_inputs(
    state: &SharedState,
    tenant: &TenantContext,
    role: &str,
    object_id: Uuid,
    schema_version: Option<&str>,
) -> Result<QueryInputs> {
    // Only the active label is cacheable; the label itself is validated
    // inside the uncached path, in the compiler's original position, so
    // error precedence is unchanged on a miss.
    let cacheable = matches!(schema_version, None | Some("active"));
    let org = tenant.organization_id.0;
    if cacheable {
        if let Some(hit) = state.meta.get_inputs(org, object_id, role, "active").await {
            return Ok(hit);
        }
    }
    let inputs = query_inputs_uncached(state, tenant, role, object_id, schema_version).await?;
    if cacheable {
        state
            .meta
            .put_inputs(org, object_id, role, "active", inputs.clone())
            .await;
    }
    Ok(inputs)
}

/// The resolutions the uncached path performed, in the same order:
/// projection, policy, version-label validation, version resolve,
/// describe-with-ext.
async fn query_inputs_uncached(
    state: &SharedState,
    tenant: &TenantContext,
    role: &str,
    object_id: Uuid,
    schema_version: Option<&str>,
) -> Result<QueryInputs> {
    let projection = state
        .grants
        .load_projection_for_query(tenant, &state.ontology, role, object_id)
        .await?;
    let policy = state
        .row_filters
        .load_policy(tenant, object_id, role)
        .await?;
    let version_sel = parse_version(schema_version)?;
    // AppState's evolver is always present; the compiler's
    // Option-wrapped evolver handles the None case for its own
    // standalone uses.
    let resolved = state
        .evolver
        .resolve(tenant, object_id, version_sel)
        .await?;
    let desc = state
        .ontology
        .describe_object_with_ext(tenant, object_id, &resolved.ext_fields)
        .await?;
    Ok(QueryInputs {
        object_id,
        desc,
        projection,
        policy,
        version_sel,
    })
}

/// Load (or reuse cached) the serialized `describe` output for
/// `(org, object, role)`.
///
/// On a miss this calls the same `Describer::object` the uncached path
/// used and caches the serialized value; the tool layer serializes the
/// same struct identically every time, so a cache hit returns
/// byte-identical output by construction. (`to_value` on this plain
/// struct cannot fail in practice — all keys are strings and every
/// field serializes infallibly — so the miss path propagates it like
/// the uncached path did.)
pub async fn describe_cached(
    state: &SharedState,
    tenant: &TenantContext,
    role: &str,
    slug: &str,
) -> Result<serde_json::Value> {
    let org = tenant.organization_id.0;
    let object_id = object_id_cached(state, tenant, slug).await?;

    if let Some(hit) = state.meta.get_describe(org, object_id, role).await {
        return Ok(hit);
    }

    let described = Describer::from_state(state)
        .object(tenant, role, slug)
        .await?;
    let value = serde_json::to_value(&described).map_err(TinkerError::Serde)?;
    state
        .meta
        .put_describe(org, object_id, role, value.clone())
        .await;
    Ok(value)
}
