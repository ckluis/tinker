//! Relational virtual files: authorized projections of canonical
//! records at stable paths.
//!
//! Path shape: `/tinker/{object_slug}/{record_id}/index.md`. One record,
//! many placements — every path resolves the same row through the
//! reader's policy. Files don't become another database and never bypass
//! the mutation path: this surface is read-only.
//!
//! Path parsing is hostile-input hardened: slugs are restricted to
//! `[a-z0-9_]+`, record refs must be UUIDs, and `..` never resolves.

use tinker_core::{Result, TenantContext, TinkerError};
use uuid::Uuid;

use crate::cache::{cache_key, CacheKeyParts, TransformCache};
use crate::transforms::TransformEngine;

#[derive(Debug, Clone)]
pub struct VirtualPath {
    pub object_slug: String,
    pub record_id: Uuid,
    /// The canonical path string (used in audit + cache).
    pub canonical: String,
}

impl VirtualPath {
    pub fn parse(path: &str) -> Result<Self> {
        // Strict shape: /tinker/{slug}/{uuid}/index.md
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() != 5
            || !parts[0].is_empty()
            || parts[1] != "tinker"
            || parts[4] != "index.md"
        {
            return Err(TinkerError::Validation(format!(
                "malformed virtual path: {path}"
            )));
        }
        let slug = parts[2];
        if slug.is_empty()
            || slug.len() > 64
            || !slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            return Err(TinkerError::Validation(format!(
                "invalid object slug in virtual path: {path}"
            )));
        }
        let record_id = Uuid::parse_str(parts[3]).map_err(|_| {
            TinkerError::Validation(format!("invalid record id in virtual path: {path}"))
        })?;
        Ok(Self {
            object_slug: slug.to_string(),
            record_id,
            canonical: format!("/tinker/{slug}/{record_id}/index.md"),
        })
    }
}

pub struct VirtualFileReader<'a> {
    engine: &'a TransformEngine,
    cache: &'a TransformCache,
}

impl<'a> VirtualFileReader<'a> {
    pub fn new(engine: &'a TransformEngine, cache: &'a TransformCache) -> Self {
        Self { engine, cache }
    }

    /// Read a virtual file: resolve the path to the canonical record,
    /// render through the reader's policy, serve from cache when the full
    /// key matches.
    pub async fn read(
        &self,
        ctx: &TenantContext,
        path: &str,
        attachment_id: Option<Uuid>,
    ) -> Result<String> {
        let vp = VirtualPath::parse(path)?;
        let role = self.engine.role_of(ctx).await?;
        // Entitlement set = the role (plus attachment scope when present).
        // Different roles hash to different cache keys: no privileged
        // cache entries.
        let entitlement = match attachment_id {
            Some(a) => format!("role:{role}+attachment:{a}"),
            None => format!("role:{role}"),
        };
        let policy_version = format!("field_grants/{}/{role}", vp.object_slug);
        let (fields, version) = self
            .engine
            .render_record(
                ctx,
                &vp.object_slug,
                vp.record_id,
                attachment_id,
                &vp.canonical,
            )
            .await?;
        let key = cache_key(&CacheKeyParts {
            record_version: version,
            ontology_version: "m7-v1",
            policy_version: &policy_version,
            entitlement_set: &entitlement,
            purpose: &ctx.purpose,
            transform_version: &self.engine.transform_version,
            record_id: &vp.record_id.to_string(),
            object_slug: &vp.object_slug,
        });
        if let Some(cached) = self.cache.get(ctx, &key).await? {
            if let Some(s) = cached.as_str() {
                return Ok(s.to_string());
            }
        }
        let md = render_markdown(&vp, &fields);
        self.cache
            .put(
                ctx,
                &key,
                &policy_version,
                &self.engine.transform_version,
                &serde_json::Value::String(md.clone()),
            )
            .await?;
        Ok(md)
    }
}

fn render_markdown(vp: &VirtualPath, fields: &[(String, serde_json::Value)]) -> String {
    let mut md = format!("# {} {}\n\n", vp.object_slug, vp.record_id);
    md.push_str(&format!("_path: {}_\n\n", vp.canonical));
    for (name, value) in fields {
        let v = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => "(empty)".to_string(),
            other => other.to_string(),
        };
        md.push_str(&format!("- **{name}**: {v}\n"));
    }
    md
}
