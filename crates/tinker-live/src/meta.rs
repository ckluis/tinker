//! Tenant-scoped governed-metadata cache (item 47).
//!
//! The governed read path re-resolves the same slow-moving metadata on
//! every request: the object description (with evolved fields), the
//! caller's field projection, and the caller's row policy. Each
//! resolution is several DB round trips — a tenant transaction per
//! lookup (begin + `SET LOCAL`s + catalog `SELECT`s + commit) —
//! roughly fifty round trips per cache-hit query, all for data that
//! only changes on writes.
//!
//! This cache collapses the repeat resolutions to zero round trips. The
//! key is `(organization_id, object_id, role, version_label)` — the
//! organization id is part of every key, so tenants never share
//! entries, and the role is part of the key so a projection or policy
//! cached for one role is never served to another. The version label
//! (`active`/`canary`/`preview`) is part of the key so a promotion
//! can't resurrect a plan compiled against the old schema.
//!
//! Freshness parity with the query *result* cache is by construction:
//! every call site that invalidates the result cache also invalidates
//! this one, and both share the same 30s TTL backstop, so metadata can
//! never be staler than the rows it governs.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use uuid::Uuid;

use tinker_evolve::VersionSel;
use tinker_ontology::ObjectDescription;
use tinker_query::{FieldProjection, RowPolicy};

/// TTL backstop: same 30s as the query result cache (see module docs).
pub const META_TTL: Duration = Duration::from_secs(30);

/// Hard cap on entries per map: bounds memory under a flood of distinct
/// objects/roles. Eviction drops the oldest half when exceeded.
pub const META_MAX_ENTRIES: usize = 1024;

/// The governed inputs one query (or get_record) needs, resolved once.
#[derive(Debug, Clone)]
pub struct QueryInputs {
    pub object_id: Uuid,
    /// Description with the resolved version's evolved fields merged in
    /// (what `compile_with_policy` builds its SQL from).
    pub desc: ObjectDescription,
    /// `FieldGrants::load_projection_for_query` for this role.
    pub projection: FieldProjection,
    /// `RowFilters::load_policy` for this role.
    pub policy: RowPolicy,
    /// Which schema version the description was resolved against.
    pub version_sel: VersionSel,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InputsKey {
    organization_id: Uuid,
    object_id: Uuid,
    role: String,
    version: String,
}

struct InputsEntry {
    inputs: QueryInputs,
    inserted: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SlugKey {
    organization_id: Uuid,
    slug: String,
}

struct SlugEntry {
    object_id: Uuid,
    inserted: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DescribeKey {
    organization_id: Uuid,
    object_id: Uuid,
    role: String,
}

struct DescribeEntry {
    described: serde_json::Value,
    inserted: Instant,
}

#[derive(Clone, Default)]
pub struct MetaCache {
    inputs: Arc<RwLock<HashMap<InputsKey, InputsEntry>>>,
    slugs: Arc<RwLock<HashMap<SlugKey, SlugEntry>>>,
    describes: Arc<RwLock<HashMap<DescribeKey, DescribeEntry>>>,
}

impl MetaCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn fresh(inserted: Instant) -> bool {
        inserted.elapsed() <= META_TTL
    }

    // -- query inputs --------------------------------------------------------

    pub async fn get_inputs(
        &self,
        organization_id: Uuid,
        object_id: Uuid,
        role: &str,
        version: &str,
    ) -> Option<QueryInputs> {
        let map = self.inputs.read().await;
        let e = map.get(&InputsKey {
            organization_id,
            object_id,
            role: role.to_string(),
            version: version.to_string(),
        })?;
        if !Self::fresh(e.inserted) {
            return None;
        }
        Some(e.inputs.clone())
    }

    pub async fn put_inputs(
        &self,
        organization_id: Uuid,
        object_id: Uuid,
        role: &str,
        version: &str,
        inputs: QueryInputs,
    ) {
        let mut map = self.inputs.write().await;
        // Opportunistic expiry sweep + oldest-half eviction, mirroring
        // QueryCache::put: keeps the map bounded without a background
        // task.
        map.retain(|_, e| Self::fresh(e.inserted));
        if map.len() >= META_MAX_ENTRIES {
            let mut keys: Vec<(InputsKey, Instant)> =
                map.iter().map(|(k, e)| (k.clone(), e.inserted)).collect();
            keys.sort_by_key(|(_, t)| *t);
            for (k, _) in keys.into_iter().take(META_MAX_ENTRIES / 2) {
                map.remove(&k);
            }
        }
        map.insert(
            InputsKey {
                organization_id,
                object_id,
                role: role.to_string(),
                version: version.to_string(),
            },
            InputsEntry {
                inputs,
                inserted: Instant::now(),
            },
        );
    }

    // -- slug -> id ----------------------------------------------------------

    pub async fn get_slug(&self, organization_id: Uuid, slug: &str) -> Option<Uuid> {
        let map = self.slugs.read().await;
        let e = map.get(&SlugKey {
            organization_id,
            slug: slug.to_string(),
        })?;
        if !Self::fresh(e.inserted) {
            return None;
        }
        Some(e.object_id)
    }

    pub async fn put_slug(&self, organization_id: Uuid, slug: &str, object_id: Uuid) {
        let mut map = self.slugs.write().await;
        map.retain(|_, e| Self::fresh(e.inserted));
        if map.len() >= META_MAX_ENTRIES {
            let mut keys: Vec<(SlugKey, Instant)> =
                map.iter().map(|(k, e)| (k.clone(), e.inserted)).collect();
            keys.sort_by_key(|(_, t)| *t);
            for (k, _) in keys.into_iter().take(META_MAX_ENTRIES / 2) {
                map.remove(&k);
            }
        }
        map.insert(
            SlugKey {
                organization_id,
                slug: slug.to_string(),
            },
            SlugEntry {
                object_id,
                inserted: Instant::now(),
            },
        );
    }

    // -- describe output -----------------------------------------------------

    pub async fn get_describe(
        &self,
        organization_id: Uuid,
        object_id: Uuid,
        role: &str,
    ) -> Option<serde_json::Value> {
        let map = self.describes.read().await;
        let e = map.get(&DescribeKey {
            organization_id,
            object_id,
            role: role.to_string(),
        })?;
        if !Self::fresh(e.inserted) {
            return None;
        }
        Some(e.described.clone())
    }

    pub async fn put_describe(
        &self,
        organization_id: Uuid,
        object_id: Uuid,
        role: &str,
        described: serde_json::Value,
    ) {
        let mut map = self.describes.write().await;
        map.retain(|_, e| Self::fresh(e.inserted));
        if map.len() >= META_MAX_ENTRIES {
            let mut keys: Vec<(DescribeKey, Instant)> =
                map.iter().map(|(k, e)| (k.clone(), e.inserted)).collect();
            keys.sort_by_key(|(_, t)| *t);
            for (k, _) in keys.into_iter().take(META_MAX_ENTRIES / 2) {
                map.remove(&k);
            }
        }
        map.insert(
            DescribeKey {
                organization_id,
                object_id,
                role: role.to_string(),
            },
            DescribeEntry {
                described,
                inserted: Instant::now(),
            },
        );
    }

    /// Drop every cached entry for `object_id`, in `organization_id`
    /// only — all roles, all versions, and the slug mapping. Called from
    /// exactly the same sites that invalidate the query result cache.
    /// Returns the number of entries dropped.
    pub async fn invalidate(&self, organization_id: Uuid, object_id: Uuid) -> usize {
        let mut dropped = 0;
        {
            let mut map = self.inputs.write().await;
            let before = map.len();
            map.retain(|k, _| !(k.organization_id == organization_id && k.object_id == object_id));
            dropped += before - map.len();
        }
        {
            let mut map = self.describes.write().await;
            let before = map.len();
            map.retain(|k, _| !(k.organization_id == organization_id && k.object_id == object_id));
            dropped += before - map.len();
        }
        {
            // Slug entries are keyed by slug, not id: drop the org's
            // whole slug map. Slugs are immutable and the map is tiny;
            // precision here buys nothing.
            let mut map = self.slugs.write().await;
            let before = map.len();
            map.retain(|k, _| k.organization_id != organization_id);
            dropped += before - map.len();
        }
        dropped
    }

    #[cfg(test)]
    pub async fn len(&self) -> usize {
        self.inputs.read().await.len()
            + self.slugs.read().await.len()
            + self.describes.read().await.len()
    }

    #[cfg(test)]
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(object_id: Uuid) -> QueryInputs {
        QueryInputs {
            object_id,
            desc: ObjectDescription {
                id: object_id,
                api_slug: "obj".into(),
                name: "obj".into(),
                scope_kind: "organization".into(),
                fields: vec![],
                lifecycle_enabled: false,
            },
            projection: FieldProjection::default(),
            policy: RowPolicy::default(),
            version_sel: VersionSel::Active,
        }
    }

    #[tokio::test]
    async fn inputs_round_trip() {
        let c = MetaCache::new();
        let org = Uuid::now_v7();
        let obj = Uuid::now_v7();
        assert!(c.get_inputs(org, obj, "admin", "active").await.is_none());
        c.put_inputs(org, obj, "admin", "active", inputs(obj)).await;
        let got = c.get_inputs(org, obj, "admin", "active").await.unwrap();
        assert_eq!(got.object_id, obj);
        // Role isolation: another role must not see admin's entries.
        assert!(c.get_inputs(org, obj, "viewer", "active").await.is_none());
        // Version isolation: canary must not see active's entries.
        assert!(c.get_inputs(org, obj, "admin", "canary").await.is_none());
    }

    #[tokio::test]
    async fn invalidate_is_scoped() {
        let c = MetaCache::new();
        let org_a = Uuid::now_v7();
        let org_b = Uuid::now_v7();
        let obj = Uuid::now_v7();
        c.put_inputs(org_a, obj, "admin", "active", inputs(obj))
            .await;
        c.put_inputs(org_a, obj, "admin", "canary", inputs(obj))
            .await;
        c.put_inputs(org_b, obj, "admin", "active", inputs(obj))
            .await;
        c.put_slug(org_a, "obj", obj).await;
        c.put_describe(org_a, obj, "admin", serde_json::json!({"a": 1}))
            .await;
        // All roles/versions for (org_a, obj) drop; org_b untouched.
        let dropped = c.invalidate(org_a, obj).await;
        assert!(dropped >= 4, "dropped={dropped}");
        assert!(c.get_inputs(org_a, obj, "admin", "active").await.is_none());
        assert!(c.get_inputs(org_a, obj, "admin", "canary").await.is_none());
        assert!(c.get_slug(org_a, "obj").await.is_none());
        assert!(c.get_describe(org_a, obj, "admin").await.is_none());
        assert!(c.get_inputs(org_b, obj, "admin", "active").await.is_some());
    }

    #[tokio::test]
    async fn slug_and_describe_round_trip() {
        let c = MetaCache::new();
        let org = Uuid::now_v7();
        let obj = Uuid::now_v7();
        c.put_slug(org, "my-slug", obj).await;
        assert_eq!(c.get_slug(org, "my-slug").await, Some(obj));
        assert_eq!(c.get_slug(org, "other").await, None);
        let doc = serde_json::json!({"api_slug": "my-slug"});
        c.put_describe(org, obj, "admin", doc.clone()).await;
        assert_eq!(c.get_describe(org, obj, "admin").await, Some(doc));
        assert!(c.get_describe(org, obj, "viewer").await.is_none());
    }

    #[tokio::test]
    async fn cap_evicts_oldest_half() {
        let c = MetaCache::new();
        let org = Uuid::now_v7();
        for _ in 0..(META_MAX_ENTRIES + 10) {
            let obj = Uuid::now_v7();
            c.put_slug(org, &obj.to_string(), obj).await;
        }
        let len = c.len().await;
        assert!(len <= META_MAX_ENTRIES, "cap exceeded: len={len}");
        assert!(
            len >= META_MAX_ENTRIES / 2,
            "evicted too aggressively: len={len}"
        );
    }
}
