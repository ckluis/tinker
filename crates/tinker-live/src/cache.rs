//! Tenant-scoped query result cache.
//!
//! The cache key is `(organization_id, plan_hash)` — the plan hash alone
//! is NEVER a key, so two organizations running the same query shape with
//! colliding record IDs can never read each other's cached rows.
//!
//! Invalidation is by `(organization_id, object_id)`: a write to an
//! object drops every cached plan that read it, for that organization
//! only.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

/// How long a cached result lives without invalidation.
pub const CACHE_TTL: Duration = Duration::from_secs(30);

/// Hard cap on entries: bounds memory under a flood of distinct queries.
/// Eviction drops the oldest half when exceeded.
pub const CACHE_MAX_ENTRIES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    organization_id: Uuid,
    plan_hash: String,
}

struct Entry {
    rows: Vec<serde_json::Value>,
    object_id: Uuid,
    inserted: Instant,
}

#[derive(Clone, Default)]
pub struct QueryCache {
    inner: Arc<RwLock<HashMap<CacheKey, Entry>>>,
}

impl QueryCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        plan_hash: &str,
    ) -> Option<Vec<serde_json::Value>> {
        let map = self.inner.read().await;
        let e = map.get(&CacheKey {
            organization_id,
            plan_hash: plan_hash.to_string(),
        })?;
        if e.inserted.elapsed() > CACHE_TTL {
            return None;
        }
        Some(e.rows.clone())
    }

    pub async fn put(
        &self,
        organization_id: Uuid,
        plan_hash: &str,
        object_id: Uuid,
        rows: Vec<serde_json::Value>,
    ) {
        let mut map = self.inner.write().await;
        // Opportunistic expiry sweep: keep the map bounded without a
        // background task.
        map.retain(|_, e| e.inserted.elapsed() <= CACHE_TTL);
        if map.len() >= CACHE_MAX_ENTRIES {
            // Evict the oldest half. Tenant isolation is preserved:
            // eviction never moves an entry across organizations.
            let mut keys: Vec<(CacheKey, Instant)> =
                map.iter().map(|(k, e)| (k.clone(), e.inserted)).collect();
            keys.sort_by_key(|(_, t)| *t);
            for (k, _) in keys.into_iter().take(CACHE_MAX_ENTRIES / 2) {
                map.remove(&k);
            }
        }
        map.insert(
            CacheKey {
                organization_id,
                plan_hash: plan_hash.to_string(),
            },
            Entry {
                rows,
                object_id,
                inserted: Instant::now(),
            },
        );
    }

    /// Drop cached plans for `object_id`, in `organization_id` only.
    /// Returns the number of entries dropped.
    pub async fn invalidate(&self, organization_id: Uuid, object_id: Uuid) -> usize {
        let mut map = self.inner.write().await;
        let before = map.len();
        map.retain(|k, e| !(k.organization_id == organization_id && e.object_id == object_id));
        before - map.len()
    }
}
