//! Multi-instance session/cache contract (PRD v0.6 §43).
//!
//! Redis owns sessions, cache, and pub/sub — never durable truth — and
//! is required for multi-instance live sessions. This module defines the
//! [`SessionStore`] trait plus [`InMemorySessionStore`], an in-test fake
//! behind the same trait. The multi-instance safety property is that two
//! handles sharing one backend see each other's writes: nothing about a
//! session may live in process-local memory when the backend is shared.
//!
//! Post-M8 item 19 proved the contract against a real Redis server too:
//! [`RedisSessionStore`](crate::redis_store::RedisSessionStore)
//! implements this trait over `SET .. EX` / `GET` / `DEL`, and
//! `crates/tinker-transfer/tests/redis_session_store.rs` pins the
//! serialization format, server-side TTL semantics, loud failure mode,
//! and restart recovery against a live `redis-server`.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tinker_core::{Result, TinkerError};
use tokio::sync::RwLock;

/// Session/cache backend. Implementations: the in-test fake here, a real
/// Redis adapter later. Keys are namespaced by the caller.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn set(&self, key: &str, value: Vec<u8>, ttl_secs: u64) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn del(&self, key: &str) -> Result<()>;
}

#[derive(Debug)]
struct Entry {
    value: Vec<u8>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    map: HashMap<String, Entry>,
}

/// In-test fake behind [`SessionStore`]. Two handles created from
/// [`InMemorySessionStore::shared`] see each other's writes — the
/// multi-instance property. A `ttl_secs` of 0 expires immediately.
#[derive(Debug, Clone, Default)]
pub struct InMemorySessionStore {
    inner: Arc<RwLock<Inner>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// A second handle over the same backend: simulates a second
    /// instance behind the same Redis.
    pub fn shared(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Test hook: force-expire one key.
    pub async fn expire_now(&self, key: &str) {
        let mut g = self.inner.write().await;
        if let Some(e) = g.map.get_mut(key) {
            e.expires_at = Instant::now() - Duration::from_secs(1);
        }
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.map.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

#[async_trait]
impl SessionStore for InMemorySessionStore {
    async fn set(&self, key: &str, value: Vec<u8>, ttl_secs: u64) -> Result<()> {
        if key.is_empty() || key.len() > 512 {
            return Err(TinkerError::Validation(
                "session key must be 1..=512 chars".into(),
            ));
        }
        if value.len() > 1024 * 1024 {
            return Err(TinkerError::Validation(
                "session value exceeds 1 MiB".into(),
            ));
        }
        let expires_at = Instant::now() + Duration::from_secs(ttl_secs);
        let mut g = self.inner.write().await;
        // Opportunistic sweep: expired entries are garbage, and an
        // unbounded map is a memory DoS.
        g.map.retain(|_, e| e.expires_at > Instant::now());
        g.map.insert(key.to_string(), Entry { value, expires_at });
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let g = self.inner.read().await;
        Ok(g.map.get(key).and_then(|e| {
            if e.expires_at > Instant::now() {
                Some(e.value.clone())
            } else {
                None
            }
        }))
    }

    async fn del(&self, key: &str) -> Result<()> {
        let mut g = self.inner.write().await;
        g.map.remove(key);
        Ok(())
    }
}

/// Typed JSON session helper over any [`SessionStore`].
pub struct SessionCache<S: SessionStore> {
    store: S,
    prefix: String,
}

impl<S: SessionStore> SessionCache<S> {
    pub fn new(store: S, prefix: impl Into<String>) -> Self {
        Self {
            store,
            prefix: prefix.into(),
        }
    }

    fn namespaced(&self, key: &str) -> String {
        format!("{}:{key}", self.prefix)
    }

    pub async fn put_json(
        &self,
        key: &str,
        value: &serde_json::Value,
        ttl_secs: u64,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        self.store.set(&self.namespaced(key), bytes, ttl_secs).await
    }

    pub async fn get_json(&self, key: &str) -> Result<Option<serde_json::Value>> {
        Ok(match self.store.get(&self.namespaced(key)).await? {
            Some(bytes) => Some(serde_json::from_slice(&bytes)?),
            None => None,
        })
    }

    pub async fn invalidate(&self, key: &str) -> Result<()> {
        self.store.del(&self.namespaced(key)).await
    }
}
