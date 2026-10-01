//! Live Redis behind the [`SessionStore`](crate::sessions::SessionStore) trait.
//!
//! Post-M8 item 19: the multi-instance session/cache contract is now
//! proven against a real Redis server, not just the in-test fake. The
//! migration contract this pins:
//!
//! - **Serialization format:** values are stored as raw bytes (`SET` with
//!   a binary-safe argument). No encoding, no JSON envelope —
//!   non-UTF-8 byte strings round-trip exactly.
//! - **TTL semantics:** `set` issues `SET key value EX ttl_secs`, so
//!   expiry is enforced server-side. A second instance (or a restarted
//!   process) observes the same TTL; nothing about expiry lives in
//!   process-local memory.
//! - **Failure mode:** any Redis I/O or protocol error becomes
//!   [`TinkerError::Internal`] — loud, never `Ok(None)`. A dead Redis
//!   must not read as "session missing".
//!
//! Boundary validation (key `1..=512` chars, value `<= 1 MiB`) matches
//! [`InMemorySessionStore`](crate::sessions::InMemorySessionStore) so
//! the two backends are interchangeable behind the trait. A `ttl_secs`
//! of 0 expires immediately (implemented as `DEL`, since Redis rejects
//! `EX 0`).

use async_trait::async_trait;
use redis::aio::MultiplexedConnection;
use tinker_core::{Result, TinkerError};

use crate::sessions::SessionStore;

/// Maximum session value size: the trait contract, not a Redis limit.
const MAX_VALUE_BYTES: usize = 1024 * 1024;
/// Maximum session key length: the trait contract, not a Redis limit.
const MAX_KEY_CHARS: usize = 512;

/// A [`SessionStore`] backed by a real Redis server.
///
/// Cloning shares the underlying multiplexed connection; two stores
/// built from the same URL with separate `connect` calls are two
/// independent clients (two "instances") that observe each other only
/// through the server — which is exactly the property the live tests
/// prove.
#[derive(Debug, Clone)]
pub struct RedisSessionStore {
    conn: MultiplexedConnection,
}

impl RedisSessionStore {
    /// Connect to the Redis at `url` (e.g. `redis://127.0.0.1:6379/`).
    /// Fails closed if the server is unreachable.
    pub async fn connect(url: &str) -> Result<Self> {
        let client =
            redis::Client::open(url).map_err(|e| TinkerError::Internal(format!("redis: {e}")))?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| TinkerError::Internal(format!("redis: {e}")))?;
        Ok(Self { conn })
    }

    fn check_bounds(key: &str, value: &[u8]) -> Result<()> {
        if key.is_empty() || key.len() > MAX_KEY_CHARS {
            return Err(TinkerError::Validation(
                "session key must be 1..=512 chars".into(),
            ));
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(TinkerError::Validation(
                "session value exceeds 1 MiB".into(),
            ));
        }
        Ok(())
    }

    async fn conn(&self) -> Result<MultiplexedConnection> {
        Ok(self.conn.clone())
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn set(&self, key: &str, value: Vec<u8>, ttl_secs: u64) -> Result<()> {
        Self::check_bounds(key, &value)?;
        let mut con = self.conn().await?;
        if ttl_secs == 0 {
            // Redis rejects EX 0; immediate expiry is observably a delete.
            let _: i64 = redis::cmd("DEL")
                .arg(key)
                .query_async(&mut con)
                .await
                .map_err(|e| TinkerError::Internal(format!("redis: {e}")))?;
            return Ok(());
        }
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(&value)
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut con)
            .await
            .map_err(|e| TinkerError::Internal(format!("redis: {e}")))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut con = self.conn().await?;
        let value: Option<Vec<u8>> = redis::cmd("GET")
            .arg(key)
            .query_async(&mut con)
            .await
            .map_err(|e| TinkerError::Internal(format!("redis: {e}")))?;
        Ok(value)
    }

    async fn del(&self, key: &str) -> Result<()> {
        let mut con = self.conn().await?;
        let _: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut con)
            .await
            .map_err(|e| TinkerError::Internal(format!("redis: {e}")))?;
        Ok(())
    }
}
