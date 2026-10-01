//! Change signals: the per-organization bus behind SSE fan-out.
//!
//! Writers publish [`Signal`]s after mutating an object; SSE subscribers
//! receive id-only invalidation envelopes. The envelope carries record
//! IDs, never row contents — the client refetches through the governed
//! query path, so field-level authorization still applies.
//!
//! Each organization gets its own broadcast channel and its own sequence
//! space. A subscriber can only ever observe its own organization's
//! signals, and per-connection sequence numbers make patches ordered.
//!
//! Post-M8 item 30 (scale-out spike): [`SignalBus::enable_redis_fanout`]
//! bridges the in-process broadcast channels across instances through
//! Redis pub/sub. The wire format is one JSON envelope per signal on a
//! per-organization channel (`tinker:signals:{org_id}`); the per-org
//! sequence becomes a Redis `INCR` so every instance assigns from one
//! global counter. Tenant isolation is enforced three times: the
//! channel name, a re-check of the envelope's organization id on
//! receipt, and the SSE layer subscribing only with the session's own
//! org id.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tinker_core::{Result, TinkerError};
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

use crate::cache::QueryCache;
use crate::meta::MetaCache;

/// Id-only change envelope for one object in one organization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Signal {
    pub organization_id: Uuid,
    pub object_id: Uuid,
    /// Changed record IDs. Contents are never included. Empty for
    /// [`SignalKind::SchemaVersion`].
    pub record_ids: Vec<Uuid>,
    /// Per-organization sequence number; strictly increasing.
    pub seq: u64,
    pub kind: SignalKind,
}

/// What a signal announces. Row edits and schema-version changes share
/// the per-organization broadcast channel and sequence space, but the
/// SSE layer maps them to distinct events: a client that only refetches
/// rows on `invalidate` would never re-resolve its schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignalKind {
    /// Row data changed; `record_ids` names the changed records.
    Invalidate,
    /// The object's active schema version changed (promotion/rollback).
    /// Clients re-resolve the schema and refetch; the query cache for
    /// the object is dropped server-side at the same time.
    SchemaVersion,
}

struct OrgBus {
    tx: broadcast::Sender<Signal>,
    next_seq: u64,
}

/// Redis channel carrying one organization's signal envelopes.
pub fn redis_channel_for(organization_id: Uuid) -> String {
    format!("tinker:signals:{organization_id}")
}

/// Redis key holding one organization's global sequence counter.
fn redis_seq_key_for(organization_id: Uuid) -> String {
    format!("tinker:signals:seq:{organization_id}")
}

const ENVELOPE_VERSION: u8 = 1;

/// The wire envelope: one JSON object per signal on the org's channel.
/// `from` is the publishing instance's id; receivers skip their own
/// echoes (the publisher already delivered locally).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct Envelope {
    v: u8,
    from: Uuid,
    signal: Signal,
}

struct FanoutState {
    client: redis::Client,
    conn: redis::aio::MultiplexedConnection,
    instance_id: Uuid,
    /// Organizations with a live Redis subscriber task.
    subs: RwLock<HashSet<Uuid>>,
}

#[derive(Clone, Default)]
pub struct SignalBus {
    inner: Arc<RwLock<HashMap<Uuid, OrgBus>>>,
    fanout: Arc<RwLock<Option<Arc<FanoutState>>>>,
    /// The instance's query cache, invalidated when a schema-version
    /// signal arrives from ANOTHER instance (local publishes already
    /// invalidate explicitly at the promote/rollback call sites).
    /// Set once at startup; sync because `build_state` is sync.
    cache: Arc<std::sync::OnceLock<QueryCache>>,
    /// The instance's governed-metadata cache, invalidated alongside
    /// the query cache on remote schema-version signals. Set once at
    /// startup; sync because `build_state` is sync.
    meta: Arc<std::sync::OnceLock<MetaCache>>,
}

impl SignalBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable cross-instance fan-out through Redis pub/sub. Fails closed
    /// when the server is unreachable — a configured-but-dead Redis must
    /// not silently boot a single-instance bus. Call once at startup,
    /// before the first publish.
    pub async fn enable_redis_fanout(&self, url: &str) -> Result<()> {
        let client = redis::Client::open(url)
            .map_err(|e| TinkerError::Internal(format!("signal fan-out: bad redis url: {e}")))?;
        // Probe: the multiplexed connection is kept for publishes, so
        // this both verifies reachability and warms the connection.
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                TinkerError::Internal(format!("signal fan-out: redis unreachable: {e}"))
            })?;
        let mut fanout = self.fanout.write().await;
        if fanout.is_some() {
            return Err(TinkerError::Internal(
                "signal fan-out already enabled".into(),
            ));
        }
        *fanout = Some(Arc::new(FanoutState {
            client,
            conn,
            instance_id: Uuid::now_v7(),
            subs: RwLock::new(HashSet::new()),
        }));
        tracing::info!("signal fan-out enabled via redis pub/sub");
        Ok(())
    }

    /// Register the instance's query cache for cross-instance
    /// schema-version invalidation. First call wins; called once from
    /// `build_state`.
    pub fn set_cache_invalidator(&self, cache: QueryCache) {
        let _ = self.cache.set(cache);
    }

    /// Register the instance's metadata cache for cross-instance
    /// schema-version invalidation, alongside the query cache. First
    /// call wins; called once from `build_state`.
    pub fn set_meta_invalidator(&self, meta: MetaCache) {
        let _ = self.meta.set(meta);
    }

    /// Publish a change. Returns the organization-scoped sequence number.
    pub async fn publish(
        &self,
        organization_id: Uuid,
        object_id: Uuid,
        record_ids: Vec<Uuid>,
    ) -> u64 {
        self.publish_inner(
            organization_id,
            object_id,
            record_ids,
            SignalKind::Invalidate,
        )
        .await
    }

    /// Publish a schema-version change (promotion/rollback) for an
    /// object. Open SSE streams surface it as a distinct `schema_version`
    /// event so clients re-resolve the schema instead of waiting for the
    /// next row invalidation — which might never come.
    pub async fn publish_schema_version(&self, organization_id: Uuid, object_id: Uuid) -> u64 {
        self.publish_inner(
            organization_id,
            object_id,
            Vec::new(),
            SignalKind::SchemaVersion,
        )
        .await
    }

    async fn publish_inner(
        &self,
        organization_id: Uuid,
        object_id: Uuid,
        record_ids: Vec<Uuid>,
        kind: SignalKind,
    ) -> u64 {
        let fanout = self.fanout.read().await.clone();
        let Some(fanout) = fanout else {
            return self
                .publish_local(organization_id, object_id, record_ids, kind)
                .await;
        };
        match self
            .publish_remote(
                &fanout,
                organization_id,
                object_id,
                record_ids.clone(),
                kind,
            )
            .await
        {
            Ok(seq) => seq,
            Err(e) => {
                // Degraded, loudly: local subscribers still get the
                // signal; remote instances miss it until Redis recovers.
                // Signals are hints (SSE resyncs by refetch; the query
                // cache TTL bounds staleness), so local delivery beats
                // failing the write.
                tracing::error!(
                    %organization_id,
                    "signal fan-out failed, delivering locally only: {e}"
                );
                self.publish_local(organization_id, object_id, record_ids, kind)
                    .await
            }
        }
    }

    /// Single-instance path: the per-org counter lives in process.
    async fn publish_local(
        &self,
        organization_id: Uuid,
        object_id: Uuid,
        record_ids: Vec<Uuid>,
        kind: SignalKind,
    ) -> u64 {
        let mut map = self.inner.write().await;
        let bus = map.entry(organization_id).or_insert_with(|| {
            let (tx, _) = broadcast::channel(256);
            OrgBus { tx, next_seq: 0 }
        });
        bus.next_seq += 1;
        let seq = bus.next_seq;
        // A lagged or absent receiver is fine: SSE resyncs by refetching.
        let _ = bus.tx.send(Signal {
            organization_id,
            object_id,
            record_ids,
            seq,
            kind,
        });
        seq
    }

    /// Cross-instance path: the per-org sequence is a Redis `INCR`, so
    /// every instance assigns from one global counter and the sequence
    /// space stays strictly increasing per org no matter who publishes.
    async fn publish_remote(
        &self,
        fanout: &FanoutState,
        organization_id: Uuid,
        object_id: Uuid,
        record_ids: Vec<Uuid>,
        kind: SignalKind,
    ) -> Result<u64> {
        let mut conn = fanout.conn.clone();
        let seq: i64 = redis::cmd("INCR")
            .arg(redis_seq_key_for(organization_id))
            .query_async(&mut conn)
            .await
            .map_err(|e| TinkerError::Internal(format!("signal fan-out INCR: {e}")))?;
        let signal = Signal {
            organization_id,
            object_id,
            record_ids,
            seq: seq.max(0) as u64,
            kind,
        };
        let payload = serde_json::to_string(&Envelope {
            v: ENVELOPE_VERSION,
            from: fanout.instance_id,
            signal: signal.clone(),
        })
        .map_err(TinkerError::Serde)?;
        let _: () = redis::cmd("PUBLISH")
            .arg(redis_channel_for(organization_id))
            .arg(payload)
            .query_async(&mut conn)
            .await
            .map_err(|e| TinkerError::Internal(format!("signal fan-out PUBLISH: {e}")))?;
        // Local subscribers get the signal without the Redis round-trip.
        let mut map = self.inner.write().await;
        let bus = map.entry(organization_id).or_insert_with(|| {
            let (tx, _) = broadcast::channel(256);
            OrgBus { tx, next_seq: 0 }
        });
        // Keep the local counter at least as high as the global one so
        // the sequence space can never rewind, even if fan-out is
        // later disabled.
        bus.next_seq = bus.next_seq.max(signal.seq);
        let _ = bus.tx.send(signal.clone());
        Ok(signal.seq)
    }

    /// Subscribe to an organization's signal stream. The caller must have
    /// been authorized for `organization_id` before calling.
    pub async fn subscribe(&self, organization_id: Uuid) -> broadcast::Receiver<Signal> {
        let tx = {
            let mut map = self.inner.write().await;
            map.entry(organization_id)
                .or_insert_with(|| {
                    let (tx, _) = broadcast::channel(256);
                    OrgBus { tx, next_seq: 0 }
                })
                .tx
                .clone()
        };
        if let Some(fanout) = self.fanout.read().await.clone() {
            if fanout.subs.write().await.insert(organization_id) {
                let cache = self.cache.get().cloned();
                let meta = self.meta.get().cloned();
                tokio::spawn(fanout_loop(
                    fanout.client.clone(),
                    organization_id,
                    fanout.instance_id,
                    tx.clone(),
                    cache,
                    meta,
                ));
            }
        }
        tx.subscribe()
    }
}

/// One background task per organization per instance: subscribes to the
/// org's Redis channel and forwards envelopes into the local broadcast
/// channel, so instance-local SSE subscribers observe remote publishes.
async fn fanout_loop(
    client: redis::Client,
    organization_id: Uuid,
    self_id: Uuid,
    tx: broadcast::Sender<Signal>,
    cache: Option<QueryCache>,
    meta: Option<MetaCache>,
) {
    let mut pubsub = match client.get_async_pubsub().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(%organization_id, "signal fan-out pubsub connect failed: {e}");
            return;
        }
    };
    if let Err(e) = pubsub.subscribe(redis_channel_for(organization_id)).await {
        tracing::error!(%organization_id, "signal fan-out SUBSCRIBE failed: {e}");
        return;
    }
    let mut messages = pubsub.on_message();
    while let Some(msg) = tokio_stream::StreamExt::next(&mut messages).await {
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let envelope: Envelope = match serde_json::from_str(&payload) {
            Ok(e) => e,
            Err(_) => continue,
        };
        // Tenant isolation, second check (the first is the per-org
        // channel): a wrong-org envelope is dropped, never delivered to
        // this org's subscribers.
        if envelope.v != ENVELOPE_VERSION || envelope.signal.organization_id != organization_id {
            continue;
        }
        // Own publishes were already delivered locally; skip the echo.
        if envelope.from == self_id {
            continue;
        }
        let signal = envelope.signal;
        // A schema change on another instance invalidates THIS
        // instance's compiled plans too — otherwise it would serve
        // stale plans until the 30s query-cache TTL expires. The
        // governed-metadata cache shares the same freshness contract
        // as the query cache, so it is invalidated at the same sites.
        if signal.kind == SignalKind::SchemaVersion {
            if let Some(cache) = &cache {
                cache.invalidate(organization_id, signal.object_id).await;
            }
            if let Some(meta) = &meta {
                meta.invalidate(organization_id, signal.object_id).await;
            }
        }
        let _ = tx.send(signal);
    }
    tracing::warn!(%organization_id, "signal fan-out stream ended");
}
