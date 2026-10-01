//! Post-M8 item 30 (scale-out spike): cross-instance SSE signal
//! fan-out over Redis pub/sub.
//!
//! Two [`SignalBus`]es with [`SignalBus::enable_redis_fanout`] are two
//! app instances that share nothing in process memory. These tests pin:
//!
//! - a signal (`Invalidate` AND `SchemaVersion`) published on A reaches
//!   a subscriber on B;
//! - the per-org sequence is one global counter (Redis `INCR`): two
//!   publishers assign strictly increasing, gap-free seqs;
//! - tenant isolation: a subscriber only ever sees its own org's
//!   signals, even when another org publishes concurrently;
//! - a `SchemaVersion` arriving from another instance invalidates the
//!   receiving instance's query cache;
//! - an instance never receives its own publish twice (echo skip).
//!
//! Redis: uses `TINKER_TEST_REDIS_URL` when set, else spawns its own
//! `redis-server` on 127.0.0.1:16379 (no persistence). Fails loudly
//! when neither is available — never silently skips.

use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tinker_live::{QueryCache, SignalBus, SignalKind};
use uuid::Uuid;

const DEFAULT_URL: &str = "redis://127.0.0.1:16379/";
const DEFAULT_PORT: u16 = 16379;

struct ServerGuard {
    child: Mutex<Option<Child>>,
    url: String,
    dir: std::path::PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn server() -> &'static ServerGuard {
    static GUARD: OnceLock<ServerGuard> = OnceLock::new();
    GUARD.get_or_init(|| {
        let url = std::env::var("TINKER_TEST_REDIS_URL").unwrap_or_else(|_| DEFAULT_URL.into());
        let custom = std::env::var("TINKER_TEST_REDIS_URL").is_ok();
        if ping(&url) {
            return ServerGuard {
                child: Mutex::new(None),
                url,
                dir: std::path::PathBuf::new(),
            };
        }
        if custom {
            panic!(
                "TINKER_TEST_REDIS_URL={url} is unreachable and auto-spawn only covers the default; \
                 point it at a live Redis or unset it"
            );
        }
        let dir = std::env::temp_dir().join(format!("tinker-fanout-redis-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create redis test dir");
        let mut child = Command::new("redis-server")
            .arg("--port")
            .arg(DEFAULT_PORT.to_string())
            .arg("--save")
            .arg("")
            .arg("--appendonly")
            .arg("no")
            .arg("--dir")
            .arg(&dir)
            .arg("--daemonize")
            .arg("no")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap_or_else(|e| {
                panic!("could not spawn redis-server ({e}); install redis-server or set TINKER_TEST_REDIS_URL")
            });
        let mut ready = false;
        for _ in 0..100 {
            if ping(&url) {
                ready = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !ready {
            let _ = child.kill();
            panic!("spawned redis-server never answered PING on {url}");
        }
        ServerGuard {
            child: Mutex::new(Some(child)),
            url,
            dir,
        }
    })
}

fn ping(url: &str) -> bool {
    let client = match redis::Client::open(url) {
        Ok(c) => c,
        Err(_) => return false,
    };
    match client.get_connection_with_timeout(Duration::from_millis(300)) {
        Ok(mut con) => redis::cmd("PING")
            .query::<String>(&mut con)
            .map(|p| p == "PONG")
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Two "instances": separately constructed buses sharing only Redis.
async fn two_instances() -> (SignalBus, SignalBus) {
    let a = SignalBus::new();
    a.enable_redis_fanout(&server().url)
        .await
        .expect("fanout on A");
    let b = SignalBus::new();
    b.enable_redis_fanout(&server().url)
        .await
        .expect("fanout on B");
    (a, b)
}

async fn recv_timeout(
    rx: &mut tokio::sync::broadcast::Receiver<tinker_live::Signal>,
    secs: u64,
) -> Option<tinker_live::Signal> {
    tokio::time::timeout(Duration::from_secs(secs), rx.recv())
        .await
        .ok()?
        .ok()
}

#[tokio::test]
async fn invalidate_and_schema_version_reach_the_other_instance() {
    let (a, b) = two_instances().await;
    let org = Uuid::now_v7();
    let object = Uuid::now_v7();
    let record = Uuid::now_v7();

    let mut rx = b.subscribe(org).await;
    // Let the forwarder task finish SUBSCRIBE before publishing.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let s1 = a.publish(org, object, vec![record]).await;
    let s2 = a.publish_schema_version(org, object).await;
    assert!(s2 > s1, "sequence must increase across kinds");

    let m1 = recv_timeout(&mut rx, 5)
        .await
        .expect("B must receive A's invalidate");
    assert_eq!(m1.seq, s1);
    assert_eq!(m1.kind, SignalKind::Invalidate);
    assert_eq!(m1.organization_id, org);
    assert_eq!(m1.object_id, object);
    assert_eq!(m1.record_ids, vec![record]);

    let m2 = recv_timeout(&mut rx, 5)
        .await
        .expect("B must receive A's schema_version");
    assert_eq!(m2.seq, s2);
    assert_eq!(m2.kind, SignalKind::SchemaVersion);
    assert!(m2.record_ids.is_empty());
}

#[tokio::test]
async fn sequence_is_one_global_counter_across_publishers() {
    let (a1, b) = two_instances().await;
    let a2 = SignalBus::new();
    a2.enable_redis_fanout(&server().url)
        .await
        .expect("fanout on A2");
    let org = Uuid::now_v7();
    let object = Uuid::now_v7();

    let mut rx = b.subscribe(org).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Sequential publishes: Redis INCR order is deterministic.
    let s1 = a1.publish(org, object, vec![]).await;
    let s2 = a2.publish(org, object, vec![]).await;
    let s3 = a1.publish_schema_version(org, object).await;
    assert!(
        s1 < s2 && s2 < s3,
        "seqs must be strictly increasing: {s1} {s2} {s3}"
    );

    for expected in [s1, s2, s3] {
        let m = recv_timeout(&mut rx, 5)
            .await
            .expect("B must receive every publish in order");
        assert_eq!(m.seq, expected);
    }
}

#[tokio::test]
async fn subscriber_only_sees_its_own_org() {
    let (a, b) = two_instances().await;
    let org1 = Uuid::now_v7();
    let org2 = Uuid::now_v7();
    let object = Uuid::now_v7();

    let mut rx1 = b.subscribe(org1).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Another org publishes (both kinds): org1's subscriber must see
    // nothing.
    a.publish(org2, object, vec![Uuid::now_v7()]).await;
    a.publish_schema_version(org2, object).await;
    assert!(
        recv_timeout(&mut rx1, 1).await.is_none(),
        "tenant isolation: org1 subscriber must not see org2 signals"
    );

    // Sanity: its own org's signal does arrive.
    let s = a.publish(org1, object, vec![]).await;
    let m = recv_timeout(&mut rx1, 5)
        .await
        .expect("own-org signal must arrive");
    assert_eq!(m.seq, s);
}

#[tokio::test]
async fn remote_schema_version_invalidates_the_receiving_cache() {
    let (a, b) = two_instances().await;
    let org = Uuid::now_v7();
    let object = Uuid::now_v7();

    let cache = QueryCache::new();
    cache
        .put(org, "plan-1", object, vec![serde_json::json!({"r": 1})])
        .await;
    b.set_cache_invalidator(cache.clone());
    let _rx = b.subscribe(org).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    a.publish_schema_version(org, object).await;
    // Poll: the forwarder invalidates asynchronously.
    let mut cleared = false;
    for _ in 0..100 {
        if cache.get(org, "plan-1").await.is_none() {
            cleared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        cleared,
        "B's cache must drop the plan on A's schema_version"
    );

    // Row invalidates do NOT drop the cache (pre-existing 30s-TTL
    // semantics, unchanged by the fan-out).
    cache
        .put(org, "plan-2", object, vec![serde_json::json!({"r": 2})])
        .await;
    a.publish(org, object, vec![Uuid::now_v7()]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        cache.get(org, "plan-2").await.is_some(),
        "row invalidate must not drop cached plans"
    );
}

#[tokio::test]
async fn publisher_does_not_receive_its_own_echo() {
    let (a, _b) = two_instances().await;
    let org = Uuid::now_v7();
    let object = Uuid::now_v7();

    // A subscribes AND publishes: the Redis echo of its own publish
    // must be skipped (it was already delivered locally).
    let mut rx = a.subscribe(org).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let s = a.publish(org, object, vec![]).await;

    let m = recv_timeout(&mut rx, 5)
        .await
        .expect("local delivery must still work");
    assert_eq!(m.seq, s);
    assert!(
        recv_timeout(&mut rx, 1).await.is_none(),
        "own publish must not be delivered twice via the Redis echo"
    );
}

#[tokio::test]
async fn fanout_enable_fails_closed_on_unreachable_redis() {
    let bus = SignalBus::new();
    // Port 1 is (practically) always closed: fast refusal.
    let err = bus
        .enable_redis_fanout("redis://127.0.0.1:1/")
        .await
        .expect_err("unreachable redis must fail closed");
    assert!(
        err.to_string().contains("redis"),
        "error must name redis: {err}"
    );
}
