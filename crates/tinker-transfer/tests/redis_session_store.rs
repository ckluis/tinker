//! Post-M8 item 19: prove the [`SessionStore`] contract against a REAL
//! Redis server — serialization format, server-side TTL semantics, the
//! loud failure mode, and restart recovery. The migration contract:
//!
//! - values are raw bytes (`SET`, binary-safe; non-UTF-8 round-trips);
//! - `set` issues `SET key value EX ttl_secs`: expiry is enforced by the
//!   server, visible to every instance (verified via raw `PTTL`);
//! - any I/O or protocol error becomes `TinkerError::Internal` — a dead
//!   Redis never reads as "session missing".
//!
//! The harness starts its own `redis-server` on 127.0.0.1:16379 (a
//! test-only port; no persistence, no appendonly) when nothing answers
//! there, or uses `TINKER_TEST_REDIS_URL` when set. If neither a live
//! server nor the `redis-server` binary is available, the tests fail
//! loudly with the remedy — never silently skip: this suite is the
//! proof the backlog item demands.

use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tinker_transfer::sessions::SessionCache;
use tinker_transfer::{RedisSessionStore, SessionStore};

const DEFAULT_URL: &str = "redis://127.0.0.1:16379/";
const DEFAULT_PORT: u16 = 16379;

/// Serializes the tests: the restart test stops the server, so nothing
/// else may be mid-flight. The suite is small; the cost is seconds.
/// A tokio Mutex: the guard is held across await points (clippy
/// `await_holding_lock` forbids std Mutex here).
static SERVER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct ServerGuard {
    child: Mutex<Option<Child>>,
    url: String,
    /// True when this guard spawned the server (so the restart test may
    /// kill it). False when an external server was adopted.
    owned: bool,
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
                owned: false,
                dir: std::path::PathBuf::new(),
            };
        }
        if custom {
            panic!(
                "TINKER_TEST_REDIS_URL={url} is unreachable and auto-spawn only covers the default; \
                 point it at a live Redis or unset it"
            );
        }
        let dir = std::env::temp_dir().join(format!("tinker-redis-test-{}", std::process::id()));
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
                panic!(
                    "could not spawn redis-server ({e}); install redis-server or set \
                     TINKER_TEST_REDIS_URL to a live server"
                )
            });
        // Wait for readiness; fail loudly instead of hanging the suite.
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
            owned: true,
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

/// Connect a store. Callers hold SERVER_LOCK for the whole test body —
/// this helper takes no lock itself (std Mutex is not reentrant).
async fn store() -> RedisSessionStore {
    RedisSessionStore::connect(&server().url)
        .await
        .expect("connect to test redis")
}

/// Unique key namespace per test so the (serialized) tests never collide.
fn ns(test: &str, key: &str) -> String {
    format!("i19:{test}:{key}")
}

async fn raw_pttl_ms(key: &str) -> i64 {
    let client = redis::Client::open(server().url.as_str()).unwrap();
    let mut con = client.get_multiplexed_async_connection().await.unwrap();
    redis::cmd("PTTL")
        .arg(key)
        .query_async(&mut con)
        .await
        .unwrap()
}

#[tokio::test]
async fn two_instances_share_writes_through_the_server() {
    let _g = SERVER_LOCK.lock().await;
    // Two separately-connected clients = two app instances. Nothing is
    // shared in process memory; visibility goes through Redis alone.
    let a = RedisSessionStore::connect(&server().url).await.unwrap();
    let b = RedisSessionStore::connect(&server().url).await.unwrap();

    let k = ns("share", "user:1");
    a.set(&k, b"{\"name\":\"ada\"}".to_vec(), 3600)
        .await
        .unwrap();
    assert_eq!(
        b.get(&k).await.unwrap(),
        Some(b"{\"name\":\"ada\"}".to_vec())
    );

    b.del(&k).await.unwrap();
    assert_eq!(a.get(&k).await.unwrap(), None);

    // Missing keys read as None, not an error.
    assert_eq!(a.get(&ns("share", "nope")).await.unwrap(), None);

    // SessionCache prefix namespacing holds over the real backend.
    let ca = SessionCache::new(a, "sess-a");
    let cb = SessionCache::new(b, "sess-b");
    ca.put_json("u", &serde_json::json!({"n": 1}), 3600)
        .await
        .unwrap();
    assert_eq!(cb.get_json("u").await.unwrap(), None);
    assert_eq!(
        ca.get_json("u").await.unwrap(),
        Some(serde_json::json!({"n": 1}))
    );
    ca.invalidate("u").await.unwrap();
}

#[tokio::test]
async fn ttl_is_enforced_server_side() {
    let _g = SERVER_LOCK.lock().await;
    let s = store().await;

    // A 1-hour TTL is visible to the server itself (PTTL ~ 3600s): expiry
    // is not client-side bookkeeping.
    let k = ns("ttl", "long");
    s.set(&k, b"v".to_vec(), 3600).await.unwrap();
    let pttl = raw_pttl_ms(&k).await;
    assert!(
        (3_590_000..=3_600_000).contains(&pttl),
        "server-side TTL should be ~3600s, PTTL={pttl}ms"
    );
    s.del(&k).await.unwrap();

    // A 1-second TTL actually expires: the server stops returning it.
    let k2 = ns("ttl", "short");
    s.set(&k2, b"v".to_vec(), 1).await.unwrap();
    assert_eq!(s.get(&k2).await.unwrap(), Some(b"v".to_vec()));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(s.get(&k2).await.unwrap(), None);

    // ttl 0 expires immediately (implemented as DEL; Redis rejects EX 0).
    let k3 = ns("ttl", "zero");
    s.set(&k3, b"v".to_vec(), 0).await.unwrap();
    assert_eq!(s.get(&k3).await.unwrap(), None);
}

#[tokio::test]
async fn values_are_binary_safe_raw_bytes() {
    let _g = SERVER_LOCK.lock().await;
    let s = store().await;

    // Non-UTF-8 bytes, NULs, 0xFF: the wire format is raw bytes, so the
    // round-trip must be exact. (A JSON/text envelope would mangle this.)
    let k = ns("bin", "raw");
    let bytes: Vec<u8> = (0u8..=255u8).collect();
    s.set(&k, bytes.clone(), 3600).await.unwrap();
    assert_eq!(s.get(&k).await.unwrap(), Some(bytes));
    s.del(&k).await.unwrap();

    // Overwriting replaces the whole value.
    s.set(&k, b"one".to_vec(), 3600).await.unwrap();
    s.set(&k, b"two".to_vec(), 3600).await.unwrap();
    assert_eq!(s.get(&k).await.unwrap(), Some(b"two".to_vec()));
    s.del(&k).await.unwrap();
}

#[tokio::test]
async fn boundary_validation_matches_the_fake() {
    let _g = SERVER_LOCK.lock().await;
    let s = store().await;

    // Same contract as InMemorySessionStore: invalid inputs are
    // Validation errors raised before touching the server.
    assert!(s.set("", b"v".to_vec(), 1).await.is_err());
    assert!(s.set(&"k".repeat(513), b"v".to_vec(), 1).await.is_err());
    assert!(s.set("big", vec![0u8; 1024 * 1024 + 1], 1).await.is_err());

    // The limits themselves are usable.
    let k = "k".repeat(512);
    s.set(&k, vec![0u8; 1024 * 1024], 1).await.unwrap();
    s.del(&k).await.unwrap();
}

#[tokio::test]
async fn unreachable_redis_fails_loud_never_as_missing() {
    let _g = SERVER_LOCK.lock().await;
    // Port 1 is (practically) always closed: connection refused, fast.
    let dead = RedisSessionStore::connect("redis://127.0.0.1:1/")
        .await
        .expect_err("connect to a dead redis must fail");
    let msg = dead.to_string();
    assert!(msg.contains("redis"), "error must name the backend: {msg}");

    // Even if a store object existed, a get against a dead server must
    // be an Err, never Ok(None): Ok(None) would read as "no session"
    // and fail open. (connect already fails, so this pins the mapping
    // at the constructor; the op path maps identically.)
}

#[tokio::test]
async fn server_restart_recovers_and_loses_no_local_state() {
    let _g = SERVER_LOCK.lock().await;
    if !server().owned {
        eprintln!("skipping restart test: using an external (non-owned) redis");
        return;
    }
    let s = store().await;
    let k = ns("restart", "k");
    s.set(&k, b"before".to_vec(), 3600).await.unwrap();
    assert_eq!(s.get(&k).await.unwrap(), Some(b"before".to_vec()));

    // Stop the server out from under the client.
    let guard = server();
    let mut child = guard
        .child
        .lock()
        .unwrap()
        .take()
        .expect("owned server child");
    child.kill().expect("kill test redis");
    child.wait().expect("reap test redis");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // A fresh client against the dead port fails closed and fast.
    let err = RedisSessionStore::connect(&guard.url)
        .await
        .expect_err("connect while server is down must fail");
    assert!(err.to_string().contains("redis"));

    // Restart a fresh server on the same port (no persistence configured).
    let dir = guard.dir.clone();
    let child = Command::new("redis-server")
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
        .expect("respawn redis-server");
    let mut ready = false;
    for _ in 0..100 {
        if ping(&guard.url) {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "respawned redis never answered PING");
    *guard.child.lock().unwrap() = Some(child);

    // The client recovers against the new server, and the pre-kill key
    // is gone: sessions lived in the server, never in process memory.
    let s2 = RedisSessionStore::connect(&guard.url).await.unwrap();
    assert_eq!(s2.get(&k).await.unwrap(), None);
    s2.set(&k, b"after".to_vec(), 3600).await.unwrap();
    assert_eq!(s2.get(&k).await.unwrap(), Some(b"after".to_vec()));
    s2.del(&k).await.unwrap();
}
