//! Post-M8 item 30 (scale-out spike): the real two-process proof.
//!
//! Two `tinker` server binaries on different ports share one Postgres
//! and one Redis (both spawned binaries run migrations at startup —
//! which also exercises the advisory-lock serialization in production
//! shape). The test pins:
//!
//! 1. **Cross-instance sessions, no stickiness**: full passkey login on
//!    instance A, then an authenticated `GET /apps` on instance B
//!    returns 200.
//! 2. **Cross-instance SSE fan-out**: an SSE stream opened on B receives
//!    the `invalidate` event for a message posted through A's HTTP API.
//! 3. **Tenant isolation across the fan-out**: a write in org2 (via A)
//!    produces no event on org1's SSE stream (on B).
//!
//! Redis: `TINKER_TEST_REDIS_URL` when set, else a spawned `redis-server`
//! on 127.0.0.1:16379. Fails loudly when neither is available.

use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
use tinker_identity::{Authorizer, SessionManager};
use uuid::Uuid;

const REDIS_DEFAULT_URL: &str = "redis://127.0.0.1:16379/";
const REDIS_DEFAULT_PORT: u16 = 16379;
// Deliberately far from the Bocht campaign's :18080 test-server range:
// a sibling campaign binary was observed squatting on 18081 mid-run.
const PORT_A: u16 = 18681;
const PORT_B: u16 = 18682;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

// Item 35: the binary-flavor guard is gone — tinker-web's binary is
// `tinker` and tinker-m7's is `tinker-cli`, so each links to its own
// target path and the two can never collide again.

// ---------------------------------------------------------------------------
// Redis guard (spawn when nothing answers)
// ---------------------------------------------------------------------------

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

fn redis_server() -> &'static ServerGuard {
    static GUARD: OnceLock<ServerGuard> = OnceLock::new();
    GUARD.get_or_init(|| {
        let url =
            std::env::var("TINKER_TEST_REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.into());
        let custom = std::env::var("TINKER_TEST_REDIS_URL").is_ok();
        if ping_redis(&url) {
            return ServerGuard {
                child: Mutex::new(None),
                url,
                dir: std::path::PathBuf::new(),
            };
        }
        if custom {
            panic!(
                "TINKER_TEST_REDIS_URL={url} is unreachable and auto-spawn only covers the default"
            );
        }
        let dir =
            std::env::temp_dir().join(format!("tinker-scaleout-redis-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create redis test dir");
        let mut child = Command::new("redis-server")
            .arg("--port")
            .arg(REDIS_DEFAULT_PORT.to_string())
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
            .expect("spawn redis-server");
        let mut ready = false;
        for _ in 0..100 {
            if ping_redis(&url) {
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

fn ping_redis(url: &str) -> bool {
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

// ---------------------------------------------------------------------------
// Fixture: two orgs, each with workspace + actor + passkey + thread:write
// ---------------------------------------------------------------------------

struct OrgFixture {
    org_id: Uuid,
    workspace_id: Uuid,
    actor_id: Uuid,
    signing_key: SigningKey,
    credential_id: String,
}

async fn make_org(
    owner: &sqlx::PgPool,
    tenant: &sqlx::PgPool,
    sessions: &SessionManager,
    authorizer: &Authorizer,
    host_id: Uuid,
    run: &str,
    name: &str,
) -> OrgFixture {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(name)
        .bind(format!("{name}-{run}"))
        .execute(owner)
        .await
        .unwrap();
    // Forced RLS on workspaces/actors/memberships: seed through the
    // app-role pool with the org pinned, like the m1 harness.
    let workspace_id = Uuid::now_v7();
    let actor_id = Uuid::now_v7();
    let ctx = tinker_core::TenantContext::new(
        tinker_core::OrganizationId(org_id),
        actor_id,
        "scale-out-fixture".to_string(),
    );
    let mut tx = tinker_db::CoreDb(tenant.clone())
        .tenant_tx(&ctx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workspaces (id, organization_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(workspace_id)
        .bind(org_id)
        .bind("main")
        .bind(format!("main-{run}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)",
    )
    .bind(actor_id)
    .bind(org_id)
    .bind(format!("{name} admin"))
    .bind(format!("{name}-admin"))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(actor_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let credential_id = format!("cred-{name}-{run}");
    sessions
        .enroll_passkey(
            org_id,
            actor_id,
            &credential_id,
            signing_key.verifying_key().to_bytes(),
        )
        .await
        .unwrap();
    authorizer
        .grant(
            org_id,
            actor_id,
            &tinker_auth::AuthzScope::Organization {
                organization_id: org_id,
            },
            "thread:write",
            None,
        )
        .await
        .unwrap();
    OrgFixture {
        org_id,
        workspace_id,
        actor_id,
        signing_key,
        credential_id,
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

/// Full passkey ceremony over HTTP against one instance. Returns the
/// raw session cookie value.
async fn passkey_login(base: &str, org: &OrgFixture) -> String {
    let c = client();
    let start: serde_json::Value = c
        .post(format!("{base}/login/passkey/start"))
        .json(&serde_json::json!({
            "organization_id": org.org_id.to_string(),
            "actor_id": org.actor_id.to_string(),
        }))
        .send()
        .await
        .expect("passkey start")
        .error_for_status()
        .expect("passkey start 200")
        .json()
        .await
        .expect("start json");
    let challenge = URL_SAFE_NO_PAD
        .decode(start["challenge"].as_str().unwrap())
        .unwrap();
    // A real WebAuthn assertion for the servers' relying party
    // (TINKER_HOST=tinker.test → RP ID tinker.test, origin https://tinker.test).
    let rp = tinker_auth::webauthn::RelyingParty::from_env("tinker.test");
    let (cd, ad, sig) = tinker_auth::webauthn::soft_authenticator::ed25519_assertion(
        &org.signing_key,
        &rp,
        &challenge,
        0,
        true,
    );
    let res = c
        .post(format!("{base}/login/passkey/finish"))
        .json(&serde_json::json!({
            "organization_id": org.org_id.to_string(),
            "workspace_id": org.workspace_id.to_string(),
            "credential_id": org.credential_id,
            "challenge_id": start["challenge_id"].as_str().unwrap(),
            "client_data_json": cd,
            "authenticator_data": ad,
            "signature": sig,
        }))
        .send()
        .await
        .expect("passkey finish");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::SEE_OTHER,
        "passkey finish must redirect"
    );
    let set_cookie = res
        .headers()
        .get(reqwest::header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .unwrap()
        .to_string();
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix(&format!("{}=", tinker_web::SESSION_COOKIE))
        .unwrap()
        .to_string()
}

async fn wait_ready(inst: &mut Instance) {
    let base = inst.base.clone();
    let c = client();
    for _ in 0..150 {
        if let Ok(Some(_status)) = inst.child.try_wait() {
            let log = std::fs::read_to_string(&inst.err_log).unwrap_or_default();
            panic!(
                "{base} instance exited during startup; stderr log tail:\n{}",
                tail(&log, 20)
            );
        }
        if let Ok(r) = c.get(format!("{base}/login")).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let log = std::fs::read_to_string(&inst.err_log).unwrap_or_default();
    panic!(
        "{base} never became ready; stderr log tail:\n{}",
        tail(&log, 20)
    );
}

fn tail(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

/// Block until nothing listens on `port` (a previous run's instance may
/// still be releasing it), up to ~15s.
fn wait_port_free(port: u16) {
    for _ in 0..150 {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("port {port} still occupied after 15s");
}

struct Instance {
    child: Child,
    base: String,
    err_log: std::path::PathBuf,
}

impl Drop for Instance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_instance(port: u16, redis_url: &str) -> Instance {
    wait_port_free(port);
    // main.rs reads TINKER_CORE_URL as the OWNER url and TINKER_APP_URL
    // as the app-role url.
    let err_log = std::path::PathBuf::from(format!("/tmp/tinker-scaleout-{port}.log"));
    let err_file = std::fs::File::create(&err_log).expect("create instance stderr log");
    let child = Command::new(env!("CARGO_BIN_EXE_tinker"))
        .env("TINKER_CORE_URL", env("TINKER_CORE_OWNER_URL"))
        .env("TINKER_APP_URL", env("TINKER_CORE_URL"))
        .env("TINKER_HOST", "tinker.test")
        .env("TINKER_ADDR", format!("127.0.0.1:{port}"))
        .env("TINKER_REDIS_URL", redis_url)
        .stdout(Stdio::null())
        .stderr(err_file)
        .spawn()
        .expect("spawn tinker instance");
    Instance {
        child,
        base: format!("http://127.0.0.1:{port}"),
        err_log,
    }
}

/// Parsed SSE frames flowing from the background reader.
#[derive(Debug)]
struct SseEvent {
    event: String,
    data: String,
}

/// Open an SSE stream; spawn a background reader pushing parsed frames
/// into the returned channel. The stream (and reader) live until the
/// returned task handle is dropped/aborted.
async fn open_sse(
    base: &str,
    cookie: &str,
    object_id: Uuid,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::UnboundedReceiver<SseEvent>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let url = format!("{base}/api/sse?object={object_id}");
    let cookie = cookie.to_string();
    let handle = tokio::spawn(async move {
        let c = client();
        let res = c
            .get(&url)
            .header("Cookie", format!("{}={cookie}", tinker_web::SESSION_COOKIE))
            .send()
            .await
            .expect("sse connect");
        assert!(
            res.status().is_success(),
            "sse subscribe must succeed, got {}",
            res.status()
        );
        let mut stream = res.bytes_stream();
        let mut buf = String::new();
        use tokio_stream::StreamExt as _;
        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(b) => b,
                Err(_) => break,
            };
            buf.push_str(&String::from_utf8_lossy(&chunk));
            while let Some(idx) = buf.find("\n\n") {
                let frame = buf[..idx].to_string();
                buf = buf[idx + 2..].to_string();
                let mut event = String::new();
                let mut data = String::new();
                for line in frame.lines() {
                    if let Some(e) = line.strip_prefix("event:") {
                        event = e.trim().to_string();
                    } else if let Some(d) = line.strip_prefix("data:") {
                        data = d.trim().to_string();
                    }
                }
                if !event.is_empty() {
                    let _ = tx.send(SseEvent { event, data });
                }
            }
        }
    });
    (handle, rx)
}

async fn post_message(base: &str, cookie: &str, thread_id: Uuid, body: &str) -> Uuid {
    let c = client();
    let v: serde_json::Value = c
        .post(format!("{base}/api/comms/threads/{thread_id}/messages"))
        .header("Cookie", format!("{}={cookie}", tinker_web::SESSION_COOKIE))
        .json(&serde_json::json!({ "body": body }))
        .send()
        .await
        .expect("post message")
        .error_for_status()
        .expect("post message 201")
        .json()
        .await
        .expect("message json");
    v["id"].as_str().unwrap().parse().unwrap()
}

async fn make_thread(base: &str, cookie: &str) -> Uuid {
    let c = client();
    let hdr = |b: reqwest::RequestBuilder| {
        b.header("Cookie", format!("{}={cookie}", tinker_web::SESSION_COOKIE))
    };
    let ch: serde_json::Value = hdr(c.post(format!("{base}/api/comms/channels")))
        .json(&serde_json::json!({ "name": "scale-out", "kind": "channel" }))
        .send()
        .await
        .expect("create channel")
        .error_for_status()
        .expect("create channel 201")
        .json()
        .await
        .expect("channel json");
    let channel_id = ch["id"].as_str().unwrap().to_string();
    let th: serde_json::Value = hdr(c.post(format!("{base}/api/comms/threads")))
        .json(&serde_json::json!({ "channel_id": channel_id, "subject": "scale-out thread" }))
        .send()
        .await
        .expect("create thread")
        .error_for_status()
        .expect("create thread 201")
        .json()
        .await
        .expect("thread json");
    th["id"].as_str().unwrap().parse().unwrap()
}

// ---------------------------------------------------------------------------
// The proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn two_processes_share_sessions_and_signals() {
    let redis_url = redis_server().url.clone();

    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let tenant = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    // Migrations first (the binaries also migrate at startup, under the
    // advisory lock — the second instance's migrate must simply wait).
    tinker_db::MIGRATOR_CORE
        .run(&owner)
        .await
        .expect("core migrations");

    let sessions = SessionManager::new(tenant.clone(), owner.clone());
    let authorizer = Authorizer::new(tenant.clone(), owner.clone());
    let run: String = Uuid::now_v7().simple().to_string()[..8].into();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind(format!("host-{run}"))
        .execute(&owner)
        .await
        .unwrap();
    let org1 = make_org(
        &owner,
        &tenant,
        &sessions,
        &authorizer,
        host_id,
        &run,
        "acme",
    )
    .await;
    let org2 = make_org(
        &owner,
        &tenant,
        &sessions,
        &authorizer,
        host_id,
        &run,
        "globex",
    )
    .await;

    let mut a = spawn_instance(PORT_A, &redis_url);
    let mut b = spawn_instance(PORT_B, &redis_url);
    wait_ready(&mut a).await;
    wait_ready(&mut b).await;

    // 1. Login on A...
    let cookie1 = passkey_login(&a.base, &org1).await;
    let cookie2 = passkey_login(&a.base, &org2).await;

    // ...authenticated request on B: no stickiness.
    let res = client()
        .get(format!("{}/apps", b.base))
        .header(
            "Cookie",
            format!("{}={cookie1}", tinker_web::SESSION_COOKIE),
        )
        .send()
        .await
        .expect("GET /apps on B");
    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "session minted on A must be accepted on B"
    );

    // 2+3. SSE fan-out with tenant isolation. The comms message object
    // is platform-wide; resolve its id for the subscription.
    let (message_object,): (Uuid,) =
        sqlx::query_as("SELECT id FROM ontology_objects WHERE api_slug = 'comm_message'")
            .fetch_one(&owner)
            .await
            .expect("comm_message object must exist after install");
    let (sse_task, mut events) = open_sse(&b.base, &cookie1, message_object).await;
    // Let B's fan-out task finish SUBSCRIBE before A publishes.
    tokio::time::sleep(Duration::from_secs(1)).await;

    let thread1 = make_thread(&a.base, &cookie1).await;
    let thread2 = make_thread(&a.base, &cookie2).await;

    // Org2 writes on A: org1's stream on B must stay silent.
    let other_msg = post_message(&a.base, &cookie2, thread2, "org2 hello").await;
    let silent = tokio::time::timeout(Duration::from_millis(1500), events.recv()).await;
    assert!(
        silent.is_err(),
        "tenant isolation: org2's write must not reach org1's SSE stream"
    );

    // Org1 writes on A: the invalidate event must arrive on B.
    let msg_id = post_message(&a.base, &cookie1, thread1, "org1 hello").await;
    let got = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let e = events.recv().await.expect("sse stream alive");
            if e.event == "invalidate" {
                return e;
            }
        }
    })
    .await
    .expect("B must receive A's invalidate within 10s");
    let data: serde_json::Value = serde_json::from_str(&got.data).expect("event json");
    let records: Vec<String> = serde_json::from_value(data["record_ids"].clone()).unwrap();
    assert!(
        records.contains(&msg_id.to_string()),
        "invalidate must name the posted message"
    );
    assert!(
        !records.contains(&other_msg.to_string()),
        "invalidate must not leak the other org's record"
    );
    assert!(data["seq"].as_u64().unwrap() > 0, "seq must be assigned");

    sse_task.abort();
    drop(a);
    drop(b);
}
