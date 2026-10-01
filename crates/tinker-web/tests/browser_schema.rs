//! Post-M8 item 34: real-browser verification of the `/schema` builder page.
//!
//! The builder page (`crates/tinker-web/src/schema_page.rs`, Askama
//! template `schema.html`) is server-rendered with plain
//! POST/redirect/GET forms and ships no JavaScript. The HTTP-level
//! coverage lives in `tinker-m4/tests/m4_schema_page.rs`; this test
//! drives the real thing through headless Chromium over CDP
//! (`browser_cdp.py`, stdlib-only Python):
//!
//! 1. Layout intact at 1440px and 390px (no horizontal overflow,
//!    screenshots to prove it).
//! 2. Zero JS console errors/warnings on load.
//! 3. Every evolve form submittable in the browser: a full New draft ->
//!    add field -> mark canary -> promote round trip, each step a real
//!    form submission, each redirect landing back on the builder; the
//!    rollback form driven over HTTP afterwards.
//! 4. Auth gates: unauthenticated -> /login; a member without the
//!    `schema:evolve` grant sees viewer mode and no evolve controls.
//!
//! Serial discipline: one #[tokio::test]; never run concurrently with
//! `cargo test` (shares the test database with the workspace suite).
//! Chromium is headless only -- no real mobile device, no touch.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use uuid::Uuid;

const CHROME: &str = "/opt/meta-chromium/chrome";
// Deliberately far from the Bocht campaign's :18080 range and from the
// item-30 scale-out ports (18681/18682).
const PORT: u16 = 18683;
const CDP_PORT: u16 = 19222;
const REDIS_DEFAULT_URL: &str = "redis://127.0.0.1:6379/";

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

fn proof_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set");
    let dir = std::path::PathBuf::from(home)
        .join("workspace")
        .join("tinker-item34-proofs");
    std::fs::create_dir_all(&dir).expect("create proof dir");
    dir
}

// Item 35: the binary-flavor guard is gone — tinker-web's binary is
// `tinker` and tinker-m7's is `tinker-cli`, so each links to its own
// target path and the two can never collide again.

// ---------------------------------------------------------------------------
// Fixture: one org, a builder (schema:evolve grant) and a member.
// ---------------------------------------------------------------------------

struct ActorSeed {
    actor_id: Uuid,
    cookie: String,
}

async fn seed_actor(
    owner: &sqlx::PgPool,
    sessions: &tinker_identity::SessionManager,
    org_id: Uuid,
    tag: &str,
) -> ActorSeed {
    let workspace_id = Uuid::now_v7();
    sqlx::query("INSERT INTO workspaces (id, organization_id, slug, name) VALUES ($1,$2,$3,$4)")
        .bind(workspace_id)
        .bind(org_id)
        .bind(format!("ws34-{tag}"))
        .bind("item34 ws")
        .execute(owner)
        .await
        .unwrap();
    let actor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$4)",
    )
    .bind(actor_id)
    .bind(org_id)
    .bind(format!("item34-{tag}"))
    .bind(format!(
        "item34-{tag}-{}",
        &actor_id.simple().to_string()[..8]
    ))
    .execute(owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,'member')",
    )
    .bind(actor_id)
    .bind(org_id)
    .execute(owner)
    .await
    .unwrap();
    let authn = tinker_auth::AuthnContext {
        actor_id,
        principal_kind: tinker_auth::PrincipalKind::Human,
        organization_ids: vec![org_id],
        method: "item34-fixture".into(),
        assurance: tinker_auth::AssuranceLevel::MultiFactor,
        authenticated_at: chrono::Utc::now(),
        credential_id: format!("fixture-34-{tag}"),
    };
    let token = sessions
        .create_session(&authn, org_id, workspace_id)
        .await
        .unwrap();
    ActorSeed {
        actor_id,
        cookie: format!("{}={token}", tinker_web::SESSION_COOKIE),
    }
}

// ---------------------------------------------------------------------------
// Process management
// ---------------------------------------------------------------------------

struct ServerGuard {
    child: Child,
    base: String,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_port_free(port: u16) {
    for _ in 0..150 {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_err() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("port {port} still occupied after 15s");
}

fn spawn_server(port: u16, redis_url: &str, log_path: &std::path::Path) -> ServerGuard {
    wait_port_free(port);
    let err_file = std::fs::File::create(log_path).expect("create server stderr log");
    let child = Command::new(env!("CARGO_BIN_EXE_tinker"))
        .env("TINKER_CORE_URL", env("TINKER_CORE_OWNER_URL"))
        .env("TINKER_APP_URL", env("TINKER_CORE_URL"))
        .env("TINKER_HOST", "tinker.test")
        .env("TINKER_ADDR", format!("127.0.0.1:{port}"))
        .env("TINKER_REDIS_URL", redis_url)
        .stdout(Stdio::null())
        .stderr(err_file)
        .spawn()
        .expect("spawn tinker server");
    ServerGuard {
        child,
        base: format!("http://127.0.0.1:{port}"),
    }
}

async fn wait_ready(server: &ServerGuard) {
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for _ in 0..150 {
        if let Ok(r) = c.get(format!("{}/login", server.base)).send().await {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server on {} never became ready", server.base);
}

struct ChromeGuard {
    child: Child,
}

impl Drop for ChromeGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_cdp(port: u16) {
    let c = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for _ in 0..100 {
        if let Ok(r) = c
            .get(format!("http://127.0.0.1:{port}/json/list"))
            .send()
            .await
        {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("chromium CDP on {port} never answered /json/list");
}

// ---------------------------------------------------------------------------
// The proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn browser_verifies_schema_builder() {
    let proofs = proof_dir();

    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let tenant = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    tinker_db::MIGRATOR_CORE
        .run(&owner)
        .await
        .expect("core migrations");

    // Install the CRM pack so the builder has objects to show (idempotent).
    let pack_toml = include_str!("../../../packs/crm/pack.toml");
    let pack = tinker_packs::PackDefinition::from_toml(pack_toml).unwrap();
    let installer = tinker_packs::PackInstaller::new(
        tinker_ontology::Ontology::new(
            tinker_db::CoreDb(tenant.clone()),
            tinker_db::OwnerDb(owner.clone()),
        ),
        tinker_apps::AppRegistry::new(tenant.clone()),
    );
    let installed = installer.install_objects(&pack).await.unwrap();
    let contact_id = installed.objects["crm_contact"];

    let run: String = Uuid::now_v7().simple().to_string()[..8].into();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,$2)")
        .bind(host_id)
        .bind(format!("host34-{run}"))
        .execute(&owner)
        .await
        .unwrap();
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1,$2,$3,$4)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("org34-{run}"))
        .bind("item34 org")
        .execute(&owner)
        .await
        .unwrap();

    let sessions = tinker_identity::SessionManager::new(tenant.clone(), owner.clone());
    let builder = seed_actor(&owner, &sessions, org_id, "builder").await;
    let member = seed_actor(&owner, &sessions, org_id, "member").await;
    tinker_identity::Authorizer::new(tenant.clone(), owner.clone())
        .grant(
            org_id,
            builder.actor_id,
            &tinker_auth::AuthzScope::Organization {
                organization_id: org_id,
            },
            "schema:evolve",
            None,
        )
        .await
        .unwrap();

    let redis_url =
        std::env::var("TINKER_TEST_REDIS_URL").unwrap_or_else(|_| REDIS_DEFAULT_URL.into());
    let server_log = proofs.join("tinker-item34-server.log");
    let server = spawn_server(PORT, &redis_url, &server_log);
    wait_ready(&server).await;

    // Headless Chromium with a CDP endpoint. This build enforces Local
    // Network Access checks and treats CDP-initiated navigations as
    // public-initiated (ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS), so
    // Chrome launches at a file:// bootstrap page whose *inline* script
    // performs the first hop to the server; every later navigation in
    // the driver goes through a page-created link click (see navigate()
    // in browser_cdp.py).
    let bootstrap_target = format!("{}/schema", server.base);
    let bootstrap = proofs.join("lna_bootstrap.html");
    std::fs::write(
        &bootstrap,
        format!(
            "<!doctype html>\n<html><head><meta charset=\"utf-8\">\
             <title>item34 bootstrap</title></head>\n\
             <body>redirecting to the schema builder...\
             <script>location.href=\"{bootstrap_target}\";</script>\n\
             </body></html>\n"
        ),
    )
    .expect("write bootstrap page");
    let chrome_profile = proofs.join("chrome-profile");
    let _ = std::fs::remove_dir_all(&chrome_profile);
    let mut chrome = ChromeGuard {
        child: Command::new(CHROME)
            .args([
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                "--allow-file-access-from-files",
                &format!("--remote-debugging-port={CDP_PORT}"),
                &format!("--user-data-dir={}", chrome_profile.display()),
                "--window-size=1440,900",
                &format!("file://{}", bootstrap.display()),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn chromium"),
    };
    wait_cdp(CDP_PORT).await;
    // Let the bootstrap's inline script finish the first hop before the
    // driver connects (it polls location anyway, but avoid racing it).
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Drive the browser: layout, console, forms, auth gates.
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/browser_cdp.py");
    let out = Command::new("python3")
        .args([
            script,
            &CDP_PORT.to_string(),
            &server.base,
            tinker_web::SESSION_COOKIE,
            builder.cookie.split('=').nth(1).unwrap(),
            member.cookie.split('=').nth(1).unwrap(),
            &contact_id.to_string(),
            &proofs.display().to_string(),
        ])
        .output()
        .expect("run CDP driver");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    std::fs::write(proofs.join("cdp-driver-stdout.log"), stdout.as_bytes()).unwrap();
    std::fs::write(proofs.join("cdp-driver-stderr.log"), stderr.as_bytes()).unwrap();
    assert!(
        out.status.success(),
        "CDP driver failed (exit {}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status
    );

    let results: serde_json::Value =
        serde_json::from_slice(&std::fs::read(proofs.join("results.json")).expect("results.json"))
            .expect("results.json parses");
    assert_eq!(
        results["passed"],
        serde_json::Value::Bool(true),
        "CDP driver reported failures: {}",
        results["failures"]
    );
    let version_id = results["version_id"]
        .as_str()
        .expect("version_id")
        .to_string();

    // Rollback form over HTTP as the builder: 303 back to the builder,
    // and the page then shows the rolled-back version.
    let c = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let res = c
        .post(format!(
            "{}/schema/versions/{version_id}/rollback",
            server.base
        ))
        .header("Cookie", &builder.cookie)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .expect("rollback form POST");
    assert_eq!(res.status(), 303, "rollback form must 303");
    let loc = res
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        loc.contains(&format!("object={contact_id}")),
        "rollback redirects back to the builder: {loc}"
    );
    let page = c
        .get(format!("{}{loc}", server.base))
        .header("Cookie", &builder.cookie)
        .send()
        .await
        .expect("GET builder after rollback");
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(
        html.contains("rolled_back"),
        "builder shows the rolled-back version"
    );

    // Grant gate over HTTP: member cannot promote via the form.
    let res = c
        .post(format!(
            "{}/schema/versions/{}/promote",
            server.base,
            Uuid::now_v7()
        ))
        .header("Cookie", &member.cookie)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .expect("member promote POST");
    assert_eq!(res.status(), 403, "member promote must 403");

    // Unauthenticated form POST fails closed toward login.
    let res = c
        .post(format!(
            "{}/schema/objects/{contact_id}/drafts",
            server.base
        ))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body("")
        .send()
        .await
        .expect("unauth draft POST");
    assert_eq!(res.status(), 303, "unauth draft POST must 303");
    assert_eq!(
        res.headers().get("location").unwrap().to_str().unwrap(),
        "/login",
        "unauth draft POST redirects to /login"
    );

    // Proof files exist.
    for shot in [
        "schema_builder_desktop_1440.png",
        "schema_builder_mobile_390.png",
        "schema_promoted_desktop_1440.png",
        "schema_viewer_desktop_1440.png",
        "schema_unauth_login_1440.png",
    ] {
        assert!(
            proofs.join(shot).exists(),
            "missing proof screenshot {shot}"
        );
    }

    let _ = chrome.child.kill();
    drop(server);
}
