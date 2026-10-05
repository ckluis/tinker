//! Item 47: single-server efficiency bench — measure first, then optimize.
//!
//! `#[ignore]`d on purpose: it is timing-sensitive and never runs in the
//! default gate. Run it via `scripts/bench_item47.sh`:
//!
//! ```text
//! scripts/bench_item47.sh [/tmp/tinker-bench]
//! ```
//!
//! What it measures, per transport (HTTP `tinker-mcp serve` and the real
//! stdio binary, both driven as a real client would drive them):
//!
//! - `describe` (one object) — request latency p50/p99
//! - `query` on the cache-HIT path (the same intent 300x) — p50/p99 and
//!   the observed hit rate through the `cached` response flag
//! - `query` on the cache-MISS path (`create_record` invalidates between
//!   queries, 150x) — p50/p99 and the observed miss rate
//! - `create_record` — request latency p50/p99
//! - server RSS (`VmRSS`): at startup, peak during the workload, at end
//!
//! Fixed fixtures: one org, one credential (admin role, full MCP
//! scopes), one object (`name`/`email`/`notes` text fields), 100 seeded
//! records. 25 warmup + 150–300 measured iterations per op. The report
//! is written as JSON to `$TINKER_BENCH_OUT/report-<unix-ts>.json`
//! (default `/tmp/tinker-bench/`), including canonicalized sample tool
//! responses (`describe`, `query`, `get_record`, `create_record` shape)
//! so `scripts/compare_bench.py` can assert byte-equality of tool
//! outputs before/after optimizations.
//!
//! Deterministic assertions (no timing): the hit block must observe
//! `cached=true` on every measured query, and the miss block must
//! observe `cached=false` on every measured query — a broken
//! invalidator (item-46 fix) fails the bench loudly instead of
//! silently skewing the latency split.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use serde_json::{json, Value};
use tinker_auth::apikey::{MachineCredentialStore, VerifiedCredential};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope, ValidationRules};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness (mirrors mcp_http.rs fixture setup)
// ---------------------------------------------------------------------------

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

struct Env {
    core: CoreDb,
    core_owner: sqlx::PgPool,
    host_id: Uuid,
}

async fn setup() -> Env {
    std::env::set_var(
        "TINKER_FILE_ROOT",
        std::env::temp_dir().join(format!("tinker-mcp-bench-{}", std::process::id())),
    );
    let core_owner = sqlx::PgPool::connect(&env_var("TINKER_CORE_OWNER_URL"))
        .await
        .expect("core owner connect");
    tinker_db::MIGRATOR_CORE
        .run(&core_owner)
        .await
        .expect("core migrations");
    let core = CoreDb::connect(&env_var("TINKER_CORE_URL"))
        .await
        .expect("core app-role connect");
    let host_id = Uuid::from_u128(0x0);
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,'bench') ON CONFLICT (id) DO NOTHING")
        .bind(host_id)
        .execute(&core_owner)
        .await
        .expect("host upsert");
    Env {
        core,
        core_owner,
        host_id,
    }
}

async fn new_org(env: &Env) -> TenantContext {
    let org_id = Uuid::now_v7();
    let s = Uuid::now_v7().simple().to_string();
    let slug = format!("mcpbenchorg{}", &s[24..32]);
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(&slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "mcp-bench".to_string(),
    )
}

fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{prefix}{}", &s[24..32])
}

fn ontology(env: &Env) -> Ontology {
    Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
}

fn object_def(slug: &str) -> ObjectDef {
    ObjectDef {
        name: slug.into(),
        api_slug: slug.into(),
        label: slug.into(),
        scope: Scope::Organization,
        pack_id: None,
        pack_version: None,
    }
}

fn text_field(api_name: &str, required: bool) -> FieldDef {
    FieldDef {
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type: FieldType::Text,
        options: serde_json::json!({}),
        required,
        validation: ValidationRules::default(),
        preset: None,
        max_pii_class: "none".into(),
        sensitive: false,
    }
}

async fn issue_key(
    env: &Env,
    org_id: Uuid,
    name: &str,
    role: &str,
    scopes: &[&str],
) -> (String, VerifiedCredential) {
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let issued = store
        .issue(org_id, name, &scopes, None, None)
        .await
        .expect("key issue");
    store
        .grant_machine_role(org_id, issued.credential.actor_id, role)
        .await
        .expect("grant role");
    let verified = store.verify(&issued.secret).await.expect("key verify");
    (issued.secret, verified)
}

/// Fixture: org + admin credential + one object with 3 text fields +
/// 100 seeded records. Returns (secret, object slug, one record id).
async fn fixture(env: &Env) -> (String, String, Uuid) {
    let ctx = new_org(env).await;
    let org_id = ctx.organization_id.0;
    let ont = ontology(env);
    let slug = uniq("benchobj");
    let obj = ont
        .define_object(&ctx, &object_def(&slug))
        .await
        .expect("define object");
    for (name, required) in [("name", true), ("email", false), ("notes", false)] {
        ont.add_field(&ctx, obj.id, &text_field(name, required))
            .await
            .expect("add field");
    }
    let (secret, _) = issue_key(
        env,
        org_id,
        "bench",
        "admin",
        &["mcp:tools", "mcp:resources"],
    )
    .await;

    // Physical column names for the direct-SQL seed (validation is
    // exercised separately by the measured create_record ops).
    let cols: Vec<(String, String)> =
        sqlx::query_as("SELECT api_name, physical_column FROM ontology_fields WHERE object_id=$1")
            .bind(obj.id)
            .fetch_all(&env.core_owner)
            .await
            .expect("field columns");
    let col = |api: &str| {
        cols.iter()
            .find(|(a, _)| a == api)
            .unwrap_or_else(|| panic!("no column for {api}"))
            .1
            .clone()
    };
    let (c_name, c_email, c_notes) = (col("name"), col("email"), col("notes"));
    let table = format!("data.{slug}");
    for i in 0..100 {
        sqlx::query(&format!(
            "INSERT INTO {table} (organization_id, \"{c_name}\", \"{c_email}\", \"{c_notes}\") \
             VALUES ($1,$2,$3,$4)"
        ))
        .bind(org_id)
        .bind(format!("bench-{i:03}"))
        .bind(format!("bench-{i:03}@example.com"))
        .bind(format!("seeded note {i}"))
        .execute(&env.core_owner)
        .await
        .expect("seed record");
    }
    let (rid,): (Uuid,) = sqlx::query_as(&format!("SELECT id FROM {table} LIMIT 1"))
        .fetch_one(&env.core_owner)
        .await
        .expect("sample record id");
    (secret, slug, rid)
}

// ---------------------------------------------------------------------------
// Latency stats
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Stats {
    samples: Vec<u128>,
}

impl Stats {
    fn push(&mut self, d: Duration) {
        self.samples.push(d.as_micros());
    }

    fn percentile(&self, p: f64) -> u128 {
        assert!(!self.samples.is_empty());
        let mut s = self.samples.clone();
        s.sort_unstable();
        let idx = ((s.len() as f64 * p / 100.0).ceil() as usize)
            .saturating_sub(1)
            .min(s.len() - 1);
        s[idx]
    }

    fn report(&self) -> Value {
        let n = self.samples.len() as u64;
        let sum: u128 = self.samples.iter().sum();
        json!({
            "n": n,
            "p50_us": self.percentile(50.0),
            "p99_us": self.percentile(99.0),
            "mean_us": sum / n as u128,
            "min_us": self.samples.iter().min().unwrap(),
            "max_us": self.samples.iter().max().unwrap(),
        })
    }
}

/// VmRSS in KiB for `pid`, via /proc.
fn rss_kb(pid: u32) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

// ---------------------------------------------------------------------------
// HTTP transport driver
// ---------------------------------------------------------------------------

struct HttpServer {
    child: Child,
    base: String,
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn spawn_http_server() -> HttpServer {
    let bin = env_var("CARGO_BIN_EXE_tinker-mcp");
    let mut child = Command::new(&bin)
        .arg("serve")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .env("TINKER_CORE_OWNER_URL", env_var("TINKER_CORE_OWNER_URL"))
        .env("TINKER_CORE_URL", env_var("TINKER_CORE_URL"))
        .env(
            "TINKER_FILE_ROOT",
            std::env::temp_dir().join(format!("tinker-mcp-bench-{}", std::process::id())),
        )
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn tinker-mcp serve");
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stderr);
        let mut sent = false;
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if !sent {
                        if let Some(rest) = line.split("listening on ").nth(1) {
                            if let Some(addr) = rest.split_whitespace().next() {
                                let _ = tx.send(addr.to_string());
                                sent = true;
                            }
                        }
                    }
                }
                Err(_) => break,
            }
        }
    });
    let addr = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("server did not print its listening address");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(s) => {
                drop(s);
                break;
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("server at {addr} never accepted connections: {e}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    HttpServer {
        child,
        base: format!("http://{addr}"),
    }
}

struct HttpClient {
    client: reqwest::Client,
    base: String,
    key: String,
    session: String,
    next_id: i64,
}

impl HttpClient {
    async fn new(server: &HttpServer, key: &str) -> Self {
        let client = reqwest::Client::new();
        let body = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" },
        })
        .to_string();
        let resp = client
            .post(format!("{}/mcp", server.base))
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {key}"))
            .body(body)
            .send()
            .await
            .expect("initialize");
        assert_eq!(resp.status(), StatusCode::OK, "initialize failed");
        let session = resp
            .headers()
            .get("mcp-session-id")
            .expect("session header")
            .to_str()
            .expect("header str")
            .to_string();
        Self {
            client,
            base: server.base.clone(),
            key: key.to_string(),
            session,
            next_id: 100,
        }
    }

    /// One `tools/call`; returns the tool `result` payload.
    async fn call_tool(&mut self, name: &str, args: Value) -> Value {
        self.next_id += 1;
        let body = json!({
            "jsonrpc": "2.0", "id": self.next_id, "method": "tools/call",
            "params": { "name": name, "arguments": args },
        })
        .to_string();
        let resp = self
            .client
            .post(format!("{}/mcp", self.base))
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, format!("Bearer {}", self.key))
            .header("mcp-session-id", &self.session)
            .body(body)
            .send()
            .await
            .expect("POST /mcp");
        assert_eq!(resp.status(), StatusCode::OK, "tools/call failed");
        let body: Value =
            serde_json::from_str(&resp.text().await.expect("body")).expect("response parses");
        assert!(body.get("error").is_none(), "protocol error: {body}");
        let result = body["result"].clone();
        assert!(
            result.get("isError").is_none(),
            "tool error: {}",
            result["content"][0]["text"].as_str().unwrap_or("?")
        );
        result
    }
}

/// The parsed tool payload: `result.content[0].text` as JSON.
fn tool_payload(result: &Value) -> Value {
    let text = result["content"][0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("tool payload parses")
}

// ---------------------------------------------------------------------------
// stdio transport driver (blocking; run inside spawn_blocking)
// ---------------------------------------------------------------------------

struct Pipe {
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    child: Child,
}

fn spawn_stdio(secret: &str) -> Pipe {
    let bin = env_var("CARGO_BIN_EXE_tinker-mcp");
    let mut child = Command::new(&bin)
        .env("TINKER_API_KEY", secret)
        .env("TINKER_CORE_OWNER_URL", env_var("TINKER_CORE_OWNER_URL"))
        .env("TINKER_CORE_URL", env_var("TINKER_CORE_URL"))
        .env(
            "TINKER_FILE_ROOT",
            std::env::temp_dir().join(format!("tinker-mcp-bench-{}", std::process::id())),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn tinker-mcp stdio");
    let stdin = child.stdin.take().expect("child stdin");
    let stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    Pipe {
        stdin,
        stdout,
        child,
    }
}

impl Pipe {
    fn rpc(&mut self, id: i64, method: &str, params: Value) -> Value {
        let raw =
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        writeln!(self.stdin, "{raw}").expect("write to child");
        self.stdin.flush().expect("flush");
        let mut line = String::new();
        self.stdout.read_line(&mut line).expect("read from child");
        assert!(!line.trim().is_empty(), "child went quiet on {method}");
        let body: Value = serde_json::from_str(&line).expect("child response parses");
        assert!(body.get("error").is_none(), "protocol error: {body}");
        body["result"].clone()
    }

    fn call_tool(&mut self, id: i64, name: &str, args: Value) -> Value {
        let result = self.rpc(id, "tools/call", json!({ "name": name, "arguments": args }));
        assert!(
            result.get("isError").is_none(),
            "tool error: {}",
            result["content"][0]["text"].as_str().unwrap_or("?")
        );
        result
    }
}

// ---------------------------------------------------------------------------
// The bench
// ---------------------------------------------------------------------------

const WARMUP: usize = 25;
const N_DESCRIBE: usize = 300;
const N_QUERY_HIT: usize = 300;
const N_MISS_LOOP: usize = 150;

fn query_intent() -> Value {
    json!({
        "select": ["name", "email"],
        "filters": [],
        "order": [{"field": "name", "descending": false}],
        "limit": 50,
    })
}

#[derive(Default)]
struct TransportReport {
    describe: Stats,
    query_hit: Stats,
    query_miss: Stats,
    create_record: Stats,
    hit_rate: f64,
    miss_rate: f64,
    rss_startup_kb: u64,
    rss_peak_kb: u64,
    rss_end_kb: u64,
}

impl TransportReport {
    fn json(&self) -> Value {
        json!({
            "describe": self.describe.report(),
            "query_hit": self.query_hit.report(),
            "query_miss": self.query_miss.report(),
            "create_record": self.create_record.report(),
            "query_hit_rate": self.hit_rate,
            "query_miss_rate": self.miss_rate,
            "rss_kb": {
                "startup": self.rss_startup_kb,
                "peak": self.rss_peak_kb,
                "end": self.rss_end_kb,
            },
        })
    }
}

fn print_table(name: &str, r: &TransportReport) {
    println!("--- transport: {name} ---");
    for (op, s) in [
        ("describe     ", &r.describe),
        ("query_hit    ", &r.query_hit),
        ("query_miss   ", &r.query_miss),
        ("create_record", &r.create_record),
    ] {
        let rep = s.report();
        println!(
            "  {op}  n={:<4} p50={:>7}us p99={:>7}us mean={:>7}us",
            rep["n"].as_u64().unwrap(),
            rep["p50_us"].as_u64().unwrap(),
            rep["p99_us"].as_u64().unwrap(),
            rep["mean_us"].as_u64().unwrap(),
        );
    }
    println!(
        "  query cache: hit_rate={:.3} miss_rate={:.3}",
        r.hit_rate, r.miss_rate
    );
    println!(
        "  rss_kb: startup={} peak={} end={}",
        r.rss_startup_kb, r.rss_peak_kb, r.rss_end_kb
    );
}

fn sample_rss(pid: u32, peak: &mut u64) {
    if let Some(kb) = rss_kb(pid) {
        *peak = (*peak).max(kb);
    }
}

/// Run the full op mix against the HTTP transport.
async fn bench_http(secret: &str, slug: &str) -> (TransportReport, u32) {
    let server = spawn_http_server().await;
    let pid = server.child.id();
    let mut rep = TransportReport {
        rss_startup_kb: rss_kb(pid).unwrap_or(0),
        ..Default::default()
    };
    let mut peak = rep.rss_startup_kb;

    let mut c = HttpClient::new(&server, secret).await;
    // Warmup (also primes the query cache).
    for _ in 0..WARMUP {
        c.call_tool("describe", json!({ "object": slug })).await;
    }
    for _ in 0..WARMUP {
        c.call_tool("query", json!({ "object": slug, "intent": query_intent() }))
            .await;
    }
    sample_rss(pid, &mut peak);

    for _ in 0..N_DESCRIBE {
        let t = Instant::now();
        c.call_tool("describe", json!({ "object": slug })).await;
        rep.describe.push(t.elapsed());
    }
    sample_rss(pid, &mut peak);

    let mut hits = 0;
    for _ in 0..N_QUERY_HIT {
        let t = Instant::now();
        let result = c
            .call_tool("query", json!({ "object": slug, "intent": query_intent() }))
            .await;
        rep.query_hit.push(t.elapsed());
        let payload = tool_payload(&result);
        assert!(
            payload["cached"].as_bool() == Some(true),
            "hit block: expected cached=true, got {payload}"
        );
        hits += 1;
    }
    rep.hit_rate = hits as f64 / N_QUERY_HIT as f64;
    sample_rss(pid, &mut peak);

    // Miss path: every create_record invalidates (org, object), so the
    // query that follows must execute (cached=false).
    let mut misses = 0;
    for i in 0..N_MISS_LOOP {
        let t = Instant::now();
        c.call_tool(
            "create_record",
            json!({ "object": slug, "values": {
                "name": format!("http-create-{i:04}"),
                "email": format!("hc{i:04}@example.com"),
            }}),
        )
        .await;
        rep.create_record.push(t.elapsed());
        let t = Instant::now();
        let result = c
            .call_tool("query", json!({ "object": slug, "intent": query_intent() }))
            .await;
        rep.query_miss.push(t.elapsed());
        let payload = tool_payload(&result);
        assert!(
            payload["cached"].as_bool() == Some(false),
            "miss block: expected cached=false, got {payload}"
        );
        misses += 1;
        if i % 25 == 0 {
            sample_rss(pid, &mut peak);
        }
    }
    rep.miss_rate = misses as f64 / N_MISS_LOOP as f64;
    sample_rss(pid, &mut peak);

    rep.rss_peak_kb = peak;
    rep.rss_end_kb = rss_kb(pid).unwrap_or(0);
    (rep, pid)
}

/// Blocking stdio op mix (runs inside `spawn_blocking`).
fn bench_stdio_blocking(secret: &str, slug: &str) -> (TransportReport, u32) {
    let mut pipe = spawn_stdio(secret);
    let pid = pipe.child.id();
    let mut rep = TransportReport::default();
    // NOTE: the startup RSS is sampled AFTER the handshake below, not
    // here — sampling at spawn catches the process before it has even
    // exec'd (meaningless ~28 KiB reading).

    // Wait for startup (migrations + key verification), then handshake.
    let deadline = Instant::now() + Duration::from_secs(60);
    let init = loop {
        // A failed initialize before ready returns an error payload;
        // retry until the server identifies itself.
        let raw =
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }).to_string();
        writeln!(pipe.stdin, "{raw}").expect("write");
        pipe.stdin.flush().expect("flush");
        let mut line = String::new();
        match pipe.stdout.read_line(&mut line) {
            Ok(0) => panic!("stdio server exited during startup"),
            Ok(_) => {
                let body: Value = serde_json::from_str(&line).expect("parses");
                if body.get("error").is_none()
                    && body["result"]["serverInfo"]["name"] == "tinker-mcp"
                {
                    break body;
                }
            }
            Err(e) => panic!("stdio read: {e}"),
        }
        if Instant::now() > deadline {
            panic!("stdio server never became ready");
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    assert_eq!(init["result"]["serverInfo"]["name"], "tinker-mcp");
    // Handshake complete: the server is fully up (migrations + key
    // verification done). Sample the startup RSS now.
    rep.rss_startup_kb = rss_kb(pid).unwrap_or(0);
    let mut peak = rep.rss_startup_kb;
    // initialized notification → no response.
    writeln!(
        pipe.stdin,
        "{}",
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
    )
    .unwrap();
    pipe.stdin.flush().unwrap();

    let mut next_id: i64 = 100;
    let mut call = |name: &str, args: Value| -> Value {
        next_id += 1;
        pipe.call_tool(next_id, name, args)
    };

    for _ in 0..WARMUP {
        call("describe", json!({ "object": slug }));
    }
    for _ in 0..WARMUP {
        call("query", json!({ "object": slug, "intent": query_intent() }));
    }
    sample_rss(pid, &mut peak);

    for _ in 0..N_DESCRIBE {
        let t = Instant::now();
        call("describe", json!({ "object": slug }));
        rep.describe.push(t.elapsed());
    }
    sample_rss(pid, &mut peak);

    let mut hits = 0;
    for _ in 0..N_QUERY_HIT {
        let t = Instant::now();
        let result = call("query", json!({ "object": slug, "intent": query_intent() }));
        rep.query_hit.push(t.elapsed());
        let payload = tool_payload(&result);
        assert!(
            payload["cached"].as_bool() == Some(true),
            "hit block: expected cached=true"
        );
        hits += 1;
    }
    rep.hit_rate = hits as f64 / N_QUERY_HIT as f64;
    sample_rss(pid, &mut peak);

    let mut misses = 0;
    for i in 0..N_MISS_LOOP {
        let t = Instant::now();
        call(
            "create_record",
            json!({ "object": slug, "values": {
                "name": format!("stdio-create-{i:04}"),
                "email": format!("sc{i:04}@example.com"),
            }}),
        );
        rep.create_record.push(t.elapsed());
        let t = Instant::now();
        let result = call("query", json!({ "object": slug, "intent": query_intent() }));
        rep.query_miss.push(t.elapsed());
        let payload = tool_payload(&result);
        assert!(
            payload["cached"].as_bool() == Some(false),
            "miss block: expected cached=false"
        );
        misses += 1;
        if i % 25 == 0 {
            sample_rss(pid, &mut peak);
        }
    }
    rep.miss_rate = misses as f64 / N_MISS_LOOP as f64;
    sample_rss(pid, &mut peak);

    rep.rss_peak_kb = peak;
    rep.rss_end_kb = rss_kb(pid).unwrap_or(0);
    let _ = pipe.child.kill();
    let _ = pipe.child.wait();
    (rep, pid)
}

/// Canonicalized sample tool responses for the before/after
/// byte-equality check (transport-independent `result` payloads).
async fn capture_samples(secret: &str, slug: &str, record_id: Uuid) -> Value {
    let server = spawn_http_server().await;
    let mut c = HttpClient::new(&server, secret).await;
    let describe = c.call_tool("describe", json!({ "object": slug })).await;
    // Prime the cache, then capture the hit-shaped query response.
    c.call_tool("query", json!({ "object": slug, "intent": query_intent() }))
        .await;
    let query = c
        .call_tool("query", json!({ "object": slug, "intent": query_intent() }))
        .await;
    let get_record = c
        .call_tool(
            "get_record",
            json!({ "object": slug, "record_id": record_id.to_string() }),
        )
        .await;
    let create = c
        .call_tool(
            "create_record",
            json!({ "object": slug, "values": {
                "name": "sample-create",
                "email": "sample@example.com",
            }}),
        )
        .await;
    // `record_id` is random per run: keep the shape, redact the value.
    let mut create_shape = tool_payload(&create);
    if let Some(obj) = create_shape.as_object_mut() {
        obj.insert("record_id".to_string(), Value::String("<uuid>".to_string()));
    }
    json!({
        "describe": tool_payload(&describe),
        "query": tool_payload(&query),
        "get_record": tool_payload(&get_record),
        "create_record_shape": create_shape,
    })
}

fn git_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

#[tokio::test]
#[ignore = "item 47 bench: timing-sensitive, run via scripts/bench_item47.sh"]
async fn bench_item47() {
    let env = setup().await;
    let (secret, slug, record_id) = fixture(&env).await;
    println!("bench fixtures: object slug={slug}");

    let (http_rep, http_pid) = bench_http(&secret, &slug).await;
    print_table("http", &http_rep);
    println!("(http server pid was {http_pid})");

    let secret2 = secret.clone();
    let slug2 = slug.clone();
    let (stdio_rep, stdio_pid) =
        tokio::task::spawn_blocking(move || bench_stdio_blocking(&secret2, &slug2))
            .await
            .expect("stdio bench task");
    print_table("stdio", &stdio_rep);
    println!("(stdio server pid was {stdio_pid})");

    let samples = capture_samples(&secret, &slug, record_id).await;

    let report = json!({
        "item": 47,
        "git": git_sha(),
        "profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        "transports": {
            "http": http_rep.json(),
            "stdio": stdio_rep.json(),
        },
        "samples": samples,
    });

    let out_dir =
        std::env::var("TINKER_BENCH_OUT").unwrap_or_else(|_| "/tmp/tinker-bench".to_string());
    std::fs::create_dir_all(&out_dir).expect("bench out dir");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();
    let path = format!("{out_dir}/report-{ts}.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&report).expect("serialize"),
    )
    .expect("write report");
    println!("bench report written to {path}");
}
