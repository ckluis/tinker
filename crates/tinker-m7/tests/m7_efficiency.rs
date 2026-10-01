//! Item 29: single-server efficiency — the reference workload ("crm-10k"),
//! baseline measurements, and regression tripwires.
//!
//! Workload (FIXED — defined here and in `docs/one-server-efficiency.md`,
//! never invented mid-run):
//! - 10 tenants; per tenant 50 companies, 1_000 contacts, 200 deals.
//! - 12_500 records total, seeded deterministically with `generate_series`.
//!
//! Measured paths (each tripwire: 5 warmups, 21 measured runs, assert on
//! the p50 — the m4_perf style; budgets are generous tripwires, not SLAs):
//! - `ingest_page_500` — FakeSalesforce → IngestPipeline::run, one 500-row
//!   page, extract→land→profile→model→promote with identity resolution on
//!   email (fresh stream + fresh source ids per iteration: the insert path).
//! - `query_grid_miss` — compile + QueryCache miss + QueryExecutor::execute
//!   (filtered crm_contact grid, limit 100) + the audit write.
//! - `query_grid_hit` — the same intent served from the QueryCache.
//! - `gateway_transform` — ModelGateway::transform_richtext through the
//!   fake adapter (provider-row lookup + placement enforcement, no network).
//! - `mcp_http_tools_list` — POST /mcp `tools/list` over the item-28 HTTP
//!   transport (Bearer <redacted> + scope gate + wire-server dispatch).
//! - `mcp_http_sse_handshake` — GET /sse, time to the first endpoint event.
//! - `auth_key_verify` — MachineCredentialStore::verify (SELECT +
//!   best-effort `last_used_at` UPDATE).
//! - `auth_session_load` — SessionManager::load_session (cookie token →
//!   session row).
//!
//! Throughput probes (print-only; no wall-clock asserts under load):
//! - 8 concurrent workers x 100 ops on `query_grid_hit` and
//!   `mcp_http_tools_list`, reporting sustained ops/sec.
//!
//! All measurements are debug-build, local PG16 + Redis, single node.
//! Load-sensitive budgets are proven in a quiet window and documented as
//! such in the evidence doc — never asserted under load.

#[path = "../src/mcp_http.rs"]
mod mcp_http;

use std::sync::Arc;
use std::time::{Duration, Instant};

use tinker_agents::gateway::{FakeModelAdapter, ModelGateway};
use tinker_apps::AppRegistry;
use tinker_auth::{AssuranceLevel, AuthnContext, MachineCredentialStore, PrincipalKind};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_identity::SessionManager;
use tinker_ingest::connector::{FakeSalesforce, SourceField, SourceRecord};
use tinker_ingest::pipeline::{CanonicalTarget, RunMode};
use tinker_ingest::IngestPipeline;
use tinker_live::{QueryCache, QueryExecutor};
use tinker_ontology::Ontology;
use tinker_packs::{PackDefinition, PackInstaller};
use tinker_query::{Filter, FilterOp, QueryCompiler, QueryIntent};
use uuid::Uuid;

/// Tenants in the reference workload.
const EFF_ORGS: usize = 10;
/// Records per tenant: 50 companies, 1_000 contacts, 200 deals.
const EFF_COMPANIES: i64 = 50;
const EFF_CONTACTS: i64 = 1000;
const EFF_DEALS: i64 = 200;
/// One ingest page per measured iteration.
const INGEST_PAGE: usize = 500;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

struct OrgSeed {
    org_id: Uuid,
    ctx: TenantContext,
}

pub struct EffEnv {
    core: CoreDb,
    owner: OwnerDb,
    compiler: QueryCompiler,
    executor: QueryExecutor,
    cache: QueryCache,
    pipeline: IngestPipeline,
    gateway: ModelGateway,
    store: MachineCredentialStore,
    sessions: SessionManager,
    orgs: Vec<OrgSeed>,
    contact_object_id: Uuid,
    /// Org 0's machine credential, for the MCP HTTP transport.
    key_secret: String,
    /// Org 0's web session cookie token (base64), for session_load.
    session_token: String,
    http_base: String,
    http_client: reqwest::Client,
}

/// Physical column for an api field on a pack object.
async fn phys(owner: &OwnerDb, object_slug: &str, api_name: &str) -> String {
    let row: (String,) = sqlx::query_as(
        "SELECT f.physical_column FROM ontology_fields f
         JOIN ontology_objects o ON o.id = f.object_id
         WHERE o.api_slug=$1 AND f.api_name=$2 AND f.state='active'",
    )
    .bind(object_slug)
    .bind(api_name)
    .fetch_one(&owner.0)
    .await
    .unwrap();
    row.0
}

/// Seed one org: 50 companies, 1_000 contacts, 200 deals — one batched
/// INSERT per object, deterministic content.
async fn seed_org(env: &EffEnv, org_id: Uuid) {
    let c_name = phys(&env.owner, "crm_company", "name").await;
    let c_ind = phys(&env.owner, "crm_company", "industry").await;
    let c_size = phys(&env.owner, "crm_company", "size").await;
    sqlx::query(&format!(
        "INSERT INTO data.crm_company (organization_id, \"{c_name}\", \"{c_ind}\", \"{c_size}\")
         SELECT $1, 'Company ' || g, 'Software', 'smb' FROM generate_series(1, {EFF_COMPANIES}) g"
    ))
    .bind(org_id)
    .execute(&env.owner.0)
    .await
    .unwrap();

    let c_name = phys(&env.owner, "crm_contact", "name").await;
    let c_company = phys(&env.owner, "crm_contact", "company").await;
    // Email is PII by type (vault ref + blind index); sealing EFF_CONTACTS
    // values is not what these tripwires measure, so the bulk seed leaves
    // it NULL — reads still project the field (null, as a masked read would).
    sqlx::query(&format!(
        "INSERT INTO data.crm_contact (organization_id, \"{c_name}\", \"{c_company}\")
         SELECT $1,
                'Contact ' || g || ' ' || $2,
                comp_ids[(g % {EFF_COMPANIES}) + 1]
         FROM generate_series(1, {EFF_CONTACTS}) g
         CROSS JOIN (SELECT array_agg(id ORDER BY id) AS comp_ids
                     FROM data.crm_company WHERE organization_id = $1) c"
    ))
    .bind(org_id)
    .bind(org_id.simple().to_string())
    .execute(&env.owner.0)
    .await
    .unwrap();

    let c_name = phys(&env.owner, "crm_deal", "name").await;
    let c_amount = phys(&env.owner, "crm_deal", "amount").await;
    let c_stage = phys(&env.owner, "crm_deal", "stage").await;
    let c_contact = phys(&env.owner, "crm_deal", "contact").await;
    let c_company = phys(&env.owner, "crm_deal", "company").await;
    let c_notes = phys(&env.owner, "crm_deal", "notes").await;
    sqlx::query(&format!(
        "INSERT INTO data.crm_deal
             (organization_id, \"{c_name}\", \"{c_amount}\", \"{c_stage}\",
              \"{c_contact}\", \"{c_company}\", \"{c_notes}\")
         SELECT $1,
                'Deal ' || g,
                ((g * 137) % 100000)::numeric,
                (ARRAY['lead','qualified','proposal','won','lost'])[(g % 5) + 1],
                cids[(g % {EFF_CONTACTS}) + 1],
                comp_ids[(g % {EFF_COMPANIES}) + 1],
                to_jsonb('Notes for deal ' || g)
         FROM generate_series(1, {EFF_DEALS}) g
         CROSS JOIN (SELECT array_agg(id ORDER BY id) AS cids
                     FROM data.crm_contact WHERE organization_id = $1) a
         CROSS JOIN (SELECT array_agg(id ORDER BY id) AS comp_ids
                     FROM data.crm_company WHERE organization_id = $1) b"
    ))
    .bind(org_id)
    .execute(&env.owner.0)
    .await
    .unwrap();
}

/// Build the full efficiency environment: pack, 10 orgs, seeded records,
/// ingest stream + mappings on org 0, machine credential, web session,
/// and the MCP HTTP transport on 127.0.0.1:0.
async fn setup() -> EffEnv {
    // Production pool discipline: the same constructors the app binary
    // uses (tuned max 16 / min 1), so the tripwires measure the deployed
    // profile rather than sqlx's light-duty defaults.
    let core = CoreDb::connect(&env("TINKER_CORE_URL")).await.unwrap();
    let owner = OwnerDb::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let tenant_pool = core.0.clone();
    let owner_pool = owner.0.clone();
    let ontology = Ontology::new(core.clone(), owner.clone());

    let pack_toml = include_str!("../../../packs/crm/pack.toml");
    let pack = PackDefinition::from_toml(pack_toml).unwrap();
    let installer = PackInstaller::new(
        Ontology::new(core.clone(), owner.clone()),
        AppRegistry::new(tenant_pool.clone()),
    );
    let installed = installer.install_objects(&pack).await.unwrap();
    let contact_object_id = installed.objects["crm_contact"];

    let mut orgs = Vec::with_capacity(EFF_ORGS);
    for i in 0..EFF_ORGS {
        let org_id = Uuid::now_v7();
        let host_id = Uuid::now_v7();
        let actor_id = Uuid::now_v7();
        sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
            .bind(host_id)
            .bind(format!("eff-host-{i}"))
            .execute(&owner_pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
            .bind(org_id)
            .bind(host_id)
            .bind(format!("eff-{i}-{}", org_id.simple()))
            .bind(format!("eff org {i}"))
            .execute(&owner_pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)")
            .bind(actor_id)
            .bind(org_id)
            .bind(format!("eff-actor-{i}"))
            .bind(format!("eff-actor-{i}"))
            .execute(&owner_pool)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, 'executive')",
        )
        .bind(actor_id)
        .bind(org_id)
        .execute(&owner_pool)
        .await
        .unwrap();
        orgs.push(OrgSeed {
            org_id,
            ctx: TenantContext::new(OrganizationId(org_id), actor_id, "eff"),
        });
    }

    let compiler = QueryCompiler::new(ontology.clone());
    let executor = QueryExecutor::new(core.clone());
    let cache = QueryCache::new();
    let pipeline = IngestPipeline::new(core.clone(), owner.clone());
    let mut gateway = ModelGateway::new(core.clone(), owner.clone());
    gateway.register(
        "notes-llm",
        Arc::new(
            FakeModelAdapter::new("notes-llm")
                .with_response("substance", "Seats expansion; champion identified."),
        ),
    );

    let eff = EffEnv {
        core: core.clone(),
        owner: owner.clone(),
        compiler,
        executor,
        cache,
        pipeline,
        gateway: gateway.clone(),
        store: MachineCredentialStore::new(owner.clone()),
        sessions: SessionManager::new(tenant_pool.clone(), owner_pool.clone()),
        orgs,
        contact_object_id,
        key_secret: String::new(),
        session_token: String::new(),
        http_base: String::new(),
        http_client: reqwest::Client::new(),
    };

    // Seed the workload: org 0 doubles as the ingest org, so seed orgs
    // sequentially (each INSERT is one round trip).
    for o in &eff.orgs {
        seed_org(&eff, o.org_id).await;
    }

    let org0 = &eff.orgs[0];
    // The gateway's fake provider row (placement enforcement needs it).
    // Seeded for org 0 (ingest/auth org) and org 1 (query/gateway org).
    for o in [&eff.orgs[0], &eff.orgs[1]] {
        let mut tx = eff.core.tenant_tx(&o.ctx).await.unwrap();
        sqlx::query(
            "INSERT INTO model_providers (organization_id, name, kind, placement_boundary, status)
             VALUES ($1, 'notes-llm', 'fake', 'org-controlled', 'available')
             ON CONFLICT (organization_id, name) DO NOTHING",
        )
        .bind(o.org_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    // Machine credential for the MCP HTTP transport.
    let issued = eff
        .store
        .issue(
            org0.org_id,
            "eff-mcp",
            &["mcp:tools".to_string(), "mcp:resources".to_string()],
            None,
            None,
        )
        .await
        .unwrap();
    // Web session for the session_load path.
    let workspace_id = Uuid::now_v7();
    sqlx::query("INSERT INTO workspaces (id, organization_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(workspace_id)
        .bind(org0.org_id)
        .bind("eff-ws")
        .bind(format!("eff-ws-{}", org0.org_id.simple()))
        .execute(&owner_pool)
        .await
        .unwrap();
    let authn = AuthnContext {
        actor_id: org0.ctx.actor_id,
        principal_kind: PrincipalKind::Human,
        organization_ids: vec![org0.org_id],
        method: "eff".to_string(),
        assurance: AssuranceLevel::Token,
        authenticated_at: chrono::Utc::now(),
        credential_id: "eff".to_string(),
    };
    let session_token = eff
        .sessions
        .create_session(&authn, org0.org_id, workspace_id)
        .await
        .unwrap();

    // MCP HTTP transport (item 28) on an ephemeral port.
    let stack = mcp_http::HttpStack {
        core: core.clone(),
        owner: owner.clone(),
        ontology: ontology.clone(),
        gateway: gateway.clone(),
    };
    let app = mcp_http::router(stack, MachineCredentialStore::new(owner.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    EffEnv {
        key_secret: issued.secret,
        session_token,
        http_base: format!("http://{addr}"),
        ..eff
    }
}

// ---------------------------------------------------------------------------
// Measurement helpers.
// ---------------------------------------------------------------------------

/// Assert a p50 tripwire over measured durations (the m4_perf style:
/// generous budgets, tripwires not SLAs). Prints p50/p99 for the log.
fn tripwire(name: &str, budget_ms: u128, mut durs: Vec<std::time::Duration>) {
    durs.sort();
    let n = durs.len();
    let p50 = durs[n / 2].as_millis();
    let p99 = durs[(n * 99 / 100).min(n - 1)].as_millis();
    let max = durs[n - 1].as_millis();
    println!("eff {name}: p50={p50}ms p99={p99}ms max={max}ms (budget {budget_ms}ms, n={n})");
    assert!(
        p50 <= budget_ms,
        "{name} p50 {p50}ms exceeds budget {budget_ms}ms"
    );
}

const WARMUP: usize = 5;
const ITERS: usize = 21;

fn grid_intent(contact_object_id: Uuid, name_prefix: &str) -> QueryIntent {
    QueryIntent {
        from: contact_object_id,
        select: vec!["name".into(), "email".into()],
        filters: vec![Filter {
            field: "name".into(),
            op: FilterOp::StartsWith,
            value: serde_json::json!(name_prefix),
        }],
        order: vec![],
        limit: Some(100),
        schema_version: None,
    }
}

// ---------------------------------------------------------------------------
// Per-path runners. Each returns the measured latency of one operation.
// ---------------------------------------------------------------------------

/// Ingest: one 500-row page through the full pipeline (extract → land →
/// profile → model → promote, identity resolution on email). Fresh stream
/// + fresh source ids per call: always the insert path.
async fn run_ingest_page(env: &EffEnv, iter: usize) -> std::time::Duration {
    let org0 = &env.orgs[0];
    let sf = FakeSalesforce::new();
    let base = chrono::Utc::now() - chrono::Duration::hours(1);
    let records: Vec<SourceRecord> = (0..INGEST_PAGE)
        .map(|i| SourceRecord {
            source_id: format!("eff-{iter}-{i}"),
            updated_at: base + chrono::Duration::seconds(i as i64),
            deleted: false,
            fields: [
                (
                    "FullName".to_string(),
                    serde_json::json!(format!("Ingest Contact {iter}-{i}")),
                ),
                (
                    "Email".to_string(),
                    serde_json::json!(format!("ingest-{iter}-{i}@example.com")),
                ),
            ]
            .into_iter()
            .collect(),
        })
        .collect();
    sf.seed_object(
        "Contact",
        vec![
            SourceField {
                name: "Id".to_string(),
                type_name: "id".to_string(),
            },
            SourceField {
                name: "FullName".to_string(),
                type_name: "string".to_string(),
            },
            SourceField {
                name: "Email".to_string(),
                type_name: "string".to_string(),
            },
        ],
        records,
    );
    let control = env.pipeline.control();
    let conn = control
        .create_connection(
            &org0.ctx,
            tinker_ingest::control::NewConnection {
                kind: "salesforce".to_string(),
                name: format!("eff-conn-{iter}"),
                credential_ref: None,
            },
        )
        .await
        .unwrap();
    let stream = control
        .create_stream(
            &org0.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Contact".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let m = env.pipeline.mappings();
    for (src, tgt) in [("FullName", "name"), ("Email", "email")] {
        m.put_mapping(&org0.ctx, stream.id, src, "crm_contact", tgt)
            .await
            .unwrap();
    }
    let target = CanonicalTarget {
        object_slug: "crm_contact".to_string(),
        email_api_field: Some("email".to_string()),
    };
    let t = Instant::now();
    let report = env
        .pipeline
        .run(
            &org0.ctx,
            &sf,
            stream.id,
            &[target],
            INGEST_PAGE,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    let d = t.elapsed();
    let promoted: u64 = report.stages.values().map(|s| s.promoted).sum();
    assert_eq!(
        promoted, INGEST_PAGE as u64,
        "each measured page must promote {INGEST_PAGE} rows"
    );
    let mut stage_ms: Vec<(String, u64)> = report
        .stages
        .iter()
        .map(|(k, s)| (k.clone(), s.millis))
        .collect();
    stage_ms.sort();
    println!(
        "eff ingest_page_500 stages: {} total={}ms",
        stage_ms
            .iter()
            .map(|(k, ms)| format!("{k}={ms}ms"))
            .collect::<Vec<_>>()
            .join(" "),
        report.total_millis
    );
    d
}

/// Query grid, cache miss: compile + execute (filtered, limit 100) + the
/// audit write. Distinct filter per iteration so every run misses.
async fn run_query_grid_miss(env: &EffEnv, iter: usize) -> std::time::Duration {
    let ctx = &env.orgs[1].ctx;
    let intent = grid_intent(env.contact_object_id, &format!("Contact {iter}"));
    let t = Instant::now();
    let plan = env.compiler.compile(ctx, &intent).await.unwrap();
    let hash = QueryExecutor::plan_hash(&plan);
    assert!(
        env.cache.get(ctx.organization_id.0, &hash).await.is_none(),
        "miss-path iteration must actually miss"
    );
    let rows = env.executor.execute(ctx, &plan).await.unwrap();
    assert!(rows.len() <= 100);
    let d = t.elapsed();
    env.cache
        .put(ctx.organization_id.0, &hash, plan.object_id, rows)
        .await;
    d
}

/// Query grid, cache hit: hash + QueryCache get.
async fn run_query_grid_hit(
    env: &EffEnv,
    ctx: &TenantContext,
    plan: &tinker_query::CompiledPlan,
    hash: &str,
) -> std::time::Duration {
    let t = Instant::now();
    let rows = env
        .cache
        .get(ctx.organization_id.0, hash)
        .await
        .expect("hit-path iteration must actually hit");
    assert!(!rows.is_empty());
    // Touch the plan shape the way the HTTP path does (hash discipline).
    assert_eq!(QueryExecutor::plan_hash(plan), hash);
    t.elapsed()
}

/// M7 gateway: transform_richtext through the fake adapter (provider-row
/// lookup + placement enforcement; no network).
async fn run_gateway_transform(env: &EffEnv) -> std::time::Duration {
    let ctx = &env.orgs[1].ctx;
    let t = Instant::now();
    let c = env
        .gateway
        .transform_richtext(
            ctx,
            "notes-llm",
            "substance",
            "Quarterly review notes: expansion likely next quarter.",
        )
        .await
        .unwrap();
    assert!(c.text.contains("Seats expansion"));
    t.elapsed()
}

/// MCP HTTP (item 28): POST /mcp `tools/list` — Bearer <redacted> + scope
/// gate + wire-server dispatch, full HTTP round trip.
async fn run_mcp_tools_list(env: &EffEnv) -> std::time::Duration {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let t = Instant::now();
    let r = env
        .http_client
        .post(format!("{}/mcp", env.http_base))
        .header("authorization", format!("Bearer {}", env.key_secret))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), reqwest::StatusCode::OK);
    let v: serde_json::Value = r.json().await.unwrap();
    assert!(v.get("result").is_some(), "tools/list must return a result");
    t.elapsed()
}

/// MCP HTTP (item 28): GET /sse — time to the first endpoint event.
async fn run_mcp_sse_handshake(env: &EffEnv) -> std::time::Duration {
    use tokio_stream::StreamExt;
    let t = Instant::now();
    let resp = env
        .http_client
        .get(format!("{}/sse", env.http_base))
        .header("authorization", format!("Bearer {}", env.key_secret))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let mut stream = resp.bytes_stream();
    let mut saw_endpoint = false;
    let read = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            let s = String::from_utf8_lossy(&chunk);
            if s.contains("endpoint") {
                saw_endpoint = true;
                break;
            }
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), read)
        .await
        .expect("endpoint event within 10s");
    assert!(saw_endpoint, "SSE stream must emit the endpoint event");
    t.elapsed()
}

/// Auth: machine-credential verification (SELECT + best-effort
/// `last_used_at` UPDATE).
async fn run_key_verify(env: &EffEnv) -> std::time::Duration {
    let t = Instant::now();
    let v = env.store.verify(&env.key_secret).await.unwrap();
    assert_eq!(v.organization_id, env.orgs[0].org_id);
    t.elapsed()
}

/// Auth: web session load (cookie token → session row).
async fn run_session_load(env: &EffEnv) -> std::time::Duration {
    let t = Instant::now();
    let s = env
        .sessions
        .load_session(&env.session_token)
        .await
        .unwrap()
        .expect("session must load");
    assert_eq!(s.organization_id, env.orgs[0].org_id);
    t.elapsed()
}

// ---------------------------------------------------------------------------
// Regression tripwires. Each: WARMUP warmups, ITERS measured runs, assert on
// the p50. Budgets are generous and load-sensitive — they are proven in a
// quiet window (see docs/one-server-efficiency.md), never asserted under
// foreign load.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn efficiency_ingest_page_tripwire() {
    let env = setup().await;
    for i in 0..WARMUP {
        run_ingest_page(&env, 1000 + i).await;
    }
    let mut durs = Vec::with_capacity(ITERS);
    for i in 0..ITERS {
        durs.push(run_ingest_page(&env, i).await);
    }
    tripwire("ingest_page_500", 30_000, durs);
}

#[tokio::test]
async fn efficiency_query_grid_miss_tripwire() {
    let env = setup().await;
    for i in 0..WARMUP {
        run_query_grid_miss(&env, 1000 + i).await;
    }
    let mut durs = Vec::with_capacity(ITERS);
    for i in 0..ITERS {
        durs.push(run_query_grid_miss(&env, i).await);
    }
    tripwire("query_grid_miss", 500, durs);
}

#[tokio::test]
async fn efficiency_query_grid_hit_tripwire() {
    let env = setup().await;
    let ctx = &env.orgs[1].ctx;
    let intent = grid_intent(env.contact_object_id, "Contact 1");
    let plan = env.compiler.compile(ctx, &intent).await.unwrap();
    let hash = QueryExecutor::plan_hash(&plan);
    let rows = env.executor.execute(ctx, &plan).await.unwrap();
    assert!(!rows.is_empty());
    env.cache
        .put(ctx.organization_id.0, &hash, plan.object_id, rows)
        .await;
    for _ in 0..WARMUP {
        run_query_grid_hit(&env, ctx, &plan, &hash).await;
    }
    let mut durs = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        durs.push(run_query_grid_hit(&env, ctx, &plan, &hash).await);
    }
    tripwire("query_grid_hit", 100, durs);
}

#[tokio::test]
async fn efficiency_gateway_transform_tripwire() {
    let env = setup().await;
    for _ in 0..WARMUP {
        run_gateway_transform(&env).await;
    }
    let mut durs = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        durs.push(run_gateway_transform(&env).await);
    }
    tripwire("gateway_transform", 500, durs);
}

#[tokio::test]
async fn efficiency_mcp_tools_list_tripwire() {
    let env = setup().await;
    for _ in 0..WARMUP {
        run_mcp_tools_list(&env).await;
    }
    let mut durs = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        durs.push(run_mcp_tools_list(&env).await);
    }
    tripwire("mcp_http_tools_list", 500, durs);
}

#[tokio::test]
async fn efficiency_mcp_sse_handshake_tripwire() {
    let env = setup().await;
    for _ in 0..3 {
        run_mcp_sse_handshake(&env).await;
    }
    let mut durs = Vec::with_capacity(7);
    for _ in 0..7 {
        durs.push(run_mcp_sse_handshake(&env).await);
    }
    tripwire("mcp_http_sse_handshake", 5_000, durs);
}

#[tokio::test]
async fn efficiency_key_verify_tripwire() {
    let env = setup().await;
    for _ in 0..WARMUP {
        run_key_verify(&env).await;
    }
    let mut durs = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        durs.push(run_key_verify(&env).await);
    }
    tripwire("auth_key_verify", 100, durs);
}

#[tokio::test]
async fn efficiency_session_load_tripwire() {
    let env = setup().await;
    for _ in 0..WARMUP {
        run_session_load(&env).await;
    }
    let mut durs = Vec::with_capacity(ITERS);
    for _ in 0..ITERS {
        durs.push(run_session_load(&env).await);
    }
    tripwire("auth_session_load", 100, durs);
}

// ---------------------------------------------------------------------------
// Throughput probes (print-only): sustained ops/sec under 8-way
// concurrency on the two hottest read paths. No wall-clock asserts —
// throughput is load-sensitive by definition.
// ---------------------------------------------------------------------------

/// Prime the cache and return the (ctx, plan, hash) for the hit path.
async fn prime_hit_path(env: &EffEnv) -> (TenantContext, tinker_query::CompiledPlan, String) {
    let ctx = env.orgs[1].ctx.clone();
    let intent = grid_intent(env.contact_object_id, "Contact 1");
    let plan = env.compiler.compile(&ctx, &intent).await.unwrap();
    let hash = QueryExecutor::plan_hash(&plan);
    let rows = env.executor.execute(&ctx, &plan).await.unwrap();
    assert!(!rows.is_empty());
    env.cache
        .put(ctx.organization_id.0, &hash, plan.object_id, rows)
        .await;
    (ctx, plan, hash)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn efficiency_throughput_probe() {
    let env = Arc::new(setup().await);
    let (ctx, plan, hash) = prime_hit_path(&env).await;

    // Phase 1: 8 workers x 100 cached grid queries.
    let t = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let (env, ctx, plan, hash) = (env.clone(), ctx.clone(), plan.clone(), hash.clone());
        handles.push(tokio::spawn(async move {
            for _ in 0..100 {
                let rows = env
                    .cache
                    .get(ctx.organization_id.0, &hash)
                    .await
                    .expect("primed");
                assert!(!rows.is_empty());
                assert_eq!(QueryExecutor::plan_hash(&plan), hash);
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "eff throughput query_grid_hit: {:.0} ops/sec (800 ops in {:.2}s, 8 workers)",
        800.0 / secs,
        secs
    );

    // Phase 2: 8 workers x 25 MCP tools/list round trips.
    let t = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let env = env.clone();
        handles.push(tokio::spawn(async move {
            for _ in 0..25 {
                run_mcp_tools_list(&env).await;
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "eff throughput mcp_http_tools_list: {:.0} ops/sec (200 ops in {:.2}s, 8 workers)",
        200.0 / secs,
        secs
    );
}

/// Ceiling ramp (print-only): workers = 1, 2, 4, 8, 16, 32 on the MCP
/// tools/list path — the DB-authenticated machine-traffic path. Each
/// worker issues 40 sequential round trips; per level we report
/// throughput plus p50/p99. The knee where throughput stops scaling
/// (or p99 blows past budget) is the measured single-server ceiling
/// for machine-API traffic. No wall-clock asserts: the ceiling is
/// evidence for the doc, not a tripwire.
#[tokio::test(flavor = "multi_thread", worker_threads = 32)]
async fn efficiency_ceiling_ramp() {
    let env = Arc::new(setup().await);
    const OPS: u32 = 40;
    for workers in [1u32, 2, 4, 8, 16, 32] {
        let t = Instant::now();
        let mut handles = Vec::new();
        for _ in 0..workers {
            let env = env.clone();
            handles.push(tokio::spawn(async move {
                let mut durs = Vec::with_capacity(OPS as usize);
                for _ in 0..OPS {
                    let t0 = Instant::now();
                    run_mcp_tools_list(&env).await;
                    durs.push(t0.elapsed());
                }
                durs
            }));
        }
        let mut all: Vec<Duration> = Vec::new();
        for h in handles {
            all.extend(h.await.unwrap());
        }
        all.sort();
        let p50 = all[all.len() / 2].as_millis();
        let p99 = all[all.len() * 99 / 100].as_millis();
        let ops = workers * OPS;
        println!(
            "eff ceiling mcp_http_tools_list: workers={workers} ops={ops} throughput={:.0}/s p50={p50}ms p99={p99}ms",
            ops as f64 / t.elapsed().as_secs_f64(),
        );
    }
}
