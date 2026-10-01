//! M2 test harness: two organizations, one shared platform object, one
//! record ID deliberately colliding across both orgs.
//!
//! The fixture defines a platform-scoped `m2_widget` object (visible to
//! both orgs, one physical table) and inserts the SAME record UUID under
//! org A ("Alpha") and org B ("Beta"). Every M2 path must keep them apart.

use sqlx::PgPool;
use tokio::sync::OnceCell;
use uuid::Uuid;

use tinker_auth::{AssuranceLevel, AuthnContext, PrincipalKind};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::CoreDb;
use tinker_durable::DurableRuntime;
use tinker_identity::SessionManager;
use tinker_ontology::{FieldType, ObjectDef, Scope};
use tinker_search::NativeSearchBackend;
use tinker_web::{build_router, build_state, SharedState};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// The deliberately colliding record ID, shared by both orgs' rows.
pub fn colliding_id() -> Uuid {
    Uuid::parse_str("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa").unwrap()
}

#[allow(dead_code)]
pub struct OrgCtx {
    pub org_id: Uuid,
    pub workspace_id: Uuid,
    pub actor_id: Uuid,
    pub cookie: String,
    pub tenant: TenantContext,
}

#[allow(dead_code)]
pub struct Env {
    pub router: axum::Router,
    pub state: SharedState,
    pub tenant_pool: PgPool,
    pub system_pool: PgPool,
    pub org_a: OrgCtx,
    pub org_b: OrgCtx,
    pub durable: DurableRuntime,
    pub search: NativeSearchBackend,
    pub object_id: Uuid,
    pub run: String,
}

async fn make_org(
    system: &PgPool,
    sessions: &SessionManager,
    host_id: Uuid,
    run: &str,
    name: &str,
) -> OrgCtx {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(name)
        .bind(format!("{name}-{run}"))
        .execute(system)
        .await
        .unwrap();

    // Forced RLS on identity tables: seed inside a tenant-scoped tx.
    let mut tx = system.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.organization_id', $1, true)")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    let workspace_id = Uuid::now_v7();
    sqlx::query("INSERT INTO workspaces (id, organization_id, name, slug) VALUES ($1, $2, $3, $4)")
        .bind(workspace_id)
        .bind(org_id)
        .bind("main")
        .bind(format!("main-{run}"))
        .execute(&mut *tx)
        .await
        .unwrap();
    let actor_id = Uuid::now_v7();
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

    // Mint a session directly: M2 tests the reactivity loop, not auth
    // (M1 proved the adapters). The AuthnContext is constructed, not forged —
    // the actor really is a member of this org.
    let authn = AuthnContext {
        actor_id,
        principal_kind: PrincipalKind::Human,
        organization_ids: vec![org_id],
        method: "test-fixture".into(),
        assurance: AssuranceLevel::MultiFactor,
        authenticated_at: chrono::Utc::now(),
        credential_id: format!("fixture-{name}-{run}"),
    };
    let token = sessions
        .create_session(&authn, org_id, workspace_id)
        .await
        .unwrap();

    OrgCtx {
        org_id,
        workspace_id,
        actor_id,
        cookie: format!("tinker_session={token}"),
        tenant: TenantContext::new(OrganizationId(org_id), actor_id, "m2-test"),
    }
}

pub async fn setup() -> Env {
    let system_pool = PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("owner connect");
    MIGRATED
        .get_or_init(|| async {
            tinker_db::MIGRATOR_CORE
                .run(&system_pool)
                .await
                .expect("core migrations");
        })
        .await;
    let tenant_pool = PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("app-role connect");

    let run: String = Uuid::now_v7().simple().to_string();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind(format!("host-{run}"))
        .execute(&system_pool)
        .await
        .unwrap();

    let sessions = SessionManager::new(tenant_pool.clone(), system_pool.clone());
    let org_a = make_org(&system_pool, &sessions, host_id, &run, "acme").await;
    let org_b = make_org(&system_pool, &sessions, host_id, &run, "globex").await;

    let core = CoreDb(tenant_pool.clone());
    let durable = DurableRuntime::new(core.clone(), system_pool.clone());
    let search = NativeSearchBackend::new(core.clone());

    let broker = tinker_auth::AuthBroker::new(vec![]);
    let state: SharedState = build_state(
        tenant_pool.clone(),
        system_pool.clone(),
        broker,
        "tinker.test".into(),
        false,
    );
    let router = build_router(state.clone());

    // Platform object DDL goes through the state's ontology (owner handle
    // inside). The slug is run-unique: the slug namespace is portfolio-shared.
    //
    // Fixture elevation: tenant actors cannot define platform objects
    // (define_object rejects Scope::Platform — proven by the Forbidden
    // error this setup used to hit). So the fixture defines an
    // organization object through the product API, then flips it to
    // platform scope via the owner pool — exactly the shape the privileged
    // pack-install path produces (scope_kind='platform', NULL orgs).
    let slug = format!("m2_widget_{run}").replace('-', "_");
    let def = ObjectDef {
        name: "M2 Widget".into(),
        api_slug: slug.clone(),
        label: "M2 Widget".into(),
        scope: Scope::Organization,
        pack_id: None,
        pack_version: None,
    };
    let meta = state
        .ontology
        .define_object(&org_a.tenant, &def)
        .await
        .unwrap();
    for (api_name, label, ftype) in [
        ("name", "Name", FieldType::Text),
        ("score", "Score", FieldType::Number),
    ] {
        state
            .ontology
            .add_field(
                &org_a.tenant,
                meta.id,
                &tinker_ontology::FieldDef {
                    validation: Default::default(),
                    preset: None,
                    max_pii_class: "restricted".to_string(),
                    name: label.to_string(),
                    api_name: api_name.to_string(),
                    label: label.to_string(),
                    field_type: ftype,
                    options: serde_json::json!({}),
                    required: false,
                },
            )
            .await
            .unwrap();
    }
    let desc = state
        .ontology
        .describe_object(&org_a.tenant, meta.id)
        .await
        .unwrap();

    // Elevate to platform scope: visible to both orgs, one physical table.
    sqlx::query(
        "UPDATE ontology_objects SET scope_kind='platform', organization_id=NULL WHERE id=$1",
    )
    .bind(meta.id)
    .execute(&system_pool)
    .await
    .unwrap();
    sqlx::query("UPDATE ontology_fields SET organization_id=NULL WHERE object_id=$1")
        .bind(meta.id)
        .execute(&system_pool)
        .await
        .unwrap();
    let name_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let score_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "score")
        .unwrap()
        .physical_column
        .clone();

    // The collision: the SAME record id in both orgs, different content.
    let cid = colliding_id();
    for (org, name, score) in [(&org_a, "Alpha", 1), (&org_b, "Beta", 2)] {
        let mut tx = core.tenant_tx(&org.tenant).await.unwrap();
        sqlx::query(&format!(
            "INSERT INTO data.{slug} (organization_id, id, \"{name_col}\", \"{score_col}\") \
             VALUES ($1, $2, $3, $4)"
        ))
        .bind(org.org_id)
        .bind(cid)
        .bind(name)
        .bind(score)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    Env {
        router,
        state,
        tenant_pool,
        system_pool,
        org_a,
        org_b,
        durable,
        search,
        object_id: meta.id,
        run,
    }
}

/// POST a QueryIntent to /api/query with a session cookie.
#[allow(dead_code)]
pub async fn post_query(
    router: &axum::Router,
    cookie: &str,
    intent: &serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let req = Request::builder()
        .method("POST")
        .uri("/api/query")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, cookie)
        .body(axum::body::Body::from(intent.to_string()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}
