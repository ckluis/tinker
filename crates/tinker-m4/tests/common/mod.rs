//! M4 test harness: schema evolution with immutable versions.
//!
//! - Installs `packs/crm/pack.toml` (platform objects, shared tables).
//! - Org A ("Acme") has a `builder` (holds the `schema:evolve` grant) and a
//!   `member` (no grant). Org B ("Globex") is the sibling with its own
//!   builder; its schema must never change when A evolves.
//! - Seeds one contact per org through the owner pool.
//! - Builds the real web router + compiler with the evolver attached, so

#![allow(dead_code)]
//!   HTTP tests prove the grant gate and the full lifecycle.

use tinker_apps::AppRegistry;
use tinker_auth::{AssuranceLevel, AuthnContext, PrincipalKind};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_evolve::SchemaEvolver;
use tinker_identity::SessionManager;
use tinker_ontology::{FieldDef, FieldType, Ontology};
use tinker_packs::{InstalledPack, PackDefinition, PackInstaller};
use tinker_query::QueryCompiler;
use uuid::Uuid;

#[allow(dead_code)]
pub struct ActorCtx {
    pub actor_id: Uuid,
    pub tenant: TenantContext,
    pub cookie: String,
}

#[allow(dead_code)]
pub struct EvoEnv {
    pub router: axum::Router,
    pub org_a_id: Uuid,
    pub org_b_id: Uuid,
    pub builder_a: ActorCtx,
    pub member_a: ActorCtx,
    pub builder_b: ActorCtx,
    pub installed: InstalledPack,
    pub tenant_pool: sqlx::PgPool,
    pub system_pool: sqlx::PgPool,
    pub state: std::sync::Arc<tinker_web::AppState>,
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

pub fn ontology_of(env: &EvoEnv) -> Ontology {
    Ontology::new(
        CoreDb(env.tenant_pool.clone()),
        OwnerDb(env.system_pool.clone()),
    )
}

pub fn evolver_of(env: &EvoEnv) -> SchemaEvolver {
    SchemaEvolver::new(
        CoreDb(env.tenant_pool.clone()),
        OwnerDb(env.system_pool.clone()),
        ontology_of(env),
    )
}

pub fn compiler_of(env: &EvoEnv) -> QueryCompiler {
    let ontology = ontology_of(env);
    QueryCompiler::new(ontology.clone()).with_evolver(SchemaEvolver::new(
        CoreDb(env.tenant_pool.clone()),
        OwnerDb(env.system_pool.clone()),
        ontology,
    ))
}

/// Fresh pools per call: each #[tokio::test] runs on its own
/// current-thread runtime, and pools must not be shared across runtimes.
pub async fn setup() -> EvoEnv {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let system_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();

    let pack_toml = include_str!("../../../../packs/crm/pack.toml");
    let pack = PackDefinition::from_toml(pack_toml).unwrap();
    let installer = PackInstaller::new(
        Ontology::new(CoreDb(tenant_pool.clone()), OwnerDb(system_pool.clone())),
        AppRegistry::new(tenant_pool.clone()),
    );
    let installed = installer.install_objects(&pack).await.unwrap();
    assert_eq!(installed.objects.len(), 3, "crm pack has 3 objects");

    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("m4-host")
        .execute(&system_pool)
        .await
        .unwrap();
    let org_a_id = Uuid::now_v7();
    let org_b_id = Uuid::now_v7();
    for org_id in [org_a_id, org_b_id] {
        sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
            .bind(org_id)
            .bind(host_id)
            .bind(format!("m4org-{}", org_id.simple()))
            .bind("m4 org")
            .execute(&system_pool)
            .await
            .unwrap();
    }

    let sessions = SessionManager::new(tenant_pool.clone(), system_pool.clone());

    async fn make_actor(
        system_pool: &sqlx::PgPool,
        sessions: &SessionManager,
        org_id: Uuid,
        tag: &str,
    ) -> ActorCtx {
        let workspace_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO workspaces (id, organization_id, slug, name) VALUES ($1,$2,$3,$4)",
        )
        .bind(workspace_id)
        .bind(org_id)
        .bind(format!("m4ws-{tag}-{}", &org_id.simple().to_string()[24..]))
        .bind("m4 ws")
        .execute(system_pool)
        .await
        .unwrap();
        let actor_id = Uuid::now_v7();
        let mut tx = system_pool.begin().await.unwrap();
        sqlx::query("INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)")
            .bind(actor_id)
            .bind(org_id)
            .bind(format!("m4-{tag}"))
            .bind(format!("m4-{tag}"))
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, 'member')",
        )
        .bind(actor_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let authn = AuthnContext {
            actor_id,
            principal_kind: PrincipalKind::Human,
            organization_ids: vec![org_id],
            method: "test-fixture".into(),
            assurance: AssuranceLevel::MultiFactor,
            authenticated_at: chrono::Utc::now(),
            credential_id: format!("fixture-{tag}"),
        };
        let token = sessions
            .create_session(&authn, org_id, workspace_id)
            .await
            .unwrap();
        ActorCtx {
            actor_id,
            tenant: TenantContext::new(OrganizationId(org_id), actor_id, "m4-test"),
            cookie: format!("tinker_session={token}"),
        }
    }

    let builder_a = make_actor(&system_pool, &sessions, org_a_id, "a-builder").await;
    let member_a = make_actor(&system_pool, &sessions, org_a_id, "a-member").await;
    let builder_b = make_actor(&system_pool, &sessions, org_b_id, "b-builder").await;

    // Only org A's builder may evolve schema.
    let authorizer = tinker_identity::Authorizer::new(tenant_pool.clone(), system_pool.clone());
    authorizer
        .grant(
            org_a_id,
            builder_a.actor_id,
            &tinker_auth::AuthzScope::Organization {
                organization_id: org_a_id,
            },
            "schema:evolve",
            None,
        )
        .await
        .unwrap();

    seed_contact(&system_pool, &installed, org_a_id, "Amy").await;
    seed_contact(&system_pool, &installed, org_b_id, "Brian").await;

    let broker = tinker_auth::AuthBroker::new(vec![]);
    let state = tinker_web::build_state(
        tenant_pool.clone(),
        system_pool.clone(),
        broker,
        "tinker.test".into(),
        false,
    );
    let router = tinker_web::build_router(state.clone());

    EvoEnv {
        router,
        org_a_id,
        org_b_id,
        builder_a,
        member_a,
        builder_b,
        installed,
        tenant_pool,
        system_pool,
        state,
    }
}

async fn seed_contact(
    system_pool: &sqlx::PgPool,
    installed: &InstalledPack,
    org_id: Uuid,
    name: &str,
) -> Uuid {
    let contact_id = installed.objects["crm_contact"];
    let slug: (String,) = sqlx::query_as("SELECT api_slug FROM ontology_objects WHERE id=$1")
        .bind(contact_id)
        .fetch_one(system_pool)
        .await
        .unwrap();
    async fn col(system_pool: &sqlx::PgPool, object_id: Uuid, api_name: &str) -> String {
        let row: (String,) = sqlx::query_as(
            "SELECT physical_column FROM ontology_fields WHERE object_id=$1 AND api_name=$2",
        )
        .bind(object_id)
        .bind(api_name)
        .fetch_one(system_pool)
        .await
        .unwrap();
        row.0
    }
    // Email is PII by type: seal it and write the ref + blind index.
    let sealed = tinker_ontology::sensitive::sealer_from_env()
        .await
        .unwrap()
        .expect("TINKER_PII_URL, TINKER_KEK, TINKER_BLIND_INDEX_KEY must be set")
        .seal_for_write(
            system_pool,
            org_id,
            contact_id,
            "email",
            &format!("{name}@example.com"),
        )
        .await
        .unwrap();
    let row: (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.{} (organization_id, \"{}\", \"{}\", \"{}\") VALUES ($1,$2,$3,$4) RETURNING id",
        slug.0,
        col(system_pool, contact_id, "name").await,
        sealed.ref_column,
        sealed.bidx_column,
    ))
    .bind(org_id)
    .bind(name)
    .bind(sealed.ref_id)
    .bind(&sealed.bidx)
    .fetch_one(system_pool)
    .await
    .unwrap();
    row.0
}

/// POST through the real router as an actor.
pub async fn post_json(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
    body: &serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &actor.cookie)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// GET through the real router as an actor.
pub async fn get_json(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::COOKIE, &actor.cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// A text field definition for evolution tests.
pub fn text_field(api_name: &str) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        sensitive: false,
        validation: Default::default(),
        preset: None,
        name: api_name.to_string(),
        api_name: api_name.to_string(),
        label: api_name.to_string(),
        field_type: FieldType::Text,
        options: serde_json::json!({}),
        required: false,
    }
}

/// A relation field definition for evolution tests.
pub fn relation_field(api_name: &str, target: Uuid) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        sensitive: false,
        validation: Default::default(),
        preset: None,
        name: api_name.to_string(),
        api_name: api_name.to_string(),
        label: api_name.to_string(),
        field_type: FieldType::Relation {
            target_object_id: target,
        },
        options: serde_json::json!({}),
        required: false,
    }
}

/// Insert a row into an org's extension table (raw SQL — the test, not the
/// product, since the governed mutation connector is M4-backlog).
pub async fn insert_ext_row(
    system_pool: &sqlx::PgPool,
    org_id: Uuid,
    object_id: Uuid,
    record_id: Uuid,
    physical_column: &str,
    value: &str,
) {
    let table = tinker_evolve::ext_table_name(org_id, object_id);
    sqlx::query(&format!(
        "INSERT INTO {table} (organization_id, record_id, \"{physical_column}\") VALUES ($1,$2,$3)"
    ))
    .bind(org_id)
    .bind(record_id)
    .bind(value)
    .execute(system_pool)
    .await
    .unwrap();
}
