//! M5 test harness: native communications.
//!
//! - Installs the platform comms objects (`Comms::install`).

#![allow(dead_code)]
//! - Org A ("Acme") has `agent_a` (member, `thread:read`+`thread:write`),
//!   `viewer_a` (viewer, `thread:read`+`thread:write`, restricted field
//!   projections), and `nogrant_a` (member, no thread grants at all).
//! - Org B ("Globex") has `operator_b` (cross-plane access to A only via
//!   an explicit grant row) and `stranger_b` (no access to A at all).
//! - Field projections: role "member" is unrestricted (default-open);
//!   roles "viewer" and "operator" see channel names and thread subjects
//!   but never message bodies.
//! - Builds the real web router, so HTTP tests prove the grant gate,
//!   the card endpoint, and the write path end to end.

use std::sync::Arc;
use tinker_auth::{AssuranceLevel, AuthnContext, PrincipalKind};
use tinker_comms::InstalledComms;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::CoreDb;
use tinker_identity::SessionManager;
use tinker_vault::Vault;
use uuid::Uuid;

pub struct ActorCtx {
    pub actor_id: Uuid,
    pub tenant: TenantContext,
    pub cookie: String,
    pub display_name: String,
    /// The per-org-unique mention handle (0036). Mirrors `display_name`
    /// here because the `m5-{tag}` names are already normalized.
    pub handle: String,
}

pub struct CommsEnv {
    pub router: axum::Router,
    pub org_a_id: Uuid,
    pub org_b_id: Uuid,
    pub agent_a: ActorCtx,
    pub viewer_a: ActorCtx,
    pub admin_a: ActorCtx,
    pub nogrant_a: ActorCtx,
    pub operator_b: ActorCtx,
    pub stranger_b: ActorCtx,
    pub installed: InstalledComms,
    pub tenant_pool: sqlx::PgPool,
    pub system_pool: sqlx::PgPool,
    pub pii_pool: sqlx::PgPool,
    pub state: Arc<tinker_web::AppState>,
    pub vault: Vault,
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

/// Fresh pools per call: each #[tokio::test] runs on its own
/// current-thread runtime, and pools must not be shared across runtimes.
pub async fn setup() -> CommsEnv {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let system_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let pii_pool = sqlx::PgPool::connect(&env("TINKER_PII_URL")).await.unwrap();
    let kek_hex = env("TINKER_KEK");
    let kek = hex_decode(&kek_hex);
    let vault = Vault::new(tinker_db::PiiDb(pii_pool.clone()), &kek).unwrap();

    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("m5-host")
        .execute(&system_pool)
        .await
        .unwrap();
    let org_a_id = Uuid::now_v7();
    let org_b_id = Uuid::now_v7();
    for (org_id, slug) in [
        (org_a_id, format!("m5a-{}", org_a_id.simple())),
        (org_b_id, format!("m5b-{}", org_b_id.simple())),
    ] {
        sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
            .bind(org_id)
            .bind(host_id)
            .bind(slug)
            .bind("m5 org")
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
        membership_role: &str,
    ) -> ActorCtx {
        let workspace_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO workspaces (id, organization_id, slug, name) VALUES ($1,$2,$3,$4)",
        )
        .bind(workspace_id)
        .bind(org_id)
        .bind(format!("m5ws-{tag}"))
        .bind("m5 ws")
        .execute(system_pool)
        .await
        .unwrap();
        let actor_id = Uuid::now_v7();
        let display_name = format!("m5-{tag}");
        let mut tx = system_pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)",
        )
        .bind(actor_id)
        .bind(org_id)
        .bind(&display_name)
        .bind(&display_name)
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, $3)",
        )
        .bind(actor_id)
        .bind(org_id)
        .bind(membership_role)
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
            tenant: TenantContext::new(OrganizationId(org_id), actor_id, "m5-test"),
            cookie: format!("tinker_session={token}"),
            display_name: display_name.clone(),
            handle: display_name,
        }
    }

    let agent_a = make_actor(&system_pool, &sessions, org_a_id, "a-agent", "member").await;
    let viewer_a = make_actor(&system_pool, &sessions, org_a_id, "a-viewer", "viewer").await;
    let admin_a = make_actor(&system_pool, &sessions, org_a_id, "a-admin", "admin").await;
    let nogrant_a = make_actor(&system_pool, &sessions, org_a_id, "a-nogrant", "member").await;
    let operator_b = make_actor(&system_pool, &sessions, org_b_id, "b-operator", "member").await;
    let stranger_b = make_actor(&system_pool, &sessions, org_b_id, "b-stranger", "member").await;

    let broker = tinker_auth::AuthBroker::new(vec![]);
    let state = tinker_web::build_state(
        tenant_pool.clone(),
        system_pool.clone(),
        broker,
        "tinker.test".into(),
        false,
    );
    state.comms.install().await.unwrap();
    let installed = state.comms.installed().await.unwrap().clone();
    let router = tinker_web::build_router(state.clone());

    // Thread grants for org A members (nogrant_a deliberately excluded).
    let authorizer = tinker_identity::Authorizer::new(tenant_pool.clone(), system_pool.clone());
    for actor in [&agent_a, &viewer_a, &admin_a] {
        for action in ["thread:read", "thread:write"] {
            authorizer
                .grant(
                    org_a_id,
                    actor.actor_id,
                    &tinker_auth::AuthzScope::Organization {
                        organization_id: org_a_id,
                    },
                    action,
                    None,
                )
                .await
                .unwrap();
        }
    }

    // Field projections: "member" stays unrestricted; "viewer" and
    // "operator" see names/subjects but never message bodies.
    let ctx_a = TenantContext::new(OrganizationId(org_a_id), agent_a.actor_id, "m5-test");
    for role in ["viewer", "operator"] {
        state
            .grants
            .set_projection(&ctx_a, installed.channel_id, role, &["name"])
            .await
            .unwrap();
        state
            .grants
            .set_projection(
                &ctx_a,
                installed.thread_id,
                role,
                &["subject", "channel_id"],
            )
            .await
            .unwrap();
        state
            .grants
            .set_projection(&ctx_a, installed.message_id, role, &["author_actor_id"])
            .await
            .unwrap();
    }

    CommsEnv {
        router,
        org_a_id,
        org_b_id,
        agent_a,
        viewer_a,
        admin_a,
        nogrant_a,
        operator_b,
        stranger_b,
        installed,
        tenant_pool,
        system_pool,
        pii_pool,
        state,
        vault,
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Open a tenant-scoped transaction for test assertions. Direct pool
/// queries against RLS tables are unreliable: PostgreSQL leaves a custom
/// GUC as `''` (not unset) after `SET LOCAL` + COMMIT, so a context-free
/// query on a recycled pooled connection fails with
/// `invalid input syntax for type uuid: ""`. Every tenant read or write
/// in tests goes through `tenant_tx`, exactly like production code.
pub async fn tenant_tx(
    env: &CommsEnv,
    ctx: &TenantContext,
) -> sqlx::Transaction<'static, sqlx::Postgres> {
    CoreDb(env.tenant_pool.clone())
        .tenant_tx(ctx)
        .await
        .unwrap()
}

/// POST through the real router as an actor.
pub async fn post_json(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
    body: &serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    request_json(router, actor, "POST", uri, Some(body)).await
}

/// PUT through the real router as an actor.
pub async fn put_json(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
    body: &serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    request_json(router, actor, "PUT", uri, Some(body)).await
}

/// GET through the real router as an actor.
pub async fn get_json(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    request_json(router, actor, "GET", uri, None).await
}

async fn request_json(
    router: &axum::Router,
    actor: &ActorCtx,
    method: &str,
    uri: &str,
    body: Option<&serde_json::Value>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::COOKIE, &actor.cookie);
    let req = if let Some(b) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        builder.body(axum::body::Body::from(b.to_string())).unwrap()
    } else {
        builder.body(axum::body::Body::empty()).unwrap()
    };
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Build a thread with two messages via the HTTP write path:
/// one plain-text message and one object-ref message.
pub async fn seed_thread(env: &CommsEnv) -> (Uuid, Uuid, Uuid) {
    let (status, body) = post_json(
        &env.router,
        &env.agent_a,
        "/api/comms/channels",
        &serde_json::json!({ "name": "general", "kind": "channel" }),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CREATED,
        "create channel: {body}"
    );
    let channel_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

    let (status, body) = post_json(
        &env.router,
        &env.agent_a,
        "/api/comms/threads",
        &serde_json::json!({ "channel_id": channel_id, "subject": "Launch plan" }),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::CREATED,
        "create thread: {body}"
    );
    let thread_id: Uuid = body["id"].as_str().unwrap().parse().unwrap();

    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        &format!("/api/comms/threads/{thread_id}/messages"),
        &serde_json::json!({ "body": "Ship it Friday" }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED);

    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        &format!("/api/comms/threads/{thread_id}/messages"),
        &serde_json::json!({ "body": format!("see tinker:comm_channel:{channel_id} for context") }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED);

    (channel_id, thread_id, env.agent_a.actor_id)
}

/// Grant cross-plane access in the accessed org via the product API.
/// Returns the grant id.
pub async fn insert_cross_plane_grant(
    env: &CommsEnv,
    accessed_org: Uuid,
    grantee_actor_id: Uuid,
    granted_by: Uuid,
    expires_in_secs: i64,
) -> Uuid {
    let ctx = TenantContext::new(OrganizationId(accessed_org), granted_by, "m5-test");
    tinker_comms::grant_cross_plane_access(
        &CoreDb(env.tenant_pool.clone()),
        &ctx,
        grantee_actor_id,
        "support",
        chrono::Utc::now() + chrono::Duration::seconds(expires_in_secs),
        granted_by,
    )
    .await
    .unwrap()
    .id
}
