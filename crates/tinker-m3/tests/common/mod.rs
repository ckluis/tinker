//! M3 test harness: CRM pack installed, two orgs, role-based actors.
//!
//! - Installs `packs/crm/pack.toml` through the platform-authorized
//!   [`PackInstaller`] (no SQL in the test — the pack is the interface).
//! - Org A ("Acme") has two actors: `sales` (full projection) and
//!   `support` (restricted projection on contacts: no email/phone).
//! - Org B ("Globex") is the sibling: same pack objects, disjoint data.
//! - Seeds one company + contact + deal per org through the owner pool
//!   (explicit organization_id — the tables are RLS-isolated).

use tinker_apps::AppRegistry;
use tinker_auth::{AssuranceLevel, AuthnContext, PrincipalKind};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_identity::SessionManager;
use tinker_live::FieldGrants;
use tinker_ontology::Ontology;
use tinker_packs::{InstalledApp, InstalledPack, PackDefinition, PackInstaller};
use uuid::Uuid;

#[allow(dead_code)]
pub struct ActorCtx {
    pub actor_id: Uuid,
    pub tenant: TenantContext,
    pub cookie: String,
    pub role: String,
}

#[allow(dead_code)]
pub struct OrgCtx {
    pub org_id: Uuid,
    pub workspace_id: Uuid,
    pub sales: ActorCtx,
    pub support: ActorCtx,
}

#[allow(dead_code)]
pub struct CrmEnv {
    pub router: axum::Router,
    pub org_a: OrgCtx,
    pub org_b: OrgCtx,
    pub installed: InstalledPack,
    pub app_id: Uuid,
    pub installed_app: InstalledApp,
    pub tenant_pool: sqlx::PgPool,
    pub system_pool: sqlx::PgPool,
    pub state: std::sync::Arc<tinker_web::AppState>,
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

/// Fresh pools per call: each #[tokio::test] runs on its own
/// current-thread runtime, and pools must not be shared across runtimes.
/// The pack install is idempotent, so repeat setup is cheap.
pub async fn setup() -> CrmEnv {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let system_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();

    // Install the CRM pack through the privileged installer. The test
    // never writes DDL itself: the TOML pack is the entire interface.
    let pack_toml = include_str!("../../../../packs/crm/pack.toml");
    let pack = PackDefinition::from_toml(pack_toml).unwrap();
    let installer = PackInstaller::new(
        Ontology::new(CoreDb(tenant_pool.clone()), OwnerDb(system_pool.clone())),
        AppRegistry::new(tenant_pool.clone()),
    );
    let installed = installer.install_objects(&pack).await.unwrap();
    assert_eq!(installed.objects.len(), 3, "crm pack has 3 objects");

    // One host, two orgs.
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("m3-host")
        .execute(&system_pool)
        .await
        .unwrap();
    let org_a_id = Uuid::now_v7();
    let org_b_id = Uuid::now_v7();
    for org_id in [org_a_id, org_b_id] {
        sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
            .bind(org_id)
            .bind(host_id)
            .bind(format!("m3org-{}", org_id.simple()))
            .bind("m3 org")
            .execute(&system_pool)
            .await
            .unwrap();
    }

    let sessions = SessionManager::new(tenant_pool.clone(), system_pool.clone());

    async fn make_org(
        system_pool: &sqlx::PgPool,
        sessions: &SessionManager,
        org_id: Uuid,
        tag: &str,
    ) -> (Uuid, ActorCtx, ActorCtx) {
        let workspace_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO workspaces (id, organization_id, slug, name) VALUES ($1,$2,$3,$4)",
        )
        .bind(workspace_id)
        .bind(org_id)
        .bind(format!("m3ws-{tag}-{}", &org_id.simple().to_string()[24..]))
        .bind("m3 ws")
        .execute(system_pool)
        .await
        .unwrap();

        async fn make_actor(
            system_pool: &sqlx::PgPool,
            sessions: &SessionManager,
            org_id: Uuid,
            workspace_id: Uuid,
            tag: &str,
            role: &str,
        ) -> ActorCtx {
            let actor_id = Uuid::now_v7();
            let mut tx = system_pool.begin().await.unwrap();
            sqlx::query(
                "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)",
            )
            .bind(actor_id)
            .bind(org_id)
            .bind(format!("m3-{tag}"))
            .bind(format!("m3-{tag}"))
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, $3)",
            )
            .bind(actor_id)
            .bind(org_id)
            .bind(role)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();
            // Mint a session through the real session manager: M3 tests
            // projections, not auth (M1 proved the adapters).
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
                tenant: TenantContext::new(OrganizationId(org_id), actor_id, "m3-test"),
                cookie: format!("tinker_session={token}"),
                role: role.to_string(),
            }
        }

        // SessionManager needs the pools before seeding; create it early.
        let sales = make_actor(
            system_pool,
            sessions,
            org_id,
            workspace_id,
            &format!("{tag}-sales"),
            "sales",
        )
        .await;
        let support = make_actor(
            system_pool,
            sessions,
            org_id,
            workspace_id,
            &format!("{tag}-support"),
            "support",
        )
        .await;
        (workspace_id, sales, support)
    }

    let (ws_a, sales_a, support_a) = make_org(&system_pool, &sessions, org_a_id, "a").await;
    let (ws_b, sales_b, support_b) = make_org(&system_pool, &sessions, org_b_id, "b").await;

    // Install the dashboard app into org A's workspace.
    let installed_app = installer
        .install_app(&sales_a.tenant, ws_a, &pack, &installed, "crm-dashboard")
        .await
        .unwrap();
    let app_id = installed_app.app_id;

    // app:view at org scope covers the render for org A's actors only.
    // Org B's actors get no grant: the sibling-render test must 404/403.
    let authorizer = tinker_identity::Authorizer::new(tenant_pool.clone(), system_pool.clone());
    for actor in [&sales_a, &support_a] {
        authorizer
            .grant(
                org_a_id,
                actor.actor_id,
                &tinker_auth::AuthzScope::Organization {
                    organization_id: org_a_id,
                },
                "app:view",
                None,
            )
            .await
            .unwrap();
    }

    // Seed data through the owner pool (explicit org ids; RLS still
    // isolates at read time).
    seed_org(&system_pool, &installed, org_a_id, "Acme", "Alice").await;
    seed_org(&system_pool, &installed, org_b_id, "Globex", "Bob").await;

    // Projections: support sees a restricted contact card (no email/phone);
    // sales is unrestricted (no grant rows). Deals: support sees no amount.
    let grants = FieldGrants::new(CoreDb(tenant_pool.clone()));
    let contact_id = installed.objects["crm_contact"];
    let deal_id = installed.objects["crm_deal"];
    for org_id in [org_a_id, org_b_id] {
        // A tenant ctx for the grants writer: any member actor works.
        let ctx = TenantContext::new(OrganizationId(org_id), sales_a.actor_id, "m3-test");
        grants
            .set_projection(&ctx, contact_id, "support", &["name", "title", "company"])
            .await
            .unwrap();
        grants
            .set_projection(
                &ctx,
                deal_id,
                "support",
                &["name", "stage", "contact", "company"],
            )
            .await
            .unwrap();
    }

    let broker = tinker_auth::AuthBroker::new(vec![]);
    // The CRM pack's email/phone are PII by type: the server needs the
    // vault (masking, blind-index lookups) like any production server.
    let pii = tinker_ontology::sensitive::sealer_from_env()
        .await
        .unwrap()
        .expect("TINKER_PII_URL, TINKER_KEK, TINKER_BLIND_INDEX_KEY must be set");
    let state = tinker_web::build_state_with_pii(
        tenant_pool.clone(),
        system_pool.clone(),
        broker,
        "tinker.test".into(),
        false,
        Some(pii),
    );
    let router = tinker_web::build_router(state.clone());

    // Sanity: the session manager resolves the minted cookies.
    for actor in [&sales_a, &support_a, &sales_b, &support_b] {
        let token = actor.cookie.strip_prefix("tinker_session=").unwrap();
        assert!(
            sessions.load_session(token).await.unwrap().is_some(),
            "session resolves for {}",
            actor.role
        );
    }

    CrmEnv {
        router,
        org_a: OrgCtx {
            org_id: org_a_id,
            workspace_id: ws_a,
            sales: sales_a,
            support: support_a,
        },
        org_b: OrgCtx {
            org_id: org_b_id,
            workspace_id: ws_b,
            sales: sales_b,
            support: support_b,
        },
        installed,
        app_id,
        installed_app,
        tenant_pool,
        system_pool,
        state,
    }
}

/// Seed one company + contact + deal for an org. Column names are
/// physical (`f_*`); the test resolves them through the ontology —
/// no hardcoded column names.
async fn seed_org(
    system_pool: &sqlx::PgPool,
    installed: &InstalledPack,
    org_id: Uuid,
    company_name: &str,
    contact_name: &str,
) {
    let company_id = installed.objects["crm_company"];
    let contact_id = installed.objects["crm_contact"];
    let deal_id = installed.objects["crm_deal"];

    // Resolve slugs + physical columns via the owner pool.
    let slug_of = |id: Uuid| async move {
        let row: (String,) = sqlx::query_as("SELECT api_slug FROM ontology_objects WHERE id=$1")
            .bind(id)
            .fetch_one(system_pool)
            .await
            .unwrap();
        row.0
    };
    let cslug = slug_of(company_id).await;
    let ctslug = slug_of(contact_id).await;
    let dslug = slug_of(deal_id).await;

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

    let company_row: (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.{cslug} (organization_id, \"{}\", \"{}\") VALUES ($1,$2,$3) RETURNING id",
        col(system_pool, company_id, "name").await,
        col(system_pool, company_id, "industry").await,
    ))
    .bind(org_id)
    .bind(company_name)
    .bind("software")
    .fetch_one(system_pool)
    .await
    .unwrap();

    // Email and phone are PII by type: sealed, written as ref + blind index.
    let sealer = tinker_ontology::sensitive::sealer_from_env()
        .await
        .unwrap()
        .expect("TINKER_PII_URL, TINKER_KEK, TINKER_BLIND_INDEX_KEY must be set");
    let email = sealer
        .seal_for_write(
            system_pool,
            org_id,
            contact_id,
            "email",
            &format!("{contact_name}@example.com"),
        )
        .await
        .unwrap();
    let phone = sealer
        .seal_for_write(system_pool, org_id, contact_id, "phone", "555-0100")
        .await
        .unwrap();
    let contact_row: (Uuid,) = sqlx::query_as(&format!(
        "INSERT INTO data.{ctslug} (organization_id, \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\") VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id",
        col(system_pool, contact_id, "name").await,
        email.ref_column,
        email.bidx_column,
        phone.ref_column,
        phone.bidx_column,
        col(system_pool, contact_id, "title").await,
        col(system_pool, contact_id, "company").await,
    ))
    .bind(org_id)
    .bind(contact_name)
    .bind(email.ref_id)
    .bind(&email.bidx)
    .bind(phone.ref_id)
    .bind(&phone.bidx)
    .bind("VP Sales")
    .bind(company_row.0)
    .fetch_one(system_pool)
    .await
    .unwrap();

    sqlx::query(&format!(
        "INSERT INTO data.{dslug} (organization_id, \"{}\", \"{}\", \"{}\", \"{}\", \"{}\") VALUES ($1,$2,$3::numeric,$4,$5,$6)",
        col(system_pool, deal_id, "name").await,
        col(system_pool, deal_id, "amount").await,
        col(system_pool, deal_id, "stage").await,
        col(system_pool, deal_id, "contact").await,
        col(system_pool, deal_id, "company").await,
    ))
    .bind(org_id)
    .bind("Big Deal")
    .bind("250000")
    .bind("proposal")
    .bind(contact_row.0)
    .bind(company_row.0)
    .execute(system_pool)
    .await
    .unwrap();
}

/// POST a query intent through the real router as an actor.
pub async fn post_query(
    router: &axum::Router,
    actor: &ActorCtx,
    intent: &serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let req = Request::builder()
        .method("POST")
        .uri("/api/query")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &actor.cookie)
        .body(axum::body::Body::from(intent.to_string()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[allow(dead_code)]
pub fn contact_intent(installed: &InstalledPack) -> serde_json::Value {
    serde_json::json!({
        "from": installed.objects["crm_contact"],
        "select": ["name", "email", "phone", "title", "company.name"],
        "filters": [],
        "order": [],
        "limit": 50,
    })
}
