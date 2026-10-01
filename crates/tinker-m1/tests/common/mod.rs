//! M1 test harness: two organizations, passkey + OIDC identities, one
//! binary (the Axum router) serving both.

use axum::http::{header, Request, StatusCode};
use ed25519_dalek::SigningKey;
use sqlx::PgPool;
use tokio::sync::OnceCell;
use tower::ServiceExt;
use uuid::Uuid;

use tinker_apps::{
    AppDefinition, AppRegistry, AppTokens, CellLayout, ComponentInstance, GridLayout,
};
use tinker_auth::{AuthBroker, OidcAdapter, OidcConfig, OidcKey, PasskeyAdapter};
use tinker_identity::{Authorizer, PgOidcBindingStore, PgPasskeyStore, SessionManager};
use tinker_web::{build_router, build_state, SharedState};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// Fixture context for one organization. Not every field is read by every
/// suite — the struct documents the full per-org fixture.
#[allow(dead_code)]
pub struct OrgCtx {
    pub org_id: Uuid,
    pub workspace_id: Uuid,
    pub actor_id: Uuid,
    pub signing_key: SigningKey,
    pub credential_id: String,
    pub oidc_subject: String,
}

/// Fixture context for the whole test environment. Not every field is read
/// by every suite — the struct documents the full fixture.
#[allow(dead_code)]
pub struct Env {
    pub router: axum::Router,
    pub tenant: PgPool,
    pub system: PgPool,
    pub sessions: SessionManager,
    pub authorizer: Authorizer,
    pub registry: AppRegistry,
    pub org_a: OrgCtx,
    pub org_b: OrgCtx,
    pub run: String,
}

#[allow(dead_code)]
fn oidc_test_pem() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tinker-auth/testdata/oidc_test_rsa.pem"
    ))
    .expect("oidc test pem")
}

fn oidc_test_pub_pem() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tinker-auth/testdata/oidc_test_rsa_pub.pem"
    ))
    .expect("oidc test public pem")
}

pub fn oidc_config() -> OidcConfig {
    OidcConfig {
        issuer: "https://issuer.m1.test".into(),
        audience: "tinker-m1".into(),
        keys: vec![OidcKey {
            key_id: None,
            algorithm: jsonwebtoken::Algorithm::RS256,
            // Verifiers hold the PUBLIC key; the private key only mints.
            decoding_key: jsonwebtoken::DecodingKey::from_rsa_pem(&oidc_test_pub_pem()).unwrap(),
        }],
    }
}

#[allow(dead_code)]
pub fn mint_id_token(subject: &str, audience: &str, exp_secs: i64) -> String {
    let exp = (chrono::Utc::now() + chrono::Duration::seconds(exp_secs)).timestamp();
    let claims = serde_json::json!({
        "iss": "https://issuer.m1.test",
        "sub": subject,
        "aud": audience,
        "exp": exp,
        "iat": exp - 60,
    });
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(&oidc_test_pem()).unwrap(),
    )
    .unwrap()
}

fn dashboard_definition(title: &str, stat_value: &str) -> AppDefinition {
    AppDefinition {
        layout: GridLayout {
            layout_type: "grid".into(),
            columns: 12,
            row_height: 48,
            gap: 12,
        },
        components: vec![
            ComponentInstance {
                id: "title".into(),
                component_type: "rt-text".into(),
                props: serde_json::json!({ "content": title }),
                layout: CellLayout {
                    x: 0,
                    y: 0,
                    w: 12,
                    h: 1,
                },
                events: vec![],
            },
            ComponentInstance {
                id: "kpi".into(),
                component_type: "rt-stat".into(),
                props: serde_json::json!({ "label": "Revenue", "value": stat_value }),
                layout: CellLayout {
                    x: 0,
                    y: 1,
                    w: 4,
                    h: 2,
                },
                events: vec![],
            },
            ComponentInstance {
                id: "orders".into(),
                component_type: "rt-grid".into(),
                props: serde_json::json!({
                    "columns": [
                        { "key": "id", "label": "Order" },
                        { "key": "total", "label": "Total" },
                    ]
                }),
                layout: CellLayout {
                    x: 0,
                    y: 3,
                    w: 12,
                    h: 4,
                },
                events: vec![],
            },
        ],
    }
}

fn tokens() -> AppTokens {
    serde_json::from_value(serde_json::json!({ "brand": "Tinker", "accent": "#2563eb" })).unwrap()
}

/// Transaction on the owner pool with the tenant context set. Required
/// because the identity tables use FORCED row-level security: even the
/// owner role cannot read/write without `app.organization_id`.
pub async fn scoped_tx(system: &PgPool, org_id: Uuid) -> sqlx::Transaction<'_, sqlx::Postgres> {
    let mut tx = system.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.organization_id', $1, true)")
        .bind(org_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
    tx
}

async fn make_org(
    system: &PgPool,
    sessions: &SessionManager,
    host_id: Uuid,
    run: &str,
    name: &str,
    oidc_subject: &str,
) -> OrgCtx {
    let org_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO organizations (id, host_id, name, slug) VALUES ($1, $2, $3, $4)",
        org_id,
        host_id,
        name,
        format!("{name}-{run}")
    )
    .execute(system)
    .await
    .unwrap();
    // Forced RLS on workspaces/actors/memberships: seed inside a
    // tenant-scoped transaction even on the owner pool.
    let mut tx = scoped_tx(system, org_id).await;
    let ws_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO workspaces (id, organization_id, name, slug) VALUES ($1, $2, $3, $4)",
        ws_id,
        org_id,
        "main",
        format!("main-{run}")
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let actor_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)",
        actor_id,
        org_id,
        format!("{name} admin"),
        format!("{name}-admin")
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, 'owner')",
        actor_id,
        org_id
    )
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
    sessions
        .bind_oidc(
            org_id,
            actor_id,
            &format!("oidc-{name}-{run}"),
            "https://issuer.m1.test",
            oidc_subject,
        )
        .await
        .unwrap();
    OrgCtx {
        org_id,
        workspace_id: ws_id,
        actor_id,
        signing_key,
        credential_id,
        oidc_subject: oidc_subject.to_string(),
    }
}

pub async fn setup() -> Env {
    let system = PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("owner connect");
    MIGRATED
        .get_or_init(|| async {
            tinker_db::MIGRATOR_CORE
                .run(&system)
                .await
                .expect("core migrations");
        })
        .await;
    let tenant = PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("app-role connect");

    let run: String = Uuid::now_v7().simple().to_string()[..8].into();
    let host_id = Uuid::now_v7();
    sqlx::query!(
        "INSERT INTO hosts (id, name) VALUES ($1, $2)",
        host_id,
        format!("host-{run}")
    )
    .execute(&system)
    .await
    .unwrap();

    let sessions = SessionManager::new(tenant.clone(), system.clone());
    let authorizer = Authorizer::new(tenant.clone(), system.clone());
    let registry = AppRegistry::new(tenant.clone());

    let org_a = make_org(&system, &sessions, host_id, &run, "acme", "acme-user-1").await;
    let org_b = make_org(&system, &sessions, host_id, &run, "globex", "globex-user-1").await;

    // Publish a dashboard in each org with org-specific content.
    for (org, title, stat) in [
        (&org_a, "ACME DASHBOARD", "$1.2M"),
        (&org_b, "GLOBEX DASHBOARD", "$9.9M"),
    ] {
        let app_id = registry
            .create_app(
                org.org_id,
                org.workspace_id,
                org.actor_id,
                "dashboard",
                "Dashboard",
            )
            .await
            .unwrap();
        let v = registry
            .save_draft(
                org.org_id,
                org.actor_id,
                app_id,
                &dashboard_definition(title, stat),
                &tokens(),
            )
            .await
            .unwrap();
        registry
            .publish(org.org_id, org.actor_id, app_id, v)
            .await
            .unwrap();
        // app:view at org scope covers the render.
        authorizer
            .grant(
                org.org_id,
                org.actor_id,
                &tinker_auth::AuthzScope::Organization {
                    organization_id: org.org_id,
                },
                "app:view",
                None,
            )
            .await
            .unwrap();
    }

    let broker = AuthBroker::new(vec![
        Box::new(PasskeyAdapter::new(PgPasskeyStore::new(tenant.clone()))),
        Box::new(OidcAdapter::new(
            PgOidcBindingStore::new(system.clone()),
            oidc_config(),
        )),
    ]);
    let state: SharedState = build_state(
        tenant.clone(),
        system.clone(),
        broker,
        "tinker.test".into(),
        false,
    );
    let router = build_router(state);

    Env {
        router,
        tenant,
        system,
        sessions,
        authorizer,
        registry,
        org_a,
        org_b,
        run,
    }
}

/// Full passkey ceremony over HTTP. Returns the session cookie value.
pub async fn passkey_login(router: &axum::Router, org: &OrgCtx) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Signer;

    let start_body = serde_json::json!({
        "organization_id": org.org_id.to_string(),
        "actor_id": org.actor_id.to_string(),
    });
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/passkey/start")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(start_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
    let start: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    let challenge_b64 = start["challenge"].as_str().unwrap();
    let challenge = URL_SAFE_NO_PAD.decode(challenge_b64).unwrap();
    let sig = org.signing_key.sign(&challenge).to_bytes();

    let finish_body = serde_json::json!({
        "organization_id": org.org_id.to_string(),
        "workspace_id": org.workspace_id.to_string(),
        "credential_id": org.credential_id,
        "challenge_id": start["challenge_id"].as_str().unwrap(),
        "signature": URL_SAFE_NO_PAD.encode(sig),
    });
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/passkey/finish")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(finish_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "passkey finish");
    extract_cookie(&res)
}

/// OIDC login over HTTP. Returns the session cookie value.
/// Shared login helper; not every suite exercises OIDC.
#[allow(dead_code)]
pub async fn oidc_login(router: &axum::Router, org: &OrgCtx) -> String {
    let body = serde_json::json!({
        "organization_id": org.org_id.to_string(),
        "workspace_id": org.workspace_id.to_string(),
        "id_token": mint_id_token(&org.oidc_subject, "tinker-m1", 300),
    });
    let res = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/oidc")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER, "oidc login");
    extract_cookie(&res)
}

fn extract_cookie(res: &axum::response::Response) -> String {
    let set_cookie = res
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .unwrap();
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix(&format!("{}=", tinker_web::SESSION_COOKIE))
        .unwrap()
        .to_string()
}

pub async fn get_with_cookie(
    router: &axum::Router,
    uri: &str,
    cookie: &str,
) -> axum::response::Response {
    router
        .clone()
        .oneshot(
            Request::builder()
                .uri(uri)
                .header(
                    header::COOKIE,
                    format!("{}={cookie}", tinker_web::SESSION_COOKIE),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

pub async fn body_text(res: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(res.into_body(), 256 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}
