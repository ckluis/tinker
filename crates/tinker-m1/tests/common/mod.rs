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
use tinker_web::oidc_flow::OidcClient;
use tinker_web::{build_router_with_oidc, build_state, SharedState};

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
    /// The OIDC provider the router's code flow talks to.
    pub idp: FakeIdp,
}

/// A minimal OIDC provider for the code flow: the test plays the user's
/// browser by registering (code -> id_token, PKCE challenge) with
/// [`FakeIdp::authorize`]; the token endpoint verifies the PKCE verifier
/// against that challenge and hands back the token, once.
#[derive(Clone)]
pub struct FakeIdp {
    pub base: String,
    codes: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, (String, String)>>>,
}

#[allow(dead_code)]
impl FakeIdp {
    pub async fn start() -> Self {
        let codes: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, (String, String)>>,
        > = Default::default();
        let state = codes.clone();
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(move |body: String| {
                let codes = state.clone();
                async move {
                    let form: std::collections::HashMap<String, String> = body
                        .split('&')
                        .filter_map(|kv| kv.split_once('='))
                        .map(|(k, v)| (k.to_string(), percent_decode(v)))
                        .collect();
                    let code = form.get("code").cloned().unwrap_or_default();
                    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                    let Some((token, challenge)) = codes.lock().unwrap().remove(&code) else {
                        return (StatusCode::BAD_REQUEST, "unknown code".to_string());
                    };
                    if tinker_web::oidc_flow::pkce_challenge(&verifier) != challenge {
                        return (StatusCode::BAD_REQUEST, "pkce mismatch".to_string());
                    }
                    (
                        StatusCode::OK,
                        serde_json::json!({ "id_token": token, "token_type": "Bearer" })
                            .to_string(),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { base, codes }
    }

    /// The user approved at the provider: `code` will redeem `id_token`
    /// for a client presenting the verifier behind `challenge`.
    pub fn authorize(&self, code: &str, id_token: String, challenge: &str) {
        self.codes
            .lock()
            .unwrap()
            .insert(code.to_string(), (id_token, challenge.to_string()));
    }

    pub fn client(&self) -> OidcClient {
        OidcClient {
            authorization_endpoint: "https://idp.m1.test/authorize".into(),
            token_endpoint: format!("{}/token", self.base),
            client_id: "tinker-m1".into(),
            client_secret: None,
            redirect_uri: "https://tinker.test/login/oidc/callback".into(),
        }
    }
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8(out).unwrap()
}

/// Nonce used by tests that call the adapter directly (no login attempt).
#[allow(dead_code)]
pub const TEST_NONCE: &str = "m1-test-nonce";

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

/// An ID token answering a login attempt whose nonce is [`TEST_NONCE`].
#[allow(dead_code)]
pub fn mint_id_token(subject: &str, audience: &str, exp_secs: i64) -> String {
    mint_id_token_for(subject, audience, exp_secs, TEST_NONCE)
}

#[allow(dead_code)]
pub fn mint_id_token_for(subject: &str, audience: &str, exp_secs: i64, nonce: &str) -> String {
    let exp = (chrono::Utc::now() + chrono::Duration::seconds(exp_secs)).timestamp();
    let claims = serde_json::json!({
        "iss": "https://issuer.m1.test",
        "sub": subject,
        "aud": audience,
        "exp": exp,
        "iat": exp - 60,
        "nonce": nonce,
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

    let run: String = Uuid::now_v7().simple().to_string()[24..32].into(); // random tail: the v7 head is the timestamp
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
    let idp = FakeIdp::start().await;
    let router = build_router_with_oidc(state, Some(idp.client()));

    Env {
        idp,
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

/// One run of the OIDC code flow over HTTP, with the test playing the
/// browser and the provider: start → (provider issues `make_token(nonce)`
/// for a fresh code bound to the PKCE challenge) → callback. Returns the
/// callback response and the attempt's `state` (for replay tests).
#[allow(dead_code)]
pub async fn oidc_flow(
    env: &Env,
    org: &OrgCtx,
    make_token: impl Fn(&str) -> String,
) -> (axum::response::Response, String) {
    let res = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/login/oidc/start?organization_id={}&workspace_id={}",
                    org.org_id, org.workspace_id
                ))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::FOUND, "oidc start redirects");
    let location = res.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    let param = |name: &str| {
        location
            .split(['?', '&'])
            .find_map(|kv| kv.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("{name} in {location}"))
            .to_string()
    };
    let (state, nonce, challenge) = (param("state"), param("nonce"), param("code_challenge"));
    assert_eq!(param("code_challenge_method"), "S256");
    let code = format!("code-{}", Uuid::now_v7().simple());
    env.idp.authorize(&code, make_token(&nonce), &challenge);
    let res = oidc_callback(env, &code, &state).await;
    (res, state)
}

/// GET the callback with an explicit (code, state) pair.
#[allow(dead_code)]
pub async fn oidc_callback(env: &Env, code: &str, state: &str) -> axum::response::Response {
    env.router
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/login/oidc/callback?code={code}&state={state}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// OIDC login through the code flow. Returns the session cookie value.
/// Shared login helper; not every suite exercises OIDC.
#[allow(dead_code)]
pub async fn oidc_login(env: &Env, org: &OrgCtx) -> String {
    let subject = org.oidc_subject.clone();
    let (res, _) = oidc_flow(env, org, |nonce| {
        mint_id_token_for(&subject, "tinker-m1", 300, nonce)
    })
    .await;
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
