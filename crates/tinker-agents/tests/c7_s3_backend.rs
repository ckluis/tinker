//! Item 42 (C7): S3-compatible file backend.
//!
//! A fake S3 HTTP server (axum, localhost ephemeral port) that
//! independently verifies SigV4 signatures per the AWS spec: it
//! recomputes the expected signature from the received headers and
//! body and returns 403 for anything unsigned or mis-signed — so a
//! green round trip proves the client's signing is real, not a rubber
//! stamp.
//!
//! Coverage: backend selection (fs default, s3 selection, unknown
//! backend rejected), unconfigured-S3 fail-closed (each missing
//! variable), put/get/delete round trip through `FileStore` with the
//! S3 backend (including SSE header passthrough), the unsigned-request
//! rejection proof, and secret redaction in Debug output.
//!
//! Environment variables are process-global: every test in this
//! binary that touches them holds `ENV_LOCK`, so parallel test
//! threads cannot race each other's config.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::any;
use axum::Router;
use sha2::{Digest, Sha256};
use tinker_agents::files::{
    backend_from_env, FileBackend, FileStore, PiiClass, S3Config, S3FileBackend,
};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::CoreDb;
use uuid::Uuid;

const FAKE_AK: &str = "test-ak";
const FAKE_SECRET: &str = "test-secret";
const FAKE_BUCKET: &str = "test-bucket";
const FAKE_REGION: &str = "us-east-1";

/// Serializes all env-var manipulation in this test binary.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct FakeS3 {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    /// The `x-amz-server-side-encryption` header seen on each PUT.
    put_sse: Mutex<Vec<Option<String>>>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut kb = [0u8; BLOCK];
    if key.len() > BLOCK {
        kb[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        kb[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= kb[i];
        opad[i] ^= kb[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let d = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Independent SigV4 verification, straight from the AWS spec. Returns
/// `Ok(())` when the request's signature checks out against
/// `FAKE_SECRET`, `Err(status)` otherwise.
fn verify_sigv4(
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), StatusCode> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    // "AWS4-HMAC-SHA256 Credential=AK/DATE/REGION/s3/aws4_request, SignedHeaders=h1;h2, Signature=SIG"
    let rest = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or(StatusCode::FORBIDDEN)?;
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(", ") {
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = Some(v);
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v);
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = Some(v);
        }
    }
    let (credential, signed_headers, signature) = match (credential, signed_headers, signature) {
        (Some(c), Some(s), Some(g)) => (c, s, g),
        _ => return Err(StatusCode::FORBIDDEN),
    };
    let cred_parts: Vec<&str> = credential.split('/').collect();
    if cred_parts.len() != 5
        || cred_parts[0] != FAKE_AK
        || cred_parts[2] != FAKE_REGION
        || cred_parts[3] != "s3"
        || cred_parts[4] != "aws4_request"
    {
        return Err(StatusCode::FORBIDDEN);
    }
    let date_stamp = cred_parts[1];

    // The payload hash the client claims must match the actual body.
    let claimed = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    let actual = hex(&Sha256::digest(body));
    if claimed != actual {
        return Err(StatusCode::BAD_REQUEST);
    }
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::FORBIDDEN)?;
    if !amz_date.starts_with(date_stamp) {
        return Err(StatusCode::FORBIDDEN);
    }

    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let value = headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or(StatusCode::FORBIDDEN)?;
        canonical_headers.push_str(&format!("{}:{}\n", name.to_lowercase(), value.trim()));
    }
    let canonical_request =
        format!("{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{actual}");
    let scope = format!("{date_stamp}/{FAKE_REGION}/s3/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&Sha256::digest(canonical_request.as_bytes()))
    );
    let k_date = hmac_sha256(
        format!("AWS4{FAKE_SECRET}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, FAKE_REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let expected = hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));
    if expected != signature {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(())
}

async fn fake_s3_handler(
    State(st): State<Arc<FakeS3>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let path = uri.path().to_string();
    if verify_sigv4(method.as_str(), &path, &headers, &body).is_err() {
        return (StatusCode::FORBIDDEN, "bad signature".to_string()).into_response();
    }
    let key = match path.strip_prefix(&format!("/{FAKE_BUCKET}/")) {
        Some(k) => k.to_string(),
        None => return (StatusCode::BAD_REQUEST, "bad bucket".to_string()).into_response(),
    };
    match method {
        Method::PUT => {
            let sse = headers
                .get("x-amz-server-side-encryption")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            st.put_sse.lock().unwrap().push(sse);
            st.objects.lock().unwrap().insert(key, body.to_vec());
            (StatusCode::OK, String::new()).into_response()
        }
        Method::GET => match st.objects.lock().unwrap().get(&key) {
            Some(bytes) => (StatusCode::OK, bytes.clone()).into_response(),
            None => (StatusCode::NOT_FOUND, String::new()).into_response(),
        },
        Method::DELETE => {
            st.objects.lock().unwrap().remove(&key);
            (StatusCode::NO_CONTENT, String::new()).into_response()
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, String::new()).into_response(),
    }
}

struct FakeS3Server {
    state: Arc<FakeS3>,
    endpoint: String,
}

async fn start_fake_s3() -> FakeS3Server {
    let state = Arc::new(FakeS3::default());
    let app = Router::new()
        .route("/{*path}", any(fake_s3_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake s3");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fake s3");
    });
    FakeS3Server {
        state,
        endpoint: format!("http://127.0.0.1:{port}"),
    }
}

/// Point the process env at the fake S3. Caller must hold ENV_LOCK.
fn point_env_at(server: &FakeS3Server, with_sse: bool) {
    std::env::set_var("TINKER_FILE_BACKEND", "s3");
    std::env::set_var("TINKER_S3_ENDPOINT", &server.endpoint);
    std::env::set_var("TINKER_S3_BUCKET", FAKE_BUCKET);
    std::env::set_var("TINKER_S3_ACCESS_KEY", FAKE_AK);
    std::env::set_var("TINKER_S3_SECRET_KEY", FAKE_SECRET);
    std::env::set_var("TINKER_S3_REGION", FAKE_REGION);
    if with_sse {
        std::env::set_var("TINKER_S3_SSE", "AES256");
    } else {
        std::env::remove_var("TINKER_S3_SSE");
    }
}

fn clear_s3_env() {
    for k in [
        "TINKER_FILE_BACKEND",
        "TINKER_S3_ENDPOINT",
        "TINKER_S3_BUCKET",
        "TINKER_S3_ACCESS_KEY",
        "TINKER_S3_SECRET_KEY",
        "TINKER_S3_REGION",
        "TINKER_S3_SSE",
    ] {
        std::env::remove_var(k);
    }
}

fn must_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

struct DbEnv {
    core: CoreDb,
    core_owner: sqlx::PgPool,
    host_id: Uuid,
}

async fn db_setup() -> DbEnv {
    let core_owner = sqlx::PgPool::connect(&must_env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("core owner connect");
    tinker_db::MIGRATOR_CORE
        .run(&core_owner)
        .await
        .expect("core migrations");
    let core = CoreDb::connect(&must_env("TINKER_CORE_URL"))
        .await
        .expect("core app-role connect");
    let host_id = Uuid::from_u128(0xC7);
    sqlx::query(
        "INSERT INTO hosts (id, name) VALUES ($1,'c7-s3-test') ON CONFLICT (id) DO NOTHING",
    )
    .bind(host_id)
    .execute(&core_owner)
    .await
    .expect("host upsert");
    DbEnv {
        core,
        core_owner,
        host_id,
    }
}

async fn new_ctx(env: &DbEnv, slug: &str) -> TenantContext {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    let ctx = TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "c7-s3-test".to_string(),
    );
    // actors row for the upload audit path.
    let mut tx = env.core.tenant_tx(&ctx).await.expect("tenant tx");
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$4)",
    )
    .bind(ctx.actor_id)
    .bind(org_id)
    .bind("s3 test actor")
    .bind(format!("s3-actor-{}", org_id.simple()))
    .execute(&mut *tx)
    .await
    .expect("actor insert");
    tx.commit().await.expect("commit");
    ctx
}

// ---------------------------------------------------------------------------
// Backend selection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn backend_selection_defaults_to_fs() {
    // Recover from poisoning: a sibling test's panic must not cascade
    // into unrelated env assertions.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_s3_env();
    let backend = backend_from_env().expect("default backend");
    assert_eq!(backend.name(), "fs");
    clear_s3_env();
}

#[tokio::test]
async fn backend_selection_unknown_is_rejected() {
    // Recover from poisoning: a sibling test's panic must not cascade
    // into unrelated env assertions.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_s3_env();
    std::env::set_var("TINKER_FILE_BACKEND", "gcs");
    let err = match backend_from_env() {
        Ok(_) => panic!("expected backend_from_env to fail"),
        Err(e) => e,
    };
    assert!(format!("{err:?}").contains("unknown TINKER_FILE_BACKEND"));
    clear_s3_env();
}

#[tokio::test]
async fn s3_selected_but_unconfigured_fails_closed() {
    // Recover from poisoning: a sibling test's panic must not cascade
    // into unrelated env assertions.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Nothing set at all.
    clear_s3_env();
    std::env::set_var("TINKER_FILE_BACKEND", "s3");
    let err = match backend_from_env() {
        Ok(_) => panic!("expected backend_from_env to fail"),
        Err(e) => e,
    };
    let msg = format!("{err:?}");
    assert!(msg.contains("TINKER_S3_ENDPOINT"), "unexpected: {msg}");

    // Partially configured: endpoint + bucket only.
    std::env::set_var("TINKER_S3_ENDPOINT", "http://127.0.0.1:9");
    std::env::set_var("TINKER_S3_BUCKET", "b");
    let err = match backend_from_env() {
        Ok(_) => panic!("expected backend_from_env to fail"),
        Err(e) => e,
    };
    let msg = format!("{err:?}");
    assert!(msg.contains("TINKER_S3_ACCESS_KEY"), "unexpected: {msg}");

    // Three of four: still closed.
    std::env::set_var("TINKER_S3_ACCESS_KEY", "ak");
    let err = match backend_from_env() {
        Ok(_) => panic!("expected backend_from_env to fail"),
        Err(e) => e,
    };
    let msg = format!("{err:?}");
    assert!(msg.contains("TINKER_S3_SECRET_KEY"), "unexpected: {msg}");

    // The error names the variable, never a value.
    assert!(!msg.contains("ak"));
    clear_s3_env();
}

// ---------------------------------------------------------------------------
// Round trip against the fake S3
// ---------------------------------------------------------------------------

#[tokio::test]
async fn s3_put_get_delete_round_trip() {
    let server = start_fake_s3().await;
    // The backend reads its config from the environment exactly once at
    // construction; the lock only needs to cover that window, and the
    // env is restored immediately after so no await ever holds it.
    let backend = {
        // Recover from poisoning: a sibling test's panic must not
        // cascade into unrelated env assertions.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        point_env_at(&server, true);
        let backend = backend_from_env().expect("s3 backend");
        clear_s3_env();
        backend
    };
    assert_eq!(backend.name(), "s3");

    let env = db_setup().await;
    let ctx = new_ctx(&env, &format!("c7s3-{}", Uuid::now_v7().simple())).await;
    let store = FileStore::new(env.core.clone(), backend);

    let bytes = b"hello s3-compatible world";
    let stored = store
        .store(&ctx, "greeting.txt", "text/plain", PiiClass::None, bytes)
        .await
        .expect("store");

    // The fake S3 actually received the object under the org-prefixed key…
    let expected_key = format!(
        "{}/{}/{}",
        ctx.organization_id.0,
        &stored.sha256[..2],
        stored.sha256
    );
    assert!(server
        .state
        .objects
        .lock()
        .unwrap()
        .contains_key(&expected_key));
    // …and the SSE option arrived as a header (never in a log line here).
    let sse_seen: Vec<Option<String>> = server.state.put_sse.lock().unwrap().clone();
    assert_eq!(sse_seen, vec![Some("AES256".to_string())]);
    // …and the registry row records the s3 backend. (Inside a tenant
    // tx: the RLS policy needs the org context the tx pins.)
    let mut tx = env.core.tenant_tx(&ctx).await.expect("tenant tx");
    let (backend_name,): (String,) =
        sqlx::query_as("SELECT backend FROM stored_files WHERE organization_id = $1 AND id = $2")
            .bind(ctx.organization_id.0)
            .bind(stored.id)
            .fetch_one(&mut *tx)
            .await
            .expect("backend column");
    tx.rollback().await.expect("rollback");
    assert_eq!(backend_name, "s3");

    // GET round-trips bytes (a SigV4-signed GET the fake verified).
    let (meta, got) = store.fetch(&ctx, stored.id).await.expect("fetch");
    assert_eq!(got, bytes);
    assert_eq!(meta.id, stored.id);

    // DELETE removes the object; a later GET is a clean not-found.
    store.delete(&ctx, stored.id).await.expect("delete");
    assert!(!server
        .state
        .objects
        .lock()
        .unwrap()
        .contains_key(&expected_key));
    let err = store.fetch(&ctx, stored.id).await.unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::NotFound(_)));
}

#[tokio::test]
async fn s3_unsigned_requests_are_rejected_by_the_harness() {
    // Proves the fake is not a rubber stamp: a bare PUT with no
    // Authorization header must be refused.
    let server = start_fake_s3().await;
    let client = reqwest::Client::new();
    let resp = client
        .put(format!("{}/{}/unsigned", server.endpoint, FAKE_BUCKET))
        .body("nope")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // And a tampered signature is refused too: sign with the wrong secret.
    // Env is only needed for backend construction — scope the lock there.
    let bad = {
        // Recover from poisoning: a sibling test's panic must not
        // cascade into unrelated env assertions.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TINKER_S3_ENDPOINT", &server.endpoint);
        std::env::set_var("TINKER_S3_BUCKET", FAKE_BUCKET);
        std::env::set_var("TINKER_S3_ACCESS_KEY", FAKE_AK);
        std::env::set_var("TINKER_S3_SECRET_KEY", "wrong-secret");
        let bad = S3FileBackend::from_env().expect("bad-secret backend");
        clear_s3_env();
        bad
    };
    let err = bad.store(ctxless_org(), "k", b"data").await.unwrap_err();
    assert!(format!("{err:?}").contains("403"), "unexpected: {err:?}");
}

fn ctxless_org() -> Uuid {
    Uuid::now_v7()
}

#[tokio::test]
async fn s3_debug_output_redacts_secret() {
    // Recover from poisoning: a sibling test's panic must not cascade
    // into unrelated env assertions.
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cfg = S3Config {
        endpoint: "http://127.0.0.1:9000".into(),
        bucket: "b".into(),
        access_key: "AKIDEXAMPLE".into(),
        secret_key: "definitely-not-for-logs".into(),
        region: "us-east-1".into(),
        sse: Some("AES256".into()),
    };
    let backend = S3FileBackend::new(cfg).expect("backend");
    let dbg = format!("{backend:?}");
    assert!(!dbg.contains("definitely-not-for-logs"));
    assert!(dbg.contains("<redacted>"));
}
