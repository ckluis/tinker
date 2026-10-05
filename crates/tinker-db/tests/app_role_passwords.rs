//! App-role passwords are environment-provided, never the repo-embedded
//! defaults.
//!
//! The 0001 migrations create `tinker_app` / `tinker_pii_app` with
//! published dev passwords when the roles do not exist (frozen
//! migrations). `rotate_app_role_passwords` — called by the repo's own
//! migration runner and by `bin/pg-ensure.sh` — replaces them from the
//! environment and fails closed when no password is provided. These
//! tests pin both halves: the pure URL extraction, and the end-to-end
//! rotation that evicts a simulated published-default back to the env
//! secret.
//!
//! The end-to-end test is the only test in this file that touches the
//! shared cluster roles, and it leaves them in the correct (env) state.

use tinker_db::app_password_from_url;

#[test]
fn password_extraction_matches_pg_ensure_pw_of() {
    // Mirrors bin/pg-ensure.sh's pw_of: raw userinfo substring.
    assert_eq!(
        app_password_from_url("postgres://tinker_app:s3cret@127.0.0.1:5432/tinker_core"),
        Some("s3cret".to_string())
    );
    assert_eq!(
        app_password_from_url("postgres://u:p%40ss@h/db"),
        Some("p%40ss".to_string()),
        "no percent-decoding, exactly like pg-ensure"
    );
    assert_eq!(
        app_password_from_url("postgres://tinker_app@127.0.0.1:5432/tinker_core"),
        None,
        "no password segment"
    );
    assert_eq!(
        app_password_from_url("postgres://tinker_app:@127.0.0.1:5432/tinker_core"),
        None,
        "empty password segment"
    );
    assert_eq!(app_password_from_url("not a url"), None);
    assert_eq!(app_password_from_url(""), None);
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

/// Rebuild a Postgres URL with a different password in the userinfo
/// segment (raw-substring surgery, matching `app_password_from_url`).
fn with_password(url: &str, new_pw: &str) -> String {
    let (scheme, rest) = url.split_once("://").expect("url has a scheme");
    let (userinfo, hostpart) = rest.split_once('@').expect("url has userinfo");
    let user = userinfo.split_once(':').map(|(u, _)| u).unwrap_or(userinfo);
    format!("{scheme}://{user}:{new_pw}@{hostpart}")
}

async fn can_connect(url: &str) -> bool {
    // NOTE: PgPool::connect is lazy — it never touches the server. A
    // real authentication check must acquire a connection.
    match sqlx::PgPool::connect(url).await {
        Ok(pool) => pool.acquire().await.is_ok(),
        Err(_) => false,
    }
}

/// End-to-end: a role carrying the published default gets evicted back
/// to the environment secret by `rotate_app_role_passwords`.
#[tokio::test]
async fn rotation_evicts_published_default_passwords() {
    let core_owner_url = env("TINKER_CORE_OWNER_URL");
    let pii_owner_url = env("TINKER_PII_OWNER_URL");
    let core_app_url = env("TINKER_CORE_URL");
    let pii_app_url = env("TINKER_PII_URL");
    let core_owner = sqlx::PgPool::connect(&core_owner_url).await.unwrap();
    let pii_owner = sqlx::PgPool::connect(&pii_owner_url).await.unwrap();

    // Sanity: the environment secrets authenticate today.
    assert!(
        can_connect(&core_app_url).await,
        "env TINKER_CORE_URL must authenticate"
    );
    assert!(
        can_connect(&pii_app_url).await,
        "env TINKER_PII_URL must authenticate"
    );

    // Simulate the bad state: a deployment that ran the frozen 0001
    // migrations without the env bootstrap, leaving the published
    // defaults from the repo live on the roles.
    for (pool, role, dev_pw) in [
        (&core_owner, "tinker_app", "tinker_app_dev_pw"),
        (&pii_owner, "tinker_pii_app", "tinker_pii_app_dev_pw"),
    ] {
        sqlx::query(&format!(
            "ALTER ROLE {role} WITH PASSWORD '{}'",
            dev_pw.replace('\'', "''")
        ))
        .execute(pool)
        .await
        .unwrap();
    }
    let core_dev_url = with_password(&core_app_url, "tinker_app_dev_pw");
    let pii_dev_url = with_password(&pii_app_url, "tinker_pii_app_dev_pw");
    assert!(
        can_connect(&core_dev_url).await,
        "simulated bad state: published default must authenticate before rotation"
    );
    assert!(
        can_connect(&pii_dev_url).await,
        "simulated bad state: published PII default must authenticate before rotation"
    );

    // The fix: the repo's migration path rotates both roles from env.
    tinker_db::rotate_app_role_passwords(&core_owner, &pii_owner, &core_app_url, &pii_app_url)
        .await
        .unwrap();

    // Published defaults are dead; environment secrets work. The shared
    // cluster is left in the correct state.
    assert!(
        !can_connect(&core_dev_url).await,
        "tinker_app must not authenticate with the published default after rotation"
    );
    assert!(
        !can_connect(&pii_dev_url).await,
        "tinker_pii_app must not authenticate with the published default after rotation"
    );
    assert!(
        can_connect(&core_app_url).await,
        "env TINKER_CORE_URL must still authenticate after rotation"
    );
    assert!(
        can_connect(&pii_app_url).await,
        "env TINKER_PII_URL must still authenticate after rotation"
    );
}

/// Fail-closed: rotation refuses URLs with no password segment rather
/// than silently keeping whatever the role already has.
#[tokio::test]
async fn rotation_fails_closed_without_passwords() {
    let core_owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let pii_owner = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
        .await
        .unwrap();
    let err = tinker_db::rotate_app_role_passwords(
        &core_owner,
        &pii_owner,
        "postgres://tinker_app@127.0.0.1:5432/tinker_core",
        &env("TINKER_PII_URL"),
    )
    .await
    .expect_err("missing core app password must fail closed");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("TINKER_CORE_URL"),
        "error must name the offending URL, got: {msg}"
    );
}
