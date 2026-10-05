//! Item 28: inbound machine credentials (API keys) — issuance,
//! verification, rotation, revocation, expiry, and the scope grammar.

use tinker_auth::apikey::{
    scope_allows, validate_scope, ApiKeyAdapter, MachineCredentialStore, KEY_SECRET_PREFIX,
};
use tinker_auth::{AuthAdapter, Credential, CredentialKind};
use tinker_core::TinkerError;
use tinker_db::OwnerDb;
use uuid::Uuid;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

async fn fixture() -> (MachineCredentialStore, Uuid) {
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let store = MachineCredentialStore::new(OwnerDb(owner_pool.clone()));
    let org_id = Uuid::now_v7();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("apikey-test-host")
        .execute(&owner_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("ak-{}", org_id.simple()))
        .bind("apikey test org")
        .execute(&owner_pool)
        .await
        .unwrap();
    (store, org_id)
}

fn scopes(csv: &str) -> Vec<String> {
    csv.split(',').map(|s| s.to_string()).collect()
}

#[tokio::test]
async fn issue_then_verify_round_trips() {
    let (store, org_id) = fixture().await;
    let issued = store
        .issue(
            org_id,
            "ci-runner",
            &scopes("mcp:tools,mcp:resources"),
            None,
            None,
        )
        .await
        .unwrap();
    assert!(issued.secret.starts_with(KEY_SECRET_PREFIX));
    assert_eq!(issued.credential.key_prefix.len(), 12);
    assert!(issued.credential.key_prefix.starts_with(KEY_SECRET_PREFIX));

    let v = store.verify(&issued.secret).await.unwrap();
    assert_eq!(v.id, issued.credential.id);
    assert_eq!(v.organization_id, org_id);
    assert_eq!(v.actor_id, issued.credential.actor_id);
    assert_eq!(v.scopes, scopes("mcp:tools,mcp:resources"));

    // last_used_at is stamped by verification.
    let listed = store.list(org_id).await.unwrap();
    let row = listed
        .iter()
        .find(|c| c.id == issued.credential.id)
        .unwrap();
    assert!(row.last_used_at.is_some());
    // …and the listing never carries key material.
}

#[tokio::test]
async fn issue_creates_machine_actor() {
    let (store, org_id) = fixture().await;
    let issued = store
        .issue(org_id, "agent-9", &scopes("mcp:tools"), None, None)
        .await
        .unwrap();
    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let kind: String = sqlx::query_scalar("SELECT kind FROM actors WHERE id = $1")
        .bind(issued.credential.actor_id)
        .fetch_one(&owner)
        .await
        .unwrap();
    assert_eq!(kind, "machine");
}

#[tokio::test]
async fn wrong_secret_unknown_prefix_and_malformed_all_unauthorized() {
    let (store, org_id) = fixture().await;
    let issued = store
        .issue(org_id, "k", &scopes("mcp:tools"), None, None)
        .await
        .unwrap();

    // Tampered last char: prefix matches, hash doesn't.
    // Flip based on the popped char itself so the tamper is deterministic:
    // checking the tail after pop() would inspect the second-to-last char
    // and could reconstruct the original secret (~1/64 flake).
    let mut bad = issued.secret.clone();
    let last = bad.pop().expect("issued secret is non-empty");
    bad.push(if last == 'A' { 'B' } else { 'A' });
    for candidate in [
        bad.as_str(),
        "tk_0000000000000000000000000000000000000000000",
        "not-a-key",
        "",
        "tk_short",
    ] {
        let err = store.verify(candidate).await.unwrap_err();
        assert!(
            matches!(err, TinkerError::Forbidden(_)),
            "expected Forbidden for {candidate:?}, got {err:?}"
        );
    }
}

#[tokio::test]
async fn revoked_key_stops_working() {
    let (store, org_id) = fixture().await;
    let issued = store
        .issue(org_id, "k", &scopes("mcp:tools"), None, None)
        .await
        .unwrap();
    store.verify(&issued.secret).await.unwrap();
    store.revoke(org_id, issued.credential.id).await.unwrap();
    // Revoke is idempotent.
    store.revoke(org_id, issued.credential.id).await.unwrap();
    let err = store.verify(&issued.secret).await.unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)));
}

#[tokio::test]
async fn expired_key_stops_working() {
    let (store, org_id) = fixture().await;
    // ttl_days = -1: already expired at issuance.
    let issued = store
        .issue(org_id, "k", &scopes("mcp:tools"), Some(-1), None)
        .await
        .unwrap();
    let err = store.verify(&issued.secret).await.unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)));
}

#[tokio::test]
async fn rotate_replaces_key_material_atomically() {
    let (store, org_id) = fixture().await;
    let issued = store
        .issue(org_id, "k", &scopes("mcp:tools"), None, None)
        .await
        .unwrap();
    let rotated = store.rotate(org_id, issued.credential.id).await.unwrap();
    assert_eq!(rotated.credential.id, issued.credential.id);
    assert_eq!(rotated.credential.actor_id, issued.credential.actor_id);
    assert_ne!(rotated.secret, issued.secret);

    // Old secret is dead, new one works.
    assert!(matches!(
        store.verify(&issued.secret).await.unwrap_err(),
        TinkerError::Forbidden(_)
    ));
    let v = store.verify(&rotated.secret).await.unwrap();
    assert_eq!(v.id, issued.credential.id);
}

#[tokio::test]
async fn rotate_unknown_id_is_not_found() {
    let (store, org_id) = fixture().await;
    let err = store.rotate(org_id, Uuid::now_v7()).await.unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));
}

#[tokio::test]
async fn issue_rejects_bad_scopes_and_empty_name() {
    let (store, org_id) = fixture().await;
    for bad in ["", "admin", "mcp:tool:", "mcp:tool:has space", "http:read"] {
        let err = store
            .issue(org_id, "k", &scopes(bad), None, None)
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)), "{bad}");
    }
    assert!(validate_scope("mcp:tools").is_ok());
    assert!(validate_scope("mcp:resources").is_ok());
    assert!(validate_scope("mcp:tool:read_virtual_file").is_ok());
    let err = store
        .issue(org_id, "  ", &scopes("mcp:tools"), None, None)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
    let err = store.issue(org_id, "k", &[], None, None).await.unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
}

#[tokio::test]
async fn scope_gate_matrix() {
    let tools = scopes("mcp:tools");
    let resources = scopes("mcp:resources");
    let one_tool = scopes("mcp:tool:read_virtual_file");

    assert!(scope_allows(&tools, "tools/list", None));
    assert!(scope_allows(
        &tools,
        "tools/call",
        Some("read_virtual_file")
    ));
    assert!(!scope_allows(&tools, "resources/read", None));

    assert!(scope_allows(&resources, "resources/list", None));
    assert!(scope_allows(&resources, "resources/read", None));
    assert!(!scope_allows(
        &resources,
        "tools/call",
        Some("read_virtual_file")
    ));

    assert!(scope_allows(&one_tool, "tools/list", None));
    assert!(scope_allows(
        &one_tool,
        "tools/call",
        Some("read_virtual_file")
    ));
    assert!(!scope_allows(
        &one_tool,
        "tools/call",
        Some("expand_context")
    ));

    // Auth-only methods need no scope.
    assert!(scope_allows(&[], "initialize", None));
    assert!(scope_allows(&[], "ping", None));
    // Unknown methods are never allowed.
    assert!(!scope_allows(&tools, "tools/delete", None));
}

#[tokio::test]
async fn adapter_normalizes_to_machine_context() {
    let (store, org_id) = fixture().await;
    let issued = store
        .issue(org_id, "k", &scopes("mcp:tools"), None, None)
        .await
        .unwrap();
    let adapter = ApiKeyAdapter::new(MachineCredentialStore::new(OwnerDb(
        sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
            .await
            .unwrap(),
    )));
    assert!(adapter.supports(&Credential {
        kind: CredentialKind::ApiKey,
        payload: serde_json::json!({}),
    }));
    assert!(!adapter.supports(&Credential {
        kind: CredentialKind::Password,
        payload: serde_json::json!({}),
    }));

    let ctx = adapter
        .authenticate(&Credential {
            kind: CredentialKind::ApiKey,
            payload: serde_json::json!({"api_key": issued.secret}),
        })
        .await
        .unwrap();
    assert_eq!(ctx.actor_id, issued.credential.actor_id);
    assert_eq!(ctx.principal_kind, tinker_auth::PrincipalKind::Machine);
    assert_eq!(ctx.organization_ids, vec![org_id]);
    assert_eq!(ctx.method, "api_key");
    assert_eq!(ctx.assurance, tinker_auth::AssuranceLevel::Token);

    let err = adapter
        .authenticate(&Credential {
            kind: CredentialKind::ApiKey,
            payload: serde_json::json!({"api_key": "tk_bogus"}),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)));
}

/// Item 30 (scale-out spike): machine credentials are Postgres-backed —
/// two "instances" (two separately-connected stores, no shared process
/// state) must see the same credential lifecycle.
#[tokio::test]
async fn machine_credentials_shared_across_instances() {
    let owner_a = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    // A second, independent pool = a second instance.
    let owner_b = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let store_a = MachineCredentialStore::new(OwnerDb(owner_a.clone()));
    let store_b = MachineCredentialStore::new(OwnerDb(owner_b.clone()));

    let org_id = Uuid::now_v7();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("scale-out-host")
        .execute(&owner_a)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("so-{}", org_id.simple()))
        .bind("scale-out org")
        .execute(&owner_a)
        .await
        .unwrap();

    // Issued on A...
    let issued = store_a
        .issue(org_id, "so-runner", &scopes("mcp:tools"), None, None)
        .await
        .unwrap();
    // ...verifies on B: no stickiness, no local state.
    let v = store_b.verify(&issued.secret).await.unwrap();
    assert_eq!(v.id, issued.credential.id);
    assert_eq!(v.organization_id, org_id);

    // Revoked on A...
    store_a.revoke(org_id, issued.credential.id).await.unwrap();
    // ...rejected on B.
    let err = store_b
        .verify(&issued.secret)
        .await
        .expect_err("revoked credential must not verify on another instance");
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "revoked verify must fail closed as Forbidden, got: {err}"
    );
}
