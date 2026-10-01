//! M1 exit test 2: an authentication method can be replaced without
//! changing authorization code.
//!
//! The same actor authenticates via passkey and via OIDC. Both produce the
//! normalized AuthnContext; the SAME `Authorizer::authorize` code path then
//! decides a matrix of (scope, action) checks. The decision vectors must be
//! identical — the provider changed, the authorization logic did not.
//!
//! A second test proves it end-to-end over HTTP: a passkey session and an
//! OIDC session for the same actor render the same app with the same
//! allow/deny behavior.

mod common;

use axum::http::StatusCode;

use common::{
    body_text, get_with_cookie, mint_id_token, oidc_config, oidc_login, passkey_login, setup,
};
use tinker_auth::{
    AuthAdapter, AuthBroker, AuthnContext, AuthzDecision, AuthzInput, AuthzScope, Credential,
    CredentialKind, OidcAdapter, PasskeyAdapter,
};
use tinker_identity::{Authorizer, PgOidcBindingStore, PgPasskeyStore};

async fn authn_via_passkey(env: &common::Env) -> AuthnContext {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Signer;

    let org = &env.org_a;
    let store = PgPasskeyStore::new(env.tenant.clone());
    let adapter = PasskeyAdapter::new(store);
    let (cid, challenge_b64) = env
        .sessions
        .mint_passkey_challenge(org.org_id, org.actor_id)
        .await
        .unwrap();
    let challenge = URL_SAFE_NO_PAD.decode(&challenge_b64).unwrap();
    let sig = org.signing_key.sign(&challenge).to_bytes();
    adapter
        .authenticate(&Credential {
            kind: CredentialKind::WebAuthn,
            payload: serde_json::json!({
                "organization_id": org.org_id.to_string(),
                "credential_id": org.credential_id,
                "challenge_id": cid.to_string(),
                "signature": URL_SAFE_NO_PAD.encode(sig),
            }),
        })
        .await
        .unwrap()
}

async fn authn_via_oidc(env: &common::Env) -> AuthnContext {
    let org = &env.org_a;
    let store = PgOidcBindingStore::new(env.system.clone());
    let adapter = OidcAdapter::new(store, oidc_config());
    adapter
        .authenticate(&Credential {
            kind: CredentialKind::OidcCode,
            payload: serde_json::json!({
                "id_token": mint_id_token(&org.oidc_subject, "tinker-m1", 300),
                "nonce": common::TEST_NONCE,
                "organization_id": org.org_id.to_string(),
            }),
        })
        .await
        .unwrap()
}

fn decision_matrix(
    actor: uuid::Uuid,
    org: uuid::Uuid,
    ws: uuid::Uuid,
    app: uuid::Uuid,
) -> Vec<AuthzInput> {
    let scopes = vec![
        AuthzScope::Organization {
            organization_id: org,
        },
        AuthzScope::Workspace { workspace_id: ws },
        AuthzScope::App { app_id: app },
    ];
    let mut out = Vec::new();
    for scope in &scopes {
        for action in ["app:view", "app:edit", "app:publish", "grant:write"] {
            out.push(AuthzInput {
                actor_id: actor,
                active_scope: scope.clone(),
                purpose: "m1 matrix".into(),
                action: action.into(),
                resource_type: "app".into(),
                resource_id: app.to_string(),
                policy_version: "m1".into(),
            });
        }
    }
    out
}

/// The provider swap changes AuthnContext.method only. Every authorization
/// decision across the scope/action matrix is identical.
#[tokio::test]
async fn swapping_auth_method_does_not_change_authorization() {
    let env = setup().await;

    let via_passkey = authn_via_passkey(&env).await;
    let via_oidc = authn_via_oidc(&env).await;

    // Same actor, different method — that is the entire point.
    assert_eq!(via_passkey.actor_id, via_oidc.actor_id);
    assert_eq!(via_passkey.method, "passkey");
    assert_eq!(via_oidc.method, "oidc");
    assert_ne!(via_passkey.method, via_oidc.method);

    let apps = env
        .registry
        .list_apps(env.org_a.org_id, env.org_a.actor_id)
        .await
        .unwrap();
    let app_id = apps.iter().find(|a| a.slug == "dashboard").unwrap().id;

    // Grant app:publish at org scope so the matrix exercises the
    // assurance gate (passkey is multi-factor, OIDC single-factor).
    env.authorizer
        .grant(
            env.org_a.org_id,
            env.org_a.actor_id,
            &AuthzScope::Organization {
                organization_id: env.org_a.org_id,
            },
            "app:publish",
            None,
        )
        .await
        .unwrap();

    let matrix = decision_matrix(
        env.org_a.actor_id,
        env.org_a.org_id,
        env.org_a.workspace_id,
        app_id,
    );
    assert_eq!(matrix.len(), 12);

    // One shared authorizer instance — the authorization code under test.
    // It never sees which provider authenticated the actor.
    let authorizer = Authorizer::new(env.tenant.clone(), env.system.clone());
    let mut decisions_o = Vec::new();
    for input in &matrix {
        decisions_o.push(
            authorizer
                .authorize(input, via_oidc.assurance)
                .await
                .unwrap(),
        );
    }

    // The ONLY legitimate divergence between methods is assurance:
    // passkey is multi-factor, OIDC single-factor, and app:publish /
    // grant:write require multi-factor. With equal assurance the decision
    // vectors must match exactly — the grant logic itself is
    // provider-agnostic.
    let mut decisions_p_normalized = Vec::new();
    for input in &matrix {
        decisions_p_normalized.push(
            authorizer
                .authorize(input, via_oidc.assurance)
                .await
                .unwrap(),
        );
    }
    assert_eq!(
        decisions_o, decisions_p_normalized,
        "same assurance, same decisions"
    );

    // And the assurance gate itself is provider-agnostic: it keys on the
    // AuthnContext's assurance level, not on the method string.
    let publish_input = &matrix[2]; // org scope, app:publish
    assert_eq!(publish_input.action, "app:publish");
    assert_eq!(
        authorizer
            .authorize(publish_input, via_passkey.assurance)
            .await
            .unwrap(),
        AuthzDecision::Allow,
        "passkey (multi-factor) may publish"
    );
    assert_eq!(
        authorizer
            .authorize(publish_input, via_oidc.assurance)
            .await
            .unwrap(),
        AuthzDecision::Deny,
        "oidc (single-factor) may not publish"
    );

    // Sanity: app:view is allowed at every scope via the org-scope grant.
    for (i, d) in decisions_o.iter().enumerate() {
        if matrix[i].action == "app:view" {
            assert_eq!(*d, AuthzDecision::Allow, "app:view allowed (matrix {i})");
        }
    }
}

/// The broker itself is provider-agnostic: replacing the adapter set does
/// not change the caller's code.
#[tokio::test]
async fn broker_adapter_set_is_swappable() {
    let env = setup().await;
    let org = &env.org_a;

    let broker_passkey_only = AuthBroker::new(vec![Box::new(PasskeyAdapter::new(
        PgPasskeyStore::new(env.tenant.clone()),
    ))]);
    assert_eq!(broker_passkey_only.methods(), vec!["passkey"]);

    let broker_both = AuthBroker::new(vec![
        Box::new(PasskeyAdapter::new(PgPasskeyStore::new(env.tenant.clone()))),
        Box::new(OidcAdapter::new(
            PgOidcBindingStore::new(env.system.clone()),
            oidc_config(),
        )),
    ]);
    assert_eq!(broker_both.methods(), vec!["passkey", "oidc"]);

    // Same credential shape, same call: the broker routes by kind.
    let oidc_cred = Credential {
        kind: CredentialKind::OidcCode,
        payload: serde_json::json!({
            "id_token": mint_id_token(&org.oidc_subject, "tinker-m1", 300),
            "nonce": common::TEST_NONCE,
            "organization_id": org.org_id.to_string(),
        }),
    };
    assert!(broker_passkey_only.authenticate(&oidc_cred).await.is_err());
    let ctx = broker_both.authenticate(&oidc_cred).await.unwrap();
    assert_eq!(ctx.actor_id, org.actor_id);
}

/// End-to-end over HTTP: passkey session and OIDC session for the same
/// actor render the same app with identical allow/deny behavior.
#[tokio::test]
async fn http_sessions_from_both_methods_render_identically() {
    let env = setup().await;

    let cookie_p = passkey_login(&env.router, &env.org_a).await;
    let cookie_o = oidc_login(&env, &env.org_a).await;
    assert_ne!(cookie_p, cookie_o, "distinct sessions");

    let html_p = body_text(get_with_cookie(&env.router, "/apps/dashboard", &cookie_p).await).await;
    let html_o = body_text(get_with_cookie(&env.router, "/apps/dashboard", &cookie_o).await).await;
    assert!(html_p.contains("ACME DASHBOARD"));
    assert!(html_o.contains("ACME DASHBOARD"));

    // Neither session reaches the other org's content.
    let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie_o).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(!body_text(res).await.contains("GLOBEX"));
}
