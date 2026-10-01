//! M1 hardening: sessions fail closed, challenges are single-use,
//! grants never cross organizations, published versions are immutable,
//! drafts are validated before they can publish.

mod common;

use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use common::{body_text, get_with_cookie, mint_id_token, passkey_login, setup};
use tinker_auth::{AuthzDecision, AuthzScope};

/// An expired session resolves to nothing — the request is bounced to
/// login, never served as anonymous.
#[tokio::test]
async fn expired_session_is_rejected() {
    let env = setup().await;
    let cookie = passkey_login(&env.router, &env.org_a).await;
    let session = env.sessions.load_session(&cookie).await.unwrap().unwrap();

    // Age only this test's session out (forced RLS: scoped tx required).
    let mut tx = common::scoped_tx(&env.system, env.org_a.org_id).await;
    sqlx::query!(
        "UPDATE sessions SET expires_at = now() - INTERVAL '1 second' WHERE id = $1",
        session.id
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert_eq!(res.headers().get("location").unwrap(), "/login");

    // And the session layer itself resolves it to None.
    assert!(env.sessions.load_session(&cookie).await.unwrap().is_none());
}

/// A revoked session (logout) is dead immediately.
#[tokio::test]
async fn revoked_session_is_rejected() {
    let env = setup().await;
    let cookie = passkey_login(&env.router, &env.org_a).await;

    // Log out through the real endpoint.
    let res = env
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .header(
                    header::COOKIE,
                    format!("{}={cookie}", tinker_web::SESSION_COOKIE),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SEE_OTHER);

    let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
}

/// A tampered cookie is not a session.
#[tokio::test]
async fn tampered_cookie_is_rejected() {
    let env = setup().await;
    let cookie = passkey_login(&env.router, &env.org_a).await;
    let mut bad = cookie.clone();
    bad.replace_range(0..4, "AAAA");
    assert_ne!(bad, cookie);

    let res = get_with_cookie(&env.router, "/apps/dashboard", &bad).await;
    assert_eq!(res.status(), StatusCode::SEE_OTHER);
    assert!(env.sessions.load_session(&bad).await.unwrap().is_none());
}

/// A passkey challenge is single-use: replaying the assertion fails.
#[tokio::test]
async fn passkey_challenge_replay_fails() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Signer;

    let env = setup().await;
    let org = &env.org_a;

    let start_body = serde_json::json!({
        "organization_id": org.org_id.to_string(),
        "actor_id": org.actor_id.to_string(),
    });
    let res = env
        .router
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
    let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
    let start: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let challenge = URL_SAFE_NO_PAD
        .decode(start["challenge"].as_str().unwrap())
        .unwrap();
    let sig = URL_SAFE_NO_PAD.encode(org.signing_key.sign(&challenge).to_bytes());

    let finish = || {
        let body = serde_json::json!({
            "organization_id": org.org_id.to_string(),
            "workspace_id": org.workspace_id.to_string(),
            "credential_id": org.credential_id,
            "challenge_id": start["challenge_id"].as_str().unwrap(),
            "signature": sig,
        });
        env.router.clone().oneshot(
            Request::builder()
                .method("POST")
                .uri("/login/passkey/finish")
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
    };
    let first = finish().await.unwrap();
    assert_eq!(first.status(), StatusCode::SEE_OTHER);
    let second = finish().await.unwrap();
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED, "replay rejected");
}

/// An OIDC token for the wrong audience, or expired, never authenticates.
#[tokio::test]
async fn oidc_token_abuse_fails_closed() {
    let env = setup().await;
    let org = &env.org_a;

    for (token, label) in [
        (
            mint_id_token(&org.oidc_subject, "wrong-audience", 300),
            "audience",
        ),
        // Well past jsonwebtoken's 60s clock-skew leeway.
        (
            mint_id_token(&org.oidc_subject, "tinker-m1", -3600),
            "expired",
        ),
        (
            mint_id_token("unknown-subject", "tinker-m1", 300),
            "unknown subject",
        ),
    ] {
        let body = serde_json::json!({
            "organization_id": org.org_id.to_string(),
            "workspace_id": org.workspace_id.to_string(),
            "id_token": token,
        });
        let res = env
            .router
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
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED, "{label}");
        assert!(
            res.headers().get(header::SET_COOKIE).is_none(),
            "{label}: no session"
        );
    }
}

/// A session minted for org A cannot be used to act in org B: the
/// AuthnContext's membership list gates session creation.
#[tokio::test]
async fn session_cannot_cross_organizations() {
    let env = setup().await;
    let cookie = passkey_login(&env.router, &env.org_a).await;
    let session = env.sessions.load_session(&cookie).await.unwrap().unwrap();
    assert_eq!(session.organization_id, env.org_a.org_id);

    // Direct attempt to mint a session for org B with A's identity.
    use tinker_auth::{AssuranceLevel, AuthnContext, PrincipalKind};
    let forged = AuthnContext {
        actor_id: env.org_a.actor_id,
        principal_kind: PrincipalKind::Human,
        organization_ids: vec![env.org_a.org_id], // not a member of B
        method: "passkey".into(),
        assurance: AssuranceLevel::MultiFactor,
        authenticated_at: chrono::Utc::now(),
        credential_id: "x".into(),
    };
    let err = env
        .sessions
        .create_session(&forged, env.org_b.org_id, env.org_b.workspace_id)
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::Forbidden(_)));
}

/// Grants never cross organizations: a grant issued in org A does not
/// authorize anything in org B.
#[tokio::test]
async fn grants_do_not_cross_organizations() {
    let env = setup().await;

    let apps_b = env
        .registry
        .list_apps(env.org_b.org_id, env.org_b.actor_id)
        .await
        .unwrap();
    let app_b = apps_b.iter().find(|a| a.slug == "dashboard").unwrap().id;

    let input = tinker_identity::authz_input(
        &env.sessions
            .load_session(&passkey_login(&env.router, &env.org_a).await)
            .await
            .unwrap()
            .unwrap(),
        AuthzScope::App { app_id: app_b },
        "app:view",
        "app",
        &app_b.to_string(),
        "cross-org probe",
    );
    // org_and_workspace_of_app resolves org B; the grant lookup runs in
    // org B's tenant context where actor A has no grants.
    let decision = env
        .authorizer
        .authorize(&input, tinker_auth::AssuranceLevel::MultiFactor)
        .await
        .unwrap();
    assert_eq!(decision, AuthzDecision::Deny);
}

/// A published version's definition is frozen by the database trigger.
#[tokio::test]
async fn published_version_is_immutable() {
    let env = setup().await;
    // Forced RLS: the UPDATE must run inside org A's tenant context, or it
    // matches zero rows and the trigger never fires.
    let mut tx = common::scoped_tx(&env.system, env.org_a.org_id).await;
    let err = sqlx::query!("UPDATE app_versions SET definition = '{}' WHERE status = 'published'")
        .execute(&mut *tx)
        .await
        .unwrap_err();
    tx.rollback().await.unwrap();
    let msg = err.to_string();
    assert!(msg.contains("immutable"), "unexpected error: {msg}");
}

/// Draft validation fails closed: unknown components, missing props, and
/// bad events never reach a publishable version.
#[tokio::test]
async fn draft_validation_rejects_bad_definitions() {
    let env = setup().await;
    let apps = env
        .registry
        .list_apps(env.org_a.org_id, env.org_a.actor_id)
        .await
        .unwrap();
    let app_id = apps.iter().find(|a| a.slug == "dashboard").unwrap().id;

    let bad_cases = vec![
        (
            "unknown component",
            serde_json::json!({
                "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
                "components": [
                    { "id": "x", "type": "rt-missile",
                      "props": {}, "layout": { "x": 0, "y": 0, "w": 1, "h": 1 } },
                ],
            }),
        ),
        (
            "missing required prop",
            serde_json::json!({
                "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
                "components": [
                    { "id": "x", "type": "rt-text",
                      "props": {}, "layout": { "x": 0, "y": 0, "w": 1, "h": 1 } },
                ],
            }),
        ),
        (
            "unknown event action",
            serde_json::json!({
                "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
                "components": [
                    { "id": "x", "type": "rt-select",
                      "props": { "label": "S", "options": [] },
                      "layout": { "x": 0, "y": 0, "w": 1, "h": 1 },
                      "events": [{ "on": "change", "action": "dropTables" }] },
                ],
            }),
        ),
        (
            "grid overflow",
            serde_json::json!({
                "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
                "components": [
                    { "id": "x", "type": "rt-text",
                      "props": { "content": "hi" },
                      "layout": { "x": 10, "y": 0, "w": 6, "h": 1 } },
                ],
            }),
        ),
    ];

    for (label, def_json) in bad_cases {
        let def: tinker_apps::AppDefinition = serde_json::from_value(def_json).unwrap();
        let err = env
            .registry
            .save_draft(
                env.org_a.org_id,
                env.org_a.actor_id,
                app_id,
                &def,
                &serde_json::from_value(serde_json::json!({})).unwrap(),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, tinker_core::TinkerError::Validation(_)),
            "{label}: {err:?}"
        );
    }
}

/// Without an app:view grant, rendering is 403 — the page exists but the
/// actor may not see it.
#[tokio::test]
async fn render_requires_app_view_grant() {
    let env = setup().await;

    // A second actor in org A with no grants (forced RLS: scoped tx).
    let actor2 = uuid::Uuid::now_v7();
    let mut tx = common::scoped_tx(&env.system, env.org_a.org_id).await;
    sqlx::query!(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, 'nog rants', 'nog-rants')",
        actor2,
        env.org_a.org_id
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query!(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, 'viewer')",
        actor2,
        env.org_a.org_id
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    env.sessions
        .enroll_passkey(
            env.org_a.org_id,
            actor2,
            &format!("cred-nogrants-{}", env.run),
            sk.verifying_key().to_bytes(),
        )
        .await
        .unwrap();
    let org2 = common::OrgCtx {
        org_id: env.org_a.org_id,
        workspace_id: env.org_a.workspace_id,
        actor_id: actor2,
        signing_key: sk,
        credential_id: format!("cred-nogrants-{}", env.run),
        oidc_subject: String::new(),
    };
    let cookie = passkey_login(&env.router, &org2).await;
    let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(!body_text(res).await.contains("ACME DASHBOARD"));
}

/// Concurrent challenge consumption: N racers, exactly one winner.
/// The atomic UPDATE ... WHERE consumed_at IS NULL is what makes this
/// hold; this test pins it.
#[tokio::test]
async fn concurrent_challenge_consumption_has_exactly_one_winner() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::Signer;

    let env = setup().await;
    let org = &env.org_a;

    let start_body = serde_json::json!({
        "organization_id": org.org_id.to_string(),
        "actor_id": org.actor_id.to_string(),
    });
    let res = env
        .router
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
    let bytes = axum::body::to_bytes(res.into_body(), 8192).await.unwrap();
    let start: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let challenge = URL_SAFE_NO_PAD
        .decode(start["challenge"].as_str().unwrap())
        .unwrap();
    let sig = URL_SAFE_NO_PAD.encode(org.signing_key.sign(&challenge).to_bytes());
    let challenge_id = start["challenge_id"].as_str().unwrap().to_string();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let router = env.router.clone();
        let org_id = org.org_id.to_string();
        let ws_id = org.workspace_id.to_string();
        let cred_id = org.credential_id.clone();
        let challenge_id = challenge_id.clone();
        let sig = sig.clone();
        handles.push(tokio::spawn(async move {
            let body = serde_json::json!({
                "organization_id": org_id,
                "workspace_id": ws_id,
                "credential_id": cred_id,
                "challenge_id": challenge_id,
                "signature": sig,
            });
            router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login/passkey/finish")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }));
    }
    let mut winners = 0;
    for h in handles {
        if h.await.unwrap() == StatusCode::SEE_OTHER {
            winners += 1;
        }
    }
    assert_eq!(winners, 1, "exactly one racer consumes the challenge");
}

/// Granting the same (actor, scope, action) twice leaves exactly one row —
/// the total unique index plus ON CONFLICT DO NOTHING.
#[tokio::test]
async fn duplicate_grant_is_idempotent() {
    let env = setup().await;
    let org = &env.org_a;
    let scope = AuthzScope::Organization {
        organization_id: org.org_id,
    };
    env.authorizer
        .grant(org.org_id, org.actor_id, &scope, "app:view", None)
        .await
        .unwrap();
    env.authorizer
        .grant(org.org_id, org.actor_id, &scope, "app:view", None)
        .await
        .unwrap();
    let mut tx = common::scoped_tx(&env.system, org.org_id).await;
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM grants WHERE organization_id = $1 AND actor_id = $2 AND action = 'app:view'",
    )
    .bind(org.org_id)
    .bind(org.actor_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 1, "duplicate grant did not create a second row");
}

/// An expired grant can be replaced: the old row is cleared and the new
/// grant authorizes.
#[tokio::test]
async fn expired_grant_can_be_replaced() {
    let env = setup().await;
    let org = &env.org_a;
    let scope = AuthzScope::Organization {
        organization_id: org.org_id,
    };
    // Plant an expired grant directly, on an action the fixture does not
    // grant (setup already grants live app:view).
    let mut tx = common::scoped_tx(&env.system, org.org_id).await;
    sqlx::query(
        "INSERT INTO grants (organization_id, actor_id, scope_type, scope_id, action, expires_at)
         VALUES ($1, $2, 'organization', NULL, 'app:edit', now() - interval '1 hour')",
    )
    .bind(org.org_id)
    .bind(org.actor_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Re-grant: the expired row is cleared, the live one inserted.
    env.authorizer
        .grant(org.org_id, org.actor_id, &scope, "app:edit", None)
        .await
        .unwrap();

    let session = env
        .sessions
        .load_session(&passkey_login(&env.router, org).await)
        .await
        .unwrap()
        .unwrap();
    let input = tinker_identity::authz_input(
        &session,
        AuthzScope::Organization {
            organization_id: org.org_id,
        },
        "app:edit",
        "app",
        "probe",
        "expired grant replacement",
    );
    let decision = env
        .authorizer
        .authorize(&input, tinker_auth::AssuranceLevel::SingleFactor)
        .await
        .unwrap();
    assert_eq!(decision, AuthzDecision::Allow);
}

/// A workspace from another org — or a random UUID — in the scope is
/// denied identically: no existence oracle distinguishes them.
#[tokio::test]
async fn foreign_workspace_scope_is_denied_without_oracle() {
    let env = setup().await;
    let org = &env.org_a;
    let session = env
        .sessions
        .load_session(&passkey_login(&env.router, org).await)
        .await
        .unwrap()
        .unwrap();

    for (workspace_id, label) in [
        (env.org_b.workspace_id, "sibling org workspace"),
        (uuid::Uuid::new_v4(), "random workspace"),
    ] {
        let input = tinker_identity::authz_input(
            &session,
            AuthzScope::Workspace { workspace_id },
            "app:view",
            "app",
            "probe",
            "foreign scope probe",
        );
        let decision = env
            .authorizer
            .authorize(&input, tinker_auth::AssuranceLevel::SingleFactor)
            .await
            .unwrap();
        assert_eq!(decision, AuthzDecision::Deny, "{label}");
    }
}

/// touch() extends a live session and returns false for dead ones —
/// revoked or expired — without error.
#[tokio::test]
async fn session_touch_extends_live_and_fails_on_dead() {
    let env = setup().await;
    let org = &env.org_a;
    let cookie = passkey_login(&env.router, org).await;
    let session = env.sessions.load_session(&cookie).await.unwrap().unwrap();
    let before = session.expires_at;
    assert!(env.sessions.touch(session.id).await.unwrap());
    let after = env.sessions.load_session(&cookie).await.unwrap().unwrap();
    assert!(after.expires_at >= before, "touch extends expiry");

    // Revoked: touch fails closed.
    env.sessions.revoke(session.id).await.unwrap();
    assert!(!env.sessions.touch(session.id).await.unwrap());

    // Expired: touch fails closed.
    let cookie2 = passkey_login(&env.router, org).await;
    let s2 = env.sessions.load_session(&cookie2).await.unwrap().unwrap();
    sqlx::query("UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE id = $1")
        .bind(s2.id)
        .execute(&env.system)
        .await
        .unwrap();
    assert!(!env.sessions.touch(s2.id).await.unwrap());
}

/// Composite tenant FKs: the database itself rejects a grant that pairs
/// org A's id with org B's actor — no application code involved.
#[tokio::test]
async fn composite_fk_rejects_cross_org_actor_reference() {
    let env = setup().await;
    let mut tx = common::scoped_tx(&env.system, env.org_a.org_id).await;
    let res = sqlx::query(
        "INSERT INTO grants (organization_id, actor_id, scope_type, scope_id, action)
         VALUES ($1, $2, 'organization', NULL, 'probe:composite-fk')",
    )
    .bind(env.org_a.org_id)
    .bind(env.org_b.actor_id)
    .execute(&mut *tx)
    .await;
    tx.rollback().await.unwrap();
    let err = res.expect_err("cross-org actor reference must fail");
    let db_err = err.as_database_error().expect("expected a database error");
    assert_eq!(
        db_err.code().as_deref(),
        Some("23503"),
        "foreign key violation, got: {db_err:?}"
    );
}
