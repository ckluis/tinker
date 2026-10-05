//! M1 exit test 1: one binary renders isolated app versions for two
//! organizations.
//!
//! The same router serves org A and org B. Each org sees only its own
//! published version; a session from one org cannot resolve the other's
//! apps at all (404, no existence oracle); publishing a new version in one
//! org does not disturb the other.

mod common;

use axum::http::StatusCode;

use common::{body_text, get_with_cookie, oidc_login, passkey_login, setup};

/// Two orgs, two sessions, two renders — fully isolated.
#[tokio::test]
async fn two_organizations_render_isolated_app_versions() {
    let env = setup().await;

    let cookie_a = passkey_login(&env.router, &env.org_a).await;
    let cookie_b = passkey_login(&env.router, &env.org_b).await;

    let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie_a).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html_a = body_text(res).await;
    assert!(
        html_a.contains("ACME DASHBOARD"),
        "org A sees its own content"
    );
    assert!(html_a.contains("$1.2M"));
    assert!(!html_a.contains("GLOBEX"), "org A sees none of org B");

    let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie_b).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html_b = body_text(res).await;
    assert!(
        html_b.contains("GLOBEX DASHBOARD"),
        "org B sees its own content"
    );
    assert!(html_b.contains("$9.9M"));
    assert!(!html_b.contains("ACME"), "org B sees none of org A");

    // Rendered pages carry the version marker and vendored (same-origin)
    // asset URLs — no CDN anywhere.
    assert!(html_a.contains("data-app-version=\"1\""));
    assert!(html_a.contains("/assets/tinker.js"));
    assert!(html_a.contains("/assets/datastar.js"));
    assert!(!html_a.contains("cdn.jsdelivr"));
    assert!(!html_a.contains("unpkg.com"));

    // All five M1 components are representable: the dashboard uses
    // rt-text, rt-stat, rt-grid. A form+select app renders too.
    let form_def = serde_json::json!({
        "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
        "components": [
            { "id": "pick", "type": "rt-select",
              "props": { "label": "Status", "options": ["open", "closed"] },
              "layout": { "x": 0, "y": 0, "w": 6, "h": 1 } },
            { "id": "edit", "type": "rt-form",
              "props": { "fields": [{ "name": "title", "label": "Title", "type": "text" }] },
              "layout": { "x": 0, "y": 1, "w": 6, "h": 3 },
              "events": [{ "on": "submit", "action": "submitForm" }] },
        ],
    });
    let def: tinker_apps::AppDefinition = serde_json::from_value(form_def).unwrap();
    let app_id = env
        .registry
        .create_app(
            env.org_a.org_id,
            env.org_a.workspace_id,
            env.org_a.actor_id,
            "intake",
            "Intake",
        )
        .await
        .unwrap();
    let v = env
        .registry
        .save_draft(
            env.org_a.org_id,
            env.org_a.actor_id,
            app_id,
            &def,
            &serde_json::from_value(serde_json::json!({})).unwrap(),
        )
        .await
        .unwrap();
    env.registry
        .publish(env.org_a.org_id, env.org_a.actor_id, app_id, v)
        .await
        .unwrap();

    let res = get_with_cookie(&env.router, "/apps/intake", &cookie_a).await;
    assert_eq!(res.status(), StatusCode::OK);
    let html = body_text(res).await;
    assert!(html.contains("<rt-select"));
    assert!(html.contains("<rt-form"));
}

/// A session from org A cannot resolve org B's private app slug — 404,
// no existence oracle, no cross-tenant render.
#[tokio::test]
async fn cross_organization_app_slug_is_invisible() {
    let env = setup().await;

    // Only org B gets an app under this slug.
    let def: tinker_apps::AppDefinition = serde_json::from_value(serde_json::json!({
        "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
        "components": [
            { "id": "t", "type": "rt-text",
              "props": { "content": "B SECRET" },
              "layout": { "x": 0, "y": 0, "w": 12, "h": 1 } },
        ],
    }))
    .unwrap();
    let app_id = env
        .registry
        .create_app(
            env.org_b.org_id,
            env.org_b.workspace_id,
            env.org_b.actor_id,
            "b-secret",
            "B Secret",
        )
        .await
        .unwrap();
    let v = env
        .registry
        .save_draft(
            env.org_b.org_id,
            env.org_b.actor_id,
            app_id,
            &def,
            &serde_json::from_value(serde_json::json!({})).unwrap(),
        )
        .await
        .unwrap();
    env.registry
        .publish(env.org_b.org_id, env.org_b.actor_id, app_id, v)
        .await
        .unwrap();

    let cookie_a = passkey_login(&env.router, &env.org_a).await;
    let res = get_with_cookie(&env.router, "/apps/b-secret", &cookie_a).await;
    assert_eq!(res.status(), StatusCode::NOT_FOUND);
    let html = body_text(res).await;
    assert!(!html.contains("B SECRET"));

    // Org B itself renders it fine.
    let cookie_b = oidc_login(&env, &env.org_b).await;
    let res = get_with_cookie(&env.router, "/apps/b-secret", &cookie_b).await;
    assert_eq!(res.status(), StatusCode::OK);
    assert!(body_text(res).await.contains("B SECRET"));
}

/// Publishing a new version in org A changes org A's render and leaves
/// org B pinned to its own version.
#[tokio::test]
async fn version_publish_is_per_organization() {
    let env = setup().await;

    let apps = env
        .registry
        .list_apps(env.org_a.org_id, env.org_a.actor_id)
        .await
        .unwrap();
    let app_id = apps.iter().find(|a| a.slug == "dashboard").unwrap().id;

    let def: tinker_apps::AppDefinition = serde_json::from_value(serde_json::json!({
        "layout": { "type": "grid", "columns": 12, "rowHeight": 48, "gap": 12 },
        "components": [
            { "id": "title", "type": "rt-text",
              "props": { "content": "ACME DASHBOARD v2" },
              "layout": { "x": 0, "y": 0, "w": 12, "h": 1 } },
        ],
    }))
    .unwrap();
    let v2 = env
        .registry
        .save_draft(
            env.org_a.org_id,
            env.org_a.actor_id,
            app_id,
            &def,
            &serde_json::from_value(serde_json::json!({})).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(v2, 2);
    env.registry
        .publish(env.org_a.org_id, env.org_a.actor_id, app_id, v2)
        .await
        .unwrap();

    let cookie_a = passkey_login(&env.router, &env.org_a).await;
    let html_a = body_text(get_with_cookie(&env.router, "/apps/dashboard", &cookie_a).await).await;
    assert!(html_a.contains("ACME DASHBOARD v2"));
    assert!(html_a.contains("data-app-version=\"2\""));

    let cookie_b = passkey_login(&env.router, &env.org_b).await;
    let html_b = body_text(get_with_cookie(&env.router, "/apps/dashboard", &cookie_b).await).await;
    assert!(html_b.contains("GLOBEX DASHBOARD"));
    assert!(html_b.contains("data-app-version=\"1\""));
    assert!(!html_b.contains("ACME"));
}

/// Unauthenticated requests never reach app content.
#[tokio::test]
async fn anonymous_requests_are_redirected_to_login() {
    use axum::http::Request;
    use tower::ServiceExt;
    let env = setup().await;
    for uri in ["/apps/dashboard", "/apps"] {
        let res = env
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::SEE_OTHER, "{uri}");
        let loc = res.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(loc, "/login");
    }
}
