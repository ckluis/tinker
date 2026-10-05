//! M4 schema-builder page: rendering, form actions, grant gates.

mod common;

use common::*;

async fn get_page(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
) -> (axum::http::StatusCode, String) {
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::COOKIE, &actor.cookie)
        .body(axum::body::Body::empty())
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

async fn post_form(
    router: &axum::Router,
    actor: &ActorCtx,
    uri: &str,
    body: &str,
) -> (axum::http::StatusCode, String) {
    use axum::http::{header, Request};
    use tower::ServiceExt;
    let req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(header::COOKIE, &actor.cookie)
        .body(axum::body::Body::from(body.to_string()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let loc = res
        .headers()
        .get("location")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default();
    (status, loc)
}

/// The builder page renders for a member (viewer mode) and a builder.
#[tokio::test]
async fn page_renders() {
    let env = setup().await;
    let (status, html) = get_page(&env.router, &env.member_a, "/schema").await;
    assert_eq!(status, 200);
    assert!(html.contains("Schema builder"), "page title");
    assert!(html.contains("viewer"), "member sees viewer mode");
    assert!(html.contains("crm_contact"), "object list");
    assert!(!html.contains("New draft"), "member gets no draft button");

    let (status, html) = get_page(&env.router, &env.builder_a, "/schema").await;
    assert_eq!(status, 200);
    assert!(html.contains("builder"), "builder sees builder mode");
}

/// Full lifecycle through the form endpoints: draft -> field -> canary ->
/// promote -> rollback, all as 303 redirects back to the builder.
#[tokio::test]
async fn form_lifecycle() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    let (status, loc) = post_form(
        &env.router,
        &env.builder_a,
        &format!("/schema/objects/{contact_id}/drafts"),
        "",
    )
    .await;
    assert_eq!(status, 303, "draft redirects");
    assert!(loc.contains(&format!("object={contact_id}")));
    let version = loc.split("version=").nth(1).unwrap().to_string();

    let (status, _) = post_form(
        &env.router,
        &env.builder_a,
        &format!("/schema/versions/{version}/fields"),
        "name=Nickname&api_name=nickname&label=Nickname&field_type=text",
    )
    .await;
    assert_eq!(status, 303, "add field redirects");

    let (status, loc) = post_form(
        &env.router,
        &env.builder_a,
        &format!("/schema/versions/{version}/canary"),
        "cohort=",
    )
    .await;
    assert_eq!(status, 303, "canary redirects: {loc}");

    // The version page now shows the canary chip and the evolved field.
    let (status, html) = get_page(
        &env.router,
        &env.builder_a,
        &format!("/schema?object={contact_id}&version={version}"),
    )
    .await;
    assert_eq!(status, 200);
    assert!(html.contains("canary"), "canary status chip");
    assert!(html.contains("nickname"), "evolved field listed");

    let (status, _) = post_form(
        &env.router,
        &env.builder_a,
        &format!("/schema/versions/{version}/promote"),
        "",
    )
    .await;
    assert_eq!(status, 303, "promote redirects");
    let (status, html) = get_page(
        &env.router,
        &env.builder_a,
        &format!("/schema?object={contact_id}&version={version}"),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        html.contains(">active<") || html.contains(" active"),
        "active chip"
    );

    let (status, _) = post_form(
        &env.router,
        &env.builder_a,
        &format!("/schema/versions/{version}/rollback"),
        "",
    )
    .await;
    assert_eq!(status, 303, "rollback redirects");
}

/// Form endpoints enforce the grant: members get 403 on every action.
#[tokio::test]
async fn form_grant_gate() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let (status, _) = post_form(
        &env.router,
        &env.member_a,
        &format!("/schema/objects/{contact_id}/drafts"),
        "",
    )
    .await;
    assert_eq!(status, 403, "member cannot draft via form");
    let (status, _) = post_form(
        &env.router,
        &env.member_a,
        &format!("/schema/versions/{}/promote", uuid::Uuid::now_v7()),
        "",
    )
    .await;
    assert_eq!(status, 403, "member cannot promote via form");
}

/// Cross-org object ids 404 on the page (no oracle, no leak).
#[tokio::test]
async fn page_cross_org_404() {
    let env = setup().await;
    let (status, _) = get_page(
        &env.router,
        &env.builder_a,
        &format!("/schema?object={}", uuid::Uuid::now_v7()),
    )
    .await;
    assert_eq!(status, 404);
}

/// Unauthenticated page access redirects to login (existing auth behavior).
#[tokio::test]
async fn page_requires_session() {
    let env = setup().await;
    use axum::http::Request;
    use tower::ServiceExt;
    let req = Request::builder()
        .method("GET")
        .uri("/schema")
        .body(axum::body::Body::empty())
        .unwrap();
    let res = env.router.clone().oneshot(req).await.unwrap();
    assert!(
        res.status() == 303 || res.status() == 401 || res.status() == 403,
        "no session fails closed: {}",
        res.status()
    );
}
