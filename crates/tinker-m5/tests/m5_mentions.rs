//! Item 31: @-mentions end-to-end through the real HTTP write path.
//!
//! Covered:
//! - SQL `normalize_actor_handle` matches the Rust twin.
//! - A mention of an org roster member routes a `"mention"` notification
//!   through the notify router (id-only payload, no body/PII).
//! - Unknown handles: post succeeds, no notification, no error leak.
//! - Cross-org handles: never resolve, never notify, no oracle.
//! - Self-mentions: never notify.
//! - Repeated/punctuated mentions dedupe to one notification.
//! - Routing respects the mentioned actor's prefs (off/digest/quiet).

mod common;

use common::*;
use tinker_comms::{NotificationRouter, PrefsInput, MENTION_KIND};
use tinker_core::handles::normalize_handle;
use tinker_core::TenantContext;
use tinker_db::CoreDb;
use uuid::Uuid;

async fn post_message(
    env: &CommsEnv,
    actor: &ActorCtx,
    thread_id: Uuid,
    body: &str,
) -> (axum::http::StatusCode, Uuid) {
    let (status, resp) = post_json(
        &env.router,
        actor,
        &format!("/api/comms/threads/{thread_id}/messages"),
        &serde_json::json!({ "body": body }),
    )
    .await;
    let id = resp["id"]
        .as_str()
        .unwrap_or("")
        .parse()
        .unwrap_or(Uuid::nil());
    (status, id)
}

/// Mention-notification outbox rows for `to_actor` in `ctx`'s org:
/// (row id, status, payload).
async fn mention_rows(
    env: &CommsEnv,
    ctx: &TenantContext,
    to_actor: Uuid,
) -> Vec<(Uuid, String, serde_json::Value)> {
    let mut tx = tenant_tx(env, ctx).await;
    let rows: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, status, payload_ref FROM delivery_outbox
         WHERE organization_id=$1
           AND payload_ref->>'to_actor'=$2
           AND payload_ref @> '{\"items\": [{\"kind\": \"mention\"}]}'",
    )
    .bind(ctx.organization_id.0)
    .bind(to_actor.to_string())
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    rows
}

fn mention_items(payload: &serde_json::Value) -> Vec<serde_json::Value> {
    payload["items"].as_array().cloned().unwrap_or_default()
}

fn router_for(env: &CommsEnv) -> NotificationRouter {
    NotificationRouter::new(CoreDb(env.tenant_pool.clone()))
}

#[tokio::test]
async fn sql_normalize_actor_handle_matches_rust() {
    let env = setup().await;
    let cases = [
        "Bob Smith",
        "  spaces  ",
        "UPPER_CASE.9-x",
        "a!!b",
        "---",
        "",
        "!!!",
        "éclair",
        "machine: backup",
        "@weird@",
        "trailing-",
    ];
    for raw in cases {
        let sql: String = sqlx::query_scalar("SELECT normalize_actor_handle($1)")
            .bind(raw)
            .fetch_one(&env.system_pool)
            .await
            .unwrap();
        assert_eq!(sql, normalize_handle(raw), "mismatch for {raw:?}");
    }
}

#[tokio::test]
async fn mention_notifies_org_member() {
    let env = setup().await;
    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, msg_id) =
        post_message(&env, &env.agent_a, thread_id, "@m5-a-viewer please review").await;
    assert_eq!(status, axum::http::StatusCode::CREATED);

    let rows = mention_rows(&env, &env.viewer_a.tenant, env.viewer_a.actor_id).await;
    assert_eq!(rows.len(), 1, "one mention notification for the viewer");
    let (_, status, payload) = &rows[0];
    assert_eq!(status, "queued");
    let items = mention_items(payload);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["kind"], MENTION_KIND);
    assert_eq!(items[0]["ref"], msg_id.to_string());
    assert_eq!(payload["to_actor"], env.viewer_a.actor_id.to_string());
}

#[tokio::test]
async fn mention_unknown_handle_posts_silently() {
    let env = setup().await;
    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, resp_id) = post_message(
        &env,
        &env.agent_a,
        thread_id,
        "ping @no-such-handle-xyz-123",
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    assert_ne!(resp_id, Uuid::nil());

    // No mention notification anywhere in org A.
    for actor in [&env.agent_a, &env.viewer_a, &env.admin_a, &env.nogrant_a] {
        let rows = mention_rows(&env, &actor.tenant, actor.actor_id).await;
        assert!(rows.is_empty(), "unknown handle notified {}", actor.handle);
    }
}

#[tokio::test]
async fn mention_cross_org_handle_never_resolves() {
    let env = setup().await;
    // Org B actor holding the SAME handle as org A's agent. Per-org
    // uniqueness allows this; tenant-scoped resolution must pick org A.
    let b_twin = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$4)",
    )
    .bind(b_twin)
    .bind(env.org_b_id)
    .bind("B twin")
    .bind("m5-a-agent")
    .execute(&env.system_pool)
    .await
    .unwrap();

    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, _) = post_message(&env, &env.admin_a, thread_id, "hello @m5-a-agent").await;
    assert_eq!(status, axum::http::StatusCode::CREATED);

    // Org A's agent got the mention...
    let rows = mention_rows(&env, &env.agent_a.tenant, env.agent_a.actor_id).await;
    assert_eq!(rows.len(), 1, "org-A holder of the handle is notified");
    // ...the org-B twin got nothing: no row anywhere names them.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM delivery_outbox WHERE payload_ref->>'to_actor'=$1",
    )
    .bind(b_twin.to_string())
    .fetch_one(&env.system_pool)
    .await
    .unwrap();
    assert_eq!(n, 0, "cross-org handle twin must never be notified");

    // A handle that exists ONLY in org B: silent, no leak, post succeeds.
    let (status, _) = post_message(&env, &env.admin_a, thread_id, "hello @m5-b-operator").await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    let n: i64 =
        sqlx::query_scalar("SELECT count(*) FROM delivery_outbox WHERE organization_id=$1")
            .bind(env.org_b_id)
            .fetch_one(&env.system_pool)
            .await
            .unwrap();
    assert_eq!(n, 0, "no outbox rows may land in org B from an org-A post");
}

#[tokio::test]
async fn mention_self_never_notifies() {
    let env = setup().await;
    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, _) = post_message(&env, &env.agent_a, thread_id, "@m5-a-agent I did this").await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    let rows = mention_rows(&env, &env.agent_a.tenant, env.agent_a.actor_id).await;
    assert!(rows.is_empty(), "self-mention must not notify");
}

#[tokio::test]
async fn mention_repeated_and_punctuation_dedupes() {
    let env = setup().await;
    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, _) = post_message(
        &env,
        &env.admin_a,
        thread_id,
        "@m5-a-viewer, ping @m5-a-viewer! Also (@m5-a-agent).",
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED);

    let viewer_rows = mention_rows(&env, &env.viewer_a.tenant, env.viewer_a.actor_id).await;
    assert_eq!(viewer_rows.len(), 1, "repeated mention dedupes to one row");
    assert_eq!(mention_items(&viewer_rows[0].2).len(), 1);
    let agent_rows = mention_rows(&env, &env.agent_a.tenant, env.agent_a.actor_id).await;
    assert_eq!(agent_rows.len(), 1, "trailing punctuation still resolves");
}

#[tokio::test]
async fn mention_respects_off_pref() {
    let env = setup().await;
    router_for(&env)
        .set_prefs(
            &env.viewer_a.tenant,
            env.viewer_a.actor_id,
            PrefsInput {
                mode: "off".into(),
                quiet_start: None,
                quiet_end: None,
                digest_window_minutes: None,
            },
        )
        .await
        .unwrap();

    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, _) = post_message(&env, &env.agent_a, thread_id, "@m5-a-viewer hi").await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    let rows = mention_rows(&env, &env.viewer_a.tenant, env.viewer_a.actor_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "suppressed", "off pref suppresses the mention");
}

#[tokio::test]
async fn mention_respects_digest_pref() {
    let env = setup().await;
    router_for(&env)
        .set_prefs(
            &env.viewer_a.tenant,
            env.viewer_a.actor_id,
            PrefsInput {
                mode: "digest".into(),
                quiet_start: None,
                quiet_end: None,
                digest_window_minutes: Some(60),
            },
        )
        .await
        .unwrap();

    let (_ch, thread_id, _) = seed_thread(&env).await;
    for body in ["@m5-a-viewer one", "@m5-a-viewer two"] {
        let (status, _) = post_message(&env, &env.agent_a, thread_id, body).await;
        assert_eq!(status, axum::http::StatusCode::CREATED);
    }
    let rows = mention_rows(&env, &env.viewer_a.tenant, env.viewer_a.actor_id).await;
    assert_eq!(rows.len(), 1, "digest batches both mentions into one row");
    assert_eq!(mention_items(&rows[0].2).len(), 2);
}

#[tokio::test]
async fn mention_respects_quiet_hours() {
    let env = setup().await;
    // A ±1h window around now: the post always lands inside it.
    let now = chrono::Utc::now();
    let fmt = |dt: chrono::DateTime<chrono::Utc>| dt.format("%H:%M:%S").to_string();
    router_for(&env)
        .set_prefs(
            &env.viewer_a.tenant,
            env.viewer_a.actor_id,
            PrefsInput {
                mode: "immediate".into(),
                quiet_start: Some(fmt(now - chrono::Duration::hours(1))),
                quiet_end: Some(fmt(now + chrono::Duration::hours(1))),
                digest_window_minutes: None,
            },
        )
        .await
        .unwrap();

    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, _) = post_message(&env, &env.agent_a, thread_id, "@m5-a-viewer hi").await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    let rows = mention_rows(&env, &env.viewer_a.tenant, env.viewer_a.actor_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "deferred", "quiet hours defer the mention");
}

#[tokio::test]
async fn mention_payload_carries_no_body_or_pii() {
    let env = setup().await;
    let (_ch, thread_id, _) = seed_thread(&env).await;
    let (status, _) = post_message(
        &env,
        &env.agent_a,
        thread_id,
        "zz-unique-body-qq @m5-a-viewer",
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED);
    let rows = mention_rows(&env, &env.viewer_a.tenant, env.viewer_a.actor_id).await;
    assert_eq!(rows.len(), 1);
    let text = serde_json::to_string(&rows[0].2).unwrap();
    assert!(
        !text.contains("zz-unique-body-qq"),
        "body must not leak into the payload"
    );
    assert!(
        !text.contains("m5-a-viewer"),
        "display name must not leak into the payload"
    );
}
