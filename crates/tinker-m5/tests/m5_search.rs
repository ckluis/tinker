//! M5 item 32: permission-aware message search.
//!
//! - Index-on-post: posting a message writes a `search_index` row with
//!   the body (+ thread subject) as `text_content`.
//! - Tenant isolation: org B never sees org A's hits.
//! - PII guard: `reject_pii` fails closed on `pii.*`/`secret.*` storage
//!   classes — the change is rejected and no row is written. (The write
//!   path's documented choice, STATUS.md item 32: index only under the
//!   non-PII class "text"; a rejected change skips indexing with a log
//!   line, never fails the post — the security invariant is that the
//!   index never receives PII plaintext, and a rejected change is never
//!   written.)
//! - Snippet masking: a caller whose field projection hides `body` gets
//!   the "▪▪▪" sentinel, never the raw text.

mod common;

use common::*;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::CoreDb;
use tinker_search::{IndexChange, NativeSearchBackend, SearchBackend};
use uuid::Uuid;

const BODY_TOKEN: &str = "quixotic zebra deadline";
const THREAD_SUBJECT: &str = "Searchable thread alpha";

/// Create a channel + thread + one message via the HTTP write path.
/// Returns (channel_id, thread_id, message_id).
async fn post_thread_message(env: &CommsEnv, actor: &ActorCtx, body: &str) -> (Uuid, Uuid, Uuid) {
    let (status, v) = post_json(
        &env.router,
        actor,
        "/api/comms/channels",
        &serde_json::json!({ "name": "search-chan", "kind": "channel" }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "channel: {v}");
    let channel_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

    let (status, v) = post_json(
        &env.router,
        actor,
        "/api/comms/threads",
        &serde_json::json!({ "channel_id": channel_id, "subject": THREAD_SUBJECT }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "thread: {v}");
    let thread_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

    let (status, v) = post_json(
        &env.router,
        actor,
        &format!("/api/comms/threads/{thread_id}/messages"),
        &serde_json::json!({ "body": body }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::CREATED, "message: {v}");
    let message_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    (channel_id, thread_id, message_id)
}

async fn grant_thread_read(env: &CommsEnv, org_id: Uuid, actor_id: Uuid) {
    let authorizer =
        tinker_identity::Authorizer::new(env.tenant_pool.clone(), env.system_pool.clone());
    authorizer
        .grant(
            org_id,
            actor_id,
            &tinker_auth::AuthzScope::Organization {
                organization_id: org_id,
            },
            "thread:read",
            None,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn posted_message_writes_search_index_row() {
    let env = setup().await;
    let (_c, _t, message_id) = post_thread_message(&env, &env.agent_a, BODY_TOKEN).await;

    let mut tx = tenant_tx(&env, &env.agent_a.tenant).await;
    let row: Option<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT text_content, field_versions FROM search_index
         WHERE organization_id=$1 AND record_id=$2",
    )
    .bind(env.org_a_id)
    .bind(message_id)
    .fetch_optional(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let (text, _versions) = row.expect("post must write a search_index row");
    assert!(
        text.contains(BODY_TOKEN),
        "indexed text must contain the body: {text}"
    );
    assert!(
        text.contains(THREAD_SUBJECT),
        "indexed text must contain the thread subject context: {text}"
    );
}

#[tokio::test]
async fn message_post_indexes_searchable_hit() {
    let env = setup().await;
    let (_c, thread_id, message_id) = post_thread_message(&env, &env.agent_a, BODY_TOKEN).await;

    let (status, hits) = get_json(&env.router, &env.agent_a, "/api/comms/search?q=quixotic").await;
    assert_eq!(status, axum::http::StatusCode::OK, "search: {hits}");
    let hits = hits.as_array().unwrap();
    assert_eq!(hits.len(), 1, "exactly one hit: {hits:?}");
    assert_eq!(
        hits[0]["message_id"].as_str().unwrap(),
        message_id.to_string()
    );
    assert_eq!(
        hits[0]["thread_id"].as_str().unwrap(),
        thread_id.to_string()
    );
    let snippet = hits[0]["snippet"].as_str().unwrap();
    assert!(
        snippet.contains("quixotic"),
        "snippet must contain the matched body text: {snippet}"
    );
    assert!(
        hits[0]["rank"].as_f64().unwrap() > 0.0,
        "native backend must rank the hit"
    );
}

#[tokio::test]
async fn search_matches_thread_subject_context() {
    let env = setup().await;
    let (_c, thread_id, _m) = post_thread_message(&env, &env.agent_a, BODY_TOKEN).await;

    // "Searchable" only appears in the thread subject, not the body.
    let (status, hits) =
        get_json(&env.router, &env.agent_a, "/api/comms/search?q=Searchable").await;
    assert_eq!(status, axum::http::StatusCode::OK, "search: {hits}");
    let hits = hits.as_array().unwrap();
    assert!(
        !hits.is_empty(),
        "subject context must make the message findable: {hits:?}"
    );
    for h in hits {
        assert_eq!(h["thread_id"].as_str().unwrap(), thread_id.to_string());
    }
}

#[tokio::test]
async fn search_never_surfaces_other_org_messages() {
    let env = setup().await;
    post_thread_message(&env, &env.agent_a, BODY_TOKEN).await;

    // Sanity: the org-A member finds it.
    let (status, hits) = get_json(&env.router, &env.agent_a, "/api/comms/search?q=quixotic").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(hits.as_array().unwrap().len(), 1);

    // Org-B operator with thread:read in org B: the endpoint serves org B,
    // which must contain zero hits for org A's corpus.
    grant_thread_read(&env, env.org_b_id, env.operator_b.actor_id).await;
    let (status, hits) =
        get_json(&env.router, &env.operator_b, "/api/comms/search?q=quixotic").await;
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "operator_b search: {hits}"
    );
    assert!(
        hits.as_array().unwrap().is_empty(),
        "org B must never see org A hits: {hits}"
    );
}

#[tokio::test]
async fn search_requires_thread_read_grant() {
    let env = setup().await;
    post_thread_message(&env, &env.agent_a, BODY_TOKEN).await;

    // nogrant_a is a member with no thread grants at all.
    let (status, _) = get_json(&env.router, &env.nogrant_a, "/api/comms/search?q=quixotic").await;
    assert_eq!(
        status,
        axum::http::StatusCode::FORBIDDEN,
        "search without thread:read must be forbidden"
    );
}

#[tokio::test]
async fn search_masks_body_for_restricted_viewer() {
    let env = setup().await;
    let (_c, _t, message_id) = post_thread_message(&env, &env.agent_a, BODY_TOKEN).await;

    // viewer_a's projection over comm_message allows only author_actor_id:
    // the body is a forbidden field for this caller.
    let (status, hits) = get_json(&env.router, &env.viewer_a, "/api/comms/search?q=quixotic").await;
    assert_eq!(status, axum::http::StatusCode::OK, "search: {hits}");
    let hits = hits.as_array().unwrap();
    assert_eq!(hits.len(), 1, "the hit exists; only the snippet is masked");
    assert_eq!(
        hits[0]["message_id"].as_str().unwrap(),
        message_id.to_string()
    );
    let snippet = hits[0]["snippet"].as_str().unwrap();
    assert_eq!(snippet, "▪▪▪", "forbidden body must render masked");
    assert!(
        !snippet.contains("quixotic"),
        "snippet must not leak the forbidden field value"
    );
}

#[tokio::test]
async fn search_empty_query_rejected() {
    let env = setup().await;
    let (status, _) = get_json(&env.router, &env.agent_a, "/api/comms/search?q=").await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_REQUEST,
        "empty query must be rejected"
    );
}

#[tokio::test]
async fn pii_storage_class_rejected_fail_closed() {
    let env = setup().await;
    let backend = NativeSearchBackend::new(CoreDb(env.tenant_pool.clone()));
    let ctx = TenantContext::new(
        OrganizationId(env.org_a_id),
        env.agent_a.actor_id,
        "m5-search-pii",
    );

    for class in ["pii.name", "secret.api_key", "PII.Email"] {
        let record_id = Uuid::now_v7();
        let change = IndexChange {
            object_id: env.installed.message_id,
            record_id,
            text: "should never be indexed".into(),
            field_versions: serde_json::json!({}),
            storage_classes: vec![class.into()],
        };
        backend
            .index_change(&ctx, &change)
            .await
            .expect_err(&format!("storage class {class} must be rejected"));

        // Fail-closed: the rejected change writes no row.
        let mut tx = tenant_tx(&env, &ctx).await;
        let found: Option<Uuid> = sqlx::query_scalar(
            "SELECT record_id FROM search_index WHERE organization_id=$1 AND record_id=$2",
        )
        .bind(env.org_a_id)
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert!(
            found.is_none(),
            "rejected PII change must not write a search_index row (class {class})"
        );
    }

    // The non-PII class the write path uses indexes normally.
    let record_id = Uuid::now_v7();
    backend
        .index_change(
            &ctx,
            &IndexChange {
                object_id: env.installed.message_id,
                record_id,
                text: "plain operational note".into(),
                field_versions: serde_json::json!({}),
                storage_classes: vec!["text".into()],
            },
        )
        .await
        .expect("text class must index");
    let mut tx = tenant_tx(&env, &ctx).await;
    let found: Option<String> = sqlx::query_scalar(
        "SELECT text_content FROM search_index WHERE organization_id=$1 AND record_id=$2",
    )
    .bind(env.org_a_id)
    .bind(record_id)
    .fetch_optional(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(found.as_deref(), Some("plain operational note"));
}
