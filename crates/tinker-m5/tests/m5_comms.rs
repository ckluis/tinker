//! M5 exit, hardening, and security tests for native communications.
//!
//! Exit criteria under test:
//! - `thread_renders_clear_and_masked_cards`
//! - `interrupted_delivery_resumes_without_duplicates`

mod common;

use common::*;
use std::time::Duration;
use tinker_comms::delivery::{EnqueueRequest, FakeEmailProvider, FakeMode, SendReceipt};
use tinker_comms::{
    DeliveryWorker, NotificationItem, NotificationRouter, PrefsInput, RoutingOutcome,
};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::CoreDb;
use tinker_durable::DurableRuntime;
use tinker_vault::PiiProjector;
use uuid::Uuid;

fn ctx_for(_env: &CommsEnv, actor: &ActorCtx) -> TenantContext {
    actor.tenant.clone()
}

fn worker_for(env: &CommsEnv) -> DeliveryWorker {
    let core = CoreDb(env.tenant_pool.clone());
    let durable = DurableRuntime::new(core.clone(), env.system_pool.clone());
    let projector = PiiProjector::new(core.clone(), env.vault.clone());
    DeliveryWorker::new(core, durable, Some(projector))
}

fn card_uri(thread_id: Uuid) -> String {
    format!("/api/threads/{thread_id}/card")
}

// ---------------------------------------------------------------------------
// Exit: actor-parameterized thread cards
// ---------------------------------------------------------------------------

#[tokio::test]
async fn thread_renders_clear_and_masked_cards() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;

    // The author opts in to identity disclosure (account default).
    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        "/api/comms/disclosures",
        &serde_json::json!({
            "thread_id": null,
            "actor_id": env.agent_a.actor_id,
            "disclosed": true,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);

    // --- Clear card: the author (role "member", unrestricted) ---
    let (status, card) = get_json(&env.router, &env.agent_a, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "agent card: {card}");
    assert_eq!(card["subject"], "Launch plan");
    assert_eq!(card["messages"].as_array().unwrap().len(), 2);
    assert_eq!(card["messages"][0]["body"], "Ship it Friday");
    assert_eq!(card["messages"][0]["author"], env.agent_a.display_name);
    // The object ref unfurls with full fields for the unrestricted role.
    let unfurl = &card["messages"][1]["unfurls"][0];
    assert_eq!(unfurl["slug"], "comm_channel");
    assert_eq!(unfurl["fields"]["name"], "general");
    assert_eq!(unfurl["fields"]["kind"], "channel");

    // --- Masked card: the viewer (restricted projections) ---
    let (status, card) = get_json(&env.router, &env.viewer_a, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "viewer card: {card}");
    assert_eq!(
        card["subject"], "Launch plan",
        "subject is visible to viewer"
    );
    assert_eq!(
        card["messages"][0]["body"], "▪▪▪",
        "message body is masked for viewer"
    );
    assert_eq!(
        card["messages"][0]["author"], env.agent_a.display_name,
        "the author disclosed, so the viewer sees the name"
    );
    let unfurl = &card["messages"][1]["unfurls"][0];
    assert_eq!(unfurl["fields"]["name"], "general");
    assert!(
        unfurl["fields"].get("kind").is_none(),
        "fields outside the viewer projection are omitted, not leaked"
    );

    // --- Revocation: the author opts back out; handles are stable ---
    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        "/api/comms/disclosures",
        &serde_json::json!({
            "thread_id": null,
            "actor_id": env.agent_a.actor_id,
            "disclosed": false,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let (status, card) = get_json(&env.router, &env.viewer_a, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let author0 = card["messages"][0]["author"].as_str().unwrap();
    let author1 = card["messages"][1]["author"].as_str().unwrap();
    assert!(
        author0.starts_with("actor-"),
        "undisclosed author renders as a stable handle, got {author0}"
    );
    assert_eq!(author0, author1, "the handle is stable across messages");
}

// ---------------------------------------------------------------------------
// Exit: interrupted email/notification workflow resumes without duplicates
// ---------------------------------------------------------------------------

#[tokio::test]
async fn interrupted_delivery_resumes_without_duplicates() {
    let env = setup().await;
    let ctx = ctx_for(&env, &env.agent_a);
    let worker = worker_for(&env);
    let provider = FakeEmailProvider::new();

    // The email body lives sealed in the vault; the outbox holds only the
    // opaque ref. Plaintext never enters a core row.
    let secret = "Super secret body for m5-crash-1";
    let ref_id = env
        .vault
        .seal(&ctx, env.agent_a.actor_id, "delivery", secret)
        .await
        .unwrap();
    let core = CoreDb(env.tenant_pool.clone());
    let mut tx = core.tenant_tx(&ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state)
         VALUES ($1,$2,$3,'delivery','active')",
    )
    .bind(ref_id)
    .bind(ctx.organization_id.0)
    .bind(env.agent_a.actor_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let (id, created) = worker
        .enqueue(
            &ctx,
            EnqueueRequest {
                kind: "email",
                idempotency_key: "m5-crash-1".into(),
                payload: serde_json::json!({
                    "to_actor": env.agent_a.actor_id.to_string(),
                    "subject": "interrupted",
                    "vault_body_ref": ref_id.to_string(),
                }),
                status: "queued",
                deliver_after: None,
            },
        )
        .await
        .unwrap();
    assert!(created);

    // The worker crashes after the provider accepted the message (the
    // provider recorded it; the outbox never got its checkpoint).
    provider.set_mode(FakeMode::CrashAfterRecord);
    let err = worker.run_delivery(&ctx, id, &provider).await;
    assert!(err.is_err(), "the crash must surface");
    assert_eq!(provider.actual_sends(), 1);
    assert_eq!(worker.get(&ctx, id).await.unwrap().status, "failed");

    // A new worker resumes the same outbox row. Provider-side idempotency
    // on the idempotency key means the resume does NOT send twice.
    provider.set_mode(FakeMode::Normal);
    let receipt = worker.run_delivery(&ctx, id, &provider).await.unwrap();
    assert_eq!(receipt.provider_message_id, "fake-m5-crash-1");
    assert_eq!(
        provider.actual_sends(),
        1,
        "resume must not duplicate the provider-side delivery"
    );
    let done = worker.get(&ctx, id).await.unwrap();
    assert_eq!(done.status, "sent");
    assert_eq!(done.attempts, 2);
    // The provider received the vault-resolved body; the core row never
    // held it.
    assert_eq!(provider.body_for("m5-crash-1").as_deref(), Some(secret));
    let mut tx = tenant_tx(&env, &ctx).await;
    let raw: (String,) =
        sqlx::query_as("SELECT payload_ref::text FROM delivery_outbox WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert!(
        !raw.0.contains(secret),
        "plaintext must never land in the core outbox row"
    );

    // Exactly one outbox row exists for the key: no duplicate delivery row.
    let n: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM delivery_outbox WHERE organization_id=$1 AND idempotency_key='m5-crash-1'",
    )
    .bind(ctx.organization_id.0)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert_eq!(n.0, 1);
}

// ---------------------------------------------------------------------------
// Hardening: delivery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn duplicate_enqueue_returns_same_row() {
    let env = setup().await;
    let ctx = ctx_for(&env, &env.agent_a);
    let worker = worker_for(&env);
    let req = |key: &str| EnqueueRequest {
        kind: "notification",
        idempotency_key: key.into(),
        payload: serde_json::json!({"to_actor": env.agent_a.actor_id.to_string()}),
        status: "queued",
        deliver_after: None,
    };
    let (id1, created1) = worker.enqueue(&ctx, req("m5-dup-1")).await.unwrap();
    let (id2, created2) = worker.enqueue(&ctx, req("m5-dup-1")).await.unwrap();
    assert!(created1);
    assert!(!created2);
    assert_eq!(id1, id2, "duplicate enqueue collapses to the same row");
}

#[tokio::test]
async fn concurrent_claim_has_single_winner() {
    let env = setup().await;
    let ctx = ctx_for(&env, &env.agent_a);
    let worker = worker_for(&env);
    let (id, _) = worker
        .enqueue(
            &ctx,
            EnqueueRequest {
                kind: "notification",
                idempotency_key: "m5-race-1".into(),
                payload: serde_json::json!({}),
                status: "queued",
                deliver_after: None,
            },
        )
        .await
        .unwrap();
    let w2 = worker_for(&env);
    let (r1, r2) = tokio::join!(
        worker.claim(&ctx, id, Duration::from_secs(60)),
        w2.claim(&ctx, id, Duration::from_secs(60)),
    );
    let wins = [r1.is_ok(), r2.is_ok()].iter().filter(|&&x| x).count();
    assert_eq!(wins, 1, "exactly one worker wins the claim");
}

#[tokio::test]
async fn stale_lease_completion_is_fenced() {
    let env = setup().await;
    let ctx = ctx_for(&env, &env.agent_a);
    let worker = worker_for(&env);
    let (id, _) = worker
        .enqueue(
            &ctx,
            EnqueueRequest {
                kind: "notification",
                idempotency_key: "m5-fence-1".into(),
                payload: serde_json::json!({}),
                status: "queued",
                deliver_after: None,
            },
        )
        .await
        .unwrap();
    let c1 = worker
        .claim(&ctx, id, Duration::from_secs(60))
        .await
        .unwrap();
    // The lease expires while worker 1 is "dead".
    let mut txtx = tenant_tx(&env, &ctx).await;
    sqlx::query("UPDATE delivery_outbox SET lease_until = now() - interval '1 minute' WHERE id=$1")
        .bind(id)
        .execute(&mut *txtx)
        .await
        .unwrap();
    txtx.commit().await.unwrap();
    // Worker 2 takes over the stale lease.
    let w2 = worker_for(&env);
    let c2 = w2.claim(&ctx, id, Duration::from_secs(60)).await.unwrap();
    assert_ne!(c1.lease_token, c2.lease_token);
    // The stale worker's completion is fenced: 0 rows, typed error.
    let stale = worker
        .complete(
            &ctx,
            id,
            c1.lease_token,
            &SendReceipt {
                provider_message_id: "stale".into(),
            },
        )
        .await;
    assert!(stale.is_err(), "stale lease_token must not complete");
    // And its failure report is fenced too.
    assert!(worker
        .fail(&ctx, id, c1.lease_token, "stale")
        .await
        .is_err());
    // The lease holder completes fine.
    w2.complete(
        &ctx,
        id,
        c2.lease_token,
        &SendReceipt {
            provider_message_id: "fresh".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(worker.get(&ctx, id).await.unwrap().status, "sent");
}

// ---------------------------------------------------------------------------
// Hardening: routing
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_prefs_rejected() {
    let env = setup().await;
    let bad = [
        serde_json::json!({"mode": "sometimes"}),
        serde_json::json!({"mode": "immediate", "quiet_start": "22:00:00"}),
        serde_json::json!({"mode": "immediate", "quiet_start": "22:00:00", "quiet_end": "22:00:00"}),
        serde_json::json!({"mode": "digest", "digest_window_minutes": 0}),
        serde_json::json!({"mode": "digest", "digest_window_minutes": 9999}),
        serde_json::json!({"mode": "immediate", "quiet_start": "not-a-time", "quiet_end": "07:00:00"}),
    ];
    for b in bad {
        let (status, _) = put_json(&env.router, &env.agent_a, "/api/comms/prefs", &b).await;
        assert_eq!(
            status,
            axum::http::StatusCode::BAD_REQUEST,
            "malformed prefs must be rejected, never half-applied: {b}"
        );
    }
    // A valid write still works afterwards.
    let (status, _) = put_json(
        &env.router,
        &env.agent_a,
        "/api/comms/prefs",
        &serde_json::json!({"mode": "immediate"}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

#[tokio::test]
async fn quiet_hours_defer_on_fixed_clock() {
    let env = setup().await;
    let ctx = ctx_for(&env, &env.agent_a);
    let router = NotificationRouter::new(CoreDb(env.tenant_pool.clone()));
    let worker = worker_for(&env);
    router
        .set_prefs(
            &ctx,
            env.agent_a.actor_id,
            PrefsInput {
                mode: "immediate".into(),
                quiet_start: Some("22:00:00".into()),
                quiet_end: Some("07:00:00".into()),
                digest_window_minutes: None,
            },
        )
        .await
        .unwrap();

    let item = |_n: u32| NotificationItem {
        kind: "mention".into(),
        ref_id: Uuid::now_v7(),
    };
    let t = |h: u32, m: u32| {
        chrono::DateTime::parse_from_rfc3339(&format!("2026-06-01T{h:02}:{m:02}:00Z"))
            .unwrap()
            .with_timezone(&chrono::Utc)
    };

    // 23:00 UTC is inside the overnight window -> deferred to 07:00 next day.
    let out = router
        .route(&ctx, &worker, env.agent_a.actor_id, item(1), t(23, 0))
        .await
        .unwrap();
    let RoutingOutcome::Deferred(id) = out else {
        panic!("expected Deferred, got {out:?}")
    };
    let mut txtx = tenant_tx(&env, &ctx).await;
    let row: (String, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT status, deliver_after FROM delivery_outbox WHERE id=$1")
            .bind(id)
            .fetch_one(&mut *txtx)
            .await
            .unwrap();
    assert_eq!(row.0, "deferred");
    assert_eq!(row.1.unwrap().to_rfc3339(), "2026-06-02T07:00:00+00:00");

    // 06:30 is inside the window too -> deferred to 07:00 the same day.
    let out = router
        .route(&ctx, &worker, env.agent_a.actor_id, item(2), t(6, 30))
        .await
        .unwrap();
    assert!(matches!(out, RoutingOutcome::Deferred(_)));

    // Noon is outside the window -> queued immediately.
    let out = router
        .route(&ctx, &worker, env.agent_a.actor_id, item(3), t(12, 0))
        .await
        .unwrap();
    assert!(matches!(out, RoutingOutcome::Queued(_)));
}

#[tokio::test]
async fn digest_batches_into_one_delivery() {
    let env = setup().await;
    let ctx = ctx_for(&env, &env.agent_a);
    let router = NotificationRouter::new(CoreDb(env.tenant_pool.clone()));
    let worker = worker_for(&env);
    router
        .set_prefs(
            &ctx,
            env.agent_a.actor_id,
            PrefsInput {
                mode: "digest".into(),
                quiet_start: None,
                quiet_end: None,
                digest_window_minutes: Some(60),
            },
        )
        .await
        .unwrap();
    let t = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    };
    let item = || NotificationItem {
        kind: "mention".into(),
        ref_id: Uuid::now_v7(),
    };
    let out1 = router
        .route(
            &ctx,
            &worker,
            env.agent_a.actor_id,
            item(),
            t("2026-06-01T10:05:00Z"),
        )
        .await
        .unwrap();
    let out2 = router
        .route(
            &ctx,
            &worker,
            env.agent_a.actor_id,
            item(),
            t("2026-06-01T10:35:00Z"),
        )
        .await
        .unwrap();
    let (RoutingOutcome::Batched(id1), RoutingOutcome::Batched(id2)) = (out1, out2) else {
        panic!("expected two Batched outcomes")
    };
    assert_eq!(id1, id2, "same window batches into one delivery");
    let mut txtx = tenant_tx(&env, &ctx).await;
    let payload: (serde_json::Value,) =
        sqlx::query_as("SELECT payload_ref FROM delivery_outbox WHERE id=$1")
            .bind(id1)
            .fetch_one(&mut *txtx)
            .await
            .unwrap();
    assert_eq!(payload.0["items"].as_array().unwrap().len(), 2);
    // Next window -> a new delivery row.
    let out3 = router
        .route(
            &ctx,
            &worker,
            env.agent_a.actor_id,
            item(),
            t("2026-06-01T11:05:00Z"),
        )
        .await
        .unwrap();
    let RoutingOutcome::Batched(id3) = out3 else {
        panic!("expected Batched")
    };
    assert_ne!(id3, id1);
}

#[tokio::test]
async fn hostile_thread_ids_return_not_found() {
    let env = setup().await;
    // A real thread in the sibling org, created through the writer.
    let ctx_b = ctx_for(&env, &env.operator_b);
    let ch = env
        .state
        .comms
        .writer()
        .create_channel(&ctx_b, &env.installed, "b-secret", "channel")
        .await
        .unwrap();
    let sibling_thread = env
        .state
        .comms
        .writer()
        .create_thread(&ctx_b, &env.installed, ch, "B plans")
        .await
        .unwrap();

    // Sibling thread id through the card endpoint: 404, not 403 (no oracle).
    let (status, _) = get_json(&env.router, &env.agent_a, &card_uri(sibling_thread)).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    // Posting into a sibling thread: 404 as well.
    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        &format!("/api/comms/threads/{sibling_thread}/messages"),
        &serde_json::json!({"body": "x"}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    // A random id: 404.
    let (status, _) = get_json(&env.router, &env.agent_a, &card_uri(Uuid::now_v7())).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[tokio::test]
async fn card_endpoint_requires_grant() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;
    // No thread grants at all -> 403 on card and on write.
    let (status, _) = get_json(&env.router, &env.nogrant_a, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    let (status, _) = post_json(
        &env.router,
        &env.nogrant_a,
        &format!("/api/comms/threads/{thread_id}/messages"),
        &serde_json::json!({"body": "x"}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    // No session cookie -> redirected to login.
    let req = axum::http::Request::builder()
        .uri(card_uri(thread_id))
        .body(axum::body::Body::empty())
        .unwrap();
    let res = {
        use tower::ServiceExt;
        env.router.clone().oneshot(req).await.unwrap()
    };
    assert!(res.status().is_redirection(), "got {}", res.status());
}

#[tokio::test]
async fn comms_tables_are_tenant_isolated() {
    let env = setup().await;
    let ctx_a = ctx_for(&env, &env.agent_a);
    let ctx_b = ctx_for(&env, &env.operator_b);
    let core = CoreDb(env.tenant_pool.clone());

    // Seed org-A rows in every comms table.
    let ch = env
        .state
        .comms
        .writer()
        .create_channel(&ctx_a, &env.installed, "iso", "channel")
        .await
        .unwrap();
    let th = env
        .state
        .comms
        .writer()
        .create_thread(&ctx_a, &env.installed, ch, "iso thread")
        .await
        .unwrap();
    let worker = worker_for(&env);
    worker
        .enqueue(
            &ctx_a,
            EnqueueRequest {
                kind: "notification",
                idempotency_key: "m5-iso-1".into(),
                payload: serde_json::json!({}),
                status: "queued",
                deliver_after: None,
            },
        )
        .await
        .unwrap();
    let router = NotificationRouter::new(core.clone());
    router
        .set_prefs(
            &ctx_a,
            env.agent_a.actor_id,
            PrefsInput {
                mode: "off".into(),
                quiet_start: None,
                quiet_end: None,
                digest_window_minutes: None,
            },
        )
        .await
        .unwrap();
    tinker_comms::set_disclosure(
        &core,
        &ctx_a,
        Some(th),
        env.agent_a.actor_id,
        true,
        env.agent_a.actor_id,
    )
    .await
    .unwrap();
    insert_cross_plane_grant(
        &env,
        env.org_a_id,
        env.operator_b.actor_id,
        env.agent_a.actor_id,
        3600,
    )
    .await;

    // From org B's tenant context: every comms table reads empty ...
    let mut txb = core.tenant_tx(&ctx_b).await.unwrap();
    for table in [
        "delivery_outbox",
        "notification_prefs",
        "comm_identity_disclosures",
        "cross_plane_grants",
    ] {
        let n: (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&mut *txb)
            .await
            .unwrap();
        assert_eq!(n.0, 0, "{table} leaked across tenants");
    }
    for table in [
        env.installed.channel_table.as_str(),
        env.installed.thread_table.as_str(),
        env.installed.message_table.as_str(),
    ] {
        let n: (i64,) = sqlx::query_as(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&mut *txb)
            .await
            .unwrap();
        assert_eq!(n.0, 0, "{table} leaked across tenants");
    }
    // ... and hostile writes naming org A fail closed on the RLS check.
    let hostile = sqlx::query(
        "INSERT INTO delivery_outbox (organization_id, kind, idempotency_key, status)
         VALUES ($1,'email','m5-hostile','queued')",
    )
    .bind(env.org_a_id)
    .execute(&mut *txb)
    .await;
    assert!(
        hostile.is_err(),
        "hostile insert must fail the RLS WITH CHECK"
    );
    txb.rollback().await.unwrap();
}

#[tokio::test]
async fn realtime_envelopes_are_id_only() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;
    let mut rx = env.state.signals.subscribe(env.org_a_id).await;
    // Post through the writer (same shared bus the SSE endpoint reads).
    let ctx = ctx_for(&env, &env.agent_a);
    let mid = env
        .state
        .comms
        .writer()
        .post_message(
            &ctx,
            &env.installed,
            thread_id,
            env.agent_a.actor_id,
            "id only please",
        )
        .await
        .unwrap();
    let signal = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("signal should arrive")
        .unwrap();
    let json = serde_json::to_value(&signal).unwrap();
    assert_eq!(json["organization_id"], env.org_a_id.to_string());
    assert!(json["record_ids"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v.as_str() == Some(mid.to_string().as_str())));
    let serialized = serde_json::to_string(&json).unwrap();
    assert!(
        !serialized.contains("id only please"),
        "the envelope must carry ids only, never contents: {serialized}"
    );
}

#[tokio::test]
async fn cross_plane_grant_scoping_and_expiry() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;

    // Live grant: the org-B operator renders a masked card in org A.
    let grant_id = insert_cross_plane_grant(
        &env,
        env.org_a_id,
        env.operator_b.actor_id,
        env.agent_a.actor_id,
        3600,
    )
    .await;
    let (status, card) = get_json(&env.router, &env.operator_b, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK, "operator card: {card}");
    assert_eq!(card["subject"], "Launch plan");
    assert_eq!(
        card["messages"][0]["body"], "▪▪▪",
        "operator sees masked bodies"
    );

    // A sibling actor with no grant learns nothing: 404.
    let (status, _) = get_json(&env.router, &env.stranger_b, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    // A grant issued for org B does not authorize reads in org A.
    insert_cross_plane_grant(
        &env,
        env.org_b_id,
        env.stranger_b.actor_id,
        env.operator_b.actor_id,
        3600,
    )
    .await;
    let (status, _) = get_json(&env.router, &env.stranger_b, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    // Revocation takes effect immediately.
    tinker_comms::revoke_cross_plane_access(
        &CoreDb(env.tenant_pool.clone()),
        &TenantContext::new(
            OrganizationId(env.org_a_id),
            env.agent_a.actor_id,
            "m5-test",
        ),
        grant_id,
    )
    .await
    .unwrap();
    let (status, _) = get_json(&env.router, &env.operator_b, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);

    // Expiry takes effect without any revocation call.
    insert_cross_plane_grant(
        &env,
        env.org_a_id,
        env.operator_b.actor_id,
        env.agent_a.actor_id,
        2,
    )
    .await;
    let (status, _) = get_json(&env.router, &env.operator_b, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (status, _) = get_json(&env.router, &env.operator_b, &card_uri(thread_id)).await;
    assert_eq!(
        status,
        axum::http::StatusCode::NOT_FOUND,
        "expired grant must deny"
    );
}

#[tokio::test]
async fn cross_plane_grant_use_is_audit_logged() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;

    async fn use_count(env: &CommsEnv, org: Uuid) -> i64 {
        let n: (i64,) =
            sqlx::query_as("SELECT count(*) FROM cross_plane_grant_uses WHERE organization_id=$1")
                .bind(org)
                .fetch_one(&env.system_pool)
                .await
                .unwrap();
        n.0
    }

    // No grant: 404 and no audit rows.
    let (status, _) = get_json(&env.router, &env.operator_b, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(use_count(&env, env.org_a_id).await, 0);

    // Live grant: two cross-plane reads append exactly two audit rows.
    let grant_id = insert_cross_plane_grant(
        &env,
        env.org_a_id,
        env.operator_b.actor_id,
        env.agent_a.actor_id,
        3600,
    )
    .await;
    for _ in 0..2 {
        let (status, _) = get_json(&env.router, &env.operator_b, &card_uri(thread_id)).await;
        assert_eq!(status, axum::http::StatusCode::OK);
    }
    assert_eq!(use_count(&env, env.org_a_id).await, 2);

    // The grant list shows the grant with its use count; admin sees it.
    let (status, grants) = get_json(&env.router, &env.admin_a, "/api/comms/grants").await;
    assert_eq!(status, axum::http::StatusCode::OK, "grant list: {grants}");
    let g = grants
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"].as_str() == Some(grant_id.to_string().as_str()))
        .expect("issued grant is listed");
    assert_eq!(g["purpose"], "support");
    assert_eq!(g["grantee_actor_id"], env.operator_b.actor_id.to_string());
    assert_eq!(g["use_count"], 2);

    // The uses endpoint shows the two audited reads against this thread.
    let (status, uses) = get_json(
        &env.router,
        &env.admin_a,
        &format!("/api/comms/grants/{grant_id}/uses"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "grant uses: {uses}");
    let uses = uses.as_array().unwrap();
    assert_eq!(uses.len(), 2);
    for u in uses {
        assert_eq!(u["grant_id"], grant_id.to_string());
        assert_eq!(u["thread_id"], thread_id.to_string());
        assert_eq!(u["grantee_actor_id"], env.operator_b.actor_id.to_string());
    }

    // A plain member is not an auditor: 403 on both endpoints.
    let (status, _) = get_json(&env.router, &env.nogrant_a, "/api/comms/grants").await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);
    let (status, _) = get_json(
        &env.router,
        &env.nogrant_a,
        &format!("/api/comms/grants/{grant_id}/uses"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

    // A foreign grant id yields an empty list, never a cross-org peek.
    let (status, uses) = get_json(
        &env.router,
        &env.admin_a,
        &format!("/api/comms/grants/{}/uses", Uuid::now_v7()),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(uses.as_array().unwrap().is_empty());

    // Revoked grant: reads 404 again and the audit trail stops growing.
    tinker_comms::revoke_cross_plane_access(
        &CoreDb(env.tenant_pool.clone()),
        &TenantContext::new(
            OrganizationId(env.org_a_id),
            env.agent_a.actor_id,
            "m5-test",
        ),
        grant_id,
    )
    .await
    .unwrap();
    let (status, _) = get_json(&env.router, &env.operator_b, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    assert_eq!(use_count(&env, env.org_a_id).await, 2);

    // The revoked grant is still listed (audit history is not rewritten).
    let (status, grants) = get_json(&env.router, &env.admin_a, "/api/comms/grants").await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let g = grants
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"].as_str() == Some(grant_id.to_string().as_str()))
        .expect("revoked grant stays listed");
    assert!(g["revoked_at"].is_string(), "revocation is visible");
    assert_eq!(g["use_count"], 2);
}

#[tokio::test]
async fn identity_disclosure_default_optin_revocation() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;
    let core = CoreDb(env.tenant_pool.clone());
    let ctx_a = ctx_for(&env, &env.agent_a);

    // Default: undisclosed -> stable handle.
    let (status, card) = get_json(&env.router, &env.viewer_a, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(card["messages"][0]["author"]
        .as_str()
        .unwrap()
        .starts_with("actor-"));

    // Opt in via the endpoint (self) -> version 1, name visible.
    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        "/api/comms/disclosures",
        &serde_json::json!({
            "thread_id": null,
            "actor_id": env.agent_a.actor_id,
            "disclosed": true,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let mut txtx = tenant_tx(&env, &ctx_a).await;
    let v: (i32,) = sqlx::query_as(
        "SELECT version FROM comm_identity_disclosures WHERE organization_id=$1 AND actor_id=$2 ORDER BY version DESC LIMIT 1",
    )
    .bind(env.org_a_id)
    .bind(env.agent_a.actor_id)
    .fetch_one(&mut *txtx)
    .await
    .unwrap();
    assert_eq!(v.0, 1);
    let (status, card) = get_json(&env.router, &env.viewer_a, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(card["messages"][0]["author"], env.agent_a.display_name);

    // A non-admin cannot set another actor's disclosure.
    let (status, _) = post_json(
        &env.router,
        &env.viewer_a,
        "/api/comms/disclosures",
        &serde_json::json!({
            "thread_id": null,
            "actor_id": env.agent_a.actor_id,
            "disclosed": true,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

    // An admin can; revocation bumps the version and restores the handle.
    let (status, _) = post_json(
        &env.router,
        &env.admin_a,
        "/api/comms/disclosures",
        &serde_json::json!({
            "thread_id": null,
            "actor_id": env.agent_a.actor_id,
            "disclosed": false,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    let mut txtx = tenant_tx(&env, &ctx_a).await;
    let v: (i32,) = sqlx::query_as(
        "SELECT version FROM comm_identity_disclosures WHERE organization_id=$1 AND actor_id=$2 ORDER BY version DESC LIMIT 1",
    )
    .bind(env.org_a_id)
    .bind(env.agent_a.actor_id)
    .fetch_one(&mut *txtx)
    .await
    .unwrap();
    assert_eq!(v.0, 2, "revocation is a new version, not an overwrite");
    let (status, card) = get_json(&env.router, &env.viewer_a, &card_uri(thread_id)).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert!(card["messages"][0]["author"]
        .as_str()
        .unwrap()
        .starts_with("actor-"));
    // The direct API agrees with the rendered card.
    assert!(
        !tinker_comms::is_disclosed(&core, &ctx_a, Some(thread_id), env.agent_a.actor_id)
            .await
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// Hardening: concurrent disclosure writes serialize version allocation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn concurrent_disclosures_allocate_distinct_versions() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;
    let core = CoreDb(env.tenant_pool.clone());
    let ctx_a = ctx_for(&env, &env.agent_a);

    // Ten concurrent writers race on the same (org, thread, actor) slot.
    // Without serialization, MAX(version)+1 mints duplicate versions.
    let mut handles = Vec::new();
    for i in 0..10 {
        let core = core.clone();
        let ctx = ctx_a.clone();
        let actor = env.agent_a.actor_id;
        handles.push(tokio::spawn(async move {
            tinker_comms::set_disclosure(&core, &ctx, Some(thread_id), actor, i % 2 == 0, actor)
                .await
                .unwrap();
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let mut tx = tenant_tx(&env, &ctx_a).await;
    let versions: Vec<(i32,)> = sqlx::query_as(
        "SELECT version FROM comm_identity_disclosures
         WHERE organization_id=$1 AND thread_id=$2 AND actor_id=$3 ORDER BY version",
    )
    .bind(env.org_a_id)
    .bind(thread_id)
    .bind(env.agent_a.actor_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    let got: Vec<i32> = versions.into_iter().map(|(v,)| v).collect();
    assert_eq!(
        got,
        (1..=10).collect::<Vec<_>>(),
        "versions must be a contiguous 1..=10 with no duplicates or gaps"
    );
}

// ---------------------------------------------------------------------------
// Security: the outbox PII boundary rejects plaintext bodies
// ---------------------------------------------------------------------------

#[tokio::test]
async fn outbox_rejects_plaintext_body_payload() {
    let env = setup().await;
    let ctx = ctx_for(&env, &env.agent_a);
    let worker = worker_for(&env);
    let err = worker
        .enqueue(
            &ctx,
            EnqueueRequest {
                kind: "email",
                idempotency_key: "m5-pii-1".into(),
                payload: serde_json::json!({
                    "to_actor": env.agent_a.actor_id.to_string(),
                    "body": "this plaintext must never persist",
                }),
                status: "queued",
                deliver_after: None,
            },
        )
        .await
        .expect_err("plaintext body must be rejected");
    assert!(
        matches!(err, tinker_core::TinkerError::Validation(_)),
        "typed validation error, got: {err:?}"
    );
    // An opaque vault ref is the legitimate shape and is accepted.
    let (id, created) = worker
        .enqueue(
            &ctx,
            EnqueueRequest {
                kind: "email",
                idempotency_key: "m5-pii-2".into(),
                payload: serde_json::json!({
                    "to_actor": env.agent_a.actor_id.to_string(),
                    "vault_body_ref": uuid::Uuid::now_v7().to_string(),
                }),
                status: "queued",
                deliver_after: None,
            },
        )
        .await
        .unwrap();
    assert!(created);
    let _ = id;
}

// ---------------------------------------------------------------------------
// Security: disclosure for an unknown thread is rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn disclosure_rejects_unknown_thread() {
    let env = setup().await;
    let (_channel_id, thread_id, _) = seed_thread(&env).await;
    // A thread id that does not exist -> 404, no orphan row.
    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        "/api/comms/disclosures",
        &serde_json::json!({
            "thread_id": uuid::Uuid::now_v7(),
            "actor_id": env.agent_a.actor_id,
            "disclosed": true,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
    // A real thread is accepted.
    let (status, _) = post_json(
        &env.router,
        &env.agent_a,
        "/api/comms/disclosures",
        &serde_json::json!({
            "thread_id": thread_id,
            "actor_id": env.agent_a.actor_id,
            "disclosed": true,
        }),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
}

/// Concurrent comms installs converge: the installer is check-then-create
/// on global slugs, so without the session install lock two racing
/// installs could both observe a missing slug and one would fail with
/// "object slug already exists". All racers must succeed and resolve the
/// same object ids.
#[tokio::test]
async fn concurrent_comms_installs_converge() {
    let tenant_pool = sqlx::PgPool::connect(
        &std::env::var("TINKER_CORE_URL").expect("TINKER_CORE_URL must be set"),
    )
    .await
    .unwrap();
    let system_pool = sqlx::PgPool::connect(
        &std::env::var("TINKER_CORE_OWNER_URL").expect("TINKER_CORE_OWNER_URL must be set"),
    )
    .await
    .unwrap();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (tp, sp) = (tenant_pool.clone(), system_pool.clone());
            tokio::spawn(async move {
                let ontology =
                    tinker_ontology::Ontology::new(tinker_db::CoreDb(tp), tinker_db::OwnerDb(sp));
                tinker_comms::CommsInstaller::new(ontology).install().await
            })
        })
        .collect();
    let mut ids = Vec::new();
    for h in handles {
        let installed = h.await.unwrap().expect("concurrent install must succeed");
        ids.push((
            installed.channel_id,
            installed.thread_id,
            installed.message_id,
        ));
    }
    for triple in &ids[1..] {
        assert_eq!(
            *triple, ids[0],
            "all installs must resolve the same objects"
        );
    }
}
