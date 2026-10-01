//! M5 performance tripwires: delivery-claim batch and card unfurl.
//!
//! These are regression detectors, not benchmarks: they print timings and
//! fail only if the path becomes egregiously slow. No network; local
//! PostgreSQL only.

mod common;

use common::*;
use std::time::Instant;
use tinker_comms::delivery::EnqueueRequest;
use tinker_comms::DeliveryWorker;
use tinker_core::TenantContext;
use tinker_db::CoreDb;
use tinker_durable::DurableRuntime;

#[tokio::test]
async fn delivery_claim_tripwire() {
    let env = setup().await;
    let ctx = env.agent_a.tenant.clone();
    let core = CoreDb(env.tenant_pool.clone());
    let durable = DurableRuntime::new(core.clone(), env.system_pool.clone());
    let worker = DeliveryWorker::new(core, durable, None);

    const N: usize = 200;
    for i in 0..N {
        worker
            .enqueue(
                &ctx,
                EnqueueRequest {
                    kind: "notification",
                    idempotency_key: format!("m5-perf-claim-{i}"),
                    payload: serde_json::json!({}),
                    status: "queued",
                    deliver_after: None,
                },
            )
            .await
            .unwrap();
    }
    let mut txtx = tenant_tx(&env, &ctx).await;
    let ids: Vec<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM delivery_outbox WHERE organization_id=$1 AND idempotency_key LIKE 'm5-perf-claim-%'",
    )
    .bind(ctx.organization_id.0)
    .fetch_all(&mut *txtx)
    .await
    .unwrap();
    assert_eq!(ids.len(), N);

    let start = Instant::now();
    let mut claimed = 0;
    for (id,) in &ids {
        if worker
            .claim(&ctx, *id, std::time::Duration::from_secs(60))
            .await
            .is_ok()
        {
            claimed += 1;
        }
    }
    let ms = start.elapsed().as_millis();
    println!("m5-perf: claimed {claimed}/{N} deliveries in {ms}ms");
    assert_eq!(claimed, N);
    assert!(ms < 30_000, "claim tripwire: {N} claims took {ms}ms (>30s)");
}

#[tokio::test]
async fn card_unfurl_tripwire() {
    let env = setup().await;
    let ctx: TenantContext = env.agent_a.tenant.clone();

    let channel_id = env
        .state
        .comms
        .writer()
        .create_channel(&ctx, &env.installed, "perf", "channel")
        .await
        .unwrap();
    let thread_id = env
        .state
        .comms
        .writer()
        .create_thread(&ctx, &env.installed, channel_id, "perf thread")
        .await
        .unwrap();
    const N: usize = 50;
    for i in 0..N {
        env.state
            .comms
            .writer()
            .post_message(
                &ctx,
                &env.installed,
                thread_id,
                env.agent_a.actor_id,
                &format!("perf message {i} tinker:comm_channel:{channel_id}"),
            )
            .await
            .unwrap();
    }

    let start = Instant::now();
    let card = env
        .state
        .comms
        .renderer()
        .render_thread_card(
            &ctx,
            &env.installed,
            thread_id,
            env.agent_a.actor_id,
            "member",
        )
        .await
        .unwrap();
    let ms = start.elapsed().as_millis();
    println!("m5-perf: rendered card with {N} unfurled messages in {ms}ms");
    assert_eq!(card.messages.len(), N);
    assert_eq!(card.messages[0].unfurls.len(), 1);
    assert!(
        ms < 15_000,
        "card tripwire: {N}-message card took {ms}ms (>15s)"
    );
}
