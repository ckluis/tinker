//! M7 exit test: approval expiry and escalation.
//!
//! Pending approval requests used to live forever — a stale approval could
//! authorize a destructive or external action long after its context went
//! stale. This proves: requests carry a deadline, expired requests fail
//! closed on decide AND execute (never silently revivable), the sweeper
//! expires only stale-pending rows, stale-pending rows surface exactly
//! once through the escalation hook, and escalation never changes
//! decidability.

mod common;

use common::setup;
use std::time::Duration;
use tinker_agents::{ApprovalEngine, ApprovalPolicy};

fn payload() -> serde_json::Value {
    serde_json::json!({"to": "cfo@acme.example"})
}

/// Backdate a column on one approval row through a tenant transaction (the
/// table has forced RLS — the owner pool sees zero rows without the
/// app.organization_id setting), so tests don't sleep through real TTLs.
async fn backdate(env: &common::AgentEnv, id: uuid::Uuid, column: &str, ago: &str) {
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let n = sqlx::query(&format!(
        "UPDATE approval_requests SET {column} = now() - interval '{ago}' WHERE id = $1"
    ))
    .bind(id)
    .execute(&mut *tx)
    .await
    .unwrap()
    .rows_affected();
    tx.commit().await.unwrap();
    assert_eq!(n, 1, "backdate must hit exactly one row");
}

#[tokio::test]
async fn expired_request_cannot_be_decided_or_executed() {
    let env = setup().await;
    let approvals = ApprovalEngine::new(env.core.clone(), env.owner.clone());

    // TTL zero: the deadline is already past at insert time.
    let req = approvals
        .request_with_ttl(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-1",
            Duration::from_secs(0),
        )
        .await
        .unwrap();
    assert_eq!(req.status, "pending");
    assert!(req.expires_at.is_some());

    // Decide fails closed with the expired-specific error, and the row is
    // lazily transitioned to expired.
    let err = approvals
        .decide(&env.exec_ctx, req.id, true)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired"),
        "decide on expired request must say expired, got: {err}"
    );
    assert_eq!(
        approvals.get(&env.exec_ctx, req.id).await.unwrap().status,
        "expired"
    );

    // Execute fails closed too.
    let err = approvals
        .mark_executed(&env.exec_ctx, req.id)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired"),
        "execute on expired request must say expired, got: {err}"
    );
}

#[tokio::test]
async fn sweeper_expires_only_stale_pending_rows() {
    let env = setup().await;
    let approvals = ApprovalEngine::new(env.core.clone(), env.owner.clone());

    let stale1 = approvals
        .request_with_ttl(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-2",
            Duration::from_secs(0),
        )
        .await
        .unwrap();
    let stale2 = approvals
        .request_with_ttl(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-3",
            Duration::from_secs(0),
        )
        .await
        .unwrap();
    let fresh = approvals
        .request(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-4",
        )
        .await
        .unwrap();

    // One stale row is already decided — the sweeper must not touch it.
    approvals
        .decide(&env.exec_ctx, stale2.id, false)
        .await
        .unwrap_err();

    let n = approvals
        .expire_stale_approvals(&env.exec_ctx)
        .await
        .unwrap();
    assert_eq!(n, 1, "only the stale pending row expires");
    assert_eq!(
        approvals
            .get(&env.exec_ctx, stale1.id)
            .await
            .unwrap()
            .status,
        "expired"
    );
    assert_eq!(
        approvals.get(&env.exec_ctx, fresh.id).await.unwrap().status,
        "pending"
    );

    // Second sweep is a no-op.
    assert_eq!(
        approvals
            .expire_stale_approvals(&env.exec_ctx)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn approval_lapsing_between_decide_and_execute_fails_closed() {
    let env = setup().await;
    let approvals = ApprovalEngine::new(env.core.clone(), env.owner.clone());

    let req = approvals
        .request(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-5",
        )
        .await
        .unwrap();
    let approved = approvals.decide(&env.exec_ctx, req.id, true).await.unwrap();
    assert_eq!(approved.status, "approved");

    // The deadline passes after approval but before execution.
    backdate(&env, req.id, "expires_at", "1 hour").await;

    let err = approvals
        .mark_executed(&env.exec_ctx, req.id)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("expired"),
        "lapsed approval must not execute, got: {err}"
    );
    assert_eq!(
        approvals.get(&env.exec_ctx, req.id).await.unwrap().status,
        "expired"
    );
}

#[tokio::test]
async fn escalation_surfaces_stale_pending_exactly_once() {
    let env = setup().await;
    let approvals = ApprovalEngine::new(env.core.clone(), env.owner.clone());
    let threshold = Duration::from_secs(3600);

    let req = approvals
        .request(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-6",
        )
        .await
        .unwrap();

    // Fresh requests are not escalation-due.
    assert!(approvals
        .escalation_due(&env.exec_ctx, threshold)
        .await
        .unwrap()
        .is_empty());

    // Age it past the threshold.
    backdate(&env, req.id, "created_at", "2 hours").await;

    let due = approvals
        .escalation_due(&env.exec_ctx, threshold)
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].id, req.id);
    assert!(due[0].escalated_at.is_none());

    // The hook flags it; the returned rows are exactly what was announced.
    let flagged = approvals
        .mark_escalated(&env.exec_ctx, &[req.id])
        .await
        .unwrap();
    assert_eq!(flagged.len(), 1);
    assert!(flagged[0].escalated_at.is_some());

    // Surfaced exactly once.
    assert!(approvals
        .escalation_due(&env.exec_ctx, threshold)
        .await
        .unwrap()
        .is_empty());
    // Re-flagging is a no-op.
    assert!(approvals
        .mark_escalated(&env.exec_ctx, &[req.id])
        .await
        .unwrap()
        .is_empty());

    // Escalation never changes decidability.
    let decided = approvals.decide(&env.exec_ctx, req.id, true).await.unwrap();
    assert_eq!(decided.status, "approved");
}

#[tokio::test]
async fn idempotency_retry_of_expired_request_returns_expired_row() {
    let env = setup().await;
    let approvals = ApprovalEngine::new(env.core.clone(), env.owner.clone());

    let req = approvals
        .request_with_ttl(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-7",
            Duration::from_secs(0),
        )
        .await
        .unwrap();
    approvals
        .expire_stale_approvals(&env.exec_ctx)
        .await
        .unwrap();

    // Same key: the retry returns the same dead row — the caller sees
    // "expired" and queues a fresh request under a new key instead of
    // silently reviving the approval.
    let again = approvals
        .request_with_ttl(
            &env.exec_ctx,
            env.attachment_id,
            "email.create_draft",
            payload(),
            "expiry-key-7",
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
    assert_eq!(again.id, req.id);
    assert_eq!(again.status, "expired");
}

#[tokio::test]
async fn policy_parses_ttl_and_escalation_with_defaults() {
    let p = ApprovalPolicy::from_json(&serde_json::json!({}));
    assert_eq!(p.ttl_secs, 24 * 3600);
    assert_eq!(p.escalation_after_secs, 4 * 3600);
    assert!(!p.human_before_external_send);

    let p = ApprovalPolicy::from_json(&serde_json::json!({
        "human_before_external_send": true,
        "ttl_secs": 600,
        "escalation_after_secs": 60,
    }));
    assert!(p.human_before_external_send);
    assert_eq!(p.ttl_secs, 600);
    assert_eq!(p.escalation_after_secs, 60);
}
