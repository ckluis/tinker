//! M8 exit tests: authority transfer and hardening.
//!
//! Direct from PRD v0.6 §44 and the M8 design:
//! 1. Cutover moves the Salesforce slice to Tinker-primary with evidence.
//! 2. Rollback restores mirror authority and routing.
//! 3. Retirement fails unless every required gate is genuinely present.
//! 4. External app/query/view/agent dependencies block retirement.
//! 5. Paired restore preserves valid references and fails closed for
//!    orphaned PII.
//! 6. Host/portfolio aggregates are structurally token-blind.
//! 7. Support is masked by default; reveal needs a different approver.
//! 8. Legal hold suspends core and PII retention deletion.
//! 9. Forced promotion health failure rolls back the active pointer.
//! 10. Sessions/cache traverse a Redis abstraction, not process-local truth.
//! 11. Replacement-dashboard and aggregate-query performance tripwires.
//!
//! Adversarial: illegal state jumps, retirement-gate bypass, orphan-PII
//! leak attempts, aggregate payload smuggling, unauthorized support
//! reveals, injection paths, cross-tenant paths.

mod common;

use bigdecimal::BigDecimal;
use chrono::{Duration, NaiveDate, Utc};
use common::*;
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Instant;
use tinker_transfer::host::MASK;
use tinker_transfer::sessions::SessionCache;
use tinker_transfer::{
    ActorMode, AggregateQuery, Authority, CutoverKind, DependencyScanner, InMemorySessionStore,
    PromotionResult, PromotionSoak, RefStatus, ReplacementDashboard, RestoreRehearsal,
    RetentionEngine, SessionStore, SupportEngine, Telemetry, TelemetryPoint, TransferEngine,
    TransferState,
};
use uuid::Uuid;

fn engines(env: &TransferEnv) -> (TransferEngine, DependencyScanner) {
    (
        TransferEngine::new(env.core.clone()),
        DependencyScanner::new(env.core.clone()),
    )
}

fn sync_health() -> tinker_transfer::SyncHealth {
    tinker_transfer::SyncHealth {
        system_key: "salesforce".to_string(),
        last_sync_at: Some(Utc::now()),
        lag_seconds: Some(12),
        errors_24h: 0,
        retries_24h: 1,
        reconciliation_drift: 0,
    }
}

/// Drive a system all the way to `retired` (helper for adversarial tests).
async fn to_retired(env: &TransferEnv) {
    let (eng, _) = engines(env);
    to_controlled(env).await;
    complete_run_with_evidence(env, CutoverKind::Cutover).await;
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "cutover")
        .await
        .unwrap();
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "drain")
        .await
        .unwrap();
    complete_run_with_evidence(env, CutoverKind::Retire).await;
    eng.remove_connector(&env.operator_ctx, env.system_id, env.operator_id)
        .await
        .unwrap();
    let st = eng
        .advance(&env.operator_ctx, env.system_id, env.operator_id, "retire")
        .await
        .unwrap();
    assert_eq!(st, TransferState::Retired);
}

// ---------------------------------------------------------------------------
// Exit 1: cutover moves authority to Tinker-primary with evidence.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cutover_moves_authority_with_evidence() {
    let env = setup().await;
    let (eng, _) = engines(&env);
    to_controlled(&env).await;

    // Authority starts external on the mirrored slice.
    let v1 = eng
        .set_authority(
            &env.operator_ctx,
            env.system_id,
            env.deal_object_id,
            &[
                ("amount".to_string(), Authority::External),
                ("stage".to_string(), Authority::External),
            ],
            env.operator_id,
        )
        .await
        .unwrap();
    assert_eq!(v1, 1);
    assert_eq!(
        eng.effective_authority(
            &env.operator_ctx,
            env.system_id,
            env.deal_object_id,
            "amount"
        )
        .await
        .unwrap(),
        Some(Authority::External)
    );

    // Evidence-backed cutover run, then the guarded step to primary.
    let run_id = complete_run_with_evidence(&env, CutoverKind::Cutover).await;
    let st = eng
        .advance(
            &env.operator_ctx,
            env.system_id,
            env.operator_id,
            "cutover complete",
        )
        .await
        .unwrap();
    assert_eq!(st, TransferState::Primary);

    // Flip authority to Tinker: version bumps, history preserved.
    let v2 = eng
        .set_authority(
            &env.operator_ctx,
            env.system_id,
            env.deal_object_id,
            &[("amount".to_string(), Authority::Tinker)],
            env.operator_id,
        )
        .await
        .unwrap();
    assert_eq!(v2, 2);
    assert_eq!(
        eng.effective_authority(
            &env.operator_ctx,
            env.system_id,
            env.deal_object_id,
            "amount"
        )
        .await
        .unwrap(),
        Some(Authority::Tinker)
    );
    // The untouched field stays external at the old version.
    assert_eq!(
        eng.effective_authority(
            &env.operator_ctx,
            env.system_id,
            env.deal_object_id,
            "stage"
        )
        .await
        .unwrap(),
        Some(Authority::External)
    );
    let (tinker, external) = eng
        .authority_split(&env.operator_ctx, env.system_id)
        .await
        .unwrap();
    assert_eq!((tinker, external), (1, 1));

    // History is append-only: two versions of `amount` exist.
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM authority_matrix
         WHERE organization_id = $1 AND system_id = $2
           AND object_id = $3 AND field_api_name = 'amount'",
    )
    .bind(env.org_id)
    .bind(env.system_id)
    .bind(env.deal_object_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 2, "authority history must be preserved");

    // The cutover run recorded real evidence for every gate item.
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    let (checklist,): (serde_json::Value,) =
        sqlx::query_as("SELECT checklist FROM cutover_runs WHERE id = $1")
            .bind(run_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    for item in [
        "export_verified",
        "rollback_procedure",
        "owner_signoff",
        "dependency_scan",
        "reconciliation_clean",
    ] {
        let ev = checklist
            .get(item)
            .and_then(|v| v.get("evidence"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(!ev.trim().is_empty(), "gate item {item} needs evidence");
    }
}

// ---------------------------------------------------------------------------
// Exit 2: rollback restores mirror authority and routing.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rollback_restores_mirror_with_evidence() {
    let env = setup().await;
    let (eng, _) = engines(&env);
    to_controlled(&env).await;
    complete_run_with_evidence(&env, CutoverKind::Cutover).await;
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "cutover")
        .await
        .unwrap();

    // Rollback needs its own evidence-backed run (plan + owner sign-off).
    complete_run_with_evidence(&env, CutoverKind::Rollback).await;
    let st = eng
        .rollback(
            &env.operator_ctx,
            env.system_id,
            env.operator_id,
            "reconciliation drift on retry queue",
        )
        .await
        .unwrap();
    assert_eq!(st, TransferState::Mirrored);

    // The connector is the writer again: still registered, state mirror.
    let (state, conn) = eng
        .state_of(&env.operator_ctx, env.system_id)
        .await
        .unwrap();
    assert_eq!(state, TransferState::Mirrored);
    assert_eq!(conn, "registered");

    // State history records both transitions (audit trail).
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    let (hist,): (serde_json::Value,) =
        sqlx::query_as("SELECT state_history FROM transfer_systems WHERE id = $1")
            .bind(env.system_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    let hist = hist.as_array().cloned().unwrap_or_default();
    let last = hist.last().cloned().unwrap_or_default();
    assert_eq!(last.get("to").and_then(|v| v.as_str()), Some("mirrored"));
}

// ---------------------------------------------------------------------------
// Exit 3: retirement requires the full gate, genuinely.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retire_requires_full_cutover_gate() {
    let env = setup().await;
    let (eng, _) = engines(&env);
    to_controlled(&env).await;
    complete_run_with_evidence(&env, CutoverKind::Cutover).await;
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "cutover")
        .await
        .unwrap();
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "drain")
        .await
        .unwrap();

    // A retire run with one missing gate item cannot complete.
    let run_id = eng
        .start_run(&env.operator_ctx, env.system_id, CutoverKind::Retire)
        .await
        .unwrap();
    for item in [
        "export_verified",
        "rollback_procedure",
        "owner_signoff",
        "dependency_scan",
    ] {
        eng.verify_checklist_item(
            &env.operator_ctx,
            run_id,
            item,
            env.operator_id,
            &format!("evidence for {item}"),
        )
        .await
        .unwrap();
    }
    assert!(
        eng.complete_run(&env.operator_ctx, run_id).await.is_err(),
        "retire must fail with reconciliation_clean missing"
    );
    // Unknown checklist keys are rejected, not silently absorbed.
    assert!(eng
        .verify_checklist_item(
            &env.operator_ctx,
            run_id,
            "executive_vibes",
            env.operator_id,
            "trust me"
        )
        .await
        .is_err());
    eng.verify_checklist_item(
        &env.operator_ctx,
        run_id,
        "reconciliation_clean",
        env.operator_id,
        "zero drift for 7 days, report #77",
    )
    .await
    .unwrap();
    eng.complete_run(&env.operator_ctx, run_id).await.unwrap();

    // The connector must be gone before the terminal step.
    assert!(
        eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "retire")
            .await
            .is_err(),
        "retire blocked while the connector is still registered"
    );
    eng.remove_connector(&env.operator_ctx, env.system_id, env.operator_id)
        .await
        .unwrap();
    let st = eng
        .advance(&env.operator_ctx, env.system_id, env.operator_id, "retire")
        .await
        .unwrap();
    assert_eq!(st, TransferState::Retired);

    // Retired is terminal: no transitions out.
    assert!(eng
        .advance(&env.operator_ctx, env.system_id, env.operator_id, "oops")
        .await
        .is_err());
    assert!(eng
        .rollback(&env.operator_ctx, env.system_id, env.operator_id, "oops")
        .await
        .is_err());
}

// ---------------------------------------------------------------------------
// Exit 4: external dependencies block retirement.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dependency_scan_blocks_retire_with_external_refs() {
    let env = setup().await;
    let (eng, scanner) = engines(&env);
    to_controlled(&env).await;
    complete_run_with_evidence(&env, CutoverKind::Cutover).await;
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "cutover")
        .await
        .unwrap();
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "drain")
        .await
        .unwrap();
    complete_run_with_evidence(&env, CutoverKind::Retire).await;
    eng.remove_connector(&env.operator_ctx, env.system_id, env.operator_id)
        .await
        .unwrap();

    // An app still reading the external system blocks retirement.
    scanner
        .record_edge(
            &env.operator_ctx,
            &tinker_transfer::DependencyEdge {
                source_kind: "app".to_string(),
                source_id: "pipeline-dashboard".to_string(),
                target_object_id: Some(env.deal_object_id),
                target_field_api: Some("amount".to_string()),
                edge_kind: "reads".to_string(),
                external_system_key: Some("salesforce".to_string()),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        scanner
            .external_ref_count(&env.operator_ctx, "salesforce")
            .await
            .unwrap(),
        1
    );
    assert!(
        eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "retire")
            .await
            .is_err(),
        "retirement must block on external dependency edges"
    );

    // Rewiring the app off the external system unblocks retirement.
    let removed = scanner
        .remove_source_edges(&env.operator_ctx, "app", "pipeline-dashboard")
        .await
        .unwrap();
    assert_eq!(removed, 1);
    let st = eng
        .advance(&env.operator_ctx, env.system_id, env.operator_id, "retire")
        .await
        .unwrap();
    assert_eq!(st, TransferState::Retired);
}

// ---------------------------------------------------------------------------
// Exit 5: paired restore preserves valid refs, fails closed on orphan PII.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paired_restore_preserves_valid_refs_without_leaking_orphaned_pii() {
    let env = setup().await;
    let rh = RestoreRehearsal::new(env.core.clone(), env.pii.clone());
    let key = b"m8-test-operator-key-must-stay-secret";
    let now = Utc::now();

    // Compatible windows: they overlap, and the PII window covers the
    // core reference watermark.
    let c_start = now - Duration::hours(2);
    let c_end = now - Duration::hours(1);
    let c_mark = now - Duration::minutes(90);
    let p_start = now - Duration::hours(3);
    let p_end = now;
    let p_mark = now - Duration::hours(1);
    let c_sig = RestoreRehearsal::sign_manifest(key, "core", &c_start, &c_end, &c_mark);
    let p_sig = RestoreRehearsal::sign_manifest(key, "pii", &p_start, &p_end, &p_mark);
    let c_id = rh
        .record_core_manifest(&env.operator_ctx, c_start, c_end, c_mark, &c_sig)
        .await
        .unwrap();
    let p_id = rh
        .record_pii_manifest(&env.operator_ctx, p_start, p_end, p_mark, &p_sig)
        .await
        .unwrap();

    let valid = seed_pii_value(&env).await;
    let orphan = Uuid::now_v7();
    let rep = rh
        .rehearse(&env.operator_ctx, key, c_id, p_id, &[valid, orphan])
        .await
        .unwrap();
    assert!(rep.compatible, "windows should be compatible");
    assert_eq!(rep.available, vec![valid]);
    assert_eq!(rep.orphans, vec![orphan]);

    // Fail-closed, directly: the orphan resolves as unavailable, and the
    // report carries only reference ids — no value bytes, no plaintext.
    assert_eq!(
        rh.resolve_ref(&env.operator_ctx, orphan).await.unwrap(),
        RefStatus::Unavailable
    );
    let report_json = serde_json::to_value(&rep).unwrap();
    assert!(report_json.get("ciphertext").is_none());
    assert!(report_json.get("plaintext").is_none());

    // Incompatible windows: PII window does not cover the core watermark.
    let c2_start = now - Duration::hours(10);
    let c2_end = now - Duration::hours(9);
    let c2_mark = now - Duration::hours(9) - Duration::minutes(30);
    let c2_sig = RestoreRehearsal::sign_manifest(key, "core", &c2_start, &c2_end, &c2_mark);
    let c2_id = rh
        .record_core_manifest(&env.operator_ctx, c2_start, c2_end, c2_mark, &c2_sig)
        .await
        .unwrap();
    let rep2 = rh
        .rehearse(&env.operator_ctx, key, c2_id, p_id, &[valid])
        .await
        .unwrap();
    assert!(
        !rep2.compatible,
        "restore must refuse windows that do not overlap/cover"
    );

    // A tampered signature is rejected before any reference is resolved.
    let bad_sig = "00".repeat(32);
    let c3_id = rh
        .record_core_manifest(&env.operator_ctx, c_start, c_end, c_mark, &bad_sig)
        .await
        .unwrap();
    assert!(
        rh.rehearse(&env.operator_ctx, key, c3_id, p_id, &[valid])
            .await
            .is_err(),
        "forged manifest signature must fail closed"
    );
    // A wrong operator key also fails verification.
    assert!(!RestoreRehearsal::verify_manifest(
        b"wrong-key",
        "core",
        &c_start,
        &c_end,
        &c_mark,
        &c_sig
    ));
}

// ---------------------------------------------------------------------------
// Exit 6: token-blind aggregates carry no payloads.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_blind_aggregates_carry_no_payloads() {
    let env = setup().await;
    let tel = Telemetry::new(env.core.clone());
    let day = NaiveDate::from_ymd_opt(2026, 9, 23).unwrap();

    // Attempt payload smuggling through dimensions: it lands in a
    // dimensions column, never in a payload column — because payload
    // columns do not exist.
    let point = |count: i64, sum: i64, dimensions: serde_json::Value| TelemetryPoint {
        host_id: env.host_id,
        day,
        metric_id: "msgs.sent".to_string(),
        count,
        sum: BigDecimal::from(sum),
        dimensions,
    };
    // Re-recording with the SAME dimensions upserts (sums); it never
    // stores a second payload row.
    let payload_dims = json!({"channel": "email", "note": "ssn 123-45-6789"});
    tel.record(&env.operator_ctx, &point(12, 3, payload_dims.clone()))
        .await
        .unwrap();

    // Schema-level proof: the table has no payload-capable columns.
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    let cols: Vec<(String, String)> = sqlx::query_as(
        "SELECT column_name, data_type FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'host_usage_daily'
         ORDER BY column_name",
    )
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let names: Vec<&str> = cols.iter().map(|(c, _)| c.as_str()).collect();
    for forbidden in [
        "body", "payload", "content", "prompt", "message", "email", "subject",
    ] {
        assert!(
            !names.contains(&forbidden),
            "host_usage_daily must not have a {forbidden} column"
        );
    }

    // Aggregate reads return counts only.
    let query = |org_filter: Option<Uuid>| AggregateQuery {
        host_id: env.host_id,
        org_filter,
        day_from: day,
        day_to: day,
        metric_ids: vec!["msgs.sent".to_string()],
    };
    let rows = tel
        .read_aggregates(&env.operator_ctx, ActorMode::Aggregate, &query(None))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].count_value, 12);
    assert_eq!(rows[0].sum_value, BigDecimal::from(3));
    // RLS is the backstop even for aggregate actors: only this org's rows.
    assert!(rows.iter().all(|r| r.organization_id == env.org_id));

    // Re-recording with the same dimensions upserts (sums); it never
    // stores a second payload row.
    tel.record(&env.operator_ctx, &point(3, 1, payload_dims.clone()))
        .await
        .unwrap();
    let rows = tel
        .read_aggregates(&env.operator_ctx, ActorMode::Aggregate, &query(None))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].count_value, 15);

    // Tenant actors cannot read another org's slice; support actors are
    // denied the aggregate table entirely (masked sessions instead).
    assert!(tel
        .read_aggregates(
            &env.operator_ctx,
            ActorMode::Tenant,
            &query(Some(Uuid::now_v7()))
        )
        .await
        .is_err());
    assert!(tel
        .read_aggregates(&env.operator_ctx, ActorMode::Support, &query(None))
        .await
        .is_err());
    // Dimensions must be a JSON object: arrays are not smuggled in.
    let bad = TelemetryPoint {
        metric_id: "x".to_string(),
        count: 1,
        sum: BigDecimal::from(1),
        dimensions: json!([1, 2, 3]),
        ..point(0, 0, json!({}))
    };
    assert!(tel.record(&env.operator_ctx, &bad).await.is_err());
}

// ---------------------------------------------------------------------------
// Exit 7: masked support sessions need second-party reveal approval.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn masked_support_session_requires_second_party_reveal() {
    let env = setup().await;
    let se = SupportEngine::new(env.core.clone());
    let mut classes = BTreeMap::new();
    classes.insert("email".to_string(), "restricted".to_string());
    classes.insert("name".to_string(), "operational".to_string());

    // TTL clamps: too short or effectively permanent sessions are refused.
    assert!(se
        .open_session(
            &env.support_ctx,
            env.support_id,
            env.host_id,
            &classes,
            "billing investigation",
            30,
        )
        .await
        .is_err());
    let sess = se
        .open_session(
            &env.support_ctx,
            env.support_id,
            env.host_id,
            &classes,
            "billing investigation #1234",
            3600,
        )
        .await
        .unwrap();

    let mut record = BTreeMap::new();
    record.insert("name".to_string(), json!("Ada"));
    record.insert("email".to_string(), json!("ada@example.com"));

    // Masked by default.
    let masked = se
        .masked_read(&env.support_ctx, sess, &record)
        .await
        .unwrap();
    assert_eq!(masked["name"], json!("Ada"));
    assert_eq!(masked["email"], json!(MASK));
    assert_ne!(masked["email"], json!("ada@example.com"));

    // The requester cannot approve their own reveal.
    let req = se
        .request_reveal(
            &env.support_ctx,
            sess,
            "email",
            "need to contact the customer",
        )
        .await
        .unwrap();
    assert!(
        se.decide_reveal(&env.support_ctx, req, true).await.is_err(),
        "self-approval must be forbidden"
    );

    // A different approver approves; the reveal unmasks exactly the target.
    se.decide_reveal(&env.approver_ctx, req, true)
        .await
        .unwrap();
    let revealed = se
        .revealed_read(&env.support_ctx, sess, req, &record)
        .await
        .unwrap();
    assert_eq!(revealed["email"], json!("ada@example.com"));
    assert_eq!(revealed["name"], json!("Ada"));

    // A denied reveal stays masked.
    let req2 = se
        .request_reveal(&env.support_ctx, sess, "email", "second attempt")
        .await
        .unwrap();
    se.decide_reveal(&env.approver_ctx, req2, false)
        .await
        .unwrap();
    assert!(
        se.revealed_read(&env.support_ctx, sess, req2, &record)
            .await
            .is_err(),
        "denied reveal must not unmask"
    );

    // Tenant-visible audit: open, request, approve, deny are all there.
    let trail = se.audit_trail(&env.operator_ctx, sess).await.unwrap();
    let actions: Vec<&str> = trail.iter().map(|(a, _, _)| a.as_str()).collect();
    for want in [
        "session.opened",
        "reveal.requested",
        "reveal.approved",
        "reveal.denied",
    ] {
        assert!(
            actions.contains(&want),
            "audit trail must contain {want}: {actions:?}"
        );
    }

    // Session binding: a second same-tenant support actor cannot use the
    // first actor's session — masked reads, reveal requests, and reveal
    // consumption are all bound to the opening support actor.
    assert!(
        se.masked_read(&env.support2_ctx, sess, &record)
            .await
            .is_err(),
        "second support actor must not read another's session"
    );
    assert!(
        se.request_reveal(&env.support2_ctx, sess, "email", "borrowed session")
            .await
            .is_err(),
        "second support actor must not request reveals on another's session"
    );
    assert!(
        se.revealed_read(&env.support2_ctx, sess, req, &record)
            .await
            .is_err(),
        "second support actor must not consume another's approved reveal"
    );

    // Revocation fails closed: reads stop immediately.
    se.revoke_session(&env.operator_ctx, sess).await.unwrap();
    assert!(
        se.masked_read(&env.support_ctx, sess, &record)
            .await
            .is_err(),
        "revoked session must fail closed"
    );
}

// ---------------------------------------------------------------------------
// Exit 8: legal hold suspends retention deletion (core and PII).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retention_legal_hold_suspends_deletion() {
    let env = setup().await;
    let re = RetentionEngine::new(env.core.clone(), env.pii.clone());

    // Plant an expired core row (60 days old, 30-day policy).
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO dependency_edges
             (organization_id, source_kind, source_id, edge_kind, created_at)
         VALUES ($1, 'app', 'old-app', 'reads', now() - interval '60 days')",
    )
    .bind(env.org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    re.set_policy(&env.operator_ctx, "dependency_edges", 30)
        .await
        .unwrap();
    let out = re
        .apply_core(
            &env.operator_ctx,
            "dependency_edges",
            "public.dependency_edges",
            "created_at",
            "organization_id",
        )
        .await
        .unwrap();
    assert_eq!(out.deleted, 1);
    assert!(!out.skipped_legal_hold);

    // With a legal hold, the same expired row survives.
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO dependency_edges
             (organization_id, source_kind, source_id, edge_kind, created_at)
         VALUES ($1, 'app', 'held-app', 'reads', now() - interval '60 days')",
    )
    .bind(env.org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    re.set_legal_hold(&env.operator_ctx, "dependency_edges", true)
        .await
        .unwrap();
    let out = re
        .apply_core(
            &env.operator_ctx,
            "dependency_edges",
            "public.dependency_edges",
            "created_at",
            "organization_id",
        )
        .await
        .unwrap();
    assert_eq!(out.deleted, 0);
    assert!(out.skipped_legal_hold);
    // Lifting the hold deletes it on the next run.
    re.set_legal_hold(&env.operator_ctx, "dependency_edges", false)
        .await
        .unwrap();
    let out = re
        .apply_core(
            &env.operator_ctx,
            "dependency_edges",
            "public.dependency_edges",
            "created_at",
            "organization_id",
        )
        .await
        .unwrap();
    assert_eq!(out.deleted, 1);

    // PII store: expired values are deleted unless held.
    let v1 = seed_pii_value(&env).await;
    let mut ptx = env.pii.tenant_tx(&env.operator_ctx).await.unwrap();
    sqlx::query(
        "UPDATE pii_values SET expires_at = now() - interval '1 day'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(env.org_id)
    .bind(v1)
    .execute(&mut *ptx)
    .await
    .unwrap();
    ptx.commit().await.unwrap();
    let out = re.apply_pii(&env.operator_ctx).await.unwrap();
    assert_eq!(out.deleted, 1);
    assert!(!out.skipped_legal_hold);

    let v2 = seed_pii_value(&env).await;
    let mut ptx = env.pii.tenant_tx(&env.operator_ctx).await.unwrap();
    sqlx::query(
        "UPDATE pii_values
         SET expires_at = now() - interval '1 day', legal_hold = true
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(env.org_id)
    .bind(v2)
    .execute(&mut *ptx)
    .await
    .unwrap();
    ptx.commit().await.unwrap();
    let out = re.apply_pii(&env.operator_ctx).await.unwrap();
    assert_eq!(out.deleted, 0);
    assert!(out.skipped_legal_hold);

    // Hostile identifiers never reach the statement.
    assert!(re
        .apply_core(
            &env.operator_ctx,
            "dependency_edges",
            "public.dependency_edges; DROP TABLE public.dependency_edges",
            "created_at",
            "organization_id",
        )
        .await
        .is_err());
}

// ---------------------------------------------------------------------------
// Exit 9: self-promotion soak rolls back on health-gate failure.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn self_promotion_soak_rolls_back_on_health_gate_failure() {
    let env = setup().await;
    let ps = PromotionSoak::new(env.core.clone());
    let def = |v: i64| json!({"version": v, "steps": ["compile", "fixtures"]});

    // Repeated promotions succeed and move the pointer.
    let v1 = ps
        .draft_version(&env.operator_ctx, "app", "dashboard", &def(1))
        .await
        .unwrap();
    let v2 = ps
        .draft_version(&env.operator_ctx, "app", "dashboard", &def(2))
        .await
        .unwrap();
    assert_eq!((v1, v2), (1, 2));
    let o1 = ps
        .promote(
            &env.operator_ctx,
            "app",
            "dashboard",
            v1,
            &json!({"compile": "ok", "fixtures": "ok"}),
            true,
        )
        .await
        .unwrap();
    assert_eq!(o1.result, PromotionResult::Promoted);
    assert_eq!(o1.active_pointer, 1);
    let o2 = ps
        .promote(
            &env.operator_ctx,
            "app",
            "dashboard",
            v2,
            &json!({"compile": "ok", "fixtures": "ok"}),
            true,
        )
        .await
        .unwrap();
    assert_eq!(o2.active_pointer, 2);

    // A forced health-gate failure rolls the pointer back automatically.
    let v3 = ps
        .draft_version(&env.operator_ctx, "app", "dashboard", &def(3))
        .await
        .unwrap();
    let o3 = ps
        .promote(
            &env.operator_ctx,
            "app",
            "dashboard",
            v3,
            &json!({"compile": "ok"}),
            false,
        )
        .await
        .unwrap();
    assert_eq!(o3.result, PromotionResult::RolledBack);
    assert_eq!(o3.active_pointer, 2);
    assert_eq!(
        ps.active_pointer(&env.operator_ctx, "app", "dashboard")
            .await
            .unwrap(),
        2
    );

    // History is immutable: three version rows, v3 marked rolled_back.
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version, status FROM release_versions
         WHERE organization_id = $1 AND definition_kind = 'app'
           AND definition_key = 'dashboard' ORDER BY version",
    )
    .bind(env.org_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        rows.iter()
            .map(|(v, s)| (*v, s.as_str()))
            .collect::<Vec<_>>(),
        vec![(1, "released"), (2, "released"), (3, "rolled_back")]
    );

    // Only drafts promote: re-promoting a released version fails.
    assert!(ps
        .promote(&env.operator_ctx, "app", "dashboard", v1, &json!({}), true)
        .await
        .is_err());
}

// ---------------------------------------------------------------------------
// Exit 10: sessions/cache go through the Redis trait (in-test fake).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn session_cache_path_is_redis_backed_behind_trait() {
    // Two handles over one backend = two instances behind one Redis.
    let a = InMemorySessionStore::new();
    let b = a.shared();
    let cache_a = SessionCache::new(a, "sess");
    let cache_b = SessionCache::new(b, "sess");

    cache_a
        .put_json("user:1", &json!({"name": "ada"}), 3600)
        .await
        .unwrap();
    // The second instance sees the first instance's write: nothing about
    // the session lives in process-local memory.
    assert_eq!(
        cache_b.get_json("user:1").await.unwrap(),
        Some(json!({"name": "ada"}))
    );
    cache_b.invalidate("user:1").await.unwrap();
    assert_eq!(cache_a.get_json("user:1").await.unwrap(), None);

    // TTL expiry fails closed through the trait.
    let store = InMemorySessionStore::new();
    store.set("k", b"v".to_vec(), 3600).await.unwrap();
    store.expire_now("k").await;
    assert_eq!(store.get("k").await.unwrap(), None);

    // Validation at the boundary: empty keys and oversized values.
    assert!(store.set("", b"v".to_vec(), 1).await.is_err());
    assert!(store
        .set("big", vec![0u8; 1024 * 1024 + 1], 1)
        .await
        .is_err());
}

// ---------------------------------------------------------------------------
// Exit 11: replacement-dashboard and aggregate-query perf tripwires.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dashboard_and_aggregate_perf_tripwires() {
    let env = setup().await;
    let dash = ReplacementDashboard::new(env.core.clone());
    let tel = Telemetry::new(env.core.clone());
    to_controlled(&env).await;

    let mut samples = Vec::new();
    for _ in 0..11 {
        let t = Instant::now();
        let rep = dash
            .report(&env.operator_ctx, env.system_id, sync_health())
            .await
            .unwrap();
        samples.push(t.elapsed());
        assert_eq!(rep.system_key, "salesforce");
    }
    samples.sort();
    let p50 = samples[samples.len() / 2];
    assert!(
        p50.as_millis() < 1000,
        "replacement dashboard p50 too slow: {p50:?}"
    );

    let day = NaiveDate::from_ymd_opt(2026, 9, 23).unwrap();
    tel.record(
        &env.operator_ctx,
        &TelemetryPoint {
            host_id: env.host_id,
            day,
            metric_id: "dash.probe".to_string(),
            count: 7,
            sum: BigDecimal::from(2),
            dimensions: json!({"panel": "sync"}),
        },
    )
    .await
    .unwrap();
    let mut samples = Vec::new();
    for _ in 0..11 {
        let t = Instant::now();
        tel.read_aggregates(
            &env.operator_ctx,
            ActorMode::Aggregate,
            &AggregateQuery {
                host_id: env.host_id,
                org_filter: None,
                day_from: day,
                day_to: day,
                metric_ids: vec!["dash.probe".to_string()],
            },
        )
        .await
        .unwrap();
        samples.push(t.elapsed());
    }
    samples.sort();
    let p50 = samples[samples.len() / 2];
    assert!(
        p50.as_millis() < 500,
        "token-blind aggregate query p50 too slow: {p50:?}"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: illegal state jumps are rejected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn illegal_state_jumps_rejected() {
    let env = setup().await;
    let (eng, _) = engines(&env);

    // Rollback is only defined from primary/draining.
    assert!(eng
        .rollback(&env.operator_ctx, env.system_id, env.operator_id, "x")
        .await
        .is_err());
    // Connector removal is only defined while draining.
    assert!(eng
        .remove_connector(&env.operator_ctx, env.system_id, env.operator_id)
        .await
        .is_err());
    // No skipping: the machine moves one step at a time.
    let st = eng
        .advance(&env.operator_ctx, env.system_id, env.operator_id, "one")
        .await
        .unwrap();
    assert_eq!(st, TransferState::Mirrored);
    let st = eng
        .advance(&env.operator_ctx, env.system_id, env.operator_id, "two")
        .await
        .unwrap();
    assert_eq!(st, TransferState::Augmented);

    // Retired is terminal for every operation (fresh system driven fully).
    let env2 = setup().await;
    let (eng2, _) = engines(&env2);
    to_retired(&env2).await;
    assert!(eng2
        .advance(&env2.operator_ctx, env2.system_id, env2.operator_id, "x")
        .await
        .is_err());
    assert!(eng2
        .rollback(&env2.operator_ctx, env2.system_id, env2.operator_id, "x")
        .await
        .is_err());
    assert!(
        eng2.set_authority(
            &env2.operator_ctx,
            env2.system_id,
            env2.deal_object_id,
            &[("amount".to_string(), Authority::Tinker)],
            env2.operator_id
        )
        .await
        .is_ok(),
        "authority history writes stay legal after retirement (audit), but no state moves"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: retirement-gate bypass attempts fail.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retirement_gate_bypass_attempts_fail() {
    let env = setup().await;
    let (eng, _) = engines(&env);
    to_controlled(&env).await;
    complete_run_with_evidence(&env, CutoverKind::Cutover).await;
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "cutover")
        .await
        .unwrap();
    eng.advance(&env.operator_ctx, env.system_id, env.operator_id, "drain")
        .await
        .unwrap();

    // A run can be failed; a failed run is frozen and cannot complete.
    let run_id = eng
        .start_run(&env.operator_ctx, env.system_id, CutoverKind::Retire)
        .await
        .unwrap();
    eng.fail_run(&env.operator_ctx, run_id, "operator aborted")
        .await
        .unwrap();
    assert!(
        eng.verify_checklist_item(
            &env.operator_ctx,
            run_id,
            "export_verified",
            env.operator_id,
            "late evidence"
        )
        .await
        .is_err(),
        "failed runs are frozen"
    );
    assert!(
        eng.complete_run(&env.operator_ctx, run_id).await.is_err(),
        "failed runs cannot complete"
    );

    // Advancing to primary without a completed cutover run is refused —
    // even with a *failed* cutover run on record.
    let env2 = setup().await;
    let (eng2, _) = engines(&env2);
    to_controlled(&env2).await;
    let bad_run = eng2
        .start_run(&env2.operator_ctx, env2.system_id, CutoverKind::Cutover)
        .await
        .unwrap();
    eng2.fail_run(&env2.operator_ctx, bad_run, "evidence rejected")
        .await
        .unwrap();
    assert!(
        eng2.advance(
            &env2.operator_ctx,
            env2.system_id,
            env2.operator_id,
            "cutover"
        )
        .await
        .is_err(),
        "a failed cutover run must not satisfy the primary gate"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: injection paths are bound, never interpolated.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn injection_paths_are_bound_never_interpolated() {
    let env = setup().await;
    let (eng, scanner) = engines(&env);
    let tel = Telemetry::new(env.core.clone());

    // Hostile system keys register literally; the table survives.
    let hostile = "sf'; DROP TABLE transfer_systems;--";
    let id = eng
        .register_system(&env.operator_ctx, hostile, "hostile")
        .await
        .unwrap();
    let (state, _) = eng.state_of(&env.operator_ctx, id).await.unwrap();
    assert_eq!(state, TransferState::Connected);
    let mut tx = env.core.tenant_tx(&env.operator_ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM transfer_systems")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(n >= 2, "transfer_systems must survive the hostile key");

    // Scanner allowlists source kinds.
    assert!(scanner
        .record_edge(
            &env.operator_ctx,
            &tinker_transfer::DependencyEdge {
                source_kind: "app';--".to_string(),
                source_id: "x".to_string(),
                target_object_id: None,
                target_field_api: None,
                edge_kind: "reads".to_string(),
                external_system_key: None,
            },
        )
        .await
        .is_err());

    // A hostile metric id is bound as a literal value, never a predicate.
    let day = NaiveDate::from_ymd_opt(2026, 9, 23).unwrap();
    tel.record(
        &env.operator_ctx,
        &TelemetryPoint {
            host_id: env.host_id,
            day,
            metric_id: "x' OR '1'='1".to_string(),
            count: 1,
            sum: BigDecimal::from(1),
            dimensions: json!({}),
        },
    )
    .await
    .unwrap();
    let rows = tel
        .read_aggregates(
            &env.operator_ctx,
            ActorMode::Aggregate,
            &AggregateQuery {
                host_id: env.host_id,
                org_filter: None,
                day_from: day,
                day_to: day,
                metric_ids: vec!["msgs.sent".to_string()],
            },
        )
        .await
        .unwrap();
    assert!(
        rows.is_empty(),
        "hostile metric id must not widen the predicate"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: cross-tenant paths cannot escape the org.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_tenant_paths_cannot_escape() {
    let a = setup().await;
    let b = setup().await;
    let eng_a = TransferEngine::new(a.core.clone());
    let se_a = SupportEngine::new(a.core.clone());

    // Org A's engine cannot see org B's system (404, no oracle).
    assert!(eng_a.state_of(&a.operator_ctx, b.system_id).await.is_err());
    assert!(eng_a
        .start_run(&a.operator_ctx, b.system_id, CutoverKind::Cutover)
        .await
        .is_err());
    assert!(eng_a
        .set_authority(
            &a.operator_ctx,
            b.system_id,
            a.deal_object_id,
            &[("amount".to_string(), Authority::Tinker)],
            a.operator_id
        )
        .await
        .is_err());

    // Org A's support engine cannot read org B's session audit.
    let se_b = SupportEngine::new(b.core.clone());
    let mut classes = BTreeMap::new();
    classes.insert("email".to_string(), "restricted".to_string());
    let sess_b = se_b
        .open_session(
            &b.support_ctx,
            b.support_id,
            b.host_id,
            &classes,
            "cross-tenant probe",
            3600,
        )
        .await
        .unwrap();
    let trail = se_a.audit_trail(&a.operator_ctx, sess_b).await.unwrap();
    assert!(trail.is_empty(), "org A must not see org B's support audit");
}
