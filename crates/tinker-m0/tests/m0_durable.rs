//! M0 durable exits: killed workflow resumes, no duplicate step runs,
//! duplicate effect suppression, stale CAS conflicts, queue leases.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tinker_core::{Param, TinkerError};
use tinker_durable::{DurableRuntime, RunDef};
use uuid::Uuid;

fn run_def(workflow: &str) -> RunDef {
    run_def_on_queue(
        workflow,
        &format!("q_{}", &Uuid::now_v7().simple().to_string()[24..32]),
    )
}

fn run_def_on_queue(workflow: &str, queue: &str) -> RunDef {
    RunDef {
        definition_id: workflow.into(),
        definition_version: "1".into(),
        input: serde_json::json!({}),
        queue: queue.into(),
        partition_key: String::new(),
        priority: 0,
        wake_at: None,
    }
}

#[tokio::test]
async fn killed_workflow_resumes_without_rerunning_completed_steps() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    let run_id = d.start_run(&ctx, &run_def("onboarding")).await.unwrap();

    let step1_count = Arc::new(AtomicUsize::new(0));
    let c1 = step1_count.clone();
    let out1: String = d
        .run_step(
            &ctx,
            run_id,
            "step1",
            None,
            &serde_json::json!({}),
            move || {
                let c1 = c1.clone();
                async move {
                    c1.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TinkerError>("done-1".to_string())
                }
            },
        )
        .await
        .unwrap();
    assert_eq!(out1, "done-1");

    // Simulate a crash: a step2 row left 'running' with an expired lease,
    // as if the worker died mid-step.
    sqlx::query(
        "INSERT INTO durable_steps (run_id, organization_id, step_key, status, lease_until) \
         VALUES ($1,$2,'step2','running', now() - interval '1 hour')",
    )
    .bind(run_id)
    .bind(ctx.organization_id.0)
    .execute(&env.core_owner)
    .await
    .unwrap();

    // Recovery runs at the owner level (sees every org). The run itself was
    // never leased, so recovery must not touch it — but we assert only
    // per-run outcomes, not the global reaped count, since parallel tests
    // share the owner-level recover() view.
    let _ = d.recover().await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM durable_runs WHERE id=$1")
        .bind(run_id)
        .fetch_one(&env.core_owner)
        .await
        .unwrap();
    assert_eq!(status, "queued");

    // Resume: step2 takes over the expired lease and runs exactly once.
    let step2_count = Arc::new(AtomicUsize::new(0));
    let c2 = step2_count.clone();
    let out2: String = d
        .run_step(
            &ctx,
            run_id,
            "step2",
            None,
            &serde_json::json!({}),
            move || {
                let c2 = c2.clone();
                async move {
                    c2.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TinkerError>("done-2".to_string())
                }
            },
        )
        .await
        .unwrap();
    assert_eq!(out2, "done-2");
    assert_eq!(step2_count.load(Ordering::SeqCst), 1);

    // Replay: step1 returns its recorded output WITHOUT re-running.
    let c3 = step1_count.clone();
    let replay: String = d
        .run_step(
            &ctx,
            run_id,
            "step1",
            None,
            &serde_json::json!({}),
            move || {
                let c3 = c3.clone();
                async move {
                    c3.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TinkerError>("different".to_string())
                }
            },
        )
        .await
        .unwrap();
    assert_eq!(replay, "done-1", "replay must return recorded output");
    assert_eq!(
        step1_count.load(Ordering::SeqCst),
        1,
        "completed step must not re-run"
    );
}

#[tokio::test]
async fn expired_run_lease_is_requeued_by_recovery() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    let def = run_def("wf");
    let run_id = d.start_run(&ctx, &def).await.unwrap();
    let claimed = d
        .claim_next(&ctx, &def.queue, "worker-1", Duration::from_secs(3600), 10)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].id, run_id);

    // Kill the worker: expire the lease via owner, then recover.
    sqlx::query("UPDATE durable_runs SET lease_until = now() - interval '1 hour' WHERE id=$1")
        .bind(run_id)
        .execute(&env.core_owner)
        .await
        .unwrap();
    let _ = d.recover().await.unwrap();

    // The run is claimable again, with attempts incremented. (No exact
    // global count assertion: recover() is owner-level and shared with
    // parallel tests.)
    let claimed2 = d
        .claim_next(&ctx, &def.queue, "worker-2", Duration::from_secs(3600), 10)
        .await
        .unwrap();
    assert_eq!(claimed2.len(), 1);
    assert_eq!(claimed2[0].id, run_id);
    assert!(claimed2[0].attempts >= 2);
}

#[tokio::test]
async fn duplicate_effect_is_suppressed_across_runs() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    let counter = Arc::new(AtomicUsize::new(0));

    let run_a = d.start_run(&ctx, &run_def("billing")).await.unwrap();
    let ca = counter.clone();
    let out_a: String = d
        .run_step(
            &ctx,
            run_a,
            "charge",
            Some("pay-1"),
            &serde_json::json!({}),
            move || {
                let ca = ca.clone();
                async move {
                    ca.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TinkerError>("charged".to_string())
                }
            },
        )
        .await
        .unwrap();
    assert_eq!(out_a, "charged");

    // A retry with a NEW run id but the SAME idempotency key must NOT
    // re-execute the effect.
    let run_b = d.start_run(&ctx, &run_def("billing")).await.unwrap();
    let cb = counter.clone();
    let out_b: String = d
        .run_step(
            &ctx,
            run_b,
            "charge",
            Some("pay-1"),
            &serde_json::json!({}),
            move || {
                let cb = cb.clone();
                async move {
                    cb.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, TinkerError>("charged-twice".to_string())
                }
            },
        )
        .await
        .unwrap();
    assert_eq!(out_b, "charged", "duplicate effect returns first result");
    assert_eq!(
        counter.load(Ordering::SeqCst),
        1,
        "effect closure ran more than once"
    );
}

#[tokio::test]
async fn failed_effect_releases_reservation_for_retry() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    let run_id = d.start_run(&ctx, &run_def("billing")).await.unwrap();

    // First attempt fails after reserving the effect key.
    let err = d
        .run_step(
            &ctx,
            run_id,
            "charge",
            Some("pay-retry"),
            &serde_json::json!({}),
            || async { Err::<String, _>(TinkerError::Internal("boom".into())) },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Internal(_)));

    // Retry of the same step (same effect key) must be able to re-reserve
    // and execute instead of deadlocking on the abandoned reservation.
    let out: String = d
        .run_step(
            &ctx,
            run_id,
            "charge",
            Some("pay-retry"),
            &serde_json::json!({}),
            || async { Ok::<_, TinkerError>("charged".to_string()) },
        )
        .await
        .unwrap();
    assert_eq!(out, "charged");
}

#[tokio::test]
async fn stale_cas_update_conflicts() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    // A minimal data table for the CAS exercise.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS data.cas_widget \
         (organization_id uuid NOT NULL, id uuid NOT NULL, version bigint NOT NULL DEFAULT 1, \
          updated_at timestamptz NOT NULL DEFAULT now(), \
          f_x text, PRIMARY KEY (organization_id, id))",
    )
    .execute(&env.core_owner)
    .await
    .unwrap();
    sqlx::query("ALTER TABLE data.cas_widget ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now()")
        .execute(&env.core_owner)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE data.cas_widget ENABLE ROW LEVEL SECURITY")
        .execute(&env.core_owner)
        .await
        .unwrap();
    sqlx::query("DROP POLICY IF EXISTS cas_widget_org ON data.cas_widget")
        .execute(&env.core_owner)
        .await
        .unwrap();
    sqlx::query(
        "CREATE POLICY cas_widget_org ON data.cas_widget
         USING (organization_id = current_setting('app.organization_id', true)::uuid)",
    )
    .execute(&env.core_owner)
    .await
    .unwrap();

    let rec_id = Uuid::now_v7();
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO data.cas_widget (organization_id, id, version, f_x) VALUES ($1,$2,1,'a')",
    )
    .bind(ctx.organization_id.0)
    .bind(rec_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let v = d
        .cas_update(
            &ctx,
            "data.cas_widget",
            rec_id,
            1,
            &[("f_x".into(), Param::Text("b".into()))],
        )
        .await
        .unwrap();
    assert_eq!(v, 2);

    // Stale version: the row is now at version 2.
    let err = d
        .cas_update(
            &ctx,
            "data.cas_widget",
            rec_id,
            1,
            &[("f_x".into(), Param::Text("c".into()))],
        )
        .await
        .unwrap_err();
    match err {
        TinkerError::Conflict {
            expected,
            current,
            record_id: rid,
            ..
        } => {
            assert_eq!(expected, 1);
            assert_eq!(current, 2);
            assert_eq!(rid, rec_id);
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn queue_claim_is_exclusive() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    let def = run_def("q");
    let r1 = d.start_run(&ctx, &def).await.unwrap();
    let r2 = d.start_run(&ctx, &def).await.unwrap();
    let _r3 = d.start_run(&ctx, &def).await.unwrap();

    let got = d
        .claim_next(&ctx, &def.queue, "worker-1", Duration::from_secs(3600), 2)
        .await
        .unwrap();
    assert_eq!(got.len(), 2);
    let ids: Vec<Uuid> = got.iter().map(|r| r.id).collect();
    assert!(ids.contains(&r1) && ids.contains(&r2));

    // Claimed runs are not visible to a second worker.
    let got2 = d
        .claim_next(&ctx, &def.queue, "worker-2", Duration::from_secs(3600), 10)
        .await
        .unwrap();
    assert_eq!(got2.len(), 1);
    assert!(!got2.iter().any(|r| ids.contains(&r.id)));
}

#[tokio::test]
async fn cross_tenant_run_ids_do_not_leak() {
    let env = common::setup().await;
    let ctx_a = common::new_org(&env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(&env, &common::uniq("orgb")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    let def = run_def("wf");
    let run_a = d.start_run(&ctx_a, &def).await.unwrap();

    // Org B's claim cannot see org A's queued run (tenant context pins it).
    let got = d
        .claim_next(&ctx_b, &def.queue, "w", Duration::from_secs(60), 10)
        .await
        .unwrap();
    assert!(!got.iter().any(|r| r.id == run_a));

    // Org B cannot step into org A's run: the run is invisible under org
    // B's tenant context, so run_step fails closed with NotFound before
    // any step row can be attached cross-tenant.
    let err = d
        .run_step(&ctx_b, run_a, "s", None, &serde_json::json!({}), || async {
            Ok::<_, TinkerError>("x".to_string())
        })
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));
}

#[tokio::test]
async fn run_events_are_durable_and_tenant_scoped() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());

    let run_id = d.start_run(&ctx, &run_def("wf")).await.unwrap();
    d.send_event(
        &ctx,
        run_id,
        "approval.requested",
        &serde_json::json!({"by": "mgr"}),
    )
    .await
    .unwrap();
    d.send_event(
        &ctx,
        run_id,
        "approval.granted",
        &serde_json::json!({"by": "mgr"}),
    )
    .await
    .unwrap();

    // Read back via owner: two ordered events.
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT seq, event_type FROM durable_events WHERE run_id=$1 ORDER BY seq")
            .bind(run_id)
            .fetch_all(&env.core_owner)
            .await
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1, "approval.requested");
    assert_eq!(rows[1].1, "approval.granted");

    // Tenant-scoped: org B's app-role context cannot see org A's events.
    let ctx_b = common::new_org(&env, &common::uniq("orgb")).await;
    let mut tx = env.core.tenant_tx(&ctx_b).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM durable_events WHERE run_id=$1")
        .bind(run_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn stale_worker_completion_is_fenced() {
    use tokio::sync::Notify;
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());
    let run_id = d.start_run(&ctx, &run_def("wf")).await.unwrap();

    let claimed = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let c1 = claimed.clone();
    let r1 = release.clone();

    // Worker A claims the step, then stalls mid-execution (no effect_key:
    // this test is about step fencing, not effect dedup).
    let d_a = d.clone();
    let ctx_a = ctx.clone();
    let worker_a = tokio::spawn(async move {
        d_a.run_step(
            &ctx_a,
            run_id,
            "s",
            None,
            &serde_json::json!({}),
            || async move {
                c1.notify_one();
                r1.notified().await;
                Ok::<_, TinkerError>("a-output".to_string())
            },
        )
        .await
    });
    claimed.notified().await;

    // A's lease expires; worker B takes over the same step and completes.
    sqlx::query(
        "UPDATE durable_steps SET lease_until = now() - interval '1 minute' \
         WHERE run_id=$1 AND step_key='s'",
    )
    .bind(run_id)
    .execute(&env.core_owner)
    .await
    .unwrap();
    let out_b: String = d
        .run_step(&ctx, run_id, "s", None, &serde_json::json!({}), || async {
            Ok::<_, TinkerError>("b-output".to_string())
        })
        .await
        .unwrap();
    assert_eq!(out_b, "b-output");

    // Worker A wakes up and tries to complete with its stale token: the
    // write is rejected instead of clobbering B's checkpoint.
    release.notify_one();
    let err = worker_a.await.unwrap().unwrap_err();
    assert!(
        format!("{err:?}").contains("stale worker"),
        "stale completion must be fenced, got {err:?}"
    );

    // B's checkpoint stands.
    let (status, output): (String, serde_json::Value) = sqlx::query_as(
        "SELECT status, output_ref FROM durable_steps WHERE run_id=$1 AND step_key='s'",
    )
    .bind(run_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(status, "completed");
    assert_eq!(output, serde_json::json!("b-output"));
}

#[tokio::test]
async fn crashed_reservation_is_reaped_on_next_claim() {
    // Adversarial: a worker crashed between reserve_effect and the
    // checkpoint, leaving a NULL-output reservation and a failed step.
    // The next claim must reap the ghost and execute exactly once —
    // otherwise every retry loses the reserve race and fails forever.
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let d = DurableRuntime::new(env.core.clone(), env.core_owner.clone());
    let run_id = d.start_run(&ctx, &run_def("wf")).await.unwrap();
    let q = format!("crashq-{}", Uuid::now_v7().simple());
    let effect_key = format!("ek-crash-{}", Uuid::now_v7().simple());

    // Plant the ghost: a failed step (lease NULL, so claimable) plus a
    // NULL-output reservation pinned to it, as a crashed worker would leave.
    sqlx::query(
        "INSERT INTO durable_steps (organization_id, run_id, step_key, input_hash, status) \
         VALUES ($1,$2,'s','h','failed')",
    )
    .bind(ctx.organization_id.0)
    .bind(run_id)
    .execute(&env.core_owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO durable_effects (organization_id, effect_key, run_id, step_key, output_ref) \
         VALUES ($1,$2,$3,'s',NULL)",
    )
    .bind(ctx.organization_id.0)
    .bind(&effect_key)
    .bind(run_id)
    .execute(&env.core_owner)
    .await
    .unwrap();

    let _ = q;
    let executions = Arc::new(AtomicUsize::new(0));
    let ex = executions.clone();
    let out: String = d
        .run_step(
            &ctx,
            run_id,
            "s",
            Some(&effect_key),
            &serde_json::json!({}),
            || async move {
                ex.fetch_add(1, Ordering::SeqCst);
                Ok::<_, TinkerError>("recovered".to_string())
            },
        )
        .await
        .unwrap();
    assert_eq!(out, "recovered");
    assert_eq!(executions.load(Ordering::SeqCst), 1);

    // The ghost reservation was replaced by a recorded one.
    let recorded: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT output_ref FROM durable_effects WHERE organization_id=$1 AND effect_key=$2",
    )
    .bind(ctx.organization_id.0)
    .bind(&effect_key)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(recorded, Some(serde_json::json!("recovered")));
}
