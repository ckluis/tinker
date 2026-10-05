//! DBOS-style durable execution on Postgres (PRD §37).
//!
//! One substrate owns workflows, queues, timers, and messages. No orchestrator
//! service, no sidecar: the runtime is a library over [`tinker_db::CoreDb`].
//!
//! Guarantees (each covered by an M0 exit test):
//! - Checkpointed steps: a completed step is never re-run; a crashed run
//!   resumes from its last completed step.
//! - Exactly-once effects: a stable `effect_key` is recorded once per
//!   organization; replays return the recorded output.
//! - Crash recovery: expired worker leases are re-queued on startup.
//! - Optimistic concurrency: stale writes fail with a typed [`VersionConflict`].

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{Postgres, Transaction};
use std::future::Future;
use std::time::Duration;
use tinker_core::{Param, Result, TenantContext, TinkerError, VersionConflict};
use tinker_db::CoreDb;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DurableRuntime {
    core: CoreDb,
    /// Owner-level handle for system operations (crash recovery). Recovery
    /// deliberately bypasses tenant RLS because it must requeue runs for
    /// every organization; it never reads or writes business state.
    owner: sqlx::PgPool,
}

/// Definition of a run to start.
#[derive(Debug, Clone)]
pub struct RunDef {
    pub definition_id: String,
    pub definition_version: String,
    pub input: serde_json::Value,
    pub queue: String,
    pub partition_key: String,
    pub priority: i32,
    /// If set, the run starts dormant until this time (durable timer).
    pub wake_at: Option<DateTime<Utc>>,
}

impl Default for RunDef {
    fn default() -> Self {
        Self {
            definition_id: String::new(),
            definition_version: "1".into(),
            input: serde_json::Value::Null,
            queue: "default".into(),
            partition_key: String::new(),
            priority: 0,
            wake_at: None,
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ClaimedRun {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub definition_id: String,
    pub definition_version: String,
    pub input_ref: serde_json::Value,
    pub attempts: i32,
    pub queue: String,
    pub partition_key: String,
}

#[derive(Debug, Clone, Default)]
pub struct Recovered {
    pub expired_leases_requeued: u64,
    pub timers_fired: u64,
}

/// A typed bind value for compare-and-swap updates.
/// Shared with the query compiler: [`tinker_core::Param`].
pub type BoundValue = Param;

fn valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c == '_' => (),
        _ => return false,
    }
    s.len() <= 63 && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

impl DurableRuntime {
    pub fn new(core: CoreDb, owner: sqlx::PgPool) -> Self {
        Self { core, owner }
    }

    /// Start a run. When the caller already holds a transaction that touches
    /// Tinker state, prefer [`Self::start_run_in`] so enqueue joins it.
    pub async fn start_run(&self, ctx: &TenantContext, def: &RunDef) -> Result<Uuid> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let id = Self::start_run_in(&mut tx, ctx, def).await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn start_run_in(
        tx: &mut Transaction<'_, Postgres>,
        ctx: &TenantContext,
        def: &RunDef,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        let status = if def.wake_at.is_some() {
            "scheduled"
        } else {
            "queued"
        };
        sqlx::query(
            r#"INSERT INTO durable_runs
               (id, organization_id, definition_id, definition_version, input_ref,
                status, wake_at, queue, partition_key, priority)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)"#,
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(&def.definition_id)
        .bind(&def.definition_version)
        .bind(&def.input)
        .bind(status)
        .bind(def.wake_at)
        .bind(&def.queue)
        .bind(&def.partition_key)
        .bind(def.priority)
        .execute(&mut **tx)
        .await?;
        Ok(id)
    }

    /// Claim up to `limit` ready runs from a queue with a worker lease.
    /// Uses FOR UPDATE SKIP LOCKED; expired leases are claimable.
    /// Claim up to `limit` queued runs for a worker. The candidate set is
    /// selected in a MATERIALIZED CTE: without it, PostgreSQL may plan the
    /// `IN (SELECT ... LIMIT n FOR UPDATE ...)` as a nested-loop semi join
    /// that re-evaluates the subquery per outer row. Since the outer UPDATE
    /// flips `status` mid-statement, each re-evaluation would see newly
    /// eligible rows and the LIMIT would silently stop applying — claiming
    /// the whole queue. The CTE is evaluated exactly once, so the limit is
    /// a real global bound. (Caught by the M0 exclusivity test.)
    pub async fn claim_next(
        &self,
        ctx: &TenantContext,
        queue: &str,
        worker: &str,
        lease: Duration,
        limit: i64,
    ) -> Result<Vec<ClaimedRun>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let lease_secs = lease.as_secs() as i32;
        let rows = sqlx::query_as::<_, ClaimedRun>(
            r#"WITH candidates AS MATERIALIZED (
                   SELECT id FROM durable_runs
                   WHERE queue = $1
                     AND status IN ('queued','scheduled')
                     AND (wake_at IS NULL OR wake_at <= now())
                     AND (lease_until IS NULL OR lease_until < now())
                   ORDER BY priority DESC, created_at
                   LIMIT $4
                   FOR UPDATE SKIP LOCKED
               )
               UPDATE durable_runs AS d
               SET status='running', lease_owner=$2,
                   lease_until = now() + make_interval(secs => $3),
                   attempts = attempts + 1, updated_at = now()
               FROM candidates AS c
               WHERE d.id = c.id
               RETURNING d.id, d.organization_id, d.definition_id,
                         d.definition_version, d.input_ref, d.attempts,
                         d.queue, d.partition_key"#,
        )
        .bind(queue)
        .bind(worker)
        .bind(lease_secs)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    pub async fn heartbeat(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        lease: Duration,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            r#"UPDATE durable_runs SET lease_until = now() + make_interval(secs => $3),
                      updated_at = now()
               WHERE id = $1 AND organization_id = $2 AND status = 'running'"#,
        )
        .bind(run_id)
        .bind(ctx.organization_id.0)
        .bind(lease.as_secs() as i32)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::NotFound(format!("running run {run_id}")));
        }
        Ok(())
    }

    pub async fn complete_run(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        succeeded: bool,
        error: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            r#"UPDATE durable_runs
               SET status = CASE WHEN $3 THEN 'succeeded' ELSE 'failed' END,
                   error = $4, lease_until = NULL, lease_owner = NULL,
                   updated_at = now()
               WHERE id = $1 AND organization_id = $2"#,
        )
        .bind(run_id)
        .bind(ctx.organization_id.0)
        .bind(succeeded)
        .bind(error)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Durable sleep: the run goes dormant until `until`, then becomes
    /// claimable again. Recovery fires overdue timers.
    pub async fn sleep_until(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        until: DateTime<Utc>,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            r#"UPDATE durable_runs
               SET status='sleeping', wake_at=$3, lease_until=NULL, lease_owner=NULL,
                   updated_at=now()
               WHERE id=$1 AND organization_id=$2"#,
        )
        .bind(run_id)
        .bind(ctx.organization_id.0)
        .bind(until)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The core primitive: run a named step exactly once per completion.
    ///
    /// - If the step already completed, its recorded output is returned and
    ///   `f` is NOT executed.
    /// - If `effect_key` is set and another step already recorded that effect
    ///   for this organization, the recorded output is returned and `f` is
    ///   NOT executed (duplicate-effect suppression).
    /// - Otherwise `f` runs outside any database transaction (side effects
    ///   never hold a transaction open across a network call), then the
    ///   output is checkpointed.
    pub async fn run_step<T, F, Fut>(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        step_key: &str,
        effect_key: Option<&str>,
        input: &impl Serialize,
        f: F,
    ) -> Result<T>
    where
        T: Serialize + DeserializeOwned,
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let input_hash = hash_input(input)?;

        // 0. Fail closed unless the run belongs to the caller's org.
        self.assert_run_owned(ctx, run_id).await?;

        // 1. Fast path: completed step replays its recorded output.
        if let Some(output) = self.completed_step_output(ctx, run_id, step_key).await? {
            return Ok(output);
        }

        // 2. Effect dedup: a recorded effect_key wins over re-execution.
        if let Some(key) = effect_key {
            if let Some(output) = self.recorded_effect_output(ctx, key).await? {
                return Ok(output);
            }
        }

        // 3. Claim the step (or take over an expired lease) BEFORE reserving
        // the effect. Reserving first meant a failed claim left an
        // abandoned reservation behind, permanently poisoning the
        // effect_key for every later attempt.
        let lease_token = self.claim_step(ctx, run_id, step_key, &input_hash).await?;

        // 4. Reserve the effect now that we hold the step: only the first
        // reserver runs the closure. A loser either reads the winner's
        // recorded output or fails the step so retry replays later.
        if let Some(key) = effect_key {
            let reserved = self.reserve_effect(ctx, run_id, step_key, key).await?;
            if !reserved {
                if let Some(output) = self.recorded_effect_output(ctx, key).await? {
                    return Ok(output);
                }
                self.fail_step(ctx, run_id, step_key, lease_token, effect_key)
                    .await?;
                return Err(TinkerError::Internal(format!(
                    "effect {key} is being executed by another worker; retry"
                )));
            }
        }

        // 5. Execute OUTSIDE the transaction.
        let result = f().await;

        // 6. Checkpoint the outcome. The fencing token proves we still hold
        // the lease; a stale worker's completion is rejected, not applied.
        match result {
            Ok(value) => {
                let output = serde_json::to_value(&value)?;
                self.complete_step(ctx, run_id, step_key, lease_token, effect_key, &output)
                    .await?;
                Ok(value)
            }
            Err(e) => {
                self.fail_step(ctx, run_id, step_key, lease_token, effect_key)
                    .await?;
                Err(e)
            }
        }
    }

    async fn completed_step_output<T: DeserializeOwned>(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        step_key: &str,
    ) -> Result<Option<T>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            r#"SELECT output_ref FROM durable_steps
               WHERE run_id=$1 AND step_key=$2 AND status='completed'"#,
        )
        .bind(run_id)
        .bind(step_key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            Some((v,)) => Ok(Some(serde_json::from_value(v)?)),
            None => Ok(None),
        }
    }

    async fn recorded_effect_output<T: DeserializeOwned>(
        &self,
        ctx: &TenantContext,
        effect_key: &str,
    ) -> Result<Option<T>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        // output_ref is NULL while a reservation is in flight (a crashed
        // worker leaves exactly such a row); decode as Option so the
        // ghost reservation reads as "not recorded" instead of erroring.
        let row: Option<(Option<serde_json::Value>,)> = sqlx::query_as(
            r#"SELECT output_ref FROM durable_effects
               WHERE organization_id=$1 AND effect_key=$2"#,
        )
        .bind(ctx.organization_id.0)
        .bind(effect_key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            Some((Some(v),)) if !v.is_null() => Ok(Some(serde_json::from_value(v)?)),
            _ => Ok(None),
        }
    }

    /// Claim a step for execution, minting a fencing token. Returns the
    /// token the worker must present to complete or fail the step: if the
    /// lease was taken over meanwhile, the stale worker's writes are
    /// rejected instead of clobbering the new owner's checkpoint.
    async fn claim_step(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        step_key: &str,
        input_hash: &str,
    ) -> Result<Uuid> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let lease_token = Uuid::now_v7();
        let res = sqlx::query(
            r#"INSERT INTO durable_steps
               (organization_id, run_id, step_key, input_hash, status, lease_until, lease_token)
               VALUES ($1,$2,$3,$4,'running', now() + interval '5 minutes', $5)
               ON CONFLICT (run_id, step_key) DO UPDATE
               SET attempt = durable_steps.attempt + 1,
                   input_hash = EXCLUDED.input_hash,
                   status = 'running',
                   lease_until = now() + interval '5 minutes',
                   lease_token = EXCLUDED.lease_token
               WHERE durable_steps.status != 'completed'
                 AND (durable_steps.lease_until IS NULL OR durable_steps.lease_until < now())"#,
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .bind(step_key)
        .bind(input_hash)
        .bind(lease_token)
        .execute(&mut *tx)
        .await?;
        if res.rows_affected() == 0 {
            // Either completed (handled by fast path) or owned by a live worker.
            tx.rollback().await?;
            return Err(TinkerError::Internal(format!(
                "step {step_key} of run {run_id} is not claimable"
            )));
        }
        // Reap this step's own abandoned reservations. A worker that crashed
        // between reserve_effect and the checkpoint left NULL-output rows
        // pinned to (run_id, step_key); without this, the next claim of this
        // step would lose every reserve race against the ghost and fail
        // forever. This only runs on a SUCCESSFUL claim, so a live owner's
        // reservation is never touched. Rows of other steps are untouched.
        sqlx::query(
            r#"DELETE FROM durable_effects
               WHERE organization_id=$1 AND run_id=$2 AND step_key=$3
                 AND output_ref IS NULL"#,
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .bind(step_key)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(lease_token)
    }

    /// First-writer reservation for an effect key. Returns true iff this
    /// caller owns the reservation and may execute the effect.
    async fn reserve_effect(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        step_key: &str,
        effect_key: &str,
    ) -> Result<bool> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            r#"INSERT INTO durable_effects
               (organization_id, effect_key, run_id, step_key)
               VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING"#,
        )
        .bind(ctx.organization_id.0)
        .bind(effect_key)
        .bind(run_id)
        .bind(step_key)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(n == 1)
    }

    async fn complete_step(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        step_key: &str,
        lease_token: Uuid,
        effect_key: Option<&str>,
        output: &serde_json::Value,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        // The lease_token fences out stale workers: if the lease was taken
        // over, this matches 0 rows and the stale completion is rejected
        // instead of clobbering the new owner's checkpoint.
        let n = sqlx::query(
            r#"UPDATE durable_steps SET status='completed', output_ref=$5,
                      completed_at=now(), lease_until=NULL
               WHERE run_id=$1 AND step_key=$2 AND organization_id=$3
                 AND lease_token=$4"#,
        )
        .bind(run_id)
        .bind(step_key)
        .bind(ctx.organization_id.0)
        .bind(lease_token)
        .bind(output)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(TinkerError::Internal(format!(
                "stale worker: step {step_key} of run {run_id} was taken over; discarding result"
            )));
        }
        if let Some(key) = effect_key {
            // We hold the reservation (inserted before execution), so this
            // UPDATE can only fill in our own row. A concurrent duplicate
            // never got past reserve_effect. Fail loudly if the reservation
            // vanished: silently skipping the checkpoint would break
            // exactly-once recording.
            let filled = sqlx::query(
                r#"UPDATE durable_effects SET output_ref=$3
                   WHERE organization_id=$1 AND effect_key=$2"#,
            )
            .bind(ctx.organization_id.0)
            .bind(key)
            .bind(output)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if filled == 0 {
                return Err(TinkerError::Internal(format!(
                    "effect reservation for {key} vanished before checkpoint"
                )));
            }
        }
        tx.commit().await?;
        Ok(())
    }

    async fn fail_step(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        step_key: &str,
        lease_token: Uuid,
        effect_key: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Fenced like complete_step: a stale worker must not fail a step
        // it no longer owns.
        let n = sqlx::query(
            r#"UPDATE durable_steps SET status='failed', lease_until=NULL
               WHERE run_id=$1 AND step_key=$2 AND organization_id=$3
                 AND lease_token=$4"#,
        )
        .bind(run_id)
        .bind(step_key)
        .bind(ctx.organization_id.0)
        .bind(lease_token)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if n == 0 {
            return Err(TinkerError::Internal(format!(
                "stale worker: step {step_key} of run {run_id} was taken over; discarding failure"
            )));
        }
        // Release our own reservation so a retry can re-reserve the key.
        // Only the row this step created is deleted (run_id + step_key pin).
        if let Some(key) = effect_key {
            sqlx::query(
                r#"DELETE FROM durable_effects
                   WHERE organization_id=$1 AND effect_key=$2
                     AND run_id=$3 AND step_key=$4 AND output_ref IS NULL"#,
            )
            .bind(ctx.organization_id.0)
            .bind(key)
            .bind(run_id)
            .bind(step_key)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Send a durable message to a run (DBOS.send). A waiting run resolves it.
    pub async fn send_event(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        event_type: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        self.assert_run_owned(ctx, run_id).await?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            r#"INSERT INTO durable_events (organization_id, run_id, seq, event_type, payload_ref)
               VALUES ($1,$2, coalesce((SELECT max(seq)+1 FROM durable_events WHERE run_id=$2),0), $3, $4)"#,
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .bind(event_type)
        .bind(payload)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Fail closed unless the run belongs to the caller's organization.
    /// RLS on durable_runs makes a foreign run_id simply not exist here.
    async fn assert_run_owned(&self, ctx: &TenantContext, run_id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM durable_runs WHERE id=$1")
            .bind(run_id)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        if exists.is_none() {
            return Err(TinkerError::NotFound(format!("run {run_id}")));
        }
        Ok(())
    }

    /// Crash recovery, run at startup and periodically: re-queue runs whose
    /// worker lease expired, and fire overdue timers. Idempotent.
    ///
    /// Recovery runs on the OWNER handle, not the app pool: it must see runs
    /// for every organization, and the app pool's tenant RLS would silently
    /// filter them all out. It touches only durable_runs rows.
    pub async fn recover(&self) -> Result<Recovered> {
        let mut conn = self.owner.acquire().await?;
        let expired = sqlx::query(
            r#"UPDATE durable_runs SET status='queued', lease_owner=NULL,
                      lease_until=NULL, attempts=attempts+1, updated_at=now()
               WHERE status IN ('running','sleeping')
                 AND lease_until IS NOT NULL AND lease_until < now()"#,
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
        let timers = sqlx::query(
            r#"UPDATE durable_runs SET status='queued', updated_at=now()
               WHERE status='scheduled' AND wake_at IS NOT NULL AND wake_at <= now()"#,
        )
        .execute(&mut *conn)
        .await?
        .rows_affected();
        Ok(Recovered {
            expired_leases_requeued: expired,
            timers_fired: timers,
        })
    }

    /// Optimistic compare-and-swap update on a `data.*` table.
    /// Returns the new version, or a typed [`VersionConflict`].
    /// Column and table names are allowlist-validated; values are bound.
    pub async fn cas_update(
        &self,
        ctx: &TenantContext,
        table: &str,
        record_id: Uuid,
        expected_version: i64,
        set: &[(String, BoundValue)],
    ) -> Result<i64> {
        if !table.starts_with("data.") || !valid_ident(&table[5..]) {
            return Err(TinkerError::Validation(format!("bad table: {table}")));
        }
        if set.is_empty() {
            return Err(TinkerError::Validation("cas_update: empty patch".into()));
        }
        for (col, _) in set {
            if !valid_ident(col) {
                return Err(TinkerError::Validation(format!("bad column: {col}")));
            }
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let mut qb: sqlx::QueryBuilder<Postgres> = sqlx::QueryBuilder::new("UPDATE ");
        qb.push(table);
        qb.push(" SET ");
        for (i, (col, val)) in set.iter().enumerate() {
            if i > 0 {
                qb.push(", ");
            }
            qb.push(format!("\"{col}\" = "));
            match val {
                Param::Text(s) => {
                    qb.push_bind(s);
                }
                Param::Int(n) => {
                    qb.push_bind(n);
                }
                Param::Float(f) => {
                    qb.push_bind(f);
                }
                Param::Bool(b) => {
                    qb.push_bind(b);
                }
                Param::Uuid(u) => {
                    qb.push_bind(u);
                }
                Param::Date(d) => {
                    qb.push_bind(d);
                }
                Param::Timestamp(t) => {
                    qb.push_bind(t);
                }
                Param::Json(j) => {
                    qb.push_bind(j);
                }
                Param::Null => {
                    qb.push("NULL");
                }
            }
        }
        qb.push(", version = version + 1, updated_at = now() WHERE organization_id = ");
        qb.push_bind(ctx.organization_id.0);
        qb.push(" AND id = ");
        qb.push_bind(record_id);
        qb.push(" AND version = ");
        qb.push_bind(expected_version);
        qb.push(" RETURNING version");
        let new_version: Option<i64> = qb.build_query_scalar().fetch_optional(&mut *tx).await?;
        match new_version {
            Some(v) => {
                tx.commit().await?;
                Ok(v)
            }
            None => {
                // Zero rows: distinguish a stale version from a missing row.
                let current: Option<i64> = sqlx::query_scalar(&format!(
                    "SELECT version FROM {table} WHERE organization_id = $1 AND id = $2"
                ))
                .bind(ctx.organization_id.0)
                .bind(record_id)
                .fetch_optional(&mut *tx)
                .await?;
                tx.commit().await?;
                match current {
                    Some(cur) => Err(TinkerError::conflict(VersionConflict {
                        object: table.to_string(),
                        record_id,
                        expected_version,
                        current_version: cur,
                    })),
                    None => Err(TinkerError::NotFound(format!("{table} {record_id}"))),
                }
            }
        }
    }
}

fn hash_input(input: &impl Serialize) -> Result<String> {
    let v = serde_json::to_value(input)?;
    Ok(format!("{:x}", fnv(&v.to_string())))
}

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
