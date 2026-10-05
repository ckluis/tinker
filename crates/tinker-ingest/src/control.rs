//! Ingest control plane: connections, streams, runs.
//!
//! All writes go through tenant-scoped transactions; RLS is the backstop.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

/// A run whose heartbeat is older than this is considered crashed and may
/// be superseded by the next run. Live runs heartbeat once per page, so a
/// healthy run is never mistaken for stale.
pub const STALE_RUN_THRESHOLD_SECS: f64 = 300.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestConnection {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub kind: String,
    pub name: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestStream {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub connection_id: Uuid,
    pub source_object: String,
    pub cursor_kind: String,
    pub cursor_state: serde_json::Value,
}

pub struct NewConnection {
    pub kind: String,
    pub name: String,
    pub credential_ref: Option<String>,
}

pub struct NewStream {
    pub connection_id: Uuid,
    pub source_object: String,
    pub cursor_kind: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Running,
    Complete,
    Failed,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            RunStatus::Running => "running",
            RunStatus::Complete => "complete",
            RunStatus::Failed => "failed",
        }
    }
}

pub struct IngestControl {
    core: CoreDb,
}

impl IngestControl {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    pub async fn create_connection(
        &self,
        ctx: &TenantContext,
        req: NewConnection,
    ) -> Result<IngestConnection> {
        if req.name.trim().is_empty() || req.name.len() > 200 {
            return Err(tinker_core::TinkerError::Validation(
                "connection name must be 1-200 chars".into(),
            ));
        }
        if req.kind != "salesforce" {
            return Err(tinker_core::TinkerError::Validation(format!(
                "unsupported source kind: {}",
                req.kind
            )));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: (Uuid, Uuid, String, String, String) = sqlx::query_as(
            "INSERT INTO ingest_connection (id, organization_id, kind, name, credential_ref)
             VALUES ($1,$2,$3,$4,$5)
             RETURNING id, organization_id, kind, name, state",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(&req.kind)
        .bind(req.name.trim())
        .bind(req.credential_ref)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(IngestConnection {
            id: row.0,
            organization_id: row.1,
            kind: row.2,
            name: row.3,
            state: row.4,
        })
    }

    pub async fn create_stream(&self, ctx: &TenantContext, req: NewStream) -> Result<IngestStream> {
        if !matches!(req.cursor_kind.as_str(), "updated_at" | "id" | "snapshot") {
            return Err(tinker_core::TinkerError::Validation(format!(
                "bad cursor kind: {}",
                req.cursor_kind
            )));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        // The connection must belong to this org (RLS makes a foreign id
        // simply not exist).
        let conn: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM ingest_connection WHERE organization_id=$1 AND id=$2")
                .bind(ctx.organization_id.0)
                .bind(req.connection_id)
                .fetch_optional(&mut *tx)
                .await?;
        if conn.is_none() {
            return Err(tinker_core::TinkerError::NotFound(format!(
                "connection {}",
                req.connection_id
            )));
        }
        let row: (Uuid, Uuid, Uuid, String, String, serde_json::Value) = sqlx::query_as(
            "INSERT INTO ingest_stream
             (id, organization_id, connection_id, source_object, cursor_kind, cursor_state)
             VALUES ($1,$2,$3,$4,$5,'{}')
             ON CONFLICT (organization_id, connection_id, source_object)
             DO UPDATE SET cursor_kind=EXCLUDED.cursor_kind
             RETURNING id, organization_id, connection_id, source_object, cursor_kind, cursor_state",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(req.connection_id)
        .bind(&req.source_object)
        .bind(&req.cursor_kind)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(IngestStream {
            id: row.0,
            organization_id: row.1,
            connection_id: row.2,
            source_object: row.3,
            cursor_kind: row.4,
            cursor_state: row.5,
        })
    }

    pub async fn get_stream(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
    ) -> Result<Option<IngestStream>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(Uuid, Uuid, Uuid, String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT id, organization_id, connection_id, source_object, cursor_kind, cursor_state
                 FROM ingest_stream WHERE organization_id=$1 AND id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|r| IngestStream {
            id: r.0,
            organization_id: r.1,
            connection_id: r.2,
            source_object: r.3,
            cursor_kind: r.4,
            cursor_state: r.5,
        }))
    }

    pub async fn list_streams(
        &self,
        ctx: &TenantContext,
        connection_id: Uuid,
    ) -> Result<Vec<IngestStream>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, Uuid, Uuid, String, String, serde_json::Value)> = sqlx::query_as(
            "SELECT id, organization_id, connection_id, source_object, cursor_kind, cursor_state
                 FROM ingest_stream
                 WHERE organization_id=$1 AND connection_id=$2
                 ORDER BY source_object",
        )
        .bind(ctx.organization_id.0)
        .bind(connection_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|r| IngestStream {
                id: r.0,
                organization_id: r.1,
                connection_id: r.2,
                source_object: r.3,
                cursor_kind: r.4,
                cursor_state: r.5,
            })
            .collect())
    }

    /// Advance the durable cursor after a successful page. The cursor is
    /// the resume point: a crashed run replays from the last committed page.
    pub async fn advance_cursor(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        cursor: &serde_json::Value,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Serialize cursor writers per stream: two concurrent ingesters must
        // not interleave page commits.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
            .bind(format!("ingest-cursor:{}", ctx.organization_id.0))
            .bind(stream_id.to_string())
            .execute(&mut *tx)
            .await?;
        let updated: Option<(Uuid,)> = sqlx::query_as(
            "UPDATE ingest_stream SET cursor_state=$3, version=version+1
             WHERE organization_id=$1 AND id=$2
             RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(cursor)
        .fetch_optional(&mut *tx)
        .await?;
        if updated.is_none() {
            return Err(tinker_core::TinkerError::NotFound(format!(
                "stream {stream_id}"
            )));
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn start_run(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        checkpoint_in: serde_json::Value,
    ) -> Result<Uuid> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Per-stream advisory lock (transaction-scoped): serializes
        // concurrent run starts on the same stream. The second starter
        // waits here, then sees the first starter's `running` row below
        // and fails with Busy instead of interleaving.
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended('tinker_ingest_run:' || $1::text, 0))",
        )
        .bind(stream_id)
        .execute(&mut *tx)
        .await?;
        // Belt and suspenders: fail anything that went stale since the
        // pipeline's earlier fail_stale_runs call (same statement).
        Self::fail_stale_runs_in(&mut tx, ctx.organization_id.0, stream_id).await?;
        // A still-`running` row here has a fresh heartbeat: it is a live
        // run, not a crashed one. Refuse to interleave.
        let live: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM ingest_run
             WHERE organization_id=$1 AND stream_id=$2 AND status='running'
             LIMIT 1",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((live_id,)) = live {
            return Err(TinkerError::Busy(format!(
                "ingest run {live_id} already in progress for stream {stream_id}"
            )));
        }
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO ingest_run (id, organization_id, stream_id, checkpoint_in, status)
             VALUES ($1,$2,$3,$4,'running') RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(checkpoint_in)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Refresh the run's liveness heartbeat. Called once per page during
    /// execution so a long-running run is never mistaken for crashed.
    pub async fn heartbeat_run(&self, ctx: &TenantContext, run_id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "UPDATE ingest_run
             SET last_heartbeat_at=now()
             WHERE organization_id=$1 AND id=$2 AND status='running'",
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn finish_run(
        &self,
        ctx: &TenantContext,
        run_id: Uuid,
        status: RunStatus,
        checkpoint_out: Option<serde_json::Value>,
        counts: serde_json::Value,
    ) -> Result<()> {
        // First-class outcome columns (migration 0024): the scalar run
        // outcome promoted out of the counts JSON for querying. Missing
        // keys (e.g. failed runs, whose counts are {"error": ...}) stay
        // NULL — never fabricate an outcome. All values are extracted
        // before `counts` is moved into the query.
        let int = |k: &str| counts.get(k).and_then(serde_json::Value::as_i64);
        let fingerprint: Option<String> = counts
            .get("fingerprint")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let drift_breaking: Option<bool> = counts
            .get("drift_breaking")
            .and_then(serde_json::Value::as_bool);
        let (landed, promoted, linked, created, queued, pages, millis) = (
            int("landed"),
            int("promoted"),
            int("linked"),
            int("created"),
            int("queued_for_review"),
            int("pages"),
            int("millis"),
        );
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "UPDATE ingest_run
             SET status=$3, checkpoint_out=$4, counts=$5, finished_at=now(),
                 fingerprint=$6, count_landed=$7, count_promoted=$8,
                 count_linked=$9, count_created=$10,
                 count_queued_for_review=$11, count_pages=$12,
                 drift_breaking=$13, duration_millis=$14
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(run_id)
        .bind(status.as_str())
        .bind(checkpoint_out)
        .bind(counts)
        .bind(fingerprint)
        .bind(landed)
        .bind(promoted)
        .bind(linked)
        .bind(created)
        .bind(queued)
        .bind(pages)
        .bind(drift_breaking)
        .bind(millis)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn last_complete_run(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
    ) -> Result<Option<(Uuid, DateTime<Utc>, serde_json::Value)>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(Uuid, DateTime<Utc>, serde_json::Value)> = sqlx::query_as(
            "SELECT id, finished_at, counts FROM ingest_run
             WHERE organization_id=$1 AND stream_id=$2 AND status='complete'
             ORDER BY finished_at DESC LIMIT 1",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Mark runs still `running` for this stream as failed/superseded —
    /// but ONLY those whose heartbeat is older than
    /// [`STALE_RUN_THRESHOLD_SECS`]. A live run heartbeats every page, so
    /// a fresh `running` row belongs to a genuinely concurrent worker and
    /// must not be murdered. Returns the superseded count.
    pub async fn fail_stale_runs(&self, ctx: &TenantContext, stream_id: Uuid) -> Result<u64> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = Self::fail_stale_runs_in(&mut tx, ctx.organization_id.0, stream_id).await?;
        tx.commit().await?;
        Ok(n)
    }

    async fn fail_stale_runs_in(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        organization_id: Uuid,
        stream_id: Uuid,
    ) -> Result<u64> {
        let n = sqlx::query(
            "UPDATE ingest_run
             SET status='failed', finished_at=now(),
                 counts = counts || '{\"superseded\": true}'::jsonb
             WHERE organization_id=$1 AND stream_id=$2 AND status='running'
               AND last_heartbeat_at < now() - make_interval(secs => $3)",
        )
        .bind(organization_id)
        .bind(stream_id)
        .bind(STALE_RUN_THRESHOLD_SECS)
        .execute(&mut **tx)
        .await?
        .rows_affected();
        Ok(n)
    }
}
