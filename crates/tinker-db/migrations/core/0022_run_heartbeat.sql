-- 0022: ingest run liveness (heartbeat) + per-stream run serialization.
--
-- fail_stale_runs previously treated EVERY pre-existing `running` row as
-- crashed, so a second concurrent start_run on the same stream would
-- silently interleave with (or murder) a live run. Now:
--   1. last_heartbeat_at records run liveness (refreshed per page);
--      only runs whose heartbeat is older than the staleness threshold
--      are superseded.
--   2. A partial unique index guarantees at most one `running` row per
--      stream at the database level (backstop behind the application
--      advisory lock in start_run).

ALTER TABLE ingest_run
    ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Runs for one stream are serial: at most one `running` row per stream.
CREATE UNIQUE INDEX IF NOT EXISTS uq_ingest_run_active
    ON ingest_run (stream_id)
    WHERE status = 'running';
