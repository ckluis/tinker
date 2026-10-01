-- M6 backlog: promote the run reconciliation fingerprint and run counts
-- from ingest_run.counts JSON to first-class columns for querying.
-- The counts JSON remains the source of truth for the nested profile;
-- these columns carry the scalar outcome of each run.
ALTER TABLE ingest_run
    ADD COLUMN IF NOT EXISTS fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS count_landed BIGINT,
    ADD COLUMN IF NOT EXISTS count_promoted BIGINT,
    ADD COLUMN IF NOT EXISTS count_linked BIGINT,
    ADD COLUMN IF NOT EXISTS count_created BIGINT,
    ADD COLUMN IF NOT EXISTS count_queued_for_review BIGINT,
    ADD COLUMN IF NOT EXISTS count_pages BIGINT,
    ADD COLUMN IF NOT EXISTS drift_breaking BOOLEAN,
    ADD COLUMN IF NOT EXISTS duration_millis BIGINT;

-- Honest backfill: the counts JSON already carries every one of these
-- values for completed runs (the pipeline has always written them).
-- Rows whose counts JSON lacks a key keep NULL for that column; failed
-- runs (counts = {"error": ...}) get NULLs throughout.
UPDATE ingest_run SET
    fingerprint = counts->>'fingerprint',
    count_landed = (counts->>'landed')::bigint,
    count_promoted = (counts->>'promoted')::bigint,
    count_linked = (counts->>'linked')::bigint,
    count_created = (counts->>'created')::bigint,
    count_queued_for_review = (counts->>'queued_for_review')::bigint,
    count_pages = (counts->>'pages')::bigint,
    drift_breaking = (counts->>'drift_breaking')::boolean,
    duration_millis = (counts->>'millis')::bigint
WHERE counts IS NOT NULL AND counts <> '{}'::jsonb;

-- The point of the promotion: query runs by fingerprint / outcome.
CREATE INDEX IF NOT EXISTS ix_ingest_run_fingerprint
    ON ingest_run (fingerprint);
CREATE INDEX IF NOT EXISTS ix_ingest_run_drift_breaking
    ON ingest_run (stream_id, drift_breaking) WHERE drift_breaking;
