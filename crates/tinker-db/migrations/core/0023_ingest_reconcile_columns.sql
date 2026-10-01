-- M6 hardening (post-M8 item 4): per-stream reconciliation rollup.
--
-- Reconciliation wrote only ingest_reconciliation rows; a stream's
-- last-known-good state was invisible without scanning history. These
-- columns carry the latest reconciliation outcome on the stream row
-- itself, populated atomically by Reconciler::reconcile in the same
-- transaction as the reconciliation row:
--   reconcile_fingerprint  sha256 of the canonical reconciliation
--                          outcome (stream, source object, counts,
--                          differences) — a stable identity for the
--                          observed state; a change across runs means
--                          the source shape drifted.
--   reconcile_seen_at      when the stream was last reconciled.
--   reconcile_expected     source_count at last reconciliation (the
--                          expectation: what the source reported).
--   reconcile_unexpected   differences at last reconciliation ('[]'
--                          when clean).
ALTER TABLE ingest_stream
    ADD COLUMN IF NOT EXISTS reconcile_fingerprint TEXT,
    ADD COLUMN IF NOT EXISTS reconcile_seen_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS reconcile_expected BIGINT,
    ADD COLUMN IF NOT EXISTS reconcile_unexpected JSONB NOT NULL DEFAULT '[]'::jsonb;

-- The existing tenant_isolation RLS policy on ingest_stream covers the
-- new columns (row-level, column-agnostic); no policy change needed.
