-- 0035: index for the ingest cross-stream identity lookup (item 29).
--
-- `IngestPipeline::find_candidates_tx` resolves a source id against every
-- stream of the organization ("the cross-stream external-id match"):
--   SELECT DISTINCT tinker_record_id FROM ingest_identity_link
--   WHERE organization_id=$1 AND source_id=$2
-- The pre-existing unique index is (organization_id, stream_id,
-- source_id); without a stream_id predicate Postgres scans every link of
-- the organization per candidate lookup, so the lookup degrades linearly
-- as the link table grows. This index makes the designed query an
-- index-only seek. Purely additive: no table rewrite, no behavior
-- change.
CREATE INDEX IF NOT EXISTS ix_ingest_identity_link_org_source
    ON ingest_identity_link (organization_id, source_id);
