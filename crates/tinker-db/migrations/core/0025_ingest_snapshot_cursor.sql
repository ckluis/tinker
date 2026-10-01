-- 0025: allow the snapshot cursor kind for non-monotonic sources.
--
-- Sources with out-of-order or rewritten history cannot be captured with a
-- monotonic `updated_at`/`id` cursor: the cursor would skip records whose
-- timestamps move backwards. The `snapshot` cursor kind tells the pipeline
-- to re-fetch the full source snapshot every run and land only the diff
-- (content-hash compare), marking mirror rows absent from the snapshot as
-- deleted. The durable cursor is not used as a resume point in this mode.
ALTER TABLE ingest_stream DROP CONSTRAINT IF EXISTS ingest_stream_cursor_kind_check;
ALTER TABLE ingest_stream
    ADD CONSTRAINT ingest_stream_cursor_kind_check
    CHECK (cursor_kind IN ('updated_at', 'id', 'snapshot'));
