-- 0019: M6 hardening, part 1 — composite tenant FKs and mapping lifecycle.
--
-- 0018's single-column FKs (e.g. stream_id -> ingest_stream(id)) check the
-- id only: a buggy caller could pair org A's organization_id with org B's
-- stream id and the reference would still pass. Composite
-- (organization_id, parent_id) references close that hole — a child row can
-- only point at a parent row in the SAME organization.
--
-- Also adds the mapping lifecycle: draft -> proposed -> approved ->
-- activated. Promotion reads only 'activated' rows. New rows start as
-- drafts (fail closed); the operator fast path (put_mapping) activates
-- explicitly, and the deterministic proposer / AI assistants create
-- 'proposed' rows for human approval.

-- 1. Parent-side composite unique keys (FK targets need them).
ALTER TABLE ingest_connection
    ADD CONSTRAINT uq_ingest_connection_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_stream
    ADD CONSTRAINT uq_ingest_stream_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_schema_version
    ADD CONSTRAINT uq_ingest_schema_version_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_run
    ADD CONSTRAINT uq_ingest_run_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_mapping
    ADD CONSTRAINT uq_ingest_mapping_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_identity_link
    ADD CONSTRAINT uq_ingest_identity_link_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_review_item
    ADD CONSTRAINT uq_ingest_review_item_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_provenance
    ADD CONSTRAINT uq_ingest_provenance_org_id UNIQUE (organization_id, id);
ALTER TABLE ingest_reconciliation
    ADD CONSTRAINT uq_ingest_reconciliation_org_id UNIQUE (organization_id, id);

-- 2. Replace single-column FKs with composite tenant FKs.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT 'ingest_stream'::text AS child, 'connection_id'::text AS col,
               'ingest_connection'::text AS parent
        UNION ALL SELECT 'ingest_schema_version', 'stream_id', 'ingest_stream'
        UNION ALL SELECT 'ingest_run', 'stream_id', 'ingest_stream'
        UNION ALL SELECT 'ingest_mapping', 'stream_id', 'ingest_stream'
        UNION ALL SELECT 'ingest_identity_link', 'stream_id', 'ingest_stream'
        UNION ALL SELECT 'ingest_review_item', 'stream_id', 'ingest_stream'
        UNION ALL SELECT 'ingest_provenance', 'stream_id', 'ingest_stream'
        UNION ALL SELECT 'ingest_reconciliation', 'stream_id', 'ingest_stream'
    LOOP
        -- Drop 0018's single-column FK (conventional auto-generated name).
        EXECUTE format(
            'ALTER TABLE %I DROP CONSTRAINT IF EXISTS %I',
            r.child, r.child || '_' || r.col || '_fkey'
        );
        EXECUTE format(
            'ALTER TABLE %I ADD CONSTRAINT %I
             FOREIGN KEY (organization_id, %I)
             REFERENCES %I (organization_id, id) ON DELETE CASCADE',
            r.child,
            'fk_' || r.child || '_' || r.col || '_tenant',
            r.col,
            r.parent
        );
    END LOOP;
END
$$;

-- 3. Mapping lifecycle.
ALTER TABLE ingest_mapping
    ADD COLUMN state TEXT NOT NULL DEFAULT 'draft'
    CHECK (state IN ('draft', 'proposed', 'approved', 'activated'));
ALTER TABLE ingest_mapping
    ADD COLUMN proposal JSONB;

-- Rows written before the lifecycle existed came from put_mapping, the
-- operator fast path: they were activated mappings. Preserve that meaning.
UPDATE ingest_mapping SET state = 'activated' WHERE state = 'draft';
