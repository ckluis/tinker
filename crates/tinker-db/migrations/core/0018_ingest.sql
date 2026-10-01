-- 0018: M6 ingest control plane.
--
-- Managed ingestion: source connections, streams with durable cursors,
-- schema-version drift tracking, ingest runs, mappings, identity links,
-- review queue, field-level provenance, reconciliation runs.
--
-- Landing tables are physical per-stream tables created by the ingester
-- (ingest_landing_<stream>); this migration holds the control plane only.
-- All tables are tenant-scoped via organization_id with RLS fail-closed.

CREATE TABLE IF NOT EXISTS ingest_connection (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('salesforce')),
    name            TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    credential_ref  TEXT,
    state           TEXT NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'paused', 'error')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    version         BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_ingest_connection_org
    ON ingest_connection (organization_id);

CREATE TABLE IF NOT EXISTS ingest_stream (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connection_id   UUID NOT NULL REFERENCES ingest_connection(id) ON DELETE CASCADE,
    source_object   TEXT NOT NULL CHECK (char_length(source_object) BETWEEN 1 AND 120),
    cursor_kind     TEXT NOT NULL CHECK (cursor_kind IN ('updated_at', 'id')),
    cursor_state    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    version         BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT uq_ingest_stream UNIQUE (organization_id, connection_id, source_object)
);
CREATE INDEX IF NOT EXISTS ix_ingest_stream_conn
    ON ingest_stream (connection_id);

CREATE TABLE IF NOT EXISTS ingest_schema_version (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stream_id       UUID NOT NULL REFERENCES ingest_stream(id) ON DELETE CASCADE,
    fingerprint     TEXT NOT NULL,
    observed_schema JSONB NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ingest_schema_version UNIQUE (stream_id, fingerprint)
);

CREATE TABLE IF NOT EXISTS ingest_run (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stream_id       UUID NOT NULL REFERENCES ingest_stream(id) ON DELETE CASCADE,
    checkpoint_in   JSONB NOT NULL,
    checkpoint_out  JSONB,
    counts          JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL CHECK (status IN ('running', 'complete', 'failed')),
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_ingest_run_stream
    ON ingest_run (stream_id, started_at DESC);

-- Activated field mappings: source field -> ontology (object, field).
CREATE TABLE IF NOT EXISTS ingest_mapping (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stream_id       UUID NOT NULL REFERENCES ingest_stream(id) ON DELETE CASCADE,
    source_field    TEXT NOT NULL CHECK (char_length(source_field) BETWEEN 1 AND 120),
    target_object   TEXT NOT NULL CHECK (char_length(target_object) BETWEEN 1 AND 120),
    target_field    TEXT NOT NULL CHECK (char_length(target_field) BETWEEN 1 AND 120),
    transform       TEXT NOT NULL DEFAULT 'direct' CHECK (transform IN ('direct')),
    version         BIGINT NOT NULL DEFAULT 1,
    CONSTRAINT uq_ingest_mapping UNIQUE (organization_id, stream_id, source_field)
);

-- Identity decisions: source record -> canonical Tinker record.
-- Ambiguous matches NEVER create a row here; they go to the review queue.
CREATE TABLE IF NOT EXISTS ingest_identity_link (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stream_id       UUID NOT NULL REFERENCES ingest_stream(id) ON DELETE CASCADE,
    source_id       TEXT NOT NULL,
    tinker_record_id UUID NOT NULL,
    confidence      NUMERIC NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    decided_by      TEXT NOT NULL CHECK (decided_by IN ('auto', 'human')),
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_ingest_identity_link UNIQUE (organization_id, stream_id, source_id)
);
CREATE INDEX IF NOT EXISTS ix_ingest_identity_link_record
    ON ingest_identity_link (tinker_record_id);

-- Human review queue: ambiguous identity, schema drift, conflicts.
CREATE TABLE IF NOT EXISTS ingest_review_item (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stream_id       UUID NOT NULL REFERENCES ingest_stream(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('ambiguous_identity', 'schema_drift', 'conflict')),
    payload         JSONB NOT NULL,
    state           TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'resolved', 'rejected')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS ix_ingest_review_open
    ON ingest_review_item (organization_id, state) WHERE state = 'open';

-- Field-level provenance: every winning canonical value keeps its source.
CREATE TABLE IF NOT EXISTS ingest_provenance (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tinker_record_id UUID NOT NULL,
    field           TEXT NOT NULL,
    stream_id       UUID NOT NULL REFERENCES ingest_stream(id) ON DELETE CASCADE,
    source_id       TEXT NOT NULL,
    source_field    TEXT NOT NULL,
    value           JSONB,
    won_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_ingest_provenance_record
    ON ingest_provenance (organization_id, tinker_record_id);

CREATE TABLE IF NOT EXISTS ingest_reconciliation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stream_id       UUID NOT NULL REFERENCES ingest_stream(id) ON DELETE CASCADE,
    source_count    BIGINT NOT NULL,
    landed_count    BIGINT NOT NULL,
    differences     JSONB NOT NULL DEFAULT '[]'::jsonb,
    ran_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS: tenant backstop on every M6 table. Fail closed via NULLIF guard
-- (see 0017 for the recycled-connection '' quirk).
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'ingest_connection', 'ingest_stream', 'ingest_schema_version',
        'ingest_run', 'ingest_mapping', 'ingest_identity_link',
        'ingest_review_item', 'ingest_provenance', 'ingest_reconciliation'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'DROP POLICY IF EXISTS %I ON %I',
            'tenant_isolation_' || t, t
        );
        EXECUTE format(
            $pol$CREATE POLICY %I ON %I
             USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
             WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)$pol$,
            'tenant_isolation_' || t, t
        );
    END LOOP;
END
$$;
