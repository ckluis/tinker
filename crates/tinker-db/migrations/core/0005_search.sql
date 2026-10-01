-- M0: portable search baseline (tsvector/GIN + pg_trgm). This is the
-- SearchBackend every deployment has. TIN plugs in behind the same trait
-- where the extension is available.
--
-- SECURITY RULE: the core search index NEVER receives PII plaintext.
-- PII search, when enabled, runs inside the PII store and returns opaque
-- references. The indexer rejects storage_class values that name PII.

CREATE TABLE IF NOT EXISTS search_index(
    organization_id uuid NOT NULL REFERENCES organizations(id),
    object_id uuid NOT NULL,
    record_id uuid NOT NULL,
    field_versions jsonb NOT NULL DEFAULT '{}',
    text_content text NOT NULL,
    tsv tsvector GENERATED ALWAYS AS (to_tsvector('english', coalesce(text_content, ''))) STORED,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, object_id, record_id)
);
CREATE INDEX IF NOT EXISTS search_index_tsv_idx ON search_index USING GIN(tsv);
-- pg_trgm is required for the trigram similarity index. Install it if the
-- database does not have it (a manual install in the dev DB previously
-- masked this), and build the index with the operator class
-- schema-qualified so this migration applies under any search_path —
-- fresh databases and fresh schemas alike.
CREATE EXTENSION IF NOT EXISTS pg_trgm;
DO $$
DECLARE
    trigram_schema text;
BEGIN
    SELECT n.nspname INTO trigram_schema
    FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'pg_trgm';
    IF trigram_schema IS NULL THEN
        RAISE EXCEPTION 'pg_trgm extension is not installed';
    END IF;
    EXECUTE format(
        'CREATE INDEX IF NOT EXISTS search_index_trgm_idx ON search_index USING GIN (text_content %I.gin_trgm_ops)',
        trigram_schema
    );
END
$$;

ALTER TABLE search_index ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS search_index_org ON search_index;
CREATE POLICY search_index_org ON search_index
    USING (organization_id = current_setting('app.organization_id', true)::uuid);
