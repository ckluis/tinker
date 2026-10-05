-- 0044_record_embeddings: durable embedding cache for item-48 semantic
-- ranking of record search.
--
-- Why a plain table and not pgvector: the vendored PG16 is stock Debian
-- (no vector extension in the lib dir), and the self-healing story in
-- bin/pg-ensure.sh reinstalls from those vendored debs — a
-- non-vendored extension would silently break provisioning after a
-- rootfs roll. Cosine similarity over the candidate pool (<=200 rows)
-- is microseconds in Rust; no index structure is needed.
--
-- Write discipline: rows are written ONLY by the semantic search
-- decorator, which fills the cache lazily at query time (one batched
-- embed call for the query text plus cache misses, bounded by the
-- candidate-pool cap). The record write path never touches this table,
-- so post latency never pays provider round trips.
--
-- Staleness: exact, not TTL. A row is reused only when text_sha256
-- matches the sha256 hex of the CURRENT search_index.text_content for
-- the record AND dimensions match the provider's current output;
-- otherwise the decorator re-embeds and upserts. Restart-safe: the
-- cache is durable, so there is no boot-time re-embedding storm.
--
-- SECURITY: embeddings are derived from search_index.text_content,
-- which by policy never contains PII plaintext (see 0005_search.sql).
-- Tenant isolation: organization_id is in the PK and the RLS policy
-- mirrors search_index_org. Vectors are namespaced per
-- (provider_name, model) so a model swap can never silently reuse
-- another model's vectors.

CREATE TABLE IF NOT EXISTS record_embeddings(
    organization_id uuid NOT NULL REFERENCES organizations(id),
    object_id uuid NOT NULL,
    record_id uuid NOT NULL,
    provider_name text NOT NULL,
    model text NOT NULL,
    dimensions int NOT NULL CHECK (dimensions > 0),
    text_sha256 text NOT NULL,
    embedding bytea NOT NULL,
    embedded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, object_id, record_id, provider_name)
);
CREATE INDEX IF NOT EXISTS record_embeddings_lookup_idx
    ON record_embeddings (organization_id, provider_name, model);

ALTER TABLE record_embeddings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS record_embeddings_org ON record_embeddings;
CREATE POLICY record_embeddings_org ON record_embeddings
    USING (organization_id = current_setting('app.organization_id', true)::uuid);
