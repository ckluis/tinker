-- 0032_stored_files: governed file/blob subsystem (Directus C7).
--
-- The `file` ontology field kind previously had no storage behind it:
-- a TEXT column holding an ungoverned string. This table is the
-- registry: tenant-scoped metadata + content addressing. BYTES NEVER
-- TOUCH POSTGRES — they live on the configured FileBackend
-- (local filesystem content-addressed store by default), isolated
-- per organization. The PII store stays physically separate; a file
-- that contains PII is flagged via pii_class, audited on every
-- access, and never copied into PG columns.
--
-- Retention interplay: file rows carry created_at, so the retention
-- engine's object_key convention applies (e.g. object_key
-- 'stored_files'); FileStore.apply_retention deletes backend bytes
-- AND registry rows for expired files, and honors legal_hold by
-- skipping deletion (mirroring tinker-transfer's apply_core
-- semantics, extended to bytes).

CREATE TABLE IF NOT EXISTS stored_files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    uploaded_by     UUID,
    -- Operator-facing name; the backend key is content-derived.
    name            TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 256),
    mime            TEXT NOT NULL CHECK (mime LIKE '%/%'),
    byte_size       BIGINT NOT NULL CHECK (byte_size >= 0),
    sha256          TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    backend         TEXT NOT NULL DEFAULT 'fs' CHECK (char_length(backend) BETWEEN 1 AND 32),
    -- Backend-local key, never an absolute path (backends resolve it
    -- under their own root; storage keys must not escape the root).
    storage_key     TEXT NOT NULL CHECK (char_length(storage_key) BETWEEN 1 AND 512),
    -- PII-safe handling: 'none' | 'pii' | 'restricted'. Flagged at
    -- upload; every fetch is audit-logged regardless of class.
    pii_class       TEXT NOT NULL DEFAULT 'none'
                    CHECK (pii_class IN ('none', 'pii', 'restricted')),
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'deleted')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_stored_files_org_id UNIQUE (organization_id, id),
    -- Content dedup within a tenant: same bytes, one row.
    CONSTRAINT uq_stored_files_org_sha UNIQUE (organization_id, sha256, byte_size)
);

ALTER TABLE stored_files ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stored_files_org ON stored_files;
CREATE POLICY stored_files_org ON stored_files
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

CREATE INDEX IF NOT EXISTS ix_stored_files_org_created
    ON stored_files (organization_id, created_at);
CREATE INDEX IF NOT EXISTS ix_stored_files_org_status
    ON stored_files (organization_id, status);

-- App role: full DML on its own tenant's rows (RLS enforces scope).
GRANT SELECT, INSERT, UPDATE, DELETE ON stored_files TO tinker_app;
