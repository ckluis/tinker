-- 0034: inbound machine credentials (API keys) for the MCP HTTP/SSE
-- transport (Directus C6, second half).
--
-- Only SHA-256(secret) is stored; the plaintext is returned exactly once
-- at issuance/rotation. `key_prefix` (the first 12 chars, e.g.
-- `tk_a1B2c3D4e5`) is the lookup key — the key itself identifies the
-- organization, so verification cannot be tenant-RLS-scoped and runs
-- through the owner pool (table owners bypass RLS; this table is NOT
-- forced-RLS). The SHA-256 comparison is the authorization.
--
-- Scope grammar (enforced by the MCP HTTP layer, validated at issuance):
--   mcp:tools      — tools/list + tools/call on any tool
--   mcp:resources  — resources/list + resources/read
--   mcp:tool:<name> — tools/call on one named tool
CREATE TABLE IF NOT EXISTS machine_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    key_prefix      TEXT NOT NULL UNIQUE,
    key_hash        BYTEA NOT NULL,
    scopes          TEXT[] NOT NULL,
    expires_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    created_by      UUID REFERENCES actors(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_machine_credential_scopes
        CHECK (array_length(scopes, 1) > 0)
);

ALTER TABLE machine_credentials ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS machine_credentials_org ON machine_credentials;
CREATE POLICY machine_credentials_org ON machine_credentials
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

CREATE INDEX IF NOT EXISTS ix_machine_credentials_prefix
    ON machine_credentials (key_prefix) WHERE revoked_at IS NULL;
