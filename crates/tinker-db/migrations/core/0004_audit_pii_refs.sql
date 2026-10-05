-- M0: audit trail and the core-side half of PII references.
-- pii_refs holds OPAQUE RANDOM TOKENS ONLY. No plaintext, no reversible
-- hashes of small identifier domains. The ciphertext lives in the separate
-- PII store; there is no foreign key, FDW, or dblink between the stores.

CREATE TABLE IF NOT EXISTS audit_events(
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    actor_id uuid,
    action text NOT NULL,
    resource_type text,
    resource_id text,
    status text NOT NULL,
    duration_ms int,
    row_count int,
    policy_version text,
    -- Audit records reference IDs, policy versions, and outcomes.
    -- NEVER credentials, response rows, raw tokens, or resolved PII.
    metadata jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id)
);
CREATE INDEX IF NOT EXISTS audit_events_action_idx
    ON audit_events(organization_id, action, created_at);

CREATE TABLE IF NOT EXISTS pii_refs(
    organization_id uuid NOT NULL REFERENCES organizations(id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    subject_id uuid NOT NULL,
    storage_class text NOT NULL,  -- e.g. 'pii.name', 'pii.email', 'secret.api_key'
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','revoked','tombstoned')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id)
);
CREATE INDEX IF NOT EXISTS pii_refs_subject_idx
    ON pii_refs(organization_id, subject_id);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_events_org ON audit_events
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

ALTER TABLE pii_refs ENABLE ROW LEVEL SECURITY;
CREATE POLICY pii_refs_org ON pii_refs
    USING (organization_id = current_setting('app.organization_id', true)::uuid);
