-- 0021: M8 — authority transfer and hardening.
--
-- Governed strangler migration (PRD v0.6 §22): per-system authority state
-- machine, field-level authority matrix, cutover/rollback/retire runs with
-- evidence checklists, dependency scanner over the strict reference graph,
-- replacement dashboard, host/portfolio telemetry with token-blind
-- aggregates, masked support sessions with second-party reveal, retention
-- with legal hold, two-store restore rehearsal, and the self-promotion
-- soak. Multi-instance sessions live behind a trait (see tinker-transfer);
-- no Redis schema is required in the database.
--
-- Conventions (same as 0018/0019/0020): composite (organization_id,
-- parent_id) FKs so a child row can only reference a parent in its own
-- org; NULLIF-guarded RLS as the tenant backstop (the recycled-connection
-- '' quirk from 0017); explicit tinker_app DML grants per table.
--
-- NOTE: uq_actors_org_id on actors(organization_id, id) exists from 0012;
-- tenant FKs below reference it.

-- 1. Source systems under strangler migration. One row per
-- (organization, external system). State machine (enforced in code):
--   connected -> mirrored -> augmented -> controlled -> primary
--   -> draining -> retired (terminal)
-- Rollback returns to mirrored from primary or draining.
CREATE TABLE IF NOT EXISTS transfer_systems (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    system_key      TEXT NOT NULL CHECK (char_length(system_key) BETWEEN 1 AND 128),
    display_name    TEXT NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 256),
    current_state   TEXT NOT NULL DEFAULT 'connected'
                    CHECK (current_state IN ('connected', 'mirrored', 'augmented',
                                             'controlled', 'primary', 'draining',
                                             'retired')),
    -- state_history: [{from, to, at, by, reason}] — the audit trail of
    -- every transition. Append-only in code; never rewritten.
    state_history   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- connector_state: 'registered' | 'removed'. Retirement requires
    -- 'removed': the connector and its credential are gone, not merely
    -- disabled. Verified by the retire gate against this row, not a claim.
    connector_state TEXT NOT NULL DEFAULT 'registered'
                    CHECK (connector_state IN ('registered', 'removed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, system_key)
);
ALTER TABLE transfer_systems
    ADD CONSTRAINT uq_transfer_systems_org_id UNIQUE (organization_id, id);

-- 2. Field-level authority matrix. Versioned policy: cutover supersedes
-- the old rows and inserts new ones; history is never rewritten. Exactly
-- one effective row per (org, object, field).
CREATE TABLE IF NOT EXISTS authority_matrix (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    system_id       UUID NOT NULL,
    object_id       UUID NOT NULL,
    field_api_name  TEXT NOT NULL CHECK (char_length(field_api_name) BETWEEN 1 AND 128),
    authority       TEXT NOT NULL CHECK (authority IN ('tinker', 'external')),
    version         BIGINT NOT NULL,
    effective_from  TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at   TIMESTAMPTZ,
    CONSTRAINT fk_authority_matrix_system_tenant
        FOREIGN KEY (organization_id, system_id)
        REFERENCES transfer_systems (organization_id, id) ON DELETE CASCADE
    -- No FK to ontology_objects: pack/platform objects carry
    -- organization_id NULL, so a composite tenant FK cannot reference
    -- them. Object visibility (platform or own-org) is enforced in code
    -- before any authority row is written.
);
-- Exactly one effective row per (org, object, field).
CREATE UNIQUE INDEX IF NOT EXISTS uq_authority_matrix_effective
    ON authority_matrix (organization_id, object_id, field_api_name)
    WHERE superseded_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_authority_matrix_system
    ON authority_matrix (organization_id, system_id) WHERE superseded_at IS NULL;

-- 3. Cutover / rollback / retire runs. The checklist is evidence, not a
-- boolean: every item carries who verified it, when, and what the
-- evidence was. kind='retire' requires the full cutover gate
-- (export_verified, rollback_procedure, owner_signoff, dependency_scan,
-- reconciliation_clean); kind='cutover' the same five; kind='rollback'
-- requires rollback_procedure + owner_signoff.
CREATE TABLE IF NOT EXISTS cutover_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    system_id       UUID NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('cutover', 'rollback', 'retire')),
    -- checklist: {item_key: {verified: bool, by: uuid, at: timestamptz,
    --                        evidence: text}}
    checklist       JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'complete', 'failed')),
    evidence        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    CONSTRAINT fk_cutover_runs_system_tenant
        FOREIGN KEY (organization_id, system_id)
        REFERENCES transfer_systems (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_cutover_runs_system
    ON cutover_runs (organization_id, system_id, kind);

-- 4. Strict reference graph for the dependency scanner. Populated from
-- apps, queries, views, transforms, mutation mappings, and agent
-- attachments. external_system_key is set when the edge's target is
-- still owned by an external system (authority='external') or the source
-- itself is the connector. Retirement is blocked while any edge points
-- at the retiring system.
CREATE TABLE IF NOT EXISTS dependency_edges (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_kind        TEXT NOT NULL CHECK (char_length(source_kind) BETWEEN 1 AND 64),
    source_id          TEXT NOT NULL CHECK (char_length(source_id) BETWEEN 1 AND 256),
    target_object_id   UUID,
    target_field_api   TEXT,
    edge_kind          TEXT NOT NULL CHECK (char_length(edge_kind) BETWEEN 1 AND 64),
    external_system_key TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_dependency_edges_system
    ON dependency_edges (organization_id, external_system_key);
CREATE INDEX IF NOT EXISTS ix_dependency_edges_source
    ON dependency_edges (organization_id, source_kind, source_id);

-- 5. Retention policies per (org, retained object). legal_hold suspends
-- deletion; without it, the engine deletes expired rows per policy.
CREATE TABLE IF NOT EXISTS retention_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    object_key      TEXT NOT NULL CHECK (char_length(object_key) BETWEEN 1 AND 256),
    retention_days  INT NOT NULL CHECK (retention_days >= 0),
    legal_hold      BOOLEAN NOT NULL DEFAULT false,
    last_run_at     TIMESTAMPTZ,
    last_run_result JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, object_key)
);

-- 6. Token-blind host/portfolio aggregates (PRD v0.6 §34). Aggregate
-- actors read only this table — and this table structurally cannot carry
-- message bodies, email content, field values, prompts, or record
-- payloads, because those columns do not exist. Counts and sums only.
CREATE TABLE IF NOT EXISTS host_usage_daily (
    host_id         UUID NOT NULL,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    day             DATE NOT NULL,
    metric_id       TEXT NOT NULL CHECK (char_length(metric_id) BETWEEN 1 AND 128),
    count_value     BIGINT NOT NULL DEFAULT 0,
    sum_value       NUMERIC NOT NULL DEFAULT 0,
    dimensions_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    policy_version  TEXT NOT NULL DEFAULT 'v1',
    dimensions_hash TEXT NOT NULL,
    collected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, organization_id, day, metric_id, dimensions_hash)
);

-- 7. Masked support sessions (PRD v0.6 §34). A support actor enters a
-- time-boxed, reason-bound session that is masked by default; a
-- sensitive reveal requires a second-party approval and becomes
-- tenant-visible audit.
CREATE TABLE IF NOT EXISTS support_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL,
    support_actor_id UUID NOT NULL,
    -- field_classes: {field_api_name: "restricted" | "operational"}.
    -- Restricted fields render as masked in this session.
    field_classes   JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason          TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1024),
    expires_at      TIMESTAMPTZ NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'expired', 'revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_support_sessions_actor_tenant
        FOREIGN KEY (organization_id, support_actor_id)
        REFERENCES actors (organization_id, id) ON DELETE CASCADE
);
ALTER TABLE support_sessions
    ADD CONSTRAINT uq_support_sessions_org_id UNIQUE (organization_id, id);

CREATE TABLE IF NOT EXISTS reveal_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    session_id      UUID NOT NULL,
    target_ref      TEXT NOT NULL CHECK (char_length(target_ref) BETWEEN 1 AND 512),
    reason          TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 1024),
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    requested_by    UUID NOT NULL,
    decided_by      UUID,
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_reveal_requests_session_tenant
        FOREIGN KEY (organization_id, session_id)
        REFERENCES support_sessions (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_reveal_requests_session
    ON reveal_requests (organization_id, session_id) WHERE status = 'pending';

-- 8. Tenant-visible support audit: every session open, reveal request,
-- reveal decision, and revocation is visible to the tenant org.
CREATE TABLE IF NOT EXISTS support_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    session_id      UUID,
    action          TEXT NOT NULL CHECK (char_length(action) BETWEEN 1 AND 64),
    actor_id        UUID,
    details         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_support_audit_session
    ON support_audit (organization_id, session_id);

-- 9. Restore manifests for the core store. The PII store has its own
-- manifest table (pii 0003); the *pairing* of the two manifests is the
-- product. A paired restore is compatible only when the windows overlap
-- and the reference watermarks are ordered; recovery then reconciles or
-- deletes orphaned writes.
CREATE TABLE IF NOT EXISTS restore_manifests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    store               TEXT NOT NULL DEFAULT 'core' CHECK (store = 'core'),
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    -- reference_watermark: the newest pii_ref (core) or value (pii)
    -- timestamp known-good at backup time. Recovery must not trust
    -- references newer than the PII window.
    reference_watermark TIMESTAMPTZ NOT NULL,
    -- signature: HMAC/operator signature over (store, window, watermark).
    -- Verified in code before a restore is rehearsed.
    signature           TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (window_end > window_start)
);

-- 10. Self-promotion soak. Every releasable definition is immutable after
-- release; promotion flips one active-version pointer. The soak runner
-- records each round; a health-gate failure rolls the pointer back
-- automatically and marks the candidate rolled_back — history is never
-- rewritten.
CREATE TABLE IF NOT EXISTS release_pointers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    definition_kind TEXT NOT NULL CHECK (char_length(definition_kind) BETWEEN 1 AND 64),
    definition_key  TEXT NOT NULL CHECK (char_length(definition_key) BETWEEN 1 AND 256),
    active_version  BIGINT NOT NULL DEFAULT 1,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, definition_kind, definition_key)
);

CREATE TABLE IF NOT EXISTS release_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    definition_kind TEXT NOT NULL,
    definition_key  TEXT NOT NULL,
    version         BIGINT NOT NULL,
    definition      JSONB NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'released', 'rolled_back')),
    -- checks: {compile: {...}, fixtures: {...}, preview: {...}, shadow: {...}}
    checks          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, definition_kind, definition_key, version)
);

CREATE TABLE IF NOT EXISTS promotion_soak_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    definition_kind TEXT NOT NULL,
    definition_key  TEXT NOT NULL,
    candidate_version BIGINT NOT NULL,
    checks          JSONB NOT NULL DEFAULT '{}'::jsonb,
    result          TEXT NOT NULL CHECK (result IN ('promoted', 'rolled_back', 'failed')),
    -- active_pointer_after: the pointer value after this run. A rollback
    -- must leave it exactly where it was.
    active_pointer_after BIGINT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- RLS: tenant backstop on every M8 table (NULLIF guard, 0017 pattern).
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'transfer_systems', 'authority_matrix', 'cutover_runs',
        'dependency_edges', 'retention_policies', 'host_usage_daily',
        'support_sessions', 'reveal_requests', 'support_audit',
        'restore_manifests', 'release_pointers', 'release_versions',
        'promotion_soak_runs'
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

-- Explicit app-role DML grants (owner runs DDL; the app role does DML).
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'transfer_systems', 'authority_matrix', 'cutover_runs',
        'dependency_edges', 'retention_policies', 'host_usage_daily',
        'support_sessions', 'reveal_requests', 'support_audit',
        'restore_manifests', 'release_pointers', 'release_versions',
        'promotion_soak_runs'
    ]
    LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO tinker_app', t
        );
    END LOOP;
END
$$;
