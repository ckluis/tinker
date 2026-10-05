-- 0020: M7 — context and agents.
--
-- Governed agent attachment, versioned context profiles, per-role semantic
-- field policies, model providers with placement policy, spend budgets,
-- approval flows, disclosure audit, expansion manifests, and the
-- transform cache.
--
-- Conventions (same as 0018/0019): composite (organization_id, parent_id)
-- FKs so a child row can only reference a parent in its own org;
-- NULLIF-guarded RLS as the tenant backstop (the recycled-connection ''
-- quirk from 0017); explicit tinker_app DML grants per table.

-- Parent-side composite unique keys (FK targets need them).
-- NOTE: uq_actors_org_id on actors(organization_id, id) already exists from
-- 0012_composite_tenant_fks; the tenant FKs below reference it.

-- 1. Governed agent attachment. Attaching an agent is a configuration
-- operation: diffable (scope/grants/policy/budgets are data), reviewable
-- (status), versioned (updated_at), rollback-able (revoke).
CREATE TABLE IF NOT EXISTS agent_attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        UUID NOT NULL,
    name            TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    kind            TEXT NOT NULL CHECK (char_length(kind) BETWEEN 1 AND 64),
    -- scope: {root_objects: ["crm_company", ...],
    --         allowed_relation_types: ["crm_deal.company", ...],
    --         max_depth: 2}
    scope           JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- action_grants: ["deal.add_note", "task.create", "email.create_draft"]
    action_grants   JSONB NOT NULL DEFAULT '[]'::jsonb,
    -- approval_policy: {human_before_external_send: true, ...}
    approval_policy JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- budgets: {max_runs_per_hour: 50, max_tool_steps: 12}
    budgets         JSONB NOT NULL DEFAULT '{}'::jsonb,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_agent_attachments_actor_tenant
        FOREIGN KEY (organization_id, actor_id)
        REFERENCES actors (organization_id, id) ON DELETE CASCADE
);
ALTER TABLE agent_attachments
    ADD CONSTRAINT uq_agent_attachments_org_id UNIQUE (organization_id, id);

-- 2. Context profiles: versioned ontology artifacts. A profile is the
-- product/feature's declared context contract: root objects, relation
-- depth, permitted fields, token budget, ranking policy, freshness
-- threshold. Released profiles are immutable (trigger below); change
-- means a new version plus an active-pointer flip, and health gates can
-- roll the pointer back.
CREATE TABLE IF NOT EXISTS context_profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    profile_key     TEXT NOT NULL CHECK (char_length(profile_key) BETWEEN 1 AND 128),
    version         BIGINT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'released', 'rolled_back')),
    definition      JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active       BOOLEAN NOT NULL DEFAULT false,
    released_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, profile_key, version)
);
-- Exactly one active version per (org, key). The active pointer is the
-- release mechanism: flip it forward to promote, back to roll back.
CREATE UNIQUE INDEX IF NOT EXISTS uq_context_profiles_one_active
    ON context_profiles (organization_id, profile_key) WHERE is_active;

-- Immutability: a non-draft profile's definition is frozen (M1 pattern
-- from app_versions).
CREATE OR REPLACE FUNCTION freeze_released_context_profile()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status <> 'draft'
       AND OLD.definition IS DISTINCT FROM NEW.definition THEN
        RAISE EXCEPTION 'context profile % is % and immutable', OLD.id, OLD.status
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_freeze_context_profile ON context_profiles;
CREATE TRIGGER trg_freeze_context_profile
    BEFORE UPDATE ON context_profiles
    FOR EACH ROW EXECUTE FUNCTION freeze_released_context_profile();

-- 3. Per-role declarative field policies (PRD §15 "field-policy
-- sketches"). The transform engine reads these after the field_grants
-- allowlist: actual/omit/bucket/range/round/mask/tokenize are rules;
-- llm_transform routes the value through the model gateway.
CREATE TABLE IF NOT EXISTS field_transforms (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    object_id       UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (char_length(role) BETWEEN 1 AND 64),
    field_api_name  TEXT NOT NULL,
    transform       JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, object_id, role, field_api_name)
);
CREATE INDEX IF NOT EXISTS idx_field_transforms_lookup
    ON field_transforms (organization_id, object_id, role);

-- 4. Model providers: hosted and private endpoints behind adapters.
-- placement_boundary records the org policy constraint (e.g.
-- 'org-controlled'): content must not leave the boundary.
CREATE TABLE IF NOT EXISTS model_providers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name              TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    kind              TEXT NOT NULL
                      CHECK (kind IN ('hosted', 'private', 'fake', 'unavailable')),
    placement_boundary TEXT NOT NULL DEFAULT 'org-controlled',
    status            TEXT NOT NULL DEFAULT 'available'
                      CHECK (status IN ('available', 'unavailable', 'degraded')),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);
ALTER TABLE model_providers
    ADD CONSTRAINT uq_model_providers_org_id UNIQUE (organization_id, id);

-- 5. Spend ledger: per-attachment, per-hour-window budget accounting.
-- Budgets are first-class runtime telemetry (PRD §33).
CREATE TABLE IF NOT EXISTS spend_ledger (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    attachment_id   UUID NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    runs            INT NOT NULL DEFAULT 0,
    tool_steps      INT NOT NULL DEFAULT 0,
    tokens_spent    BIGINT NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, attachment_id, window_start),
    CONSTRAINT fk_spend_ledger_attachment_tenant
        FOREIGN KEY (organization_id, attachment_id)
        REFERENCES agent_attachments (organization_id, id) ON DELETE CASCADE
);

-- 6. Approval requests: typed actions that need a human (or policy)
-- decision queue here. Idempotency keys make retries safe.
CREATE TABLE IF NOT EXISTS approval_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    attachment_id   UUID NOT NULL,
    action_name     TEXT NOT NULL,
    payload         JSONB NOT NULL DEFAULT '{}'::jsonb,
    idempotency_key TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'approved', 'denied', 'executed', 'expired')),
    decided_by      UUID,
    decided_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, idempotency_key),
    CONSTRAINT fk_approval_requests_attachment_tenant
        FOREIGN KEY (organization_id, attachment_id)
        REFERENCES agent_attachments (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_approval_requests_pending
    ON approval_requests (organization_id, attachment_id)
    WHERE status = 'pending';

-- 7. Disclosure audit: which policy and transform produced each emitted
-- value — not a second copy of secrets. For model transforms this also
-- records input lineage, model/profile version, output hash, review
-- state per the retention policy.
CREATE TABLE IF NOT EXISTS disclosure_audit (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL,
    attachment_id    UUID,
    actor_id         UUID,
    virtual_path     TEXT NOT NULL,
    policy_version   TEXT NOT NULL,
    transform_version TEXT NOT NULL,
    purpose          TEXT NOT NULL,
    input_hash       TEXT NOT NULL,
    output_hash      TEXT NOT NULL,
    model_ref        TEXT,
    review_state     TEXT NOT NULL DEFAULT 'final',
    emitted_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_disclosure_audit_attachment_tenant
        FOREIGN KEY (organization_id, attachment_id)
        REFERENCES agent_attachments (organization_id, id) ON DELETE SET NULL
);

-- 8. Expansion manifests: what the graph planner traversed and what it
-- truncated, with continuation handles for high-cardinality branches.
CREATE TABLE IF NOT EXISTS expansion_manifests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    attachment_id   UUID NOT NULL,
    root_object     TEXT NOT NULL,
    root_record     UUID NOT NULL,
    traversed       JSONB NOT NULL DEFAULT '[]'::jsonb,
    truncated       JSONB NOT NULL DEFAULT '[]'::jsonb,
    records         INT NOT NULL DEFAULT 0,
    tokens          BIGINT NOT NULL DEFAULT 0,
    depth_reached   INT NOT NULL DEFAULT 0,
    continuation    JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT fk_expansion_manifests_attachment_tenant
        FOREIGN KEY (organization_id, attachment_id)
        REFERENCES agent_attachments (organization_id, id) ON DELETE CASCADE
);

-- 9. Transform cache. The key binds record version, ontology version,
-- policy version, actor entitlement set, purpose, and transform version —
-- a broad output can never satisfy a narrower request (no privileged
-- cache). Revocation invalidates by policy version.
CREATE TABLE IF NOT EXISTS transform_cache (
    cache_key       TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    value           JSONB NOT NULL,
    policy_version  TEXT NOT NULL,
    transform_version TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_transform_cache_org_policy
    ON transform_cache (organization_id, policy_version);

-- RLS: tenant backstop on every M7 table (NULLIF guard, 0017 pattern).
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'agent_attachments', 'context_profiles', 'field_transforms',
        'model_providers', 'spend_ledger', 'approval_requests',
        'disclosure_audit', 'expansion_manifests', 'transform_cache'
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
        'agent_attachments', 'context_profiles', 'field_transforms',
        'model_providers', 'spend_ledger', 'approval_requests',
        'disclosure_audit', 'expansion_manifests', 'transform_cache'
    ]
    LOOP
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO tinker_app', t
        );
    END LOOP;
END
$$;
