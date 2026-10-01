-- Automations over sealed fields (docs/automations.md).
--
-- automations        saved definitions. Sensitive-field condition
--                    literals are stored ONLY as blind-index digests.
-- automation_events  transactional outbox: written in the same transaction
--                    as the record mutation, so an event exists iff the
--                    write committed. Workers claim with SKIP LOCKED.
-- automation_runs    one row per (automation, event): the idempotency
--                    fence and the run log (outcomes + keys, never values).
-- automation_saves   save log for the guessing guard (counts, no literals).

CREATE TABLE automations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    object_id       UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    name            TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    trigger         JSONB NOT NULL,
    conditions      JSONB NOT NULL DEFAULT '[]'::jsonb,
    actions         JSONB NOT NULL,
    run_as_actor    UUID NOT NULL,
    run_as_role     TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    version         BIGINT NOT NULL DEFAULT 1,
    created_by      UUID NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_automations_object ON automations (organization_id, object_id) WHERE enabled;

CREATE TABLE automation_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    object_id       UUID NOT NULL,
    record_id       UUID NOT NULL,
    kind            TEXT NOT NULL CHECK (kind IN ('created', 'updated', 'published')),
    changed         TEXT[] NOT NULL DEFAULT '{}',
    -- Chain depth: 0 for human/agent writes, n+1 for writes made by an
    -- automation action handling a depth-n event (loop guard).
    depth           INTEGER NOT NULL DEFAULT 0,
    caused_by       UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_until   TIMESTAMPTZ,
    processed_at    TIMESTAMPTZ
);
CREATE INDEX ix_automation_events_pending
    ON automation_events (organization_id, created_at) WHERE processed_at IS NULL;

CREATE TABLE automation_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    automation_id   UUID NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
    event_id        UUID NOT NULL,
    record_id       UUID NOT NULL,
    outcome         TEXT NOT NULL
                    CHECK (outcome IN ('skipped', 'succeeded', 'failed', 'loop_blocked')),
    detail          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (automation_id, event_id)
);
CREATE INDEX ix_automation_runs_automation ON automation_runs (automation_id, created_at DESC);

CREATE TABLE automation_saves (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id           UUID NOT NULL,
    automation_id      UUID NOT NULL,
    sensitive_literals INTEGER NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_automation_saves_actor ON automation_saves (organization_id, actor_id, created_at);

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['automations', 'automation_events', 'automation_runs', 'automation_saves']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format(
            $pol$CREATE POLICY %I ON %I
             USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
             WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)$pol$,
            'tenant_isolation_' || t, t
        );
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO tinker_app', t);
    END LOOP;
    -- The worker discovers which organizations have pending events on the
    -- owner handle (ids only), then processes each through tenant
    -- transactions. Everything except that discovery is FORCE'd.
    FOREACH t IN ARRAY ARRAY['automations', 'automation_runs', 'automation_saves']
    LOOP
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END
$$;
