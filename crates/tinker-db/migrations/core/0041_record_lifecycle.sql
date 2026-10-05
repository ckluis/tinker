-- Item 40 (C1): per-record draft → review → publish lifecycle.
--
-- Storage design (documented in tinker-ontology/src/lifecycle.rs):
-- - `data.{slug}` rows hold PUBLISHED content only (lifecycle_state is
--   'published' or 'archived'). In-flight work never touches the data
--   table, so default readers structurally cannot see draft content —
--   no half-written record ever leaks through a missed predicate.
-- - `record_drafts` holds the working copy: draft → in_review → rejected.
--   One in-flight draft per existing record (partial unique index);
--   brand-new records (record_id NULL) may have several drafts per
--   author, each publishing as its own record.
-- - `record_versions` is the immutable publish history: one row per
--   publish, version_no tracking the data row's version.
-- - `ontology_objects.lifecycle_enabled`: when true, the governed
--   MutationConnector refuses direct create/update — writes must go
--   through the lifecycle engine (fail closed, never silently forked
--   into a draft).
--
-- Backfill: every pre-lifecycle row is published content by definition,
-- so existing rows become 'published'.

-- 1. Per-object lifecycle opt-in flag.
ALTER TABLE ontology_objects
    ADD COLUMN IF NOT EXISTS lifecycle_enabled boolean NOT NULL DEFAULT false;

-- (Membership roles are free-form per 0014's memberships_role_sane, so
-- 'reviewer' needs no schema change.)

-- 2. In-flight drafts.
CREATE TABLE record_drafts (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    draft_id        uuid NOT NULL DEFAULT gen_random_uuid(),
    object_id       uuid NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    record_id       uuid NULL,
    state           text NOT NULL CHECK (state IN ('draft', 'in_review', 'rejected')),
    content         jsonb NOT NULL,
    base_version    bigint NULL,
    created_by      uuid NOT NULL,
    updated_by      uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, draft_id)
);

-- One in-flight draft per existing record: concurrent drafts of the same
-- record would be an unresolvable merge, so the second fails closed.
CREATE UNIQUE INDEX idx_record_drafts_one_per_record
    ON record_drafts (organization_id, object_id, record_id)
    WHERE record_id IS NOT NULL;

CREATE INDEX idx_record_drafts_lookup
    ON record_drafts (organization_id, object_id, created_by);

ALTER TABLE record_drafts ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'record_drafts' AND policyname = 'org_isolation'
    ) THEN
        CREATE POLICY org_isolation ON record_drafts
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

-- 3. Immutable publish history.
CREATE TABLE record_versions (
    organization_id     uuid NOT NULL REFERENCES organizations(id),
    object_id           uuid NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    record_id           uuid NOT NULL,
    version_no          bigint NOT NULL,
    content             jsonb NOT NULL,
    published_by        uuid NOT NULL,
    published_at        timestamptz NOT NULL DEFAULT now(),
    approval_request_id uuid NULL,
    PRIMARY KEY (organization_id, object_id, record_id, version_no)
);

CREATE INDEX idx_record_versions_lookup
    ON record_versions (organization_id, object_id, record_id);

ALTER TABLE record_versions ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'record_versions' AND policyname = 'org_isolation'
    ) THEN
        CREATE POLICY org_isolation ON record_versions
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

-- 3b. Lifecycle transition audit. Separate from mutation_audit (which is
-- scoped to direct create/update mutations with a NOT NULL record_id):
-- lifecycle transitions include draft events that precede any record.
CREATE TABLE lifecycle_audit (
    id                  uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    organization_id     uuid NOT NULL REFERENCES organizations(id),
    actor_id            uuid NOT NULL,
    object_id           uuid NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    record_id           uuid NULL,
    draft_id            uuid NULL,
    transition          text NOT NULL,
    before_json         jsonb NULL,
    after_json          jsonb NULL,
    approval_request_id uuid NULL,
    created_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_lifecycle_audit_lookup
    ON lifecycle_audit (organization_id, object_id, record_id, created_at);

ALTER TABLE lifecycle_audit ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'lifecycle_audit' AND policyname = 'org_isolation'
    ) THEN
        CREATE POLICY org_isolation ON lifecycle_audit
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON %I.record_drafts TO tinker_app', sch);
    -- Versions are append-only for the app: no UPDATE, ever.
    EXECUTE format(
        'GRANT SELECT, INSERT, DELETE ON %I.record_versions TO tinker_app', sch);
    -- Lifecycle audit is append-only: no UPDATE, no DELETE by the app.
    EXECUTE format(
        'GRANT SELECT, INSERT ON %I.lifecycle_audit TO tinker_app', sch);
END $$;

-- 4. lifecycle_state on every data table. New tables get the column in
-- the DDL (tinker-ontology); this backfills the tables that already
-- exist. All existing rows are published content.
DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN SELECT api_slug FROM ontology_objects LOOP
        BEGIN
            EXECUTE format(
                'ALTER TABLE data.%I ADD COLUMN lifecycle_state text NOT NULL DEFAULT ''published'' CHECK (lifecycle_state IN (''published'',''archived''))',
                r.api_slug);
        EXCEPTION WHEN duplicate_column THEN
            -- Idempotent: a previous partial run already added it.
            NULL;
        WHEN undefined_table THEN
            -- Defensive: a registered object whose table was never
            -- created (should not happen; define_object is atomic).
            NULL;
        END;
    END LOOP;
END $$;
