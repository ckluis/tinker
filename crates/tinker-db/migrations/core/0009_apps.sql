-- M1: app registry — versioned, immutable app definitions.
--
-- An app is a named container in an organization. Its content lives in
-- app_versions; once a version leaves 'draft' its definition is frozen by
-- the trigger below. Publishing creates a NEW version row — history is
-- never rewritten. Rollback (M4) is just re-pointing the published marker.

CREATE TABLE IF NOT EXISTS apps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    created_by      UUID REFERENCES actors(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    version         BIGINT NOT NULL DEFAULT 1,
    UNIQUE (organization_id, slug)
);

-- status: 'draft' | 'published' | 'archived'. Only one published version
-- per app at a time (partial unique index).
CREATE TABLE IF NOT EXISTS app_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    app_id          UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    version_number  INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'published', 'archived')),
    definition      JSONB NOT NULL,
    tokens          JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_by      UUID REFERENCES actors(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at    TIMESTAMPTZ,
    version         BIGINT NOT NULL DEFAULT 1,
    UNIQUE (app_id, version_number)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_app_versions_one_published
    ON app_versions (app_id) WHERE status = 'published';

-- Immutability: a non-draft version's definition and tokens are frozen.
CREATE OR REPLACE FUNCTION freeze_published_app_version()
RETURNS TRIGGER AS $$
BEGIN
    IF OLD.status <> 'draft'
       AND (OLD.definition IS DISTINCT FROM NEW.definition
            OR OLD.tokens IS DISTINCT FROM NEW.tokens) THEN
        RAISE EXCEPTION 'app version % is % and immutable', OLD.id, OLD.status
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_freeze_app_version ON app_versions;
CREATE TRIGGER trg_freeze_app_version
    BEFORE UPDATE ON app_versions
    FOR EACH ROW EXECUTE FUNCTION freeze_published_app_version();

-- Publishing is an explicit, auditable transition: exactly one published
-- version per app. Archive the old published row in the same statement
-- batch (callers should do this in one transaction).
CREATE OR REPLACE FUNCTION publish_app_version(p_version_id UUID)
RETURNS VOID AS $$
DECLARE v_app UUID;
BEGIN
    SELECT app_id INTO v_app FROM app_versions WHERE id = p_version_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'app version % not found', p_version_id
            USING ERRCODE = 'raise_exception';
    END IF;
    UPDATE app_versions
       SET status = 'archived'
     WHERE app_id = v_app AND status = 'published';
    UPDATE app_versions
       SET status = 'published', published_at = now()
     WHERE id = p_version_id AND status = 'draft';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'app version % is not a draft', p_version_id
            USING ERRCODE = 'raise_exception';
    END IF;
END;
$$ LANGUAGE plpgsql;

-- RLS: organization-scoped, fail closed.
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['apps','app_versions']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = t AND policyname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I
                 USING (organization_id = current_setting(''app.organization_id'', true)::uuid)
                 WITH CHECK (organization_id = current_setting(''app.organization_id'', true)::uuid)',
                t);
        END IF;
    END LOOP;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO tinker_app',
        sch);
END $$;
