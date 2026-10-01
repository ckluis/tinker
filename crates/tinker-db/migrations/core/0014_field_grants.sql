-- M3: field-level projections. `field_grants` is an allowlist: when rows
-- exist for (organization_id, object_id, role), that role sees ONLY the
-- listed fields of the object. When no rows exist, the role sees all
-- fields (default-open; the CRM pack installer writes explicit rows for
-- restricted roles). The query compiler intersects `select` with the
-- projection and rejects filters/sorts on hidden fields — the SQL never
-- selects a hidden column, so there is no boolean-oracle leak.
--
-- M3 also widens `memberships.role`: M1's closed CHECK
-- ('owner','admin','member','viewer') cannot express company-defined
-- roles like 'sales' or 'support'. Roles are now free-form (validated
-- for length/sanity at the app layer).

ALTER TABLE memberships DROP CONSTRAINT IF EXISTS memberships_role_check;
ALTER TABLE memberships ADD CONSTRAINT memberships_role_sane
    CHECK (char_length(role) BETWEEN 1 AND 64);

CREATE TABLE field_grants (
    organization_id UUID NOT NULL,
    object_id       UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    role            TEXT NOT NULL CHECK (char_length(role) BETWEEN 1 AND 64),
    field_api_name  TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, object_id, role, field_api_name)
);

CREATE INDEX idx_field_grants_lookup
    ON field_grants (organization_id, object_id, role);

ALTER TABLE field_grants ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'field_grants' AND policyname = 'org_isolation'
    ) THEN
        CREATE POLICY org_isolation ON field_grants
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, DELETE ON %I.field_grants TO tinker_app', sch);
END $$;
