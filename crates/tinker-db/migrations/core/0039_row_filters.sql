-- Item 38 (C2): row-level permission filters.
--
-- Filters stored per (organization_id, object_id, role) as DATA — field,
-- operator, value shapes — never raw SQL. The query compiler ANDs the
-- role's filters with the tenant predicate at SQL build time ("policy
-- before ranking"): a row the actor's role cannot see never reaches
-- matching, ranking, snippets, or counts.
--
-- operator: eq | ne | in | lt | lte | gt | gte | is_null | is_not_null
-- value: a JSON constant, or {"actor": "id"} for a per-caller reference
--        (v1: only actor.id). NULL/omitted for is_null/is_not_null.
-- position: deterministic AND order (semantics are order-independent).
--
-- Semantics: no rows for (org, object, role) = default-open (documented;
-- matches field_grants). A filter matching nothing returns nothing —
-- never a "forbidden vs absent" distinction.

CREATE TABLE row_filters (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    object_id       uuid NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    role            text NOT NULL CHECK (char_length(role) BETWEEN 1 AND 64),
    field_api_name  text NOT NULL,
    operator        text NOT NULL,
    value           jsonb,
    position        int NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, object_id, role, field_api_name, position)
);

CREATE INDEX idx_row_filters_lookup
    ON row_filters (organization_id, object_id, role);

ALTER TABLE row_filters ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'row_filters' AND policyname = 'org_isolation'
    ) THEN
        CREATE POLICY org_isolation ON row_filters
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, DELETE ON %I.row_filters TO tinker_app', sch);
END $$;
