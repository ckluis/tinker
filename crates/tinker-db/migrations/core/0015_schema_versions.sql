-- M4: immutable schema versions for per-organization ontology evolution.
--
-- A company evolves its schema (add field / add relation) as a new
-- immutable version: draft -> preview -> canary -> active. Promotion and
-- rollback flip the single active pointer in one transaction. Versions are
-- per (organization, object), so a canary/promote/rollback in one company
-- never touches a sibling.
--
-- The version spec is an immutable snapshot of the fields ADDED in that
-- version (additive only in M4). The physical columns live in the org's
-- extension table (data.ext_<org>_<obj>), created by the evolver; the base
-- table is never altered by evolution, so rolling back is a pointer flip.

CREATE TABLE schema_versions (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    object_id uuid NOT NULL REFERENCES ontology_objects(id),
    version_number integer NOT NULL CHECK (version_number >= 1),
    parent_version_id uuid REFERENCES schema_versions(id),
    status text NOT NULL CHECK (status IN (
        'draft', 'preview', 'canary', 'active', 'superseded', 'rolled_back'
    )),
    -- Immutable snapshot of fields added in this version:
    -- {"fields": [{"api_name","label","field_type","physical_column",
    --              "relation_target_id" (nullable), "options" (nullable)}]}
    spec jsonb NOT NULL DEFAULT '{"fields": []}',
    -- Canary cohort: null = every org member may use the canary;
    -- otherwise an array of actor UUIDs allowed to resolve it.
    canary_cohort jsonb,
    created_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, object_id, version_number)
);

-- Exactly one live pointer per lifecycle stage per (org, object).
CREATE UNIQUE INDEX schema_versions_one_active
    ON schema_versions (organization_id, object_id)
    WHERE status = 'active';
CREATE UNIQUE INDEX schema_versions_one_canary
    ON schema_versions (organization_id, object_id)
    WHERE status = 'canary';
CREATE UNIQUE INDEX schema_versions_one_preview
    ON schema_versions (organization_id, object_id)
    WHERE status = 'preview';

CREATE INDEX schema_versions_org_object
    ON schema_versions (organization_id, object_id, version_number);

ALTER TABLE schema_versions ENABLE ROW LEVEL SECURITY;

CREATE POLICY schema_versions_org_isolation ON schema_versions
    USING (organization_id = current_setting('app.organization_id', true)::uuid);
