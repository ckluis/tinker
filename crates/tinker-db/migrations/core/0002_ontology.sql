-- M0: ontology metadata plane (Twenty-style). Rows here DESCRIBE objects;
-- the DDL runner materializes them as real tables in the `data` schema.

-- scope_kind: 'platform' (base), 'portfolio', 'organization' (overlay).
-- Platform rows have organization_id NULL and are visible to every org.
CREATE TABLE IF NOT EXISTS ontology_objects(
    id uuid PRIMARY KEY,
    scope_kind text NOT NULL CHECK (scope_kind IN ('platform','portfolio','organization')),
    scope_id uuid,                       -- portfolio id or organization id; NULL for platform
    organization_id uuid REFERENCES organizations(id),  -- NULL unless scope_kind='organization'
    pack_id text,                        -- e.g. 'community.crm'; NULL for ad-hoc
    pack_version text,
    name text NOT NULL,                  -- display name, mutable
    api_slug text NOT NULL,              -- validated slug, used for the physical table
    label text NOT NULL,
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('draft','active','deprecated','blocked')),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(scope_kind, scope_id, api_slug)
);

CREATE TABLE IF NOT EXISTS ontology_fields(
    id uuid PRIMARY KEY,
    object_id uuid NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    organization_id uuid REFERENCES organizations(id),  -- NULL for platform/pack fields
    physical_column text NOT NULL,       -- stable physical column name, e.g. f_a3k9_name
    name text NOT NULL,                  -- display name, mutable
    api_name text NOT NULL,              -- validated slug
    label text NOT NULL,
    field_type text NOT NULL CHECK (field_type IN (
        'text','richtext','number','date','datetime','boolean',
        'select','multi_select','currency','email','phone','url',
        'relation','file')),
    options_json jsonb NOT NULL DEFAULT '{}',  -- select options, relation target, etc.
    relation_target_id uuid REFERENCES ontology_objects(id),
    required boolean NOT NULL DEFAULT false,
    state text NOT NULL DEFAULT 'active' CHECK (state IN ('active','deprecated','blocked')),
    version bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(object_id, physical_column),
    UNIQUE(object_id, api_name)
);
CREATE INDEX IF NOT EXISTS ontology_fields_object_idx ON ontology_fields(object_id);

-- Every metadata change is audited with its DDL outcome.
CREATE TABLE IF NOT EXISTS ontology_changes(
    organization_id uuid REFERENCES organizations(id),
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    object_id uuid REFERENCES ontology_objects(id),
    change_kind text NOT NULL,           -- object.created, field.added, ...
    detail jsonb NOT NULL DEFAULT '{}',
    ddl_statements text[] NOT NULL DEFAULT '{}',
    applied_at timestamptz NOT NULL DEFAULT now(),
    applied_by uuid,
    PRIMARY KEY (id)
);

ALTER TABLE ontology_objects ENABLE ROW LEVEL SECURITY;
-- Fail closed: platform base plus the caller's own organization overlay.
-- Portfolio membership does not exist yet; portfolio rows stay invisible
-- until M1 defines the membership model (BACKLOG.md).
CREATE POLICY ontology_objects_visible ON ontology_objects
    USING (scope_kind = 'platform'
        OR (scope_kind = 'organization'
            AND organization_id = current_setting('app.organization_id', true)::uuid));

ALTER TABLE ontology_fields ENABLE ROW LEVEL SECURITY;
CREATE POLICY ontology_fields_visible ON ontology_fields
    USING (
        organization_id IS NULL
        OR organization_id = current_setting('app.organization_id', true)::uuid
    );

ALTER TABLE ontology_changes ENABLE ROW LEVEL SECURITY;
CREATE POLICY ontology_changes_org ON ontology_changes
    USING (organization_id IS NULL
        OR organization_id = current_setting('app.organization_id', true)::uuid);
