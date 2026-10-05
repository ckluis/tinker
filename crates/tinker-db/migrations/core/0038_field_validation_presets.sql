-- Item 37 (C3, Directus-derived ideas only): server-side field validation
-- rules + write presets, stored as field metadata.
--
-- validation_json: per-field validation rules as DATA (never code):
--   {"min": <f64>, "max": <f64>,            -- number value range, or text length range
--    "pattern": "<regex>",                   -- text-ish types only
--    "options": ["a", "b"]}                  -- explicit enum allow-list
-- `required` stays a first-class column (enforced by the mutation layer).
--
-- preset_json: forced defaults applied at write time by the governed
-- mutation connector:
--   {"mode": "when_missing"|"always",
--    "value": {"kind": "static", "value": <json>} | {"kind": "actor_id"}}
-- Presets apply BEFORE validation, so a preset can satisfy `required`.
-- Rules are org-scoped metadata (the field row carries organization_id)
-- and are versioned with the schema: M4 evolution carries them in the
-- version spec (SpecField), and add_field persists them.

ALTER TABLE ontology_fields
    ADD COLUMN IF NOT EXISTS validation_json jsonb NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS preset_json jsonb NOT NULL DEFAULT 'null'::jsonb;

-- Canonical "no preset" is JSON null, not '{}': an empty object cannot
-- decode as Option<WritePreset> and must never be stored. Normalize any
-- rows written while the default was the (buggy) '{}' so stored metadata
-- fails closed only on real corruption, not on the absence of a preset.
UPDATE ontology_fields
SET preset_json = 'null'::jsonb
WHERE preset_json = '{}'::jsonb;

-- Item 37: mutation audit. Every write through the governed mutation
-- connector records who wrote what, before/after images, and which
-- approval (if any) authorized it. Written in the same transaction as
-- the mutation itself, so the log cannot describe a write that rolled
-- back -- and a committed write is never missing its audit row.
CREATE TABLE IF NOT EXISTS mutation_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        UUID NOT NULL,
    object_id       UUID NOT NULL REFERENCES ontology_objects(id) ON DELETE CASCADE,
    record_id       UUID NOT NULL,
    operation       TEXT NOT NULL CHECK (operation IN ('create', 'update')),
    before_json     JSONB,              -- NULL on create
    after_json      JSONB NOT NULL,     -- post-preset, post-validation values by api_name
    approval_request_id UUID,           -- consumed approval, if the write required one
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_mutation_audit_org_time
    ON mutation_audit (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_mutation_audit_record
    ON mutation_audit (organization_id, object_id, record_id);

ALTER TABLE mutation_audit ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'mutation_audit' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON mutation_audit
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT ON %I.mutation_audit TO tinker_app', sch);
END $$;
