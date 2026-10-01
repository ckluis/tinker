-- Item 41 (C5): dashboard composer.
--
-- Dashboards are governed objects: org-scoped and RLS-isolated like every
-- other tenant table. Panels are embedded in `layout` as JSONB — each
-- panel carries its saved query (a QueryIntent), a visualization kind,
-- and grid geometry. The server accepts layout saves; drag-and-drop
-- itself is client-side (DataStar).
--
-- Security contract (enforced in tinker-query/src/dashboard.rs, not here):
-- - Panel queries are validated at SAVE time: each must compile under the
--   author's own row policy and field projection. Unknown objects/fields,
--   hidden fields, and bad operators fail the save, never render.
-- - Render ALWAYS executes each panel's query under the VIEWER's
--   permissions (row filters, field projection, lifecycle visibility).
--   A dashboard shared from a privileged author to a restricted viewer
--   shows the viewer only what they may see — no privilege escalation
--   via shared dashboards.
-- - Panel failures are per-panel: one bad panel never breaks the
--   dashboard.
--
-- `layout` shape: [{id, query, visualization, x, y, w, h}]. The shape is
-- validated in Rust on every write; a corrupt layout fails closed on
-- read (never silently treated as empty).
--
-- `created_by` is informational (no FK): actors may be removed while
-- their dashboards remain org property.

CREATE TABLE dashboards (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id),
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '',
    layout          jsonb NOT NULL DEFAULT '[]',
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_dashboards_org ON dashboards (organization_id);

ALTER TABLE dashboards ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'dashboards' AND policyname = 'org_isolation'
    ) THEN
        CREATE POLICY org_isolation ON dashboards
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON %I.dashboards TO tinker_app', sch);
END $$;
