-- M2: governed reactivity loop — query audit log.
--
-- Every executed typed query records who ran what, against which object,
-- how many rows came back, and how long it took. The audit row is written
-- by the executor in the same tenant context as the query itself, so the
-- log cannot attribute one org's query to another.

CREATE TABLE IF NOT EXISTS query_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        UUID NOT NULL,
    object_id       UUID,
    sql_hash        TEXT NOT NULL,
    row_count       INTEGER NOT NULL,
    duration_ms     INTEGER NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_query_audit_org_time
    ON query_audit (organization_id, created_at DESC);

ALTER TABLE query_audit ENABLE ROW LEVEL SECURITY;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'query_audit' AND policyname = 'tenant_isolation'
    ) THEN
        CREATE POLICY tenant_isolation ON query_audit
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT ON %I.query_audit TO tinker_app', sch);
END $$;
