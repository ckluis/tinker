-- Item 39 (C4): portable schema snapshot apply guard log.
--
-- One row per (organization, vendor) recording the newest snapshot
-- version applied and its payload hash. The applier semantics:
--   - same (vendor, version, payload hash) as the log row -> safe no-op
--     (reapplying the exact same artifact is idempotent);
--   - same (vendor, version) but a DIFFERENT hash -> reject (replay of a
--     substituted artifact);
--   - lower version -> reject (downgrade);
--   - higher version -> apply and advance the log row.
-- Any snapshot whose vendor_id does not match the expected vendor is
-- rejected. This table is the durable half of the version/vendor hash
-- guard; the signature check is the other half.

CREATE TABLE schema_snapshot_log (
    organization_id  uuid NOT NULL REFERENCES organizations(id),
    vendor_id        text NOT NULL CHECK (char_length(vendor_id) BETWEEN 1 AND 128),
    snapshot_version bigint NOT NULL CHECK (snapshot_version > 0),
    payload_sha256   text NOT NULL,
    applied_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, vendor_id)
);

ALTER TABLE schema_snapshot_log ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
        WHERE schemaname = current_schema()
          AND tablename = 'schema_snapshot_log' AND policyname = 'org_isolation'
    ) THEN
        CREATE POLICY org_isolation ON schema_snapshot_log
            USING (organization_id = current_setting('app.organization_id', true)::uuid)
            WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
    END IF;
END $$;

DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE ON %I.schema_snapshot_log TO tinker_app', sch);
END $$;
