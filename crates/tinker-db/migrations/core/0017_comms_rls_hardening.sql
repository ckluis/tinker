-- 0017: Harden the comms RLS tenant predicate against the pooled-
-- connection steady state.
--
-- PostgreSQL leaves a custom GUC as '' (not unset) after
-- `SET LOCAL app.organization_id = '<uuid>'` + COMMIT. Every recycled
-- tenant-pool connection therefore sits in an `app.organization_id = ''`
-- steady state. The 0016 policies evaluate
-- `current_setting('app.organization_id')::uuid`, so any context-free
-- query on these tables (a test assertion, an admin probe, a future code
-- path that forgets tenant_tx) fails with
-- `invalid input syntax for type uuid: ""` instead of failing closed
-- cleanly. The failure never leaks rows, but it is a reliability trap
-- and a confusing error.
--
-- The hardened predicate maps '' (and unset) to NULL, so the comparison
-- yields "no rows" instead of an error. Valid tenant contexts behave
-- exactly as before. This is strictly fail-closed in every case:
--   valid uuid -> scoped to that org (unchanged)
--   ''        -> no rows (was: uuid parse error)
--   unset     -> no rows (was: unrecognized-parameter error)
-- WITH CHECK rejects writes without a valid context, as before.

DROP POLICY delivery_outbox_tenant ON delivery_outbox;
CREATE POLICY delivery_outbox_tenant ON delivery_outbox
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

DROP POLICY notification_prefs_tenant ON notification_prefs;
CREATE POLICY notification_prefs_tenant ON notification_prefs
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

DROP POLICY comm_identity_disclosures_tenant ON comm_identity_disclosures;
CREATE POLICY comm_identity_disclosures_tenant ON comm_identity_disclosures
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);

DROP POLICY cross_plane_grants_tenant ON cross_plane_grants;
CREATE POLICY cross_plane_grants_tenant ON cross_plane_grants
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
