-- 0026: cross-plane grant USE audit trail (post-M8 backlog: the PRD calls
-- cross-plane grants "tenant-auditable", but grant use was never logged
-- and there was no list surface).
--
-- Every successful cross-plane read under a grant appends one row here.
-- Rows are pinned to the ACCESSED organization (same fail-closed RLS
-- shape as cross_plane_grants), so a tenant's admins can audit exactly
-- who looked at their threads, under which grant and purpose.

CREATE TABLE cross_plane_grant_uses (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The ACCESSED organization: rows are pinned here for fail-closed RLS.
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    grant_id         uuid NOT NULL REFERENCES cross_plane_grants(id) ON DELETE CASCADE,
    -- The EXTERNAL actor who performed the read.
    grantee_actor_id uuid NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    -- The thread that was read. No FK: the thread tables are
    -- install-scoped; the grant_id chain back to purpose is the join.
    thread_id        uuid NOT NULL,
    used_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX cross_plane_grant_uses_grant_idx
    ON cross_plane_grant_uses (grant_id, used_at DESC);
CREATE INDEX cross_plane_grant_uses_grantee_idx
    ON cross_plane_grant_uses (organization_id, grantee_actor_id, used_at DESC);
ALTER TABLE cross_plane_grant_uses ENABLE ROW LEVEL SECURITY;
CREATE POLICY cross_plane_grant_uses_tenant ON cross_plane_grant_uses
    USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
    WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid);
-- The app role appends use rows and reads the audit trail; it never
-- updates or deletes audit history.
GRANT SELECT, INSERT ON cross_plane_grant_uses TO tinker_app;
