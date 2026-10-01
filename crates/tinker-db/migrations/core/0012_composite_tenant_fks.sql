-- M1 secure: composite tenant foreign keys.
--
-- Single-column FKs (actor_id → actors(id)) let a row in org A reference an
-- actor/workspace/app from org B at the database level; only application
-- discipline prevented it. Composite FKs on (organization_id, id) make
-- cross-organization references impossible in the schema itself.
--
-- Parent-side UNIQUE(organization_id, id) constraints are the new targets.
-- Nullable created_by FKs use MATCH SIMPLE semantics: NULL skips the check.

-- Parent targets.
ALTER TABLE actors
    ADD CONSTRAINT uq_actors_org_id UNIQUE (organization_id, id);
ALTER TABLE workspaces
    ADD CONSTRAINT uq_workspaces_org_id UNIQUE (organization_id, id);
ALTER TABLE apps
    ADD CONSTRAINT uq_apps_org_id UNIQUE (organization_id, id);

-- memberships.actor_id
ALTER TABLE memberships DROP CONSTRAINT memberships_actor_id_fkey;
ALTER TABLE memberships ADD CONSTRAINT fk_memberships_actor
    FOREIGN KEY (organization_id, actor_id)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;

-- auth_credentials.actor_id
ALTER TABLE auth_credentials DROP CONSTRAINT auth_credentials_actor_id_fkey;
ALTER TABLE auth_credentials ADD CONSTRAINT fk_auth_credentials_actor
    FOREIGN KEY (organization_id, actor_id)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;

-- auth_challenges.actor_id
ALTER TABLE auth_challenges DROP CONSTRAINT auth_challenges_actor_id_fkey;
ALTER TABLE auth_challenges ADD CONSTRAINT fk_auth_challenges_actor
    FOREIGN KEY (organization_id, actor_id)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;

-- sessions.actor_id / sessions.workspace_id
ALTER TABLE sessions DROP CONSTRAINT sessions_actor_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT fk_sessions_actor
    FOREIGN KEY (organization_id, actor_id)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;
ALTER TABLE sessions DROP CONSTRAINT sessions_workspace_id_fkey;
ALTER TABLE sessions ADD CONSTRAINT fk_sessions_workspace
    FOREIGN KEY (organization_id, workspace_id)
    REFERENCES workspaces (organization_id, id) ON DELETE CASCADE;

-- grants.actor_id / grants.created_by
ALTER TABLE grants DROP CONSTRAINT grants_actor_id_fkey;
ALTER TABLE grants ADD CONSTRAINT fk_grants_actor
    FOREIGN KEY (organization_id, actor_id)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;
ALTER TABLE grants DROP CONSTRAINT grants_created_by_fkey;
ALTER TABLE grants ADD CONSTRAINT fk_grants_created_by
    FOREIGN KEY (organization_id, created_by)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;

-- apps.workspace_id / apps.created_by
ALTER TABLE apps DROP CONSTRAINT apps_workspace_id_fkey;
ALTER TABLE apps ADD CONSTRAINT fk_apps_workspace
    FOREIGN KEY (organization_id, workspace_id)
    REFERENCES workspaces (organization_id, id) ON DELETE CASCADE;
ALTER TABLE apps DROP CONSTRAINT apps_created_by_fkey;
ALTER TABLE apps ADD CONSTRAINT fk_apps_created_by
    FOREIGN KEY (organization_id, created_by)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;

-- app_versions.app_id / app_versions.created_by
ALTER TABLE app_versions DROP CONSTRAINT app_versions_app_id_fkey;
ALTER TABLE app_versions ADD CONSTRAINT fk_app_versions_app
    FOREIGN KEY (organization_id, app_id)
    REFERENCES apps (organization_id, id) ON DELETE CASCADE;
ALTER TABLE app_versions DROP CONSTRAINT app_versions_created_by_fkey;
ALTER TABLE app_versions ADD CONSTRAINT fk_app_versions_created_by
    FOREIGN KEY (organization_id, created_by)
    REFERENCES actors (organization_id, id) ON DELETE CASCADE;
