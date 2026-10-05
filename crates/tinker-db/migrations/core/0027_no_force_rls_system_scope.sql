-- M1/post-M8 security fix: system-scope reads need owner RLS bypass.
--
-- Several code paths query through the owner / system pool BEFORE a tenant
-- context exists or can exist, so they cannot SET app.organization_id:
--
--   * auth_credentials + memberships: the OIDC pre-tenant login
--     (PgOidcBindingStore::find_actor_by_subject resolves the
--     (issuer, subject, org) binding and the actor's org list before any
--     tenant context exists; tinker-identity).
--   * workspaces + apps: Authorizer::authorize resolves a workspace- or
--     app-scoped request to its organization (org_of_workspace,
--     org_and_workspace_of_app) before the grant lookup can be scoped.
--   * actors: operator tooling (tinker-m7) resolves org/actor identity
--     through the owner DB, which is the designated identity store.
--
-- With FORCE ROW LEVEL SECURITY the non-superuser owner matched zero rows
-- on these tables and authentication/authorization silently broke
-- (fail-closed in the wrong direction). This went unnoticed while the
-- owner was a superuser, which bypasses even FORCE; least-privilege
-- owners (post-M8 item 11) exposed it.
--
-- Remove FORCE (keep RLS enabled): the owner role is the designated
-- system scope and may read these tables without a tenant context; the
-- app role remains bound by the tenant_isolation policy on every table.
-- All tenant data paths continue to use the app role with a
-- transaction-local tenant context. This mirrors 0011, which did the
-- same for sessions for the identical reason. No other table is changed:
-- every other forced table is only ever accessed with the tenant context
-- set (audited 2026-09-24).

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'auth_credentials', 'memberships', 'workspaces', 'apps', 'actors'
    ]
    LOOP
        EXECUTE format('ALTER TABLE %I NO FORCE ROW LEVEL SECURITY', t);
    END LOOP;
END $$;
