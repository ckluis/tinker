-- M1 security fix: session token lookup is the pre-tenant bootstrap.
--
-- `load_session`, `touch`, and `revoke` resolve a session from its cookie
-- token BEFORE the organization is known, so they cannot set
-- `app.organization_id` first. With FORCE ROW LEVEL SECURITY the owner /
-- system pool matched zero rows and every login silently produced no
-- session (fail-closed in the wrong direction: authentication itself
-- broke).
--
-- Remove FORCE (keep RLS enabled): the owner role is the designated
-- system scope and may resolve sessions by token hash; the app role
-- remains bound by the tenant_isolation policy. All tenant data paths
-- continue to use the app role with a transaction-local tenant context.
-- No other table is changed: every other forced table is always accessed
-- with the tenant context set.

ALTER TABLE sessions NO FORCE ROW LEVEL SECURITY;
