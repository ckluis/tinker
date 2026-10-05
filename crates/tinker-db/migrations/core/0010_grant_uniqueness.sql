-- M1 hardening: the grants uniqueness constraint in 0008 is
--   UNIQUE (organization_id, actor_id, scope_type, scope_id, action)
-- but organization-scoped grants store scope_id = NULL, and PostgreSQL
-- treats NULLs as distinct, so duplicate organization grants were
-- possible. Replace it with a COALESCE-based unique index so one row per
-- (organization, scope type, scope, actor, action) is enforced.
--
-- No now() predicate: index predicates must be IMMUTABLE. Expired rows
-- are cleaned by the application layer (Authorizer::grant deletes
-- expired conflicting rows before inserting), so the index stays total
-- and duplicates are impossible at the database level.

ALTER TABLE grants
    DROP CONSTRAINT IF EXISTS grants_organization_id_actor_id_scope_type_scope_id_action_key;

CREATE UNIQUE INDEX ux_grants_one_row_per_scope
    ON grants (organization_id,
               scope_type,
               COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'),
               actor_id,
               action);
