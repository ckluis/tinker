-- M0: tenancy roots, data schema, and the application role.
-- The app NEVER connects as the owner (tinker_core): RLS is bypassed for
-- table owners, so tenant access goes through tinker_app, which owns nothing.

-- Application role: owns no tables, so RLS policies always apply to it.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tinker_app') THEN
        CREATE ROLE tinker_app LOGIN PASSWORD 'tinker_app_dev_pw';
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS hosts(
    id uuid PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organizations(
    id uuid PRIMARY KEY,
    host_id uuid NOT NULL REFERENCES hosts(id),
    name text NOT NULL,
    slug text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(host_id, slug)
);

CREATE TABLE IF NOT EXISTS workspaces(
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Required by later migrations (gen_random_uuid defaults). Install here so
-- a fresh database bootstraps without manual extension setup.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- User-defined ontology objects materialize as real tables here.
CREATE SCHEMA IF NOT EXISTS data;

-- Grants follow the schema/database the migration actually runs in, not
-- hardcoded names: the privileged bootstrap may install into a fresh
-- database or a dedicated schema, and the app role must reach the tables
-- wherever they land.
DO $$
DECLARE
    install_schema text := current_schema();
    db_name text := current_database();
    owner_role text := current_user;
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO tinker_app', db_name);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO tinker_app', install_schema);
    EXECUTE 'GRANT USAGE ON SCHEMA data TO tinker_app';
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO tinker_app',
        install_schema
    );
    EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA data TO tinker_app';
    EXECUTE format(
        'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO tinker_app',
        install_schema
    );
    EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA data TO tinker_app';

    -- Future tables created by the owner (migrations, DDL runner) are
    -- automatically visible to the app role. RLS still applies per-row.
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tinker_app',
        owner_role, install_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA data '
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tinker_app',
        owner_role
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
        'GRANT USAGE, SELECT ON SEQUENCES TO tinker_app',
        owner_role, install_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA data '
        'GRANT USAGE, SELECT ON SEQUENCES TO tinker_app',
        owner_role
    );
END
$$;

-- Hosts are invisible to the app role until the host plane (M1+) defines
-- its grant model. Fail closed.
ALTER TABLE hosts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS host_none ON hosts;
CREATE POLICY host_none ON hosts USING (false);

-- An app-role session sees exactly its own organization.
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_self ON organizations;
CREATE POLICY organization_self ON organizations
    USING (id = current_setting('app.organization_id', true)::uuid);

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS workspace_org ON workspaces;
CREATE POLICY workspace_org ON workspaces
    USING (organization_id = current_setting('app.organization_id', true)::uuid);
