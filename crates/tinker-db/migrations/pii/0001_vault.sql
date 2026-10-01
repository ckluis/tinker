-- M0: PII vault store. PHYSICALLY SEPARATE DATABASE from the core store.
-- Separate credentials, encryption hierarchy, backups, and connection pool.
-- No foreign data wrapper, cross-database SQL, shared search index, or
-- analytics export joins the stores. Core rows reference these values by
-- opaque random id only (pii_refs.id = pii_values.id); that equality is
-- resolved in application code through the audited projector, never in SQL.

-- Application role for the PII store: owns nothing, like tinker_app.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tinker_pii_app') THEN
        CREATE ROLE tinker_pii_app LOGIN PASSWORD 'tinker_pii_app_dev_pw';
    END IF;
END
$$;

-- Required for gen_random_uuid() defaults below. Install here so a fresh
-- PII database bootstraps without manual extension setup.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Envelope encryption: per-organization data-encryption keys wrapped by a
-- host key-encryption key (KMS/HSM/local key file in production).
CREATE TABLE IF NOT EXISTS wrapped_deks(
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,   -- deliberate: NO foreign key to core.organizations
    kek_id text NOT NULL,            -- which KEK wrapped this DEK
    wrapped_key bytea NOT NULL,
    version int NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE(organization_id, version)
);

CREATE TABLE IF NOT EXISTS pii_values(
    id uuid PRIMARY KEY,             -- matches core.pii_refs.id; joined only in app code
    organization_id uuid NOT NULL,
    subject_id uuid NOT NULL,
    storage_class text NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_dek_id uuid NOT NULL REFERENCES wrapped_deks(id),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS pii_values_subject_idx ON pii_values(organization_id, subject_id);

-- Connector credentials and other secrets. Same envelope scheme.
CREATE TABLE IF NOT EXISTS vault_items(
    organization_id uuid NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    kind text NOT NULL,              -- credential | api_key | token
    name text NOT NULL,
    ciphertext bytea NOT NULL,
    nonce bytea NOT NULL,
    wrapped_dek_id uuid NOT NULL REFERENCES wrapped_deks(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, id)
);

-- Grants follow the database/schema the migration actually runs in, not
-- hardcoded names, so the privileged bootstrap works on fresh databases
-- and dedicated schemas alike.
DO $$
DECLARE
    install_schema text := current_schema();
    db_name text := current_database();
    owner_role text := current_user;
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO tinker_pii_app', db_name);
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO tinker_pii_app', install_schema);
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO tinker_pii_app',
        install_schema
    );
    EXECUTE format(
        'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO tinker_pii_app',
        install_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tinker_pii_app',
        owner_role, install_schema
    );
    EXECUTE format(
        'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I '
        'GRANT USAGE, SELECT ON SEQUENCES TO tinker_pii_app',
        owner_role, install_schema
    );
END
$$;
