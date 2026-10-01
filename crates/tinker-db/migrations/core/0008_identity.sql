-- M1: identity plane — actors, credentials, challenges, sessions, scoped grants.
--
-- Design notes:
--   * Sessions are server-side and opaque: the cookie carries a random
--     256-bit token; only its SHA-256 hash is stored. Stealing the
--     database does not yield live sessions.
--   * Grants are Tinker-owned. Providers authenticate; they never
--     authorize. A grant names (actor, scope, action) with an optional
--     expiry. Scope hierarchy (org > workspace > app) is resolved in
--     Rust, not SQL, so the rule stays in one auditable place.
--   * Passkey challenges are single-use and short-lived.

CREATE TABLE IF NOT EXISTS actors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL DEFAULT 'human'
                    CHECK (kind IN ('human', 'directory', 'machine', 'workload')),
    display_name    TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    version         BIGINT NOT NULL DEFAULT 1
);

-- 0001 created workspaces(id, organization_id, name, created_at); M1
-- only adds the slug column it needs for human-friendly URLs.
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS slug TEXT;
ALTER TABLE workspaces ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_workspaces_org_slug'
    ) THEN
        ALTER TABLE workspaces
            ADD CONSTRAINT uq_workspaces_org_slug UNIQUE (organization_id, slug);
    END IF;
END $$;

-- Organization membership: which orgs an identity may act in.
CREATE TABLE IF NOT EXISTS memberships (
    actor_id        UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    role            TEXT NOT NULL DEFAULT 'member'
                    CHECK (role IN ('owner', 'admin', 'member', 'viewer')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (actor_id, organization_id)
);

-- Provider-issued credential material bound to an actor. For passkey this
-- holds the Ed25519 verifying key; for OIDC the (issuer, subject) pair.
-- Secrets never live here: passkey stores only the public key, OIDC stores
-- only the binding. Session tokens live in sessions as hashes.
CREATE TABLE IF NOT EXISTS auth_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    method          TEXT NOT NULL CHECK (method IN ('passkey', 'oidc', 'api_key')),
    credential_id   TEXT NOT NULL,
    public_key      BYTEA,
    issuer          TEXT,
    subject         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    version         BIGINT NOT NULL DEFAULT 1,
    UNIQUE (organization_id, method, credential_id)
);

-- Single-use passkey challenges. Consumed or expired rows are dead.
CREATE TABLE IF NOT EXISTS auth_challenges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        UUID REFERENCES actors(id) ON DELETE CASCADE,
    challenge       BYTEA NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_expiry
    ON auth_challenges (expires_at) WHERE consumed_at IS NULL;

-- Server sessions. token_hash = SHA-256 of the cookie token.
CREATE TABLE IF NOT EXISTS sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    actor_id        UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    token_hash      BYTEA NOT NULL UNIQUE,
    method          TEXT NOT NULL,
    assurance       TEXT NOT NULL CHECK (assurance IN ('token', 'single_factor', 'multi_factor')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    version         BIGINT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_sessions_actor
    ON sessions (organization_id, actor_id) WHERE revoked_at IS NULL;

-- Scoped grants: (actor, scope, action) allow-list with optional expiry.
-- scope_type: 'organization' | 'workspace' | 'app'. scope_id is NULL for
-- organization scope.
CREATE TABLE IF NOT EXISTS grants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        UUID NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    scope_type      TEXT NOT NULL
                    CHECK (scope_type IN ('organization', 'workspace', 'app')),
    scope_id        UUID,
    action          TEXT NOT NULL,
    created_by      UUID REFERENCES actors(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    version         BIGINT NOT NULL DEFAULT 1,
    UNIQUE (organization_id, actor_id, scope_type, scope_id, action)
);

-- RLS: every identity table is organization-scoped, fail closed.
DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['actors','workspaces','memberships',
                             'auth_credentials','auth_challenges',
                             'sessions','grants']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        IF NOT EXISTS (
            SELECT 1 FROM pg_policies
            WHERE schemaname = current_schema()
              AND tablename = t AND policyname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I
                 USING (organization_id = current_setting(''app.organization_id'', true)::uuid)
                 WITH CHECK (organization_id = current_setting(''app.organization_id'', true)::uuid)',
                t);
        END IF;
    END LOOP;
END $$;

-- Least-privilege grants for the app role (created by 0001).
DO $$
DECLARE
    sch TEXT := current_schema();
BEGIN
    EXECUTE format(
        'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO tinker_app',
        sch);
END $$;
