-- OIDC authorization-code login attempts (code flow + PKCE + nonce).
--
-- /login/oidc/start writes one row and redirects to the provider with
-- its state, nonce and PKCE challenge; /login/oidc/callback consumes the
-- row exactly once (UPDATE ... WHERE consumed_at IS NULL AND unexpired)
-- and requires the ID token to echo the nonce. Replaced the old POST
-- /login/oidc that minted a session from a bare ID token.
--
-- Pre-authentication state, read and written only by the system (owner)
-- handle: RLS is enabled with NO policy, so the tenant app role sees no
-- rows at all.
CREATE TABLE oidc_login_attempts (
    state           TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    code_verifier   TEXT NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_oidc_login_attempts_expiry
    ON oidc_login_attempts (expires_at) WHERE consumed_at IS NULL;
ALTER TABLE oidc_login_attempts ENABLE ROW LEVEL SECURITY;
