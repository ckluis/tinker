-- Real WebAuthn passkeys.
--
-- auth_credentials.public_key held a raw 32-byte Ed25519 key verified
-- over the bare challenge (no origin / RP binding). Passkeys now verify
-- full WebAuthn assertions; the key is stored as a COSE_Key with its
-- algorithm (cose_alg: -7 ES256, -8 EdDSA). Rows with cose_alg NULL are
-- legacy raw Ed25519 keys and verify as EdDSA. sign_count tracks the
-- authenticator's signature counter for clone detection.
ALTER TABLE auth_credentials
    ADD COLUMN IF NOT EXISTS cose_alg INTEGER,
    ADD COLUMN IF NOT EXISTS sign_count BIGINT NOT NULL DEFAULT 0;
