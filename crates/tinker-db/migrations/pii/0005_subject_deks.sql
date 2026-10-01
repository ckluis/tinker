-- Crypto-shred erasure (docs/automations.md, samen parity): one DEK per
-- subject (the record a value belongs to) instead of one per
-- organization. Erasing a subject deletes its wrapped DEKs, so every
-- ciphertext sealed under them becomes unreadable wherever a copy of
-- pii_values survives. Rows with subject_id NULL are the legacy
-- per-organization DEKs; their values still resolve.
ALTER TABLE wrapped_deks ADD COLUMN IF NOT EXISTS subject_id uuid;
ALTER TABLE wrapped_deks DROP CONSTRAINT IF EXISTS wrapped_deks_organization_id_version_key;
ALTER TABLE wrapped_deks
    ADD CONSTRAINT wrapped_deks_org_subject_version
    UNIQUE NULLS NOT DISTINCT (organization_id, subject_id, version);
CREATE INDEX IF NOT EXISTS ix_wrapped_deks_subject ON wrapped_deks (organization_id, subject_id);
