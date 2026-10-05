-- 0003: M8 — PII retention and restore manifests.
--
-- Retention for the PII store (PRD v0.6 §41: each store has separate
-- point-in-time recovery and retention). expires_at + legal_hold on
-- pii_values; the retention engine deletes expired, non-held values.
-- pii_restore_manifests mirrors the core restore_manifests table: the
-- pairing of the two manifests is what makes a restore rehearsal
-- meaningful.

ALTER TABLE pii_values
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS legal_hold BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS pii_values_expiry_idx
    ON pii_values (organization_id, expires_at)
    WHERE expires_at IS NOT NULL AND NOT legal_hold;

-- Restore manifest for the PII store. Same shape as the core table so the
-- pairing check is a direct comparison of windows and watermarks.
CREATE TABLE IF NOT EXISTS pii_restore_manifests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL,
    store               TEXT NOT NULL DEFAULT 'pii' CHECK (store = 'pii'),
    window_start        TIMESTAMPTZ NOT NULL,
    window_end          TIMESTAMPTZ NOT NULL,
    reference_watermark TIMESTAMPTZ NOT NULL,
    signature           TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (window_end > window_start)
);

-- RLS: same transaction-local contract as the other PII tables.
ALTER TABLE pii_restore_manifests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pii_restore_manifests_org ON pii_restore_manifests;
CREATE POLICY pii_restore_manifests_org ON pii_restore_manifests
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

-- pii_values keeps its existing policy; the new columns inherit it.
-- Grant the PII app role DML on the new table (same as 0001's convention).
GRANT SELECT, INSERT, UPDATE, DELETE ON pii_restore_manifests TO tinker_pii_app;
