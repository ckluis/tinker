-- PII store tenancy: the vault is projector-only, but RLS is the
-- fail-closed backstop so a leaked credential or miscoded query cannot
-- read across organizations. Same transaction-local context contract as
-- the core store.

ALTER TABLE pii_values ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS pii_values_org ON pii_values;
CREATE POLICY pii_values_org ON pii_values
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

ALTER TABLE wrapped_deks ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS wrapped_deks_org ON wrapped_deks;
CREATE POLICY wrapped_deks_org ON wrapped_deks
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

-- vault_items is internal bookkeeping; keep it projector-side only and
-- deny the app role entirely.
ALTER TABLE vault_items ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS vault_items_none ON vault_items;
CREATE POLICY vault_items_none ON vault_items USING (false);
