-- Approval requests that no agent attachment raised: a person asking a
-- second person to approve a PII reveal (docs/automations.md, samen
-- parity). attachment_id becomes optional; the composite tenant FK
-- (organization_id, attachment_id) still applies whenever it is set.
ALTER TABLE approval_requests ALTER COLUMN attachment_id DROP NOT NULL;
