-- Post-M8 item 13: approval requests expire; expired approvals can never
-- be decided or executed. Escalation marks stale-pending requests so a
-- human-notification hook can find them.
--
-- The 0020_agents schema already anticipated the 'expired' status in the
-- CHECK constraint; nothing enforced it until now.

ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ;

-- Backfill: rows created before deadlines existed get a 24h TTL from
-- creation instead of living forever.
UPDATE approval_requests
    SET expires_at = created_at + interval '24 hours'
    WHERE expires_at IS NULL;

-- Backstop for rows inserted without an explicit deadline (the engine
-- always sets one explicitly via request_with_ttl).
ALTER TABLE approval_requests
    ALTER COLUMN expires_at SET DEFAULT now() + interval '24 hours';

-- Sweeper query: pending rows past their deadline.
CREATE INDEX IF NOT EXISTS ix_approval_requests_expiry
    ON approval_requests (organization_id, expires_at)
    WHERE status = 'pending';

-- Escalation query: pending, never escalated, oldest first.
CREATE INDEX IF NOT EXISTS ix_approval_requests_escalation_due
    ON approval_requests (organization_id, created_at)
    WHERE status = 'pending' AND escalated_at IS NULL;
