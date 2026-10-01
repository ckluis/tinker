-- 0007: fencing token on durable steps. claim_step mints a token per
-- claim; complete_step/fail_step must present it. A worker whose lease
-- was taken over (stale worker) gets 0 rows affected and a typed
-- error instead of silently clobbering the new owner's checkpoint.
ALTER TABLE durable_steps
    ADD COLUMN IF NOT EXISTS lease_token uuid;
