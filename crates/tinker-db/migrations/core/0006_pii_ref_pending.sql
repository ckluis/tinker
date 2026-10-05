-- 0006: pii_refs gains a 'pending' state for the two-phase projection
-- protocol. Phase 1 seals the vault value; phase 2 flips the core
-- reference active. A crash between the phases leaves a sealed value
-- whose reference is not active, and the projector refuses to resolve
-- anything but 'active' — so interrupted writes can never leak.
ALTER TABLE pii_refs DROP CONSTRAINT IF EXISTS pii_refs_state_check;
ALTER TABLE pii_refs
    ADD CONSTRAINT pii_refs_state_check
    CHECK (state IN ('active','pending','revoked','tombstoned'));
