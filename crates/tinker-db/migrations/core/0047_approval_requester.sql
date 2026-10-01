-- Four-eyes approvals: record who asked, so the asker can never decide.
--
-- approval_requests stored the agent attachment but not the requesting
-- actor, so ApprovalEngine::decide could not tell a self-approval from
-- a review. Rows created before this migration have no requester and
-- stay decidable as before (their requester is unknowable).
ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS requested_by UUID;
