-- 0033: record semantic-ranking provenance on expansion manifests.
-- Nullable JSONB so existing manifests stay valid; NULL = no ranker was
-- attached (deterministic milestone order).
ALTER TABLE expansion_manifests ADD COLUMN ranking JSONB;
