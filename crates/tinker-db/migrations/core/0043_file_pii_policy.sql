-- 0043_file_pii_policy: per-field ceiling for linked file PII classes (C7).
--
-- `ontology_fields.max_pii_class`: the highest `stored_files.pii_class`
-- a file linked through this field may carry. Ordering:
-- 'none' < 'pii' < 'restricted'. The record write path
-- (MutationConnector create/update, LifecycleEngine publish) rejects a
-- write whose file's pii_class exceeds the field's ceiling, fail closed.
--
-- Default 'restricted' preserves pre-item-42 behavior for existing
-- fields: nothing that previously wrote is newly rejected until an
-- operator tightens the field. Operators tighten per field via the
-- schema API; the portable snapshot carries the value (see snapshot.rs).

ALTER TABLE ontology_fields
    ADD COLUMN IF NOT EXISTS max_pii_class TEXT NOT NULL DEFAULT 'restricted'
    CHECK (max_pii_class IN ('none', 'pii', 'restricted'));
