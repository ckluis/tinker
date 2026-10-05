-- Sensitive (vault-backed) fields — docs/pii-sensitive-fields.md.
--
-- A sensitive field's physical column is UUID and holds the `pii_refs`
-- id of a value sealed in the PII vault; a sibling "<col>__bidx" TEXT
-- column holds the keyed blind index used for exact-match lookups. The
-- flag is fixed at definition time: toggling it on a populated field
-- would need a data migration, so it is not a metadata edit.
ALTER TABLE ontology_fields
    ADD COLUMN IF NOT EXISTS sensitive boolean NOT NULL DEFAULT false;
ALTER TABLE ontology_fields
    ADD CONSTRAINT ontology_fields_sensitive_kinds
    CHECK (NOT sensitive OR field_type IN ('text', 'email', 'phone'));
