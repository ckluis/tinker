-- Post-M8 item 20 (shared-object adoption): a second organization can
-- adopt an existing shared object instead of failing on the duplicate
-- table. The adopted row is metadata-only -- it points at the same
-- physical table -- and records which object it adopts so field
-- resolution can union the shared base fields with the adopter's own.
ALTER TABLE ontology_objects
    ADD COLUMN adopted_from uuid NULL REFERENCES ontology_objects(id);

-- An adopted row never adopts another adopted row: adoption always
-- points at the root definer, keeping the chain flat. (Enforced in
-- application logic; the FK keeps the reference sound.)
CREATE INDEX IF NOT EXISTS ontology_objects_adopted_from_idx
    ON ontology_objects(adopted_from) WHERE adopted_from IS NOT NULL;
