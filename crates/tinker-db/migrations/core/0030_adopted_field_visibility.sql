-- Post-M8 item 20 (shared-object adoption): an adopter must see the
-- shared base fields of the object it adopted. The base field rows are
-- stamped with the DEFINER's organization_id, so the pre-existing
-- "own org or NULL" rule would hide them from the adopter. Adoption is
-- an explicit opt-in to the shared schema: a field row is additionally
-- visible when the caller's organization holds an active adopted row
-- pointing at that field's object.
DROP POLICY IF EXISTS ontology_fields_visible ON ontology_fields;
CREATE POLICY ontology_fields_visible ON ontology_fields
    USING (
        organization_id IS NULL
        OR organization_id = current_setting('app.organization_id', true)::uuid
        OR EXISTS (
            SELECT 1 FROM ontology_objects adopter
            WHERE adopter.adopted_from = ontology_fields.object_id
              AND adopter.state = 'active'
              AND adopter.scope_kind = 'organization'
              AND adopter.organization_id = current_setting('app.organization_id', true)::uuid
        )
    );
