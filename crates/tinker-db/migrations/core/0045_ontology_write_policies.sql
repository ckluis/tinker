-- Ontology RLS: split visibility from writability.
--
-- 0002/0030 declared each ontology policy once, FOR ALL, with USING only.
-- PostgreSQL reuses USING as the write check, so every row a tenant could
-- SEE it could also UPDATE/DELETE through the app role:
--   - platform rows (scope_kind='platform', organization_id NULL) — one
--     tenant could rename/relabel a base object for every tenant;
--   - an adopted object's base fields, stamped with the DEFINER org's id
--     (0030) — the adopter could rewrite another tenant's field rows.
-- Visibility is unchanged below (FOR SELECT keeps the old predicates);
-- writes through the app role are confined to the caller's own
-- organization rows. Platform and cross-org writes stay owner-only
-- (pack installer, adoption, DDL), which never pass through RLS.

-- ontology_objects ---------------------------------------------------------
DROP POLICY IF EXISTS ontology_objects_visible ON ontology_objects;
CREATE POLICY ontology_objects_visible ON ontology_objects
    FOR SELECT
    USING (scope_kind = 'platform'
        OR (scope_kind = 'organization'
            AND organization_id = current_setting('app.organization_id', true)::uuid));
CREATE POLICY ontology_objects_own_write ON ontology_objects
    FOR ALL
    USING (scope_kind = 'organization'
        AND organization_id = current_setting('app.organization_id', true)::uuid)
    WITH CHECK (scope_kind = 'organization'
        AND organization_id = current_setting('app.organization_id', true)::uuid);

-- ontology_fields ----------------------------------------------------------
DROP POLICY IF EXISTS ontology_fields_visible ON ontology_fields;
CREATE POLICY ontology_fields_visible ON ontology_fields
    FOR SELECT
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
CREATE POLICY ontology_fields_own_write ON ontology_fields
    FOR ALL
    USING (organization_id = current_setting('app.organization_id', true)::uuid)
    WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);

-- ontology_changes (append-only audit) -------------------------------------
DROP POLICY IF EXISTS ontology_changes_org ON ontology_changes;
CREATE POLICY ontology_changes_visible ON ontology_changes
    FOR SELECT
    USING (organization_id IS NULL
        OR organization_id = current_setting('app.organization_id', true)::uuid);
CREATE POLICY ontology_changes_own_insert ON ontology_changes
    FOR INSERT
    WITH CHECK (organization_id = current_setting('app.organization_id', true)::uuid);
