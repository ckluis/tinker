-- 0037_inbound_templates: inbound email receiving + attachment links +
-- governed email templates (item 36, M5 launch scope).
--
-- inbound_addresses: recipient-address -> organization routing registry.
-- The recipient address itself identifies the organization, so routing
-- lookups run through the owner pool (table owners bypass RLS; this
-- table is NOT forced-RLS) — mirroring 0034 machine_credentials. The
-- HMAC key is derived per-org from the TINKER_INBOUND_WEBHOOK_SECRET
-- master secret (env only; never stored in the DB). Unknown addresses
-- fail closed with the same generic rejection as a bad signature: no
-- existence oracle.
--
-- inbound_email_log: replay/idempotency registry. The provider's
-- message id is claimed (INSERT ... ON CONFLICT DO NOTHING) BEFORE any
-- bytes are stored; a claimed id presented again is rejected as a
-- replay. The claim is released if the receive fails after claiming,
-- so a transient failure does not burn a legitimate message.
--
-- message_attachments: links a comm_message row to stored_files rows
-- (item-23 registry). Bytes NEVER touch Postgres; fetch authorization
-- mirrors message visibility (tenant-scoped link + tenant-scoped
-- message row must both resolve, else NotFound).
--
-- email_templates / email_template_versions: governed template
-- objects. Templates are org-scoped with RLS; versions are immutable
-- (update = new version row); rendering never reads another org's
-- rows.

CREATE TABLE IF NOT EXISTS inbound_addresses (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Normalized (lowercased, trimmed) at write time; the unique index
    -- is on lower(address) so registration is case-insensitively unique
    -- across ALL tenants — one address routes to exactly one org.
    address         TEXT NOT NULL CHECK (char_length(address) BETWEEN 3 AND 320),
    -- The shared_inbox comm_channel inbound mail lands in (soft ref to
    -- data.comm_channel; no FK — comm tables are ontology-managed DDL).
    channel_id      UUID NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_inbound_addresses_org_id UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_inbound_addresses_lower
    ON inbound_addresses (lower(address));

ALTER TABLE inbound_addresses ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inbound_addresses_org ON inbound_addresses;
CREATE POLICY inbound_addresses_org ON inbound_addresses
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

CREATE INDEX IF NOT EXISTS ix_inbound_addresses_org
    ON inbound_addresses (organization_id) WHERE active;

GRANT SELECT, INSERT, UPDATE, DELETE ON inbound_addresses TO tinker_app;

CREATE TABLE IF NOT EXISTS inbound_email_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Provider-supplied unique id for the inbound message.
    provider_id     TEXT NOT NULL CHECK (char_length(provider_id) BETWEEN 1 AND 256),
    message_id      UUID,
    thread_id       UUID,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_inbound_email_log_org_provider UNIQUE (organization_id, provider_id),
    CONSTRAINT uq_inbound_email_log_org_id UNIQUE (organization_id, id)
);

ALTER TABLE inbound_email_log ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS inbound_email_log_org ON inbound_email_log;
CREATE POLICY inbound_email_log_org ON inbound_email_log
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

CREATE INDEX IF NOT EXISTS ix_inbound_email_log_received
    ON inbound_email_log (organization_id, received_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON inbound_email_log TO tinker_app;

CREATE TABLE IF NOT EXISTS message_attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Soft ref to data.comm_message (ontology-managed DDL, no FK).
    message_id      UUID NOT NULL,
    file_id         UUID NOT NULL REFERENCES stored_files(id) ON DELETE CASCADE,
    position        INTEGER NOT NULL CHECK (position >= 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_message_attachments_org_id UNIQUE (organization_id, id),
    CONSTRAINT uq_message_attachments_msg_file UNIQUE (organization_id, message_id, file_id)
);

ALTER TABLE message_attachments ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS message_attachments_org ON message_attachments;
CREATE POLICY message_attachments_org ON message_attachments
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

CREATE INDEX IF NOT EXISTS ix_message_attachments_message
    ON message_attachments (organization_id, message_id, position);

GRANT SELECT, INSERT, UPDATE, DELETE ON message_attachments TO tinker_app;

CREATE TABLE IF NOT EXISTS email_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Operator-facing name; validated in Rust
    -- (^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$).
    name            TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
    current_version INTEGER NOT NULL DEFAULT 1 CHECK (current_version >= 1),
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'archived')),
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_email_templates_org_id UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_email_templates_org_name
    ON email_templates (organization_id, lower(name));

ALTER TABLE email_templates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_templates_org ON email_templates;
CREATE POLICY email_templates_org ON email_templates
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

CREATE INDEX IF NOT EXISTS ix_email_templates_org_status
    ON email_templates (organization_id, status);

GRANT SELECT, INSERT, UPDATE, DELETE ON email_templates TO tinker_app;

CREATE TABLE IF NOT EXISTS email_template_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id     UUID NOT NULL REFERENCES email_templates(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version         INTEGER NOT NULL CHECK (version >= 1),
    -- Subject and body are BOTH templates (variable substitution).
    subject         TEXT NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 500),
    body            TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 100000),
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_email_template_versions_tpl_ver UNIQUE (template_id, version),
    CONSTRAINT uq_email_template_versions_org_id UNIQUE (organization_id, id)
);

ALTER TABLE email_template_versions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_template_versions_org ON email_template_versions;
CREATE POLICY email_template_versions_org ON email_template_versions
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

CREATE INDEX IF NOT EXISTS ix_email_template_versions_tpl
    ON email_template_versions (template_id, version);

GRANT SELECT, INSERT, UPDATE, DELETE ON email_template_versions TO tinker_app;
