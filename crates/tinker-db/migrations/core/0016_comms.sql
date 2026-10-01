-- M5: native work and communications as ontology objects.
--
-- `comm_channel`, `comm_thread`, `comm_message` are platform-scope ontology
-- objects (defined at runtime through the owner handle by tinker-comms'
-- CommsInstaller, like the M3 pack installer) — real tables with typed
-- columns, not generic JSONB stores. This migration carries the
-- communications control plane. Column names and status values match
-- crates/tinker-comms exactly:
--
-- delivery_outbox: the transactional outbox for email + notification
-- delivery. One row per delivery; the idempotency key is unique per org
-- so duplicate enqueue attempts collapse to the same row (ON CONFLICT DO
-- NOTHING). The payload is an opaque ref (vault / record id) — never
-- plaintext PII. A claim mints lease_token/lease_until/lease_owner;
-- only the holder of the current lease_token may complete or fail the
-- row, which fences stale workers after a takeover.
--
-- notification_prefs: per-member routing preferences. mode is
-- immediate | digest | off. quiet_start/quiet_end are a daily window
-- during which immediate notifications defer (both set or both null;
-- never a half window). digest_window_minutes batches digest-mode
-- notifications into one delivery per window.
--
-- comm_identity_disclosures: append-only versioned identity disclosure
-- choices (latest version wins). A NULL thread_id is the org-wide
-- default; a thread-scoped row overrides it for that thread. disclosed
-- defaults to false (opt-in).
--
-- cross_plane_grants: purpose-bound, time-boxed grants letting an actor
-- from another organization render masked cards for threads in this
-- organization. Rows are pinned to the accessed organization (fail-closed
-- RLS); only unexpired, unrevoked rows authorize. The grantee is an
-- EXTERNAL actor, so it references actors(id), not the composite
-- membership key; created_by must be a member of the accessed org.

CREATE TABLE delivery_outbox (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('email','notification')),
    idempotency_key text NOT NULL,
    status          text NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued','sending','sent','failed','deferred','suppressed')),
    payload_ref     jsonb NOT NULL DEFAULT '{}'::jsonb,
    provider        text,
    provider_message_id text,
    attempts        integer NOT NULL DEFAULT 0,
    error           text,
    -- Lease fencing: set on claim, cleared on complete/fail.
    lease_until     timestamptz,
    lease_owner     text,
    lease_token     uuid,
    deliver_after   timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, idempotency_key)
);
CREATE INDEX delivery_outbox_claim_idx ON delivery_outbox
    (organization_id, status, deliver_after, lease_until)
    WHERE status IN ('queued','sending','failed','deferred');
ALTER TABLE delivery_outbox ENABLE ROW LEVEL SECURITY;
CREATE POLICY delivery_outbox_tenant ON delivery_outbox
    USING (organization_id = current_setting('app.organization_id')::uuid)
    WITH CHECK (organization_id = current_setting('app.organization_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON delivery_outbox TO tinker_app;

CREATE TABLE notification_prefs (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_id        uuid NOT NULL,
    mode            text NOT NULL DEFAULT 'immediate'
                    CHECK (mode IN ('immediate','digest','off')),
    quiet_start     time,
    quiet_end       time,
    digest_window_minutes integer NOT NULL DEFAULT 60
                    CHECK (digest_window_minutes BETWEEN 1 AND 1440),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, actor_id),
    -- A quiet window is all-or-nothing: both bounds or neither.
    CHECK ((quiet_start IS NULL) = (quiet_end IS NULL)),
    FOREIGN KEY (actor_id, organization_id)
        REFERENCES memberships (actor_id, organization_id)
        ON DELETE CASCADE
);
ALTER TABLE notification_prefs ENABLE ROW LEVEL SECURITY;
CREATE POLICY notification_prefs_tenant ON notification_prefs
    USING (organization_id = current_setting('app.organization_id')::uuid)
    WITH CHECK (organization_id = current_setting('app.organization_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_prefs TO tinker_app;

CREATE TABLE comm_identity_disclosures (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- NULL thread_id = org-wide default; a thread-scoped row overrides it.
    thread_id       uuid,
    actor_id        uuid NOT NULL,
    disclosed       boolean NOT NULL DEFAULT false,
    version         integer NOT NULL DEFAULT 1,
    created_by      uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- Append-only: each choice is a new versioned row, latest wins. No
    -- uniqueness on (org, thread, actor) — that would forbid new versions.
    FOREIGN KEY (actor_id, organization_id)
        REFERENCES memberships (actor_id, organization_id)
        ON DELETE CASCADE,
    FOREIGN KEY (created_by, organization_id)
        REFERENCES memberships (actor_id, organization_id)
        ON DELETE CASCADE
);
CREATE INDEX comm_identity_disclosures_actor_idx
    ON comm_identity_disclosures (organization_id, actor_id, version DESC);
ALTER TABLE comm_identity_disclosures ENABLE ROW LEVEL SECURITY;
CREATE POLICY comm_identity_disclosures_tenant ON comm_identity_disclosures
    USING (organization_id = current_setting('app.organization_id')::uuid)
    WITH CHECK (organization_id = current_setting('app.organization_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON comm_identity_disclosures TO tinker_app;

CREATE TABLE cross_plane_grants (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The ACCESSED organization: rows are pinned here for fail-closed RLS.
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The EXTERNAL actor (a member of a different organization).
    grantee_actor_id uuid NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    purpose         text NOT NULL,
    expires_at      timestamptz NOT NULL,
    revoked_at      timestamptz,
    -- The granter must be a member of the accessed organization.
    created_by      uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (created_by, organization_id)
        REFERENCES memberships (actor_id, organization_id)
        ON DELETE CASCADE,
    CHECK (expires_at > created_at)
);
CREATE INDEX cross_plane_grants_grantee_idx
    ON cross_plane_grants (organization_id, grantee_actor_id)
    WHERE revoked_at IS NULL;
ALTER TABLE cross_plane_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY cross_plane_grants_tenant ON cross_plane_grants
    USING (organization_id = current_setting('app.organization_id')::uuid)
    WITH CHECK (organization_id = current_setting('app.organization_id')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON cross_plane_grants TO tinker_app;
