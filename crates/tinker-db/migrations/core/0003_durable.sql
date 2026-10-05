-- M0: DBOS-style durable execution tables. Workflows, queues, timers, and
-- notifications all run on this substrate. Redis may accelerate fan-out;
-- it never owns a durable job.

-- One row per workflow run. The queue lives here: runs with
-- status 'queued'/'scheduled' are claimed with FOR UPDATE SKIP LOCKED.
CREATE TABLE IF NOT EXISTS durable_runs(
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    definition_id text NOT NULL,
    definition_version text NOT NULL,   -- in-flight runs pin their version
    input_ref jsonb NOT NULL DEFAULT '{}',
    status text NOT NULL DEFAULT 'queued'
        CHECK (status IN ('queued','scheduled','running','sleeping','succeeded','failed','cancelled')),
    wake_at timestamptz,               -- timers and delayed queue entries
    queue text NOT NULL DEFAULT 'default',
    partition_key text NOT NULL DEFAULT '',
    priority int NOT NULL DEFAULT 0,
    attempts int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 25,
    lease_until timestamptz,           -- worker lease; expiry => recoverable
    lease_owner text,
    error text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS durable_runs_claim_idx ON durable_runs
    (queue, status, wake_at, priority DESC, created_at)
    WHERE status IN ('queued','scheduled');
CREATE INDEX IF NOT EXISTS durable_runs_lease_idx ON durable_runs (lease_until)
    WHERE status IN ('running','sleeping');

-- Checkpointed steps. (run_id, step_key) is stable: a completed step is
-- never re-run, a crashed one resumes from its last completed step.
CREATE TABLE IF NOT EXISTS durable_steps(
    organization_id uuid NOT NULL REFERENCES organizations(id),
    run_id uuid NOT NULL REFERENCES durable_runs(id) ON DELETE CASCADE,
    step_key text NOT NULL,
    attempt int NOT NULL DEFAULT 0,
    input_hash text NOT NULL DEFAULT '',
    output_ref jsonb,                  -- recorded result; replayed, not recomputed
    effect_key text,                   -- stable invocation key for side effects
    status text NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
    lease_until timestamptz,
    completed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, step_key)
);

-- Exactly-once side effects: the first completed write of an effect_key
-- wins; replays return the recorded output instead of re-executing.
CREATE TABLE IF NOT EXISTS durable_effects(
    organization_id uuid NOT NULL REFERENCES organizations(id),
    effect_key text NOT NULL,
    run_id uuid NOT NULL REFERENCES durable_runs(id),
    step_key text NOT NULL,
    output_ref jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, effect_key)
);

-- Durable messages/events: recv() waits, send() resolves.
CREATE TABLE IF NOT EXISTS durable_events(
    organization_id uuid NOT NULL REFERENCES organizations(id),
    run_id uuid NOT NULL REFERENCES durable_runs(id) ON DELETE CASCADE,
    seq bigint NOT NULL,
    event_type text NOT NULL,
    payload_ref jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, seq)
);

ALTER TABLE durable_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY durable_runs_org ON durable_runs
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

ALTER TABLE durable_steps ENABLE ROW LEVEL SECURITY;
CREATE POLICY durable_steps_org ON durable_steps
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

ALTER TABLE durable_effects ENABLE ROW LEVEL SECURITY;
CREATE POLICY durable_effects_org ON durable_effects
    USING (organization_id = current_setting('app.organization_id', true)::uuid);

ALTER TABLE durable_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY durable_events_org ON durable_events
    USING (organization_id = current_setting('app.organization_id', true)::uuid);
