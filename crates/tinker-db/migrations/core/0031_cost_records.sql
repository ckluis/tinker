-- Post-M8 item 21: cost records in currency (PRD §46 "cost records").
--
-- spend_ledger tracks usage telemetry (runs/tool_steps/tokens) for
-- budget enforcement. These tables add the money side: a token→currency
-- price list, per-window cost records computed at record time, and
-- imported provider bills for reconciliation.

-- Token→currency price list. Global: provider list prices are public
-- and identical across orgs. NUMERIC for exact money math.
CREATE TABLE IF NOT EXISTS model_prices (
    model_ref          TEXT PRIMARY KEY,  -- e.g. 'openai/gpt-4o', 'fake/summarizer'
    input_usd_per_1k   NUMERIC(12,6) NOT NULL CHECK (input_usd_per_1k >= 0),
    output_usd_per_1k  NUMERIC(12,6) NOT NULL CHECK (output_usd_per_1k >= 0),
    currency           TEXT NOT NULL DEFAULT 'USD',
    effective_from     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- The app role reads prices (cost computation) but never writes them:
-- price changes are an operator action through the owner role.
GRANT SELECT ON model_prices TO tinker_app;

-- Per-org, per-hour-window, per-model cost records. cost_usd is computed
-- at record time from the then-current price (cost at time of use, so a
-- later price change never rewrites history). Tokens recorded while no
-- price row exists accumulate in unpriced_tokens with no cost — the
-- summary flags them instead of silently pricing them at zero.
CREATE TABLE IF NOT EXISTS cost_records (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL,
    window_start     TIMESTAMPTZ NOT NULL,
    model_ref        TEXT NOT NULL,
    input_tokens     BIGINT NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens    BIGINT NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    cost_usd         NUMERIC(14,4) NOT NULL DEFAULT 0 CHECK (cost_usd >= 0),
    unpriced_tokens  BIGINT NOT NULL DEFAULT 0 CHECK (unpriced_tokens >= 0),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, window_start, model_ref)
);

-- Provider bills, imported for reconciliation. source='manual' until a
-- provider billing API adapter exists (see "Real model-provider
-- adapters" in BACKLOG.md). provider matches the model_ref prefix
-- ('openai' matches 'openai/gpt-4o').
CREATE TABLE IF NOT EXISTS provider_bills (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL,
    provider        TEXT NOT NULL,
    period_start    DATE NOT NULL,
    period_end      DATE NOT NULL,
    billed_amount   NUMERIC(14,2) NOT NULL CHECK (billed_amount >= 0),
    currency        TEXT NOT NULL DEFAULT 'USD',
    source          TEXT NOT NULL DEFAULT 'manual',
    notes           TEXT,
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (period_end >= period_start)
);

-- RLS + grants, same pattern as the other agent tables (0020_agents).
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['cost_records', 'provider_bills']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format(
            'DROP POLICY IF EXISTS %I ON %I',
            'tenant_isolation_' || t, t
        );
        EXECUTE format(
            $pol$CREATE POLICY %I ON %I
             USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
             WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)$pol$,
            'tenant_isolation_' || t, t
        );
        EXECUTE format(
            'GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO tinker_app', t
        );
    END LOOP;
END
$$;
