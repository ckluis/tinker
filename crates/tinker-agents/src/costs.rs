//! Cost records in currency (PRD §46).
//!
//! `spend_ledger` (budgets.rs) tracks usage telemetry — runs, tool steps,
//! tokens — for budget *enforcement*. This module is the money side:
//!
//! - `model_prices`: a global token→currency price list (input/output USD
//!   per 1k tokens per model_ref). Operator-managed through the owner
//!   role; tenants read.
//! - `cost_records`: per-org, per-hour-window, per-model cost, computed at
//!   record time from the then-current price — cost at time of use, so a
//!   later price change never rewrites history. Tokens recorded while no
//!   price exists accumulate as `unpriced_tokens` (flagged, never silently
//!   zero-priced).
//! - `provider_bills`: imported provider bills; `reconcile` compares the
//!   ledger's computed cost against the bill and reports variance.
//!
//! Cost records track ACTUAL model completions (tokens_in/tokens_out +
//! model_ref from the gateway). The renewal copilot's estimated tokens
//! (len/4 heuristics with no model) stay in the budget ledger only —
//! estimates are not costs.

use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use chrono::{DateTime, NaiveDate, Utc};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

/// Variance tolerance for a "match": provider bills include rounding and
/// fees, so a bill within 2% (or $0.01, whichever is larger) reconciles.
const MATCH_TOLERANCE_RATE: f64 = 0.02;
const MATCH_TOLERANCE_ABS_USD: f64 = 0.01;

fn window_start(now: DateTime<Utc>) -> DateTime<Utc> {
    let truncated = now.timestamp() / 3600 * 3600;
    DateTime::from_timestamp(truncated, 0).unwrap_or(now)
}

/// Exact decimal from an f64 literal (test assertions).
pub fn bd(v: f64) -> BigDecimal {
    BigDecimal::from_f64(v).unwrap_or(BigDecimal::from(0))
}

/// A price-list entry.
#[derive(Debug, Clone)]
pub struct ModelPrice {
    pub model_ref: String,
    pub input_usd_per_1k: BigDecimal,
    pub output_usd_per_1k: BigDecimal,
    pub currency: String,
}

/// Per-model cost line in a summary.
#[derive(Debug, Clone)]
pub struct ModelCostLine {
    pub model_ref: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_usd: BigDecimal,
    pub unpriced_tokens: i64,
}

/// Cost summary over a time range.
#[derive(Debug, Clone)]
pub struct CostSummary {
    pub lines: Vec<ModelCostLine>,
    pub total_cost_usd: BigDecimal,
    pub total_unpriced_tokens: i64,
}

/// Reconciliation of ledger cost vs an imported provider bill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileStatus {
    /// |variance| within tolerance.
    Match,
    /// Ledger computed MORE than the bill (we over-counted or the bill
    /// has credits/discounts).
    LedgerOver,
    /// Ledger computed LESS than the bill (missing usage or price drift).
    LedgerUnder,
}

#[derive(Debug, Clone)]
pub struct Reconciliation {
    pub provider: String,
    pub period_start: NaiveDate,
    pub period_end: NaiveDate,
    pub ledger_cost_usd: BigDecimal,
    pub billed_amount_usd: BigDecimal,
    pub variance_usd: BigDecimal,
    pub unpriced_tokens: i64,
    pub status: ReconcileStatus,
    /// True when part of the ledger cost is unpriced: the variance is a
    /// lower bound and the reconciliation is provisional.
    pub provisional: bool,
}

/// DB-backed cost ledger. Writes go through the tenant transaction so RLS
/// scopes every row to the caller's org; the price list is global.
pub struct CostLedger {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
}

impl CostLedger {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    /// Set (or update) a model's price. Operator action: runs through the
    /// owner pool — the app role has no write grant on model_prices.
    /// Callers must hold an operator/owner-authorized context; this method
    /// does not itself check authorization.
    pub async fn set_model_price(
        &self,
        model_ref: &str,
        input_usd_per_1k: BigDecimal,
        output_usd_per_1k: BigDecimal,
    ) -> Result<()> {
        if input_usd_per_1k < 0 || output_usd_per_1k < 0 {
            return Err(TinkerError::Validation(
                "model prices cannot be negative".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO model_prices (model_ref, input_usd_per_1k, output_usd_per_1k)
             VALUES ($1,$2,$3)
             ON CONFLICT (model_ref) DO UPDATE
             SET input_usd_per_1k = EXCLUDED.input_usd_per_1k,
                 output_usd_per_1k = EXCLUDED.output_usd_per_1k,
                 effective_from = now(), updated_at = now()",
        )
        .bind(model_ref)
        .bind(&input_usd_per_1k)
        .bind(&output_usd_per_1k)
        .execute(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Read a model's current price, if listed.
    pub async fn model_price(&self, model_ref: &str) -> Result<Option<ModelPrice>> {
        let row: Option<(String, BigDecimal, BigDecimal, String)> = sqlx::query_as(
            "SELECT model_ref, input_usd_per_1k, output_usd_per_1k, currency
             FROM model_prices WHERE model_ref = $1",
        )
        .bind(model_ref)
        .fetch_optional(&self.core.0)
        .await
        .map_err(TinkerError::Db)?;
        Ok(row.map(
            |(model_ref, input_usd_per_1k, output_usd_per_1k, currency)| ModelPrice {
                model_ref,
                input_usd_per_1k,
                output_usd_per_1k,
                currency,
            },
        ))
    }

    /// Record an actual model completion's token usage. Cost is computed
    /// from the current price; with no price row the tokens land in
    /// `unpriced_tokens` and are flagged, never zero-priced.
    pub async fn record_usage(
        &self,
        ctx: &TenantContext,
        model_ref: &str,
        tokens_in: u64,
        tokens_out: u64,
    ) -> Result<()> {
        if model_ref.trim().is_empty() {
            return Err(TinkerError::Validation("model_ref is required".into()));
        }
        let ws = window_start(Utc::now());
        let price = self.model_price(model_ref).await?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        match price {
            Some(p) => {
                let cost = BigDecimal::from(tokens_in) * &p.input_usd_per_1k
                    / BigDecimal::from(1000)
                    + BigDecimal::from(tokens_out) * &p.output_usd_per_1k / BigDecimal::from(1000);
                sqlx::query(
                    "INSERT INTO cost_records
                         (organization_id, window_start, model_ref,
                          input_tokens, output_tokens, cost_usd)
                     VALUES ($1,$2,$3,$4,$5,$6)
                     ON CONFLICT (organization_id, window_start, model_ref)
                     DO UPDATE SET input_tokens = cost_records.input_tokens + EXCLUDED.input_tokens,
                                   output_tokens = cost_records.output_tokens + EXCLUDED.output_tokens,
                                   cost_usd = cost_records.cost_usd + EXCLUDED.cost_usd,
                                   updated_at = now()",
                )
                .bind(ctx.organization_id.0)
                .bind(ws)
                .bind(model_ref)
                .bind(tokens_in as i64)
                .bind(tokens_out as i64)
                .bind(&cost)
                .execute(&mut *tx)
                .await?;
            }
            None => {
                sqlx::query(
                    "INSERT INTO cost_records
                         (organization_id, window_start, model_ref,
                          input_tokens, output_tokens, unpriced_tokens)
                     VALUES ($1,$2,$3,$4,$5,$4+$5)
                     ON CONFLICT (organization_id, window_start, model_ref)
                     DO UPDATE SET input_tokens = cost_records.input_tokens + EXCLUDED.input_tokens,
                                   output_tokens = cost_records.output_tokens + EXCLUDED.output_tokens,
                                   unpriced_tokens = cost_records.unpriced_tokens + EXCLUDED.unpriced_tokens,
                                   updated_at = now()",
                )
                .bind(ctx.organization_id.0)
                .bind(ws)
                .bind(model_ref)
                .bind(tokens_in as i64)
                .bind(tokens_out as i64)
                .execute(&mut *tx)
                .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    /// Cost summary per model over [from, to). Totals are exact
    /// (BigDecimal); unpriced tokens are flagged, not folded into cost.
    pub async fn cost_summary(
        &self,
        ctx: &TenantContext,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> Result<CostSummary> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(String, i64, i64, BigDecimal, i64)> = sqlx::query_as(
            "SELECT model_ref,
                    SUM(input_tokens)::bigint, SUM(output_tokens)::bigint,
                    SUM(cost_usd), SUM(unpriced_tokens)::bigint
             FROM cost_records
             WHERE organization_id = $1 AND window_start >= $2 AND window_start < $3
             GROUP BY model_ref ORDER BY model_ref",
        )
        .bind(ctx.organization_id.0)
        .bind(from)
        .bind(to)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        let mut total_cost_usd = BigDecimal::from(0);
        let mut total_unpriced_tokens = 0i64;
        let lines = rows
            .into_iter()
            .map(
                |(model_ref, input_tokens, output_tokens, cost_usd, unpriced_tokens)| {
                    total_cost_usd += &cost_usd;
                    total_unpriced_tokens += unpriced_tokens;
                    ModelCostLine {
                        model_ref,
                        input_tokens,
                        output_tokens,
                        cost_usd,
                        unpriced_tokens,
                    }
                },
            )
            .collect();
        Ok(CostSummary {
            lines,
            total_cost_usd,
            total_unpriced_tokens,
        })
    }

    /// Import a provider bill for later reconciliation. Until a provider
    /// billing API adapter exists this is the manual-import path
    /// (source='manual'); the shape is what an adapter would fill.
    pub async fn import_provider_bill(
        &self,
        ctx: &TenantContext,
        provider: &str,
        period_start: NaiveDate,
        period_end: NaiveDate,
        billed_amount_usd: BigDecimal,
        notes: Option<&str>,
    ) -> Result<Uuid> {
        if provider.trim().is_empty() {
            return Err(TinkerError::Validation("provider is required".into()));
        }
        if period_end < period_start {
            return Err(TinkerError::Validation(
                "bill period_end precedes period_start".into(),
            ));
        }
        if billed_amount_usd < 0 {
            return Err(TinkerError::Validation(
                "billed amount cannot be negative".into(),
            ));
        }
        let id = Uuid::now_v7();
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO provider_bills
                 (id, organization_id, provider, period_start, period_end,
                  billed_amount, currency, source, notes)
             VALUES ($1,$2,$3,$4,$5,$6,'USD','manual',$7)",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(provider)
        .bind(period_start)
        .bind(period_end)
        .bind(&billed_amount_usd)
        .bind(notes)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        Ok(id)
    }

    /// Reconcile ledger-computed cost against an imported provider bill.
    /// `provider` matches the model_ref prefix ('openai' ~ 'openai/gpt-4o').
    /// With no bill imported for the period this fails closed — a missing
    /// bill is not a match.
    pub async fn reconcile(
        &self,
        ctx: &TenantContext,
        provider: &str,
        period_start: NaiveDate,
        period_end: NaiveDate,
    ) -> Result<Reconciliation> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let bill: Option<(BigDecimal,)> = sqlx::query_as(
            "SELECT billed_amount FROM provider_bills
             WHERE organization_id = $1 AND provider = $2
               AND period_start = $3 AND period_end = $4
             ORDER BY imported_at DESC, id DESC LIMIT 1",
        )
        .bind(ctx.organization_id.0)
        .bind(provider)
        .bind(period_start)
        .bind(period_end)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let (billed_amount_usd,) = bill.ok_or_else(|| {
            TinkerError::NotFound(format!(
                "no provider bill imported for {provider} {period_start}..{period_end}"
            ))
        })?;
        // Ledger cost for the provider's models over the bill period.
        // window_start is hourly; the period bounds are dates.
        let row: Option<(BigDecimal, i64)> = sqlx::query_as(
            "SELECT COALESCE(SUM(cost_usd), 0), COALESCE(SUM(unpriced_tokens), 0)::bigint
             FROM cost_records
             WHERE organization_id = $1
               AND split_part(model_ref, '/', 1) = $2
               AND window_start >= $3::timestamptz
               AND window_start < ($4::date + 1)::timestamptz",
        )
        .bind(ctx.organization_id.0)
        .bind(provider)
        .bind(period_start)
        .bind(period_end)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        let (ledger_cost_usd, unpriced_tokens) = row.unwrap_or((BigDecimal::from(0), 0));
        let variance_usd = &ledger_cost_usd - &billed_amount_usd;
        let variance_f = variance_usd.to_f64().unwrap_or(f64::INFINITY).abs();
        let bill_f = billed_amount_usd.to_f64().unwrap_or(0.0);
        let tolerance = (bill_f * MATCH_TOLERANCE_RATE).max(MATCH_TOLERANCE_ABS_USD);
        let status = if variance_f <= tolerance {
            ReconcileStatus::Match
        } else if variance_usd > 0 {
            ReconcileStatus::LedgerOver
        } else {
            ReconcileStatus::LedgerUnder
        };
        Ok(Reconciliation {
            provider: provider.to_string(),
            period_start,
            period_end,
            ledger_cost_usd,
            billed_amount_usd,
            variance_usd,
            unpriced_tokens,
            status,
            provisional: unpriced_tokens > 0,
        })
    }
}
