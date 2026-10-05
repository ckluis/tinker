//! Spend budgets: attachment-level, expansion-level, org-level.
//!
//! Budgets are first-class runtime telemetry (PRD §33): every run records
//! into `spend_ledger` per (attachment, hour window). Enforcement is
//! fail-closed — a runaway agent gets a typed `BudgetExceeded`, never a
//! silent overrun.

use chrono::{DateTime, Utc};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

/// Attachment-level budget, e.g. `{ max_runs_per_hour: 50,
/// max_tool_steps: 12 }` (the renewal-copilot example from the PRD).
#[derive(Debug, Clone, Default)]
pub struct SpendBudget {
    pub max_runs_per_hour: Option<u32>,
    pub max_tool_steps: Option<u32>,
    pub max_tokens_per_hour: Option<u64>,
}

impl SpendBudget {
    pub fn from_json(v: &serde_json::Value) -> Self {
        Self {
            max_runs_per_hour: v
                .get("max_runs_per_hour")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32),
            max_tool_steps: v
                .get("max_tool_steps")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32),
            max_tokens_per_hour: v.get("max_tokens_per_hour").and_then(|x| x.as_u64()),
        }
    }
}

/// Expansion-level budget: `{ depth: 2, records: 40, tokens: 12000 }`.
#[derive(Debug, Clone)]
pub struct ExpansionBudget {
    pub depth: u32,
    pub records: u32,
    pub tokens: u64,
}

impl Default for ExpansionBudget {
    fn default() -> Self {
        Self {
            depth: 2,
            records: 40,
            tokens: 12_000,
        }
    }
}

impl ExpansionBudget {
    pub fn from_json(v: &serde_json::Value) -> Self {
        let d = Self::default();
        Self {
            depth: v
                .get("depth")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(d.depth),
            records: v
                .get("records")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(d.records),
            tokens: v.get("tokens").and_then(|x| x.as_u64()).unwrap_or(d.tokens),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetDimension {
    RunsPerHour,
    ToolSteps,
    TokensPerHour,
    ExpansionDepth,
    ExpansionRecords,
    ExpansionTokens,
}

impl std::fmt::Display for BudgetDimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::RunsPerHour => "runs_per_hour",
            Self::ToolSteps => "tool_steps",
            Self::TokensPerHour => "tokens_per_hour",
            Self::ExpansionDepth => "expansion_depth",
            Self::ExpansionRecords => "expansion_records",
            Self::ExpansionTokens => "expansion_tokens",
        };
        write!(f, "{s}")
    }
}

/// DB-backed ledger. All writes go through the tenant transaction so RLS
/// scopes every row to the caller's org.
pub struct BudgetLedger {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
}

fn window_start(now: DateTime<Utc>) -> DateTime<Utc> {
    // Truncate to the hour boundary, including sub-second precision: a
    // window that keeps microseconds makes every call its own window and
    // the ON CONFLICT upsert never fires, so budgets would never trip.
    let truncated = now.timestamp() / 3600 * 3600;
    DateTime::from_timestamp(truncated, 0).unwrap_or(now)
}

impl BudgetLedger {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    /// Load the attachment's budget JSON.
    pub async fn spend_budget(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
    ) -> Result<SpendBudget> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT budgets FROM agent_attachments
             WHERE organization_id = $1 AND id = $2 AND status = 'active'",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let (budgets,) =
            row.ok_or_else(|| TinkerError::NotFound(format!("attachment {attachment_id}")))?;
        Ok(SpendBudget::from_json(&budgets))
    }

    /// Record a run start. Fails closed when the hourly run budget is hit.
    pub async fn check_and_record_run(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
    ) -> Result<()> {
        let budget = self.spend_budget(ctx, attachment_id).await?;
        let ws = window_start(Utc::now());
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO spend_ledger
                 (organization_id, attachment_id, window_start, runs)
             VALUES ($1, $2, $3, 1)
             ON CONFLICT (organization_id, attachment_id, window_start)
             DO UPDATE SET runs = spend_ledger.runs + 1,
                           updated_at = now()",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .bind(ws)
        .execute(&mut *tx)
        .await?;
        let (runs,): (i32,) = sqlx::query_as(
            "SELECT runs FROM spend_ledger
             WHERE organization_id = $1 AND attachment_id = $2 AND window_start = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .bind(ws)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        if let Some(max) = budget.max_runs_per_hour {
            if runs as u32 > max {
                return Err(TinkerError::Forbidden(format!(
                    "budget exceeded: {} runs in hour window (max {max})",
                    BudgetDimension::RunsPerHour
                )));
            }
        }
        Ok(())
    }

    /// Record tool steps + tokens. Each dimension is checked independently
    /// and fails closed with a typed error naming the dimension.
    pub async fn check_and_record_steps(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        steps: u32,
        tokens: u64,
    ) -> Result<()> {
        let budget = self.spend_budget(ctx, attachment_id).await?;
        let ws = window_start(Utc::now());
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO spend_ledger
                 (organization_id, attachment_id, window_start, tool_steps, tokens_spent)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (organization_id, attachment_id, window_start)
             DO UPDATE SET tool_steps = spend_ledger.tool_steps + EXCLUDED.tool_steps,
                           tokens_spent = spend_ledger.tokens_spent + EXCLUDED.tokens_spent,
                           updated_at = now()",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .bind(ws)
        .bind(steps as i32)
        .bind(tokens as i64)
        .execute(&mut *tx)
        .await?;
        let (cur_steps, cur_tokens): (i32, i64) = sqlx::query_as(
            "SELECT tool_steps, tokens_spent FROM spend_ledger
             WHERE organization_id = $1 AND attachment_id = $2 AND window_start = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .bind(ws)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        if let Some(max) = budget.max_tool_steps {
            if cur_steps as u32 > max {
                return Err(TinkerError::Forbidden(format!(
                    "budget exceeded: {} tool steps in hour window (max {max})",
                    BudgetDimension::ToolSteps
                )));
            }
        }
        if let Some(max) = budget.max_tokens_per_hour {
            if cur_tokens as u64 > max {
                return Err(TinkerError::Forbidden(format!(
                    "budget exceeded: {} tokens in hour window (max {max})",
                    BudgetDimension::TokensPerHour
                )));
            }
        }
        Ok(())
    }

    /// Current window usage (for telemetry assertions).
    pub async fn window_usage(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
    ) -> Result<(i32, i32, i64)> {
        let ws = window_start(Utc::now());
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(i32, i32, i64)> = sqlx::query_as(
            "SELECT runs, tool_steps, tokens_spent FROM spend_ledger
             WHERE organization_id = $1 AND attachment_id = $2 AND window_start = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .bind(ws)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.unwrap_or((0, 0, 0)))
    }
}
