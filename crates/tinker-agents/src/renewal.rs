//! The renewal agent: the PRD's example copilot, wired end to end.
//!
//! Attachment-level budgets `{ max_runs_per_hour: 50, max_tool_steps: 12 }`
//! and expansion budgets `{ depth: 2, records: 40, tokens: 12000 }` bound
//! every run. The agent:
//!   1. checks its run budget (fail closed when exhausted);
//!   2. reads the root virtual file (the account);
//!   3. expands evidence along declared edges within scope + budget;
//!   4. records tool steps against the spend ledger;
//!   5. returns the evidence bundle + the expansion manifest.
//!
//! It cannot escape its authorization scope: the expansion engine
//! filters every candidate edge/target before scoring, the attachment
//! scope caps depth and relation types, and typed actions need their own
//! grants + approvals.

use std::collections::HashMap;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::Ontology;
use uuid::Uuid;

use crate::audit::AuditWriter;
use crate::budgets::{BudgetLedger, ExpansionBudget};
use crate::cache::TransformCache;
use crate::expand::{ExpansionEngine, ExpansionManifest};
use crate::gateway::ModelGateway;
use crate::profiles::ProfileEngine;
use crate::transforms::TransformEngine;
use crate::vfile::VirtualFileReader;

pub struct EvidenceBundle {
    pub root_markdown: String,
    pub files: HashMap<String, String>,
    pub manifest: ExpansionManifest,
    pub steps_used: u32,
    pub tokens_used: u64,
}

pub struct RenewalAgent {
    core: CoreDb,
    owner: OwnerDb,
    ontology: Ontology,
    gateway: ModelGateway,
}

impl RenewalAgent {
    pub fn new(core: CoreDb, owner: OwnerDb, ontology: Ontology, gateway: ModelGateway) -> Self {
        Self {
            core,
            owner,
            ontology,
            gateway,
        }
    }

    /// Run one renewal-evidence pass from a root record (e.g. a deal).
    pub async fn run(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        profile_key: &str,
        root_object: &str,
        root_record: Uuid,
        expansion_budget: Option<ExpansionBudget>,
    ) -> Result<EvidenceBundle> {
        let audit = AuditWriter::new(self.core.clone(), self.owner.clone());
        let engine = TransformEngine::new(
            self.core.clone(),
            self.owner.clone(),
            self.ontology.clone(),
            self.gateway.clone(),
            audit,
        );
        let cache = TransformCache::new(self.core.clone(), self.owner.clone());
        let profiles = ProfileEngine::new(self.core.clone(), self.owner.clone());
        let ledger = BudgetLedger::new(self.core.clone(), self.owner.clone());

        // 1. Run budget first: exhausted budgets fail before any work.
        ledger.check_and_record_run(ctx, attachment_id).await?;

        // 2. Root virtual file through the caller's policy.
        let reader = VirtualFileReader::new(&engine, &cache);
        let root_path = format!("/tinker/{root_object}/{root_record}/index.md");
        let root_markdown = reader.read(ctx, &root_path, Some(attachment_id)).await?;
        let mut steps_used: u32 = 1;
        let mut tokens_used: u64 = (root_markdown.len() as u64) / 4;

        // 3. Budgeted expansion along declared edges.
        let profile = profiles.active(ctx, profile_key).await?;
        let budget = expansion_budget.unwrap_or_default();
        let expansion = ExpansionEngine::new(
            self.core.clone(),
            self.owner.clone(),
            &self.ontology,
            &engine,
        );
        let (files, manifest) = expansion
            .expand(
                ctx,
                attachment_id,
                &profile,
                root_object,
                root_record,
                &budget,
            )
            .await?;
        steps_used += 1;
        tokens_used += manifest.tokens;

        // 4. Record spend.
        ledger
            .check_and_record_steps(ctx, attachment_id, steps_used, tokens_used)
            .await?;

        // 5. Evidence bundle + manifest.
        Ok(EvidenceBundle {
            root_markdown,
            files,
            manifest,
            steps_used,
            tokens_used,
        })
    }

    /// Guard: the attachment must name this agent kind and be active.
    /// Prevents a generic attachment from driving the renewal flow.
    pub async fn check_attachment(&self, ctx: &TenantContext, attachment_id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT kind, status FROM agent_attachments
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        match row {
            Some((kind, status)) if kind == "renewal_copilot" && status == "active" => Ok(()),
            Some((kind, status)) => Err(TinkerError::Forbidden(format!(
                "attachment kind={kind} status={status} cannot run the renewal agent"
            ))),
            None => Err(TinkerError::NotFound(format!("attachment {attachment_id}"))),
        }
    }
}
