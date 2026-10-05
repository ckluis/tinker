//! Typed actions: write tools derived from the action registry.
//!
//! Every action has typed inputs, validation, required approvals, and
//! idempotency. The model never receives a generic database console:
//! agents can only invoke actions their attachment explicitly grants,
//! and effective access is the INTERSECTION of actor permissions,
//! attachment scope, context profile, field policy, action grant,
//! channel membership, and current approval state — a broader parent
//! attachment never weakens a narrower deny.

use std::collections::HashMap;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

/// A typed action definition: name, required input fields, whether it
/// needs human approval, and whether it is externally visible.
#[derive(Debug, Clone)]
pub struct ActionDef {
    pub name: String,
    pub required_inputs: Vec<String>,
    /// Actions in this set ALWAYS require an explicit grant and may
    /// require human approval (PRD default): external communication,
    /// deletion, permission change, secret use, authority transfer,
    /// bulk mutation.
    pub needs_human_approval: bool,
    pub external: bool,
    pub description: String,
}

impl ActionDef {
    pub fn validate_inputs(&self, inputs: &serde_json::Value) -> Result<()> {
        for req in &self.required_inputs {
            if inputs.get(req).is_none() {
                return Err(TinkerError::Validation(format!(
                    "action {} missing required input {req}",
                    self.name
                )));
            }
        }
        Ok(())
    }
}

/// The registry: the closed set of actions any agent may invoke.
/// Generated server-side — never from model output.
pub struct ActionRegistry {
    defs: HashMap<String, ActionDef>,
}

impl ActionRegistry {
    pub fn tinker_default() -> Self {
        let mut defs = HashMap::new();
        let mut add = |name: &str,
                       required_inputs: &[&str],
                       needs_human_approval: bool,
                       external: bool,
                       description: &str| {
            defs.insert(
                name.to_string(),
                ActionDef {
                    name: name.to_string(),
                    required_inputs: required_inputs.iter().map(|s| s.to_string()).collect(),
                    needs_human_approval,
                    external,
                    description: description.to_string(),
                },
            );
        };
        add(
            "deal.add_note",
            &["deal_id", "note"],
            false,
            false,
            "Append an internal note to a deal record",
        );
        add(
            "task.create",
            &["title"],
            false,
            false,
            "Create an internal task",
        );
        add(
            "email.create_draft",
            &["to", "subject", "body"],
            true,
            true,
            "Create an outbound email draft (external communication: needs human approval)",
        );
        add(
            "record.update",
            &["object", "record_id", "patch"],
            true,
            false,
            "Bulk-style mutation: always needs an explicit grant and may need human approval",
        );
        Self { defs }
    }

    pub fn get(&self, name: &str) -> Option<&ActionDef> {
        self.defs.get(name)
    }

    pub fn names(&self) -> Vec<String> {
        let mut n: Vec<String> = self.defs.keys().cloned().collect();
        n.sort();
        n
    }
}

/// Grant check + invocation gate for one attachment.
pub struct ActionGate {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
    registry: ActionRegistry,
}

impl ActionGate {
    pub fn new(core: CoreDb, owner: OwnerDb, registry: ActionRegistry) -> Self {
        Self {
            core,
            owner,
            registry,
        }
    }

    pub fn registry(&self) -> &ActionRegistry {
        &self.registry
    }

    async fn attachment_row(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
    ) -> Result<(serde_json::Value, serde_json::Value, String)> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(serde_json::Value, serde_json::Value, String)> = sqlx::query_as(
            "SELECT action_grants, approval_policy, status FROM agent_attachments
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.ok_or_else(|| TinkerError::NotFound(format!("attachment {attachment_id}")))
    }

    /// The intersection check: the action must exist in the registry AND
    /// be in the attachment's explicit grants AND the attachment must be
    /// active. Anything else fails closed.
    pub async fn check_grant(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        action_name: &str,
    ) -> Result<ActionDef> {
        let def = self
            .registry
            .get(action_name)
            .ok_or_else(|| TinkerError::Forbidden(format!("unknown action {action_name}")))?;
        let (grants, _policy, status) = self.attachment_row(ctx, attachment_id).await?;
        if status != "active" {
            return Err(TinkerError::Forbidden("attachment is revoked".into()));
        }
        let granted = grants
            .as_array()
            .map(|a| a.iter().any(|g| g.as_str() == Some(action_name)))
            .unwrap_or(false);
        if !granted {
            return Err(TinkerError::Forbidden(format!(
                "action {action_name} not granted to this attachment"
            )));
        }
        Ok(def.clone())
    }

    /// Whether this invocation needs human approval: registry default OR
    /// the attachment's approval policy says so.
    pub async fn needs_human_approval(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        def: &ActionDef,
    ) -> Result<bool> {
        if def.needs_human_approval {
            return Ok(true);
        }
        let (_grants, policy, _status) = self.attachment_row(ctx, attachment_id).await?;
        // Attachment policy can only ADD approval requirements, never
        // remove the registry defaults (narrower deny wins).
        Ok(policy
            .get("human_before_external_send")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            && def.external)
    }
}
