//! Automations over sealed fields — docs/automations.md.
//!
//! An automation reacts to record events (from the transactional outbox
//! `automation_events`), checks conditions, and runs actions. Sensitive
//! fields take part through **keys**: condition literals are hashed into
//! automation keys when the automation is saved (the definition never
//! holds plaintext), records are read with `field:key` selects, and the
//! only action that needs a value — `send_email` — hands the delivery
//! outbox a vault *reference* that the worker resolves at send time.
//!
//! Every run reads as the automation's author role (projection + row
//! policy through the governed compiler) and is recorded once per
//! (automation, event) in `automation_runs`.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tinker_comms::delivery::EnqueueRequest;
use tinker_comms::{DeliveryWorker, EmailProvider};
use tinker_core::{OrganizationId, Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_durable::DurableRuntime;
use tinker_live::{FieldGrants, QueryExecutor};
use tinker_ontology::mutate::{
    validate_fields, MutationConnector, NoHooks, UpdateRequest, AUTOMATION_PURPOSE_PREFIX,
};
use tinker_ontology::sensitive::{register_refs, PiiSealer, SealedRef, MASK};
use tinker_ontology::{FieldDescription, ObjectDescription, Ontology};
use tinker_query::{Filter, FilterOp, QueryCompiler, QueryIntent, RowFilters, KEY_SUFFIX};
use uuid::Uuid;

/// Events caused by automations at this depth are not processed (A8).
pub const MAX_DEPTH: i32 = 3;
/// Sensitive literals one actor may save per rolling hour (A9).
pub const SENSITIVE_LITERALS_PER_HOUR: i64 = 20;
const MAX_CONDITIONS: usize = 20;
const MAX_ACTIONS: usize = 10;
const MAX_IN_LITERALS: usize = 50;

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "on", rename_all = "snake_case")]
pub enum Trigger {
    RecordCreated,
    /// Fires when any of `fields` changed (empty: any update).
    RecordUpdated {
        #[serde(default)]
        fields: Vec<String>,
    },
    RecordPublished,
}

impl Trigger {
    fn matches(&self, kind: &str, changed: &[String]) -> bool {
        match (self, kind) {
            (Trigger::RecordCreated, "created") => true,
            (Trigger::RecordPublished, "published") => true,
            (Trigger::RecordUpdated { fields }, "updated") => {
                fields.is_empty() || fields.iter().any(|f| changed.contains(f))
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CondOp {
    Eq,
    Ne,
    In,
    Gt,
    Gte,
    Lt,
    Lte,
    Contains,
    IsSet,
    IsEmpty,
    Changed,
}

/// A condition as written by the author. For a sensitive field, `value`
/// is plaintext on the way in and is replaced by automation key(s) on
/// save; `keyed` marks the stored form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Condition {
    pub field: String,
    pub op: CondOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keyed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Action {
    /// Set literal values on the triggering record (non-sensitive fields).
    UpdateRecord { values: Map<String, Value> },
    /// Email the address in a sensitive email field. Subject and body are
    /// templates over the record's non-sensitive fields; sensitive
    /// placeholders render as the mask.
    SendEmail {
        to_field: String,
        subject: String,
        body: String,
    },
    /// POST a JSON event (ids, the listed non-sensitive fields, and keys
    /// for listed sensitive fields) to an HTTPS or allow-listed URL.
    Webhook {
        url: String,
        #[serde(default)]
        fields: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationDef {
    pub object_id: Uuid,
    pub name: String,
    pub trigger: Trigger,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Automation {
    pub id: Uuid,
    pub object_id: Uuid,
    pub name: String,
    pub trigger: Trigger,
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
    pub enabled: bool,
    pub run_as_role: String,
    pub created_by: Uuid,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunRecord {
    pub event_id: Uuid,
    pub record_id: Uuid,
    pub outcome: String,
    pub detail: Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct RunStats {
    pub events: u64,
    pub succeeded: u64,
    pub skipped: u64,
    pub failed: u64,
    pub loop_blocked: u64,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Which webhook targets are allowed: HTTPS always, plus exact hosts on
/// the allow-list (for internal receivers and tests).
#[derive(Debug, Clone, Default)]
pub struct WebhookPolicy {
    pub allow_hosts: Vec<String>,
}

impl WebhookPolicy {
    /// `TINKER_AUTOMATION_WEBHOOK_ALLOW_HOSTS` (comma list of host or
    /// host:port allowed over plain HTTP).
    pub fn from_env() -> Self {
        Self {
            allow_hosts: std::env::var("TINKER_AUTOMATION_WEBHOOK_ALLOW_HOSTS")
                .unwrap_or_default()
                .split(',')
                .map(|h| h.trim().to_string())
                .filter(|h| !h.is_empty())
                .collect(),
        }
    }

    fn check(&self, url: &str) -> Result<()> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| TinkerError::Validation(format!("webhook: bad url {url}")))?;
        let host = parsed.host_str().unwrap_or("");
        let host_port = match parsed.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        };
        let allowed = self
            .allow_hosts
            .iter()
            .any(|h| h == host || *h == host_port);
        if parsed.scheme() == "https" || allowed {
            Ok(())
        } else {
            Err(TinkerError::Validation(
                "webhook: url must be https (or an allow-listed host)".into(),
            ))
        }
    }
}

pub struct AutomationEngine {
    core: CoreDb,
    owner: OwnerDb,
    ontology: Ontology,
    compiler: Arc<QueryCompiler>,
    executor: QueryExecutor,
    grants: FieldGrants,
    row_filters: RowFilters,
    mutator: Arc<MutationConnector>,
    sealer: Option<PiiSealer>,
    delivery: DeliveryWorker,
    email: Option<Arc<dyn EmailProvider>>,
    webhooks: WebhookPolicy,
    http: reqwest::Client,
}

impl AutomationEngine {
    /// `sealer`: the PII vault (sensitive conditions, keys, email). Without
    /// it, automations touching sensitive fields fail closed on save.
    pub fn new(core: CoreDb, owner: OwnerDb, sealer: Option<PiiSealer>) -> Self {
        let ontology = Ontology::new(core.clone(), owner.clone());
        let mut compiler = QueryCompiler::new(ontology.clone());
        let mut executor = QueryExecutor::new(core.clone());
        let mut mutator = MutationConnector::new(core.clone(), ontology.clone());
        let projector = sealer
            .as_ref()
            .map(|s| tinker_vault::PiiProjector::new(core.clone(), s.vault().clone()));
        if let Some(s) = &sealer {
            compiler = compiler.with_blind_index(s.blind_index().clone());
            executor = executor.with_keys(s.blind_index().clone());
            mutator = mutator.with_pii(s.clone());
        }
        let durable = DurableRuntime::new(core.clone(), owner.0.clone());
        Self {
            delivery: DeliveryWorker::new(core.clone(), durable, projector),
            grants: FieldGrants::new(core.clone()),
            row_filters: RowFilters::new(core.clone()),
            compiler: Arc::new(compiler),
            executor,
            mutator: Arc::new(mutator),
            ontology,
            core,
            owner,
            sealer,
            email: None,
            webhooks: WebhookPolicy::default(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("http client"),
        }
    }

    /// The provider `send_email` actions deliver through. Without one,
    /// emails stay queued in the delivery outbox.
    pub fn with_email_provider(mut self, provider: Arc<dyn EmailProvider>) -> Self {
        self.email = Some(provider);
        self
    }

    pub fn with_webhook_policy(mut self, policy: WebhookPolicy) -> Self {
        self.webhooks = policy;
        self
    }

    async fn role_of(&self, ctx: &TenantContext, actor: Uuid) -> Result<Option<String>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM memberships WHERE actor_id = $1 AND organization_id = $2",
        )
        .bind(actor)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(role)
    }

    async fn require_manager(&self, ctx: &TenantContext) -> Result<String> {
        match self.role_of(ctx, ctx.actor_id).await? {
            Some(r) if matches!(r.as_str(), "owner" | "admin") => Ok(r),
            _ => Err(TinkerError::Forbidden(
                "automations are managed by owners and admins".into(),
            )),
        }
    }

    // -- save --------------------------------------------------------------

    /// Validate and store an automation. Sensitive literals are replaced
    /// by automation keys before anything is stored; saves are audited
    /// (counts only) and rate-limited per actor (A9).
    pub async fn save(&self, ctx: &TenantContext, def: AutomationDef) -> Result<Automation> {
        let role = self.require_manager(ctx).await?;
        if def.name.trim().is_empty() || def.name.len() > 200 {
            return Err(TinkerError::Validation(
                "automation name must be 1-200 chars".into(),
            ));
        }
        if def.actions.is_empty() || def.actions.len() > MAX_ACTIONS {
            return Err(TinkerError::Validation(format!(
                "an automation needs 1-{MAX_ACTIONS} actions"
            )));
        }
        if def.conditions.len() > MAX_CONDITIONS {
            return Err(TinkerError::Validation(format!(
                "at most {MAX_CONDITIONS} conditions"
            )));
        }
        let desc = self.ontology.describe_object(ctx, def.object_id).await?;
        let projection = self
            .grants
            .load_projection_for_query(ctx, &self.ontology, &role, desc.id)
            .await?;
        let field = |api: &str| -> Result<&FieldDescription> {
            desc.fields
                .iter()
                .find(|f| f.api_name == api && projection.allows(desc.id, api))
                .ok_or_else(|| TinkerError::Validation(format!("unknown field '{api}'")))
        };
        if let Trigger::RecordUpdated { fields } = &def.trigger {
            for f in fields {
                field(f)?;
            }
        }

        // Conditions: sensitive literals become keys here, and only here.
        let mut sensitive_literals = 0i64;
        let mut conditions = Vec::with_capacity(def.conditions.len());
        for c in def.conditions {
            let f = field(&c.field)?;
            if c.keyed {
                return Err(TinkerError::Validation(
                    "conditions are written with values; keys are computed on save".into(),
                ));
            }
            let needs_value = !matches!(c.op, CondOp::IsSet | CondOp::IsEmpty | CondOp::Changed);
            if needs_value != c.value.is_some() {
                return Err(TinkerError::Validation(format!(
                    "condition on '{}': op {:?} {} a value",
                    c.field,
                    c.op,
                    if needs_value { "needs" } else { "takes no" }
                )));
            }
            if f.sensitive {
                match c.op {
                    CondOp::Eq | CondOp::Ne | CondOp::In => {
                        let sealer = self.sealer.as_ref().ok_or_else(|| {
                            TinkerError::Validation(format!(
                                "condition on sensitive '{}' needs the PII vault on this server",
                                c.field
                            ))
                        })?;
                        let to_key = |v: &Value| -> Result<Value> {
                            let s = v.as_str().ok_or_else(|| {
                                TinkerError::Validation(format!(
                                    "condition on '{}': sensitive values are strings",
                                    c.field
                                ))
                            })?;
                            let bidx = sealer.blind_index().digest(
                                ctx.organization_id.0,
                                f.id,
                                &f.field_type,
                                s,
                            );
                            Ok(Value::String(sealer.blind_index().automation_key(&bidx)))
                        };
                        let value = match (c.op, c.value.as_ref().unwrap_or(&Value::Null)) {
                            (CondOp::In, Value::Array(items)) => {
                                if items.is_empty() || items.len() > MAX_IN_LITERALS {
                                    return Err(TinkerError::Validation(format!(
                                        "condition on '{}': in takes 1-{MAX_IN_LITERALS} values",
                                        c.field
                                    )));
                                }
                                sensitive_literals += items.len() as i64;
                                Value::Array(items.iter().map(to_key).collect::<Result<_>>()?)
                            }
                            (CondOp::In, _) => {
                                return Err(TinkerError::Validation(format!(
                                    "condition on '{}': in takes an array",
                                    c.field
                                )))
                            }
                            (_, v) => {
                                sensitive_literals += 1;
                                to_key(v)?
                            }
                        };
                        conditions.push(Condition {
                            field: c.field,
                            op: c.op,
                            value: Some(value),
                            keyed: true,
                        });
                    }
                    CondOp::IsSet | CondOp::IsEmpty | CondOp::Changed => conditions.push(c),
                    _ => {
                        return Err(TinkerError::Validation(format!(
                            "condition on sensitive '{}': only eq, ne, in, is_set, is_empty and \
                             changed apply (the value is never compared in plaintext)",
                            c.field
                        )))
                    }
                }
            } else {
                if c.op == CondOp::In && !c.value.as_ref().is_some_and(Value::is_array) {
                    return Err(TinkerError::Validation(format!(
                        "condition on '{}': in takes an array",
                        c.field
                    )));
                }
                conditions.push(c);
            }
        }

        // Actions.
        let template_ctx: Map<String, Value> = desc
            .fields
            .iter()
            .map(|f| (f.api_name.clone(), Value::String(String::new())))
            .collect();
        for a in &def.actions {
            match a {
                Action::UpdateRecord { values } => {
                    if values.is_empty() {
                        return Err(TinkerError::Validation(
                            "update_record sets no values".into(),
                        ));
                    }
                    let mut subset = Vec::new();
                    for k in values.keys() {
                        let f = field(k)?;
                        if f.sensitive {
                            return Err(TinkerError::Validation(format!(
                                "update_record cannot write sensitive '{k}' (the literal would \
                                 live in the automation definition)"
                            )));
                        }
                        subset.push(f.clone());
                    }
                    let vals: HashMap<String, Value> =
                        values.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    validate_fields(&subset, &vals, false)?;
                }
                Action::SendEmail {
                    to_field,
                    subject,
                    body,
                } => {
                    let f = field(to_field)?;
                    if !(f.sensitive && f.field_type == "email") {
                        return Err(TinkerError::Validation(format!(
                            "send_email: '{to_field}' must be an email field"
                        )));
                    }
                    if self.sealer.is_none() {
                        return Err(TinkerError::Validation(
                            "send_email needs the PII vault on this server".into(),
                        ));
                    }
                    for (label, t) in [("subject", subject), ("body", body)] {
                        tinker_comms::templates::render(t, &Value::Object(template_ctx.clone()))
                            .map_err(|e| {
                                TinkerError::Validation(format!("send_email {label}: {e:?}"))
                            })?;
                    }
                }
                Action::Webhook { url, fields } => {
                    self.webhooks.check(url)?;
                    for f in fields {
                        field(f)?;
                    }
                }
            }
        }

        // Guessing guard (A9), then store, log, audit — one transaction.
        let mut tx = self.core.tenant_tx(ctx).await?;
        if sensitive_literals > 0 {
            let recent: i64 = sqlx::query_scalar(
                "SELECT COALESCE(sum(sensitive_literals), 0)::bigint FROM automation_saves \
                 WHERE organization_id = $1 AND actor_id = $2 \
                   AND created_at > now() - interval '1 hour'",
            )
            .bind(ctx.organization_id.0)
            .bind(ctx.actor_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            if recent + sensitive_literals > SENSITIVE_LITERALS_PER_HOUR {
                return Err(TinkerError::Forbidden(format!(
                    "too many sensitive literals saved this hour ({recent} + {sensitive_literals} \
                     > {SENSITIVE_LITERALS_PER_HOUR}); equality on sealed values is rate-limited"
                )));
            }
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO automations \
             (id, organization_id, object_id, name, trigger, conditions, actions, \
              run_as_actor, run_as_role, created_by) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $8)",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(desc.id)
        .bind(def.name.trim())
        .bind(serde_json::to_value(&def.trigger).map_err(TinkerError::Serde)?)
        .bind(serde_json::to_value(&conditions).map_err(TinkerError::Serde)?)
        .bind(serde_json::to_value(&def.actions).map_err(TinkerError::Serde)?)
        .bind(ctx.actor_id)
        .bind(&role)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        sqlx::query(
            "INSERT INTO automation_saves (organization_id, actor_id, automation_id, sensitive_literals) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(id)
        .bind(sensitive_literals as i32)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        sqlx::query(
            "INSERT INTO audit_events \
             (organization_id, actor_id, action, resource_type, resource_id, status, metadata) \
             VALUES ($1, $2, 'automation.saved', 'automation', $3, 'ok', $4)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(id.to_string())
        .bind(json!({ "object_id": desc.id, "sensitive_literals": sensitive_literals }))
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(Automation {
            id,
            object_id: desc.id,
            name: def.name.trim().to_string(),
            trigger: def.trigger,
            conditions,
            actions: def.actions,
            enabled: true,
            run_as_role: role,
            created_by: ctx.actor_id,
        })
    }

    pub async fn list(
        &self,
        ctx: &TenantContext,
        object_id: Option<Uuid>,
    ) -> Result<Vec<Automation>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<AutomationRow> = sqlx::query_as(&format!(
            "SELECT {AUTOMATION_COLUMNS} FROM automations \
             WHERE organization_id = $1 AND ($2::uuid IS NULL OR object_id = $2) \
             ORDER BY created_at"
        ))
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        rows.into_iter().map(to_automation).collect()
    }

    pub async fn set_enabled(&self, ctx: &TenantContext, id: Uuid, enabled: bool) -> Result<()> {
        self.require_manager(ctx).await?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE automations SET enabled = $3, version = version + 1, updated_at = now() \
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(id)
        .bind(enabled)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        tx.commit().await.map_err(TinkerError::Db)?;
        if n == 0 {
            return Err(TinkerError::NotFound(format!("automation {id}")));
        }
        Ok(())
    }

    pub async fn runs(&self, ctx: &TenantContext, id: Uuid, limit: i64) -> Result<Vec<RunRecord>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, Uuid, String, Value, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            "SELECT event_id, record_id, outcome, detail, created_at FROM automation_runs \
             WHERE organization_id = $1 AND automation_id = $2 \
             ORDER BY created_at DESC LIMIT $3",
        )
        .bind(ctx.organization_id.0)
        .bind(id)
        .bind(limit.clamp(1, 500))
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(rows
            .into_iter()
            .map(
                |(event_id, record_id, outcome, detail, created_at)| RunRecord {
                    event_id,
                    record_id,
                    outcome,
                    detail,
                    created_at,
                },
            )
            .collect())
    }

    // -- worker ------------------------------------------------------------

    /// Process up to `limit` pending events per organization. Safe to run
    /// concurrently (events are claimed with SKIP LOCKED; runs are fenced
    /// by UNIQUE (automation, event)).
    pub async fn run_pending(&self, limit: i64) -> Result<RunStats> {
        let orgs: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT organization_id FROM automation_events \
             WHERE processed_at IS NULL LIMIT 200",
        )
        .fetch_all(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        let mut stats = RunStats::default();
        for org in orgs {
            let s = self.run_pending_org(org, limit).await?;
            stats.events += s.events;
            stats.succeeded += s.succeeded;
            stats.skipped += s.skipped;
            stats.failed += s.failed;
            stats.loop_blocked += s.loop_blocked;
        }
        Ok(stats)
    }

    /// [`run_pending`](Self::run_pending) for one organization.
    pub async fn run_pending_org(&self, org: Uuid, limit: i64) -> Result<RunStats> {
        let mut stats = RunStats::default();
        {
            let worker = TenantContext::new(OrganizationId(org), Uuid::nil(), "automation.worker");
            let mut tx = self.core.tenant_tx(&worker).await?;
            let events: Vec<(Uuid, Uuid, Uuid, String, Vec<String>, i32)> = sqlx::query_as(
                "UPDATE automation_events SET claimed_until = now() + interval '60 seconds' \
                 WHERE id IN (SELECT id FROM automation_events \
                              WHERE organization_id = $1 AND processed_at IS NULL \
                                AND (claimed_until IS NULL OR claimed_until < now()) \
                              ORDER BY created_at LIMIT $2 FOR UPDATE SKIP LOCKED) \
                 RETURNING id, object_id, record_id, kind, changed, depth",
            )
            .bind(org)
            .bind(limit)
            .fetch_all(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            let automations: Vec<AutomationRow> = sqlx::query_as(&format!(
                "SELECT {AUTOMATION_COLUMNS} FROM automations \
                 WHERE organization_id = $1 AND enabled ORDER BY created_at"
            ))
            .bind(org)
            .fetch_all(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            tx.commit().await.map_err(TinkerError::Db)?;
            let automations: Vec<(Automation, Uuid)> = automations
                .into_iter()
                .filter_map(|r| {
                    let actor = r.7;
                    to_automation(r).ok().map(|a| (a, actor))
                })
                .collect();
            for (event_id, object_id, record_id, kind, changed, depth) in events {
                stats.events += 1;
                let event = Event {
                    id: event_id,
                    record_id,
                    kind,
                    changed,
                    depth,
                };
                for (a, run_as) in automations.iter().filter(|(a, _)| {
                    a.object_id == object_id && a.trigger.matches(&event.kind, &event.changed)
                }) {
                    let (outcome, detail) = if event.depth >= MAX_DEPTH {
                        ("loop_blocked", json!({ "depth": event.depth }))
                    } else {
                        match self.run_one(org, a, *run_as, &event).await {
                            Ok(Some(detail)) => ("succeeded", detail),
                            Ok(None) => ("skipped", json!({ "reason": "conditions not met" })),
                            Err(e) => ("failed", json!({ "error": e.to_string() })),
                        }
                    };
                    let mut tx = self.core.tenant_tx(&worker).await?;
                    let inserted = sqlx::query(
                        "INSERT INTO automation_runs \
                         (organization_id, automation_id, event_id, record_id, outcome, detail) \
                         VALUES ($1, $2, $3, $4, $5, $6) \
                         ON CONFLICT (automation_id, event_id) DO NOTHING",
                    )
                    .bind(org)
                    .bind(a.id)
                    .bind(event.id)
                    .bind(event.record_id)
                    .bind(outcome)
                    .bind(&detail)
                    .execute(&mut *tx)
                    .await
                    .map_err(TinkerError::Db)?
                    .rows_affected();
                    tx.commit().await.map_err(TinkerError::Db)?;
                    if inserted == 1 {
                        match outcome {
                            "succeeded" => stats.succeeded += 1,
                            "skipped" => stats.skipped += 1,
                            "failed" => stats.failed += 1,
                            _ => stats.loop_blocked += 1,
                        }
                    }
                }
                let mut tx = self.core.tenant_tx(&worker).await?;
                sqlx::query("UPDATE automation_events SET processed_at = now() WHERE id = $1")
                    .bind(event.id)
                    .execute(&mut *tx)
                    .await
                    .map_err(TinkerError::Db)?;
                tx.commit().await.map_err(TinkerError::Db)?;
            }
        }
        Ok(stats)
    }

    /// Evaluate one automation on one event. `Ok(None)`: conditions not
    /// met; `Ok(Some(detail))`: actions ran (detail holds ids and keys).
    async fn run_one(
        &self,
        org: Uuid,
        a: &Automation,
        run_as: Uuid,
        event: &Event,
    ) -> Result<Option<Value>> {
        // The author's current role must still be the one saved (A5).
        let ctx = TenantContext::new(
            OrganizationId(org),
            run_as,
            format!("{AUTOMATION_PURPOSE_PREFIX}{}:{}", a.id, event.depth + 1),
        );
        match self.role_of(&ctx, run_as).await? {
            Some(r) if r == a.run_as_role => {}
            _ => {
                return Err(TinkerError::Forbidden(
                    "the automation's author no longer holds its role".into(),
                ))
            }
        }
        let desc = self.ontology.describe_object(&ctx, a.object_id).await?;
        let Some(row) = self
            .read_record(&ctx, &desc, &a.run_as_role, event.record_id)
            .await?
        else {
            return Ok(None);
        };
        for c in &a.conditions {
            if !evaluate(c, &row, &desc, &event.changed)? {
                return Ok(None);
            }
        }
        let mut results = Vec::with_capacity(a.actions.len());
        for (i, action) in a.actions.iter().enumerate() {
            let r = self
                .act(&ctx, &desc, a, event, i, action, &row)
                .await
                .map_err(|e| TinkerError::Validation(format!("action {i}: {e}")))?;
            results.push(r);
        }
        Ok(Some(json!({ "actions": results })))
    }

    /// The triggering record as the automation's role sees it: every
    /// visible non-sensitive field by value, every visible sensitive field
    /// as `field:key`. `None` when the record is not visible to the role.
    async fn read_record(
        &self,
        ctx: &TenantContext,
        desc: &ObjectDescription,
        role: &str,
        record_id: Uuid,
    ) -> Result<Option<Map<String, Value>>> {
        let projection = self
            .grants
            .load_projection_for_query(ctx, &self.ontology, role, desc.id)
            .await?;
        let policy = self.row_filters.load_policy(ctx, desc.id, role).await?;
        let select: Vec<String> = desc
            .fields
            .iter()
            .filter(|f| f.extension_table.is_none() && projection.allows(desc.id, &f.api_name))
            .map(|f| {
                if f.sensitive {
                    format!("{}{KEY_SUFFIX}", f.api_name)
                } else {
                    f.api_name.clone()
                }
            })
            .collect();
        if select.is_empty() {
            return Ok(None);
        }
        let intent = QueryIntent {
            from: desc.id,
            select,
            filters: vec![Filter {
                field: "__id".into(),
                op: FilterOp::Eq,
                value: Value::String(record_id.to_string()),
            }],
            order: vec![],
            limit: Some(1),
            schema_version: None,
        };
        let plan = self
            .compiler
            .compile_with_policy(ctx, &intent, &projection, &policy)
            .await?;
        let rows = self.executor.execute(ctx, &plan).await?;
        Ok(rows.into_iter().next().and_then(|r| r.as_object().cloned()))
    }

    #[allow(clippy::too_many_arguments)]
    async fn act(
        &self,
        ctx: &TenantContext,
        desc: &ObjectDescription,
        a: &Automation,
        event: &Event,
        index: usize,
        action: &Action,
        row: &Map<String, Value>,
    ) -> Result<Value> {
        match action {
            Action::UpdateRecord { values } => {
                let out = self
                    .mutator
                    .update(
                        ctx,
                        &UpdateRequest {
                            object_id: desc.id,
                            record_id: event.record_id,
                            values: values.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                            expected_version: None,
                            require_approval: false,
                            approval_request_id: None,
                        },
                        &NoHooks,
                    )
                    .await?;
                Ok(json!({ "type": "update_record", "version": out.version }))
            }
            Action::SendEmail {
                to_field,
                subject,
                body,
            } => {
                let sealer = self
                    .sealer
                    .as_ref()
                    .ok_or_else(|| TinkerError::Validation("no PII vault configured".into()))?;
                let f = desc
                    .fields
                    .iter()
                    .find(|f| f.api_name == *to_field)
                    .ok_or_else(|| {
                        TinkerError::Validation(format!("unknown field '{to_field}'"))
                    })?;
                // The recipient stays a vault reference end to end.
                let mut tx = self.core.tenant_tx(ctx).await?;
                let to_ref: Option<Uuid> = sqlx::query_scalar(&format!(
                    "SELECT \"{}\" FROM data.{} WHERE organization_id = $1 AND id = $2",
                    f.physical_column, desc.api_slug
                ))
                .bind(ctx.organization_id.0)
                .bind(event.record_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(TinkerError::Db)?
                .flatten();
                let to_ref = to_ref.ok_or_else(|| {
                    TinkerError::Validation(format!("'{to_field}' is empty on this record"))
                })?;
                // Templates see non-sensitive values; sealed fields render
                // as the mask (their keys are not a value to show).
                let mut tctx = Map::new();
                for fd in &desc.fields {
                    let v = if fd.sensitive {
                        match row.get(&format!("{}{KEY_SUFFIX}", fd.api_name)) {
                            Some(Value::String(_)) => Value::String(MASK.into()),
                            _ => Value::String(String::new()),
                        }
                    } else {
                        row.get(&fd.api_name).cloned().unwrap_or(Value::Null)
                    };
                    tctx.insert(
                        fd.api_name.clone(),
                        if v.is_null() {
                            Value::String(String::new())
                        } else {
                            v
                        },
                    );
                }
                let tctx = Value::Object(tctx);
                let subject = tinker_comms::templates::render(subject, &tctx)
                    .map_err(|e| TinkerError::Validation(format!("subject: {e:?}")))?;
                let body = tinker_comms::templates::render(body, &tctx)
                    .map_err(|e| TinkerError::Validation(format!("body: {e:?}")))?;
                // The body may carry record data: it travels sealed too.
                let body_ref = sealer
                    .vault()
                    .seal(ctx, event.record_id, "comm.body", &body)
                    .await?;
                register_refs(
                    &mut tx,
                    ctx,
                    &[SealedRef {
                        ref_id: body_ref,
                        subject: event.record_id,
                        storage_class: "comm.body".into(),
                    }],
                )
                .await?;
                tx.commit().await.map_err(TinkerError::Db)?;
                let key = format!("automation:{}:{}:{index}", a.id, event.id);
                let (delivery_id, _) = self
                    .delivery
                    .enqueue(
                        ctx,
                        EnqueueRequest {
                            kind: "email",
                            idempotency_key: key.clone(),
                            payload: json!({
                                "to_actor": Uuid::nil(),
                                "vault_to_ref": to_ref,
                                "vault_body_ref": body_ref,
                                "subject": subject,
                            }),
                            status: "queued",
                            deliver_after: None,
                        },
                    )
                    .await?;
                let status = match &self.email {
                    Some(p) => {
                        self.delivery
                            .run_delivery(ctx, delivery_id, p.as_ref())
                            .await?;
                        "sent"
                    }
                    None => "queued",
                };
                Ok(
                    json!({ "type": "send_email", "delivery_id": delivery_id, "status": status, "idempotency_key": key }),
                )
            }
            Action::Webhook { url, fields } => {
                self.webhooks.check(url)?;
                let mut values = Map::new();
                let mut keys = Map::new();
                for name in fields {
                    let Some(fd) = desc.fields.iter().find(|f| f.api_name == *name) else {
                        continue;
                    };
                    if fd.sensitive {
                        let k = row
                            .get(&format!("{name}{KEY_SUFFIX}"))
                            .cloned()
                            .unwrap_or(Value::Null);
                        keys.insert(name.clone(), k);
                    } else {
                        values.insert(name.clone(), row.get(name).cloned().unwrap_or(Value::Null));
                    }
                }
                let payload = json!({
                    "automation_id": a.id,
                    "event_id": event.id,
                    "event": event.kind,
                    "object": desc.api_slug,
                    "record_id": event.record_id,
                    "fields": values,
                    "keys": keys,
                });
                let resp = self
                    .http
                    .post(url)
                    .header("Idempotency-Key", format!("{}:{}:{index}", a.id, event.id))
                    .json(&payload)
                    .send()
                    .await
                    .map_err(|e| TinkerError::Validation(format!("webhook: {e}")))?;
                if !resp.status().is_success() {
                    return Err(TinkerError::Validation(format!(
                        "webhook returned {}",
                        resp.status()
                    )));
                }
                Ok(json!({ "type": "webhook", "status": resp.status().as_u16() }))
            }
        }
    }
}

struct Event {
    id: Uuid,
    record_id: Uuid,
    kind: String,
    changed: Vec<String>,
    depth: i32,
}

/// One condition against the record as read for the automation role.
/// Sensitive conditions compare automation keys; a field the role cannot
/// see fails the run closed rather than evaluating to "no match".
fn evaluate(
    c: &Condition,
    row: &Map<String, Value>,
    desc: &ObjectDescription,
    changed: &[String],
) -> Result<bool> {
    if c.op == CondOp::Changed {
        return Ok(changed.contains(&c.field));
    }
    let sensitive = desc
        .fields
        .iter()
        .find(|f| f.api_name == c.field)
        .map(|f| f.sensitive)
        .unwrap_or(false);
    let column = if sensitive {
        format!("{}{KEY_SUFFIX}", c.field)
    } else {
        c.field.clone()
    };
    let actual = row.get(&column).ok_or_else(|| {
        TinkerError::Forbidden(format!(
            "field '{}' is not visible to the automation",
            c.field
        ))
    })?;
    let blank = actual.is_null() || actual.as_str().is_some_and(|s| s.is_empty());
    let value = c.value.as_ref().unwrap_or(&Value::Null);
    Ok(match c.op {
        CondOp::IsSet => !blank,
        CondOp::IsEmpty => blank,
        CondOp::Eq => json_eq(actual, value),
        CondOp::Ne => !json_eq(actual, value),
        CondOp::In => value
            .as_array()
            .is_some_and(|items| items.iter().any(|v| json_eq(actual, v))),
        CondOp::Contains => match (actual.as_str(), value.as_str()) {
            (Some(a), Some(v)) => a.contains(v),
            _ => false,
        },
        CondOp::Gt | CondOp::Gte | CondOp::Lt | CondOp::Lte => {
            let ord = match (as_f64(actual), as_f64(value)) {
                (Some(a), Some(b)) => a.partial_cmp(&b),
                _ => match (actual.as_str(), value.as_str()) {
                    (Some(a), Some(b)) => Some(a.cmp(b)),
                    _ => None,
                },
            };
            match ord {
                None => false,
                Some(o) => match c.op {
                    CondOp::Gt => o.is_gt(),
                    CondOp::Gte => o.is_ge(),
                    CondOp::Lt => o.is_lt(),
                    _ => o.is_le(),
                },
            }
        }
        CondOp::Changed => unreachable!(),
    })
}

fn as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn json_eq(a: &Value, b: &Value) -> bool {
    match (as_f64(a), as_f64(b)) {
        (Some(x), Some(y)) if a.is_number() || b.is_number() => x == y,
        _ => a == b,
    }
}

type AutomationRow = (
    Uuid,
    Uuid,
    String,
    Value,
    Value,
    Value,
    bool,
    Uuid,
    String,
    Uuid,
);

const AUTOMATION_COLUMNS: &str =
    "id, object_id, name, trigger, conditions, actions, enabled, run_as_actor, run_as_role, created_by";

fn to_automation(r: AutomationRow) -> Result<Automation> {
    let corrupt = |what: &str| TinkerError::Internal(format!("corrupt automation {what}"));
    Ok(Automation {
        id: r.0,
        object_id: r.1,
        name: r.2,
        trigger: serde_json::from_value(r.3).map_err(|_| corrupt("trigger"))?,
        conditions: serde_json::from_value(r.4).map_err(|_| corrupt("conditions"))?,
        actions: serde_json::from_value(r.5).map_err(|_| corrupt("actions"))?,
        enabled: r.6,
        run_as_role: r.8,
        created_by: r.9,
    })
}
