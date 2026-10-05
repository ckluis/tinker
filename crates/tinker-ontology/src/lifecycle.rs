//! Per-record draft → review → publish lifecycle (C1, item 40).
//!
//! Storage design — the data table holds PUBLISHED content only:
//! - `data.{slug}` rows carry `lifecycle_state` (`'published'|'archived'`)
//!   and always hold the latest published content. In-flight work never
//!   touches the data table, so default readers structurally cannot see
//!   draft content — no half-written record leaks through a missed
//!   predicate. This is the same shape as M4's `VersionSel::Active`:
//!   one live version, drafts off to the side.
//! - `record_drafts` holds the working copy (`draft` → `in_review` →
//!   `rejected`). At most one in-flight draft per existing record
//!   (partial unique index — two concurrent drafts would be an
//!   unresolvable merge, so the second fails closed).
//! - `record_versions` is the immutable publish history: one row per
//!   publish, `version_no` tracking the data row's version. Append-only
//!   for the app role.
//!
//! Read path (one enforcement path, not two): the query compiler's
//! default resolves `lifecycle_state = 'published'` in the same WHERE
//! clause as the tenant predicate and the C2 row policy. `lifecycle_state`
//! is also a first-class C2 policy dimension (a role policy may filter
//! on it), and an explicit policy filter overrides the default —
//! archivists get `lifecycle_state in ('published','archived')` through
//! the normal policy machinery. Drafts need no read-path predicate at
//! all: they are not in the queried table.
//!
//! Transitions (all audit-logged into `mutation_audit` as
//! `lifecycle.<transition>`):
//! - `create_draft` → `draft`. New records start here; editing a
//!   published record forks a draft pre-filled with the published
//!   content, with the caller's values merged on top.
//! - `update_draft`: content frozen while `in_review` (reviewers decide
//!   on a stable artifact); author-only; full-content replace.
//! - `submit_for_review`: `draft|rejected` → `in_review`. Consumes an
//!   M7 approval (same atomic consume path as governed writes).
//! - `publish`: `in_review` → `published`. Consumes a second M7 approval
//!   that must be decided by someone OTHER than the author (no
//!   self-approval, enforced here). Content is re-validated against the
//!   CURRENT schema — a schema change between draft and publish fails
//!   closed instead of publishing stale-shaped data. Each publish bumps
//!   the data row version and appends a `record_versions` snapshot, so
//!   readers see the latest published version while a newer draft is in
//!   flight.
//! - `reject`: `in_review` → `rejected`. Reviewer-only (never the
//!   author), no M7 approval — rejection is the fail-safe direction.
//! - `revise`: `rejected` → `draft`. Author-only.
//! - `archive` / `unarchive`: `published` ↔ `archived`. Each consumes an
//!   M7 approval (visibility changes are destructive-ish).
//!
//! Draft visibility: `draft`/`rejected` are visible to the author only;
//! `in_review` is additionally visible to any org member (reviewers must
//! be able to read what they decide on). Everything else is NotFound —
//! never an existence oracle.
//!
//! M7 composition: submit_for_review, publish, archive, unarchive all
//! consume M7 approvals through `consume_approval` — the exact path
//! governed writes use. An approval is single-use; pending/denied/
//! executed/expired approvals all fail closed identically.
//!
//! M8 retention interplay (documented policy):
//! - Published/archived records are subject to the org's M8 retention
//!   policy via `RetentionEngine::apply_core` on the data table
//!   (`updated_at` is bumped on every publish, so the window counts
//!   from last publish). After a retention run,
//!   `purge_orphaned_versions` removes version history whose record is
//!   gone, and stale drafts of purged records go with
//!   `purge_stale_drafts`. A legal hold suspends all of it, mirroring M8.
//! - Drafts have their own shorter retention: `purge_stale_drafts`
//!   hard-deletes drafts (any state) older than the given age.
//!   Recommended default: 30 days. Drafts are working copies, not
//!   records of value; the approval lifecycle is separate (an approval
//!   expires on its own TTL regardless).
//!
//! Honest limits (v1):
//! - Record-level only: no per-field versioning, no field-level diff.
//! - No scheduled publish.
//! - No privileged "see all states" query path: archived visibility is
//!   via explicit C2 policy override; there is no version-history read
//!   beyond `list_versions`.
//! - `ontology_objects.lifecycle_enabled` gates the write path: when
//!   true, `MutationConnector` refuses direct create/update (fail
//!   closed) so records cannot bypass the lifecycle. Default false.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use super::mutate::{
    apply_presets, bind_col, consume_approval, validate_fields, write_columns, FileLinkValidator,
};
use super::sensitive::{register_refs, seal_values, sealed_json, PiiSealer, SealedRef};
use super::{FieldDescription, ObjectDescription, Ontology};

/// Lifecycle states. `draft`/`in_review`/`rejected` live in
/// `record_drafts`; `published`/`archived` live on the data row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    Draft,
    InReview,
    Rejected,
    Published,
    Archived,
}

impl LifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Draft => "draft",
            Self::InReview => "in_review",
            Self::Rejected => "rejected",
            Self::Published => "published",
            Self::Archived => "archived",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "draft" => Ok(Self::Draft),
            "in_review" => Ok(Self::InReview),
            "rejected" => Ok(Self::Rejected),
            "published" => Ok(Self::Published),
            "archived" => Ok(Self::Archived),
            other => Err(TinkerError::Internal(format!(
                "corrupt lifecycle state: {other}"
            ))),
        }
    }
}

/// One in-flight draft row.
#[derive(Debug, Clone)]
pub struct Draft {
    pub draft_id: Uuid,
    pub object_id: Uuid,
    /// None for a brand-new record (no data row yet).
    pub record_id: Option<Uuid>,
    pub state: LifecycleState,
    /// api_name → value, post-preset, validated.
    pub content: serde_json::Value,
    /// Published version this draft builds on (None for new records).
    pub base_version: Option<i64>,
    pub created_by: Uuid,
    pub updated_by: Uuid,
    pub updated_at: DateTime<Utc>,
}

/// One immutable publish snapshot.
#[derive(Debug, Clone)]
pub struct PublishedVersion {
    pub record_id: Uuid,
    pub version_no: i64,
    pub content: serde_json::Value,
    pub published_by: Uuid,
    pub published_at: DateTime<Utc>,
}

type DraftRow = (
    Uuid,
    Uuid,
    Option<Uuid>,
    String,
    serde_json::Value,
    Option<i64>,
    Uuid,
    Uuid,
    DateTime<Utc>,
);

fn to_draft(row: DraftRow) -> Result<Draft> {
    Ok(Draft {
        draft_id: row.0,
        object_id: row.1,
        record_id: row.2,
        state: LifecycleState::parse(&row.3)?,
        content: row.4,
        base_version: row.5,
        created_by: row.6,
        updated_by: row.7,
        updated_at: row.8,
    })
}

const DRAFT_COLUMNS: &str = "draft_id, object_id, record_id, state, content, base_version, created_by, updated_by, updated_at";

/// Recommended draft retention: working copies older than this are
/// purged by `purge_stale_drafts`. Drafts are not records of value.
pub const DEFAULT_DRAFT_RETENTION: Duration = Duration::from_secs(30 * 24 * 3600);

/// The outcome of a publish: the record id, the object it belongs to,
/// and its new version. The object id rides along because the draft row
/// is deleted by publish — callers that need to invalidate per-object
/// caches must not have to re-derive it.
#[derive(Debug)]
pub struct PublishOutcome {
    pub record_id: Uuid,
    pub object_id: Uuid,
    pub version: i64,
}

// Item 46 (`tinker-mcp serve`): `Clone` so the HTTP transport can hold
// one shared services triple and mint a per-session `FrontDoor` from
// it. All fields are already `Clone`; the impl changes nothing.
#[derive(Clone)]
pub struct LifecycleEngine {
    core: CoreDb,
    ontology: Ontology,
    file_validator: Option<Arc<dyn FileLinkValidator>>,
    pii: Option<PiiSealer>,
}

/// One lifecycle transition audit entry. Bundled so clippy's
/// too-many-arguments lint stays happy as the audit grows.
struct TransitionAudit<'a> {
    object_id: Uuid,
    record_id: Option<Uuid>,
    draft_id: Option<Uuid>,
    transition: &'a str,
    before: &'a serde_json::Value,
    after: &'a serde_json::Value,
    approval_request_id: Option<Uuid>,
}

impl LifecycleEngine {
    pub fn new(core: CoreDb, ontology: Ontology) -> Self {
        Self {
            core,
            ontology,
            file_validator: None,
            pii: None,
        }
    }

    /// Attach the PII vault for sensitive fields. Draft content, version
    /// history and the published row then only ever hold sealed values;
    /// without it, a draft carrying a sensitive value fails closed.
    pub fn with_pii(mut self, sealer: PiiSealer) -> Self {
        self.pii = Some(sealer);
        self
    }

    /// Seal the CALLER's sensitive values (never stored content, which is
    /// already sealed) and merge them over `merged`. Runs after
    /// validation has checked the plaintext.
    async fn seal_caller_values(
        &self,
        ctx: &TenantContext,
        fields: &[FieldDescription],
        subject: Uuid,
        values: &HashMap<String, serde_json::Value>,
        merged: &mut HashMap<String, serde_json::Value>,
    ) -> Result<Vec<SealedRef>> {
        let mut caller: HashMap<String, serde_json::Value> = values
            .iter()
            .filter(|(k, _)| fields.iter().any(|f| f.sensitive && &f.api_name == *k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let sealed = seal_values(self.pii.as_ref(), ctx, fields, subject, &mut caller).await?;
        merged.extend(caller);
        Ok(sealed)
    }

    /// Attach file-field validation for the publish path. When absent,
    /// `file` fields publish as opaque UUID text (pre-item-42
    /// behavior); callers that govern files attach the
    /// `FileStore`-backed validator.
    pub fn with_file_validator(mut self, v: Arc<dyn FileLinkValidator>) -> Self {
        self.file_validator = Some(v);
        self
    }

    fn table_slug(api_slug: &str) -> String {
        format!("data.{api_slug}")
    }

    /// Fail closed: the lifecycle engine only operates on objects opted
    /// into lifecycle management. (Direct writes are refused for such
    /// objects by the mutation connector; the engine refusing
    /// non-lifecycle objects keeps the two paths from silently
    /// diverging.)
    fn require_lifecycle(desc: &ObjectDescription) -> Result<()> {
        if !desc.lifecycle_enabled {
            return Err(TinkerError::Validation(
                "object is not lifecycle-managed".into(),
            ));
        }
        Ok(())
    }

    /// Lightweight lifecycle check by object id, for use inside an
    /// existing transaction (avoids describe_object's nested tx).
    async fn require_lifecycle_by_id(
        tx: &mut Transaction<'_, Postgres>,
        object_id: Uuid,
    ) -> Result<()> {
        let enabled: Option<(bool,)> =
            sqlx::query_as("SELECT lifecycle_enabled FROM ontology_objects WHERE id = $1")
                .bind(object_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(TinkerError::Db)?;
        match enabled {
            Some((true,)) => Ok(()),
            _ => Err(TinkerError::Validation(
                "object is not lifecycle-managed".into(),
            )),
        }
    }

    /// Base-table fields only — mirrors the connector: evolved fields are
    /// never silently misdirected at the base table.
    fn writable(fields: &[FieldDescription]) -> Vec<FieldDescription> {
        fields
            .iter()
            .filter(|f| f.extension_table.is_none())
            .cloned()
            .collect()
    }

    /// Reviewer-role check against the trusted `memberships` table
    /// (same table M7 trusts for deciders). Draft visibility and the
    /// reviewer-only transitions (`reject`) gate on this, not on
    /// caller-supplied role claims.
    async fn is_reviewer(tx: &mut Transaction<'_, Postgres>, ctx: &TenantContext) -> Result<bool> {
        let hit: Option<(i32,)> = sqlx::query_as(
            "SELECT 1 FROM memberships \
             WHERE organization_id = $1 AND actor_id = $2 AND role IN ('reviewer','admin','owner')",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(hit.is_some())
    }

    /// Verify an approval request belongs to THIS transition before it is
    /// consumed: it must be approved, carry the expected `action_name`,
    /// and its payload must name the expected draft/record id under
    /// `payload_key` (`"draft_id"` or `"record_id"`).
    ///
    /// Binding is on action + payload, not on M7's `attachment_id`:
    /// that column is FK-bound to `agent_attachments` (an agent scope),
    /// while lifecycle approvals attach to drafts/records — so the
    /// lifecycle payload contract (`{"draft_id": ...}` /
    /// `{"record_id": ...}`) is the binding the engine verifies. Without
    /// this, an approved-but-unrelated request (e.g. a publish approval
    /// reused for archive) would be silently accepted. Checked BEFORE
    /// `consume_approval` so a mismatched request is never marked
    /// executed.
    async fn check_approval_binding(
        tx: &mut Transaction<'_, Postgres>,
        ctx: &TenantContext,
        approval_request_id: Uuid,
        expected_action: &str,
        payload_key: &str,
        expected_id: Uuid,
    ) -> Result<()> {
        let row: Option<(
            String,
            String,
            serde_json::Value,
            Option<chrono::DateTime<chrono::Utc>>,
        )> = sqlx::query_as(
            "SELECT status, action_name, payload, expires_at FROM approval_requests \
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(approval_request_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        let bound = match row {
            Some((status, action, payload, expires_at)) => {
                status == "approved"
                    && action == expected_action
                    && payload.get(payload_key).and_then(|v| v.as_str())
                        == Some(expected_id.to_string()).as_deref()
                    // An approval past its deadline is dead, even if it
                    // was approved in time — the window has closed.
                    && expires_at.is_none_or(|e| e > chrono::Utc::now())
            }
            None => false,
        };
        if !bound {
            return Err(TinkerError::Forbidden(format!(
                "approval {approval_request_id} is not an approved '{expected_action}' request for this record"
            )));
        }
        Ok(())
    }

    /// Retire every live (`pending`/`approved`) approval bound to this
    /// draft. Approvals bind to (action, draft_id), not to content, so an
    /// approval decided on one version of a draft must not survive into
    /// the next: without this, a `publish` approved for v1, followed by
    /// reject → edit → resubmit, could publish v2 unreviewed. Called
    /// wherever the content a reviewer saw stops being the content that
    /// would ship (content edit, rejection). Retired rows read `expired`:
    /// the window in which that decision was valid has closed.
    async fn supersede_draft_approvals(
        tx: &mut Transaction<'_, Postgres>,
        ctx: &TenantContext,
        draft_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE approval_requests SET status = 'expired' \
             WHERE organization_id = $1 AND status IN ('pending', 'approved') \
               AND payload->>'draft_id' = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(draft_id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Read the current published content of a data row as
    /// api_name → JSON. Used to pre-fill an edit draft.
    async fn read_published_content(
        tx: &mut Transaction<'_, Postgres>,
        table: &str,
        fields: &[FieldDescription],
        org_id: Uuid,
        record_id: Uuid,
    ) -> Result<HashMap<String, serde_json::Value>> {
        let raw: Option<serde_json::Value> = sqlx::query_scalar(&format!(
            "SELECT to_jsonb(t) - 'organization_id' - 'id' - 'version' - 'lifecycle_state' - 'created_at' - 'updated_at' \
             FROM {table} t WHERE organization_id = $1 AND id = $2"
        ))
        .bind(org_id)
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        let mut out = HashMap::new();
        let phys_to_api: HashMap<&str, &str> = fields
            .iter()
            .map(|f| (f.physical_column.as_str(), f.api_name.as_str()))
            .collect();
        let raw = raw.and_then(|r| r.as_object().cloned()).unwrap_or_default();
        for (k, v) in &raw {
            if let Some(api) = phys_to_api.get(k.as_str()) {
                out.insert(api.to_string(), v.clone());
            }
        }
        // Sensitive fields: the row holds ref + blind index; the draft
        // carries them on as the sealed form, never as plaintext.
        for f in fields.iter().filter(|f| f.sensitive) {
            let ref_id = raw.get(&f.physical_column).and_then(|v| v.as_str());
            let bidx = raw
                .get(&crate::bidx_column(&f.physical_column))
                .and_then(|v| v.as_str());
            let v = match (ref_id.and_then(|r| r.parse().ok()), bidx) {
                (Some(r), Some(b)) => sealed_json(r, b),
                _ => serde_json::Value::Null,
            };
            out.insert(f.api_name.clone(), v);
        }
        Ok(out)
    }

    async fn audit_transition(
        tx: &mut Transaction<'_, Postgres>,
        ctx: &TenantContext,
        a: TransitionAudit<'_>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO lifecycle_audit \
             (organization_id, actor_id, object_id, record_id, draft_id, \
              transition, before_json, after_json, approval_request_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(a.object_id)
        .bind(a.record_id)
        .bind(a.draft_id)
        .bind(a.transition)
        .bind(a.before)
        .bind(a.after)
        .bind(a.approval_request_id)
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Create a draft. `record_id = None` starts a brand-new record;
    /// `Some(id)` forks an edit draft from the published row (pre-filled
    /// with its content, caller values merged on top). At most one
    /// in-flight draft per existing record.
    pub async fn create_draft(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        record_id: Option<Uuid>,
        values: &HashMap<String, serde_json::Value>,
    ) -> Result<Draft> {
        let desc = self.ontology.describe_object(ctx, object_id).await?;
        Self::require_lifecycle(&desc)?;
        let fields = Self::writable(&desc.fields);
        let mut tx = self.core.tenant_tx(ctx).await?;

        let (base_content, base_version) = match record_id {
            Some(rid) => {
                // Lock the published row: the draft forks a stable base.
                let state: Option<(String, i64)> = sqlx::query_as(&format!(
                    "SELECT lifecycle_state, version FROM {} WHERE organization_id = $1 AND id = $2 FOR UPDATE",
                    Self::table_slug(&desc.api_slug)
                ))
                .bind(ctx.organization_id.0)
                .bind(rid)
                .fetch_optional(&mut *tx)
                .await
                .map_err(TinkerError::Db)?;
                let Some((st, ver)) = state else {
                    return Err(TinkerError::NotFound(format!("record {rid}")));
                };
                if st == "archived" {
                    return Err(TinkerError::Validation(
                        "record is archived; unarchive it before editing".into(),
                    ));
                }
                if st != "published" {
                    return Err(TinkerError::Internal(format!(
                        "corrupt lifecycle_state on published row: {st}"
                    )));
                }
                let content = Self::read_published_content(
                    &mut tx,
                    &Self::table_slug(&desc.api_slug),
                    &fields,
                    ctx.organization_id.0,
                    rid,
                )
                .await?;
                (content, Some(ver))
            }
            None => (HashMap::new(), None),
        };

        // Caller values merge over the published base (new records: base
        // is empty). Presets then validation — the same governed path as
        // direct writes.
        let mut merged = base_content;
        for (k, v) in values {
            merged.insert(k.clone(), v.clone());
        }
        let mut merged = apply_presets(&fields, &merged, ctx.actor_id, record_id.is_none());
        validate_fields(&fields, &merged, record_id.is_none())?;
        let draft_id = Uuid::now_v7();
        let sealed = self
            .seal_caller_values(ctx, &fields, draft_id, values, &mut merged)
            .await?;
        register_refs(&mut tx, ctx, &sealed).await?;
        let content = serde_json::to_value(&merged).map_err(TinkerError::Serde)?;

        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "INSERT INTO record_drafts \
             (organization_id, draft_id, object_id, record_id, state, content, base_version, created_by, updated_by) \
             VALUES ($1,$2,$3,$4,'draft',$5,$6,$7,$7) \
             RETURNING {DRAFT_COLUMNS}"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .bind(object_id)
        .bind(record_id)
        .bind(&content)
        .bind(base_version)
        .bind(ctx.actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| match &e {
            // The partial unique index: a second in-flight draft for the
            // same record fails closed here, never as a raw 500.
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
                TinkerError::Validation("a draft is already in flight for this record".into())
            }
            _ => TinkerError::Db(e),
        })?;
        let row =
            row.ok_or_else(|| TinkerError::Internal("draft insert returned no row".into()))?;
        let draft = to_draft(row)?;
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id,
                record_id,
                draft_id: Some(draft_id),
                transition: "create_draft",
                before: &serde_json::json!({}),
                after: &serde_json::json!({"draft_id": draft_id, "state": "draft"}),
                approval_request_id: None,
            },
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(draft)
    }

    /// Load one draft with visibility rules: the author always; a
    /// reviewer-role member when `in_review` (reviewers must read what
    /// they decide on). Anything else is NotFound — never an existence
    /// oracle.
    pub async fn get_draft(&self, ctx: &TenantContext, draft_id: Uuid) -> Result<Draft> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "SELECT {DRAFT_COLUMNS} FROM record_drafts WHERE organization_id = $1 AND draft_id = $2"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft = match row {
            Some(r) => to_draft(r)?,
            None => return Err(TinkerError::NotFound(format!("draft {draft_id}"))),
        };
        let visible = draft.created_by == ctx.actor_id
            || (draft.state == LifecycleState::InReview && Self::is_reviewer(&mut tx, ctx).await?);
        tx.commit().await.map_err(TinkerError::Db)?;
        if !visible {
            return Err(TinkerError::NotFound(format!("draft {draft_id}")));
        }
        Ok(draft)
    }

    /// Drafts visible to the caller: their own (any state) plus the
    /// `in_review` queue for reviewer-role members.
    pub async fn list_drafts(&self, ctx: &TenantContext, object_id: Uuid) -> Result<Vec<Draft>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let reviewer = Self::is_reviewer(&mut tx, ctx).await?;
        let rows: Vec<DraftRow> = if reviewer {
            sqlx::query_as(&format!(
                "SELECT {DRAFT_COLUMNS} FROM record_drafts \
                 WHERE organization_id = $1 AND object_id = $2 \
                   AND (created_by = $3 OR state = 'in_review') \
                 ORDER BY updated_at DESC"
            ))
            .bind(ctx.organization_id.0)
            .bind(object_id)
            .bind(ctx.actor_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(TinkerError::Db)?
        } else {
            sqlx::query_as(&format!(
                "SELECT {DRAFT_COLUMNS} FROM record_drafts \
                 WHERE organization_id = $1 AND object_id = $2 AND created_by = $3 \
                 ORDER BY updated_at DESC"
            ))
            .bind(ctx.organization_id.0)
            .bind(object_id)
            .bind(ctx.actor_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(TinkerError::Db)?
        };
        tx.commit().await.map_err(TinkerError::Db)?;
        rows.into_iter().map(to_draft).collect()
    }

    /// Patch a draft's content: caller values merge over the existing
    /// draft content (explicit null clears an optional field). Frozen
    /// while `in_review` — reviewers decide on a stable artifact.
    /// Author-only.
    pub async fn update_draft(
        &self,
        ctx: &TenantContext,
        draft_id: Uuid,
        values: &HashMap<String, serde_json::Value>,
    ) -> Result<Draft> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "SELECT {DRAFT_COLUMNS} FROM record_drafts \
             WHERE organization_id = $1 AND draft_id = $2 FOR UPDATE"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft = match row {
            Some(r) => to_draft(r)?,
            None => return Err(TinkerError::NotFound(format!("draft {draft_id}"))),
        };
        if draft.created_by != ctx.actor_id {
            return Err(TinkerError::Forbidden(
                "only the draft author may edit it".into(),
            ));
        }
        if draft.state == LifecycleState::InReview {
            return Err(TinkerError::Validation(
                "draft content is frozen while in review".into(),
            ));
        }
        let desc = self.ontology.describe_object(ctx, draft.object_id).await?;
        Self::require_lifecycle(&desc)?;
        let fields = Self::writable(&desc.fields);
        // Patch semantics: caller values merge over the existing draft
        // content, then presets + validation run on the whole.
        let mut merged: HashMap<String, serde_json::Value> =
            serde_json::from_value(draft.content.clone()).unwrap_or_default();
        for (k, v) in values {
            merged.insert(k.clone(), v.clone());
        }
        let mut merged = apply_presets(&fields, &merged, ctx.actor_id, draft.record_id.is_none());
        validate_fields(&fields, &merged, draft.record_id.is_none())?;
        let sealed = self
            .seal_caller_values(ctx, &fields, draft_id, values, &mut merged)
            .await?;
        register_refs(&mut tx, ctx, &sealed).await?;
        let content = serde_json::to_value(&merged).map_err(TinkerError::Serde)?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "UPDATE record_drafts SET content = $3, updated_by = $4, updated_at = now() \
             WHERE organization_id = $1 AND draft_id = $2 RETURNING {DRAFT_COLUMNS}"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .bind(&content)
        .bind(ctx.actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft =
            to_draft(row.ok_or_else(|| TinkerError::Internal("draft update lost".into()))?)?;
        Self::supersede_draft_approvals(&mut tx, ctx, draft_id).await?;
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id: draft.object_id,
                record_id: draft.record_id,
                draft_id: Some(draft_id),
                transition: "update_draft",
                before: &serde_json::json!({"draft_id": draft_id}),
                after: &serde_json::json!({"draft_id": draft_id, "state": draft.state.as_str()}),
                approval_request_id: None,
            },
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(draft)
    }

    /// Submit for review: `draft|rejected` → `in_review`. Consumes an M7
    /// approval (the org's policy decides when review is required — the
    /// engine only consumes, never invents). Author-only.
    pub async fn submit_for_review(
        &self,
        ctx: &TenantContext,
        draft_id: Uuid,
        approval_request_id: Uuid,
    ) -> Result<Draft> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "SELECT {DRAFT_COLUMNS} FROM record_drafts \
             WHERE organization_id = $1 AND draft_id = $2 FOR UPDATE"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft = match row {
            Some(r) => to_draft(r)?,
            None => return Err(TinkerError::NotFound(format!("draft {draft_id}"))),
        };
        Self::require_lifecycle_by_id(&mut tx, draft.object_id).await?;
        if draft.created_by != ctx.actor_id {
            return Err(TinkerError::Forbidden(
                "only the draft author may submit it".into(),
            ));
        }
        if !matches!(
            draft.state,
            LifecycleState::Draft | LifecycleState::Rejected
        ) {
            return Err(TinkerError::Validation(format!(
                "cannot submit for review from state '{}'",
                draft.state.as_str()
            )));
        }
        // The approval must be an approved 'submit_for_review' request
        // attached to THIS draft — checked before consumption.
        Self::check_approval_binding(
            &mut tx,
            ctx,
            approval_request_id,
            "submit_for_review",
            "draft_id",
            draft_id,
        )
        .await?;
        consume_approval(&mut tx, ctx, true, Some(approval_request_id)).await?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "UPDATE record_drafts SET state = 'in_review', updated_by = $3, updated_at = now() \
             WHERE organization_id = $1 AND draft_id = $2 RETURNING {DRAFT_COLUMNS}"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .bind(ctx.actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft =
            to_draft(row.ok_or_else(|| TinkerError::Internal("draft submit lost".into()))?)?;
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id: draft.object_id,
                record_id: draft.record_id,
                draft_id: Some(draft_id),
                transition: "submit_for_review",
                before: &serde_json::json!({"state": "draft"}),
                after: &serde_json::json!({"state": "in_review"}),
                approval_request_id: Some(approval_request_id),
            },
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(draft)
    }

    /// Publish: `in_review` → `published`. Consumes an M7 approval that
    /// must have been decided by someone OTHER than the author — no
    /// self-approval, enforced here, not by convention. Content is
    /// re-validated against the current schema, then written as the new
    /// published row (INSERT for new records, UPDATE for edits); a
    /// `record_versions` snapshot is appended and the draft deleted, all
    /// in one transaction.
    /// Returns [`PublishOutcome`] with the record id, object id, and new version.
    pub async fn publish(
        &self,
        ctx: &TenantContext,
        draft_id: Uuid,
        approval_request_id: Uuid,
    ) -> Result<PublishOutcome> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "SELECT {DRAFT_COLUMNS} FROM record_drafts \
             WHERE organization_id = $1 AND draft_id = $2 FOR UPDATE"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft = match row {
            Some(r) => to_draft(r)?,
            None => return Err(TinkerError::NotFound(format!("draft {draft_id}"))),
        };
        if draft.state != LifecycleState::InReview {
            return Err(TinkerError::Validation(format!(
                "cannot publish from state '{}'",
                draft.state.as_str()
            )));
        }
        // No self-approval: the deciding actor must differ from the
        // author. Read before consuming — consume_approval would mark it
        // executed either way, and a self-approved publish must never get
        // that far.
        let decided_by: Option<(Option<Uuid>,)> = sqlx::query_as(
            "SELECT decided_by FROM approval_requests WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(approval_request_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        match decided_by {
            Some((Some(d),)) if d != draft.created_by => {}
            _ => {
                return Err(TinkerError::Forbidden(
                    "publish requires an approval decided by someone other than the author".into(),
                ));
            }
        }
        // The approval must be an approved 'publish' request attached to
        // THIS draft — an unrelated approved request (another draft, a
        // submit approval, an archive approval) is rejected, never
        // consumed.
        Self::check_approval_binding(
            &mut tx,
            ctx,
            approval_request_id,
            "publish",
            "draft_id",
            draft_id,
        )
        .await?;
        consume_approval(&mut tx, ctx, true, Some(approval_request_id)).await?;

        // Re-validate against the CURRENT schema: the schema may have
        // evolved since the draft was written. Stale-shaped data fails
        // closed instead of publishing.
        let desc = self.ontology.describe_object(ctx, draft.object_id).await?;
        Self::require_lifecycle(&desc)?;
        let fields = Self::writable(&desc.fields);
        let content_map: HashMap<String, serde_json::Value> =
            serde_json::from_value(draft.content.clone())
                .map_err(|_| TinkerError::Internal("corrupt draft content".into()))?;
        validate_fields(&fields, &content_map, draft.record_id.is_none())?;
        // Item 42 (C7): file references resolve against the governed
        // file registry at publish — the moment draft content becomes a
        // real record. Fail closed, no oracles.
        if let Some(v) = &self.file_validator {
            v.validate_file_fields(ctx, &fields, &content_map).await?;
        }
        let table = Self::table_slug(&desc.api_slug);

        // Coerce to physical columns (same coercion as direct writes;
        // sensitive fields land as ref + blind index).
        let (cols, coerced) = write_columns(&fields, &content_map)?;

        let record_id;
        let version: i64;
        if let Some(rid) = draft.record_id {
            // Edit of an existing record: the published row is replaced
            // wholesale; readers never see the in-flight draft.
            if cols.is_empty() {
                return Err(TinkerError::Validation(
                    "draft has no values to publish".into(),
                ));
            }
            let set_clause = cols
                .iter()
                .enumerate()
                .map(|(i, c)| format!("\"{c}\" = ${}", i + 3))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "UPDATE {table} SET {set_clause}, version = version + 1, \
                 updated_at = now(), lifecycle_state = 'published' \
                 WHERE organization_id = $1 AND id = $2 RETURNING version"
            );
            let mut q = sqlx::query(&sql).bind(ctx.organization_id.0).bind(rid);
            for cv in &coerced {
                q = bind_col(q, cv);
            }
            let row = q.fetch_one(&mut *tx).await.map_err(TinkerError::Db)?;
            version = row.try_get("version").map_err(TinkerError::Db)?;
            record_id = rid;
        } else {
            // Brand-new record.
            if cols.is_empty() {
                return Err(TinkerError::Validation(
                    "draft has no values to publish".into(),
                ));
            }
            let rid = Uuid::now_v7();
            let sql = format!(
                "INSERT INTO {table} (organization_id, id, version, lifecycle_state{}) \
                 VALUES ($1, $2, 1, 'published'{}) RETURNING version",
                cols.iter()
                    .map(|c| format!(", \"{c}\""))
                    .collect::<String>(),
                (0..cols.len())
                    .map(|i| format!(", ${}", i + 3))
                    .collect::<String>(),
            );
            let mut q = sqlx::query(&sql).bind(ctx.organization_id.0).bind(rid);
            for cv in &coerced {
                q = bind_col(q, cv);
            }
            let row = q.fetch_one(&mut *tx).await.map_err(TinkerError::Db)?;
            version = row.try_get("version").map_err(TinkerError::Db)?;
            record_id = rid;
        }

        // Immutable snapshot, then the draft is gone — one transaction,
        // so a crash can never leave a published row without history or
        // a zombie draft.
        sqlx::query(
            "INSERT INTO record_versions \
             (organization_id, object_id, record_id, version_no, content, published_by, approval_request_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(ctx.organization_id.0)
        .bind(draft.object_id)
        .bind(record_id)
        .bind(version)
        .bind(&draft.content)
        .bind(ctx.actor_id)
        .bind(approval_request_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        sqlx::query("DELETE FROM record_drafts WHERE organization_id = $1 AND draft_id = $2")
            .bind(ctx.organization_id.0)
            .bind(draft_id)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id: draft.object_id,
                record_id: Some(record_id),
                draft_id: Some(draft.draft_id),
                transition: "publish",
                before: &serde_json::json!({"state": "in_review"}),
                after: &serde_json::json!({"state": "published", "version": version}),
                approval_request_id: Some(approval_request_id),
            },
        )
        .await?;
        let changed: Vec<String> = content_map.keys().cloned().collect();
        crate::mutate::record_automation_event(
            &mut tx,
            ctx,
            draft.object_id,
            record_id,
            "published",
            &changed,
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(PublishOutcome {
            record_id,
            object_id: draft.object_id,
            version,
        })
    }

    /// Reject: `in_review` → `rejected`. Reviewer-only — the author can
    /// never reject their own draft (that would be a silent
    /// self-deny path around review). No M7 approval: rejection is the
    /// fail-safe direction.
    pub async fn reject(&self, ctx: &TenantContext, draft_id: Uuid, reason: &str) -> Result<Draft> {
        if reason.trim().is_empty() || reason.len() > 2000 {
            return Err(TinkerError::Validation(
                "rejection reason must be 1..=2000 chars".into(),
            ));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "SELECT {DRAFT_COLUMNS} FROM record_drafts \
             WHERE organization_id = $1 AND draft_id = $2 FOR UPDATE"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft = match row {
            Some(r) => to_draft(r)?,
            None => return Err(TinkerError::NotFound(format!("draft {draft_id}"))),
        };
        Self::require_lifecycle_by_id(&mut tx, draft.object_id).await?;
        if draft.state != LifecycleState::InReview {
            return Err(TinkerError::Validation(format!(
                "cannot reject from state '{}'",
                draft.state.as_str()
            )));
        }
        if draft.created_by == ctx.actor_id {
            return Err(TinkerError::Forbidden(
                "the author cannot reject their own draft".into(),
            ));
        }
        // Reviewer-role only: rejection is a review decision, and
        // review decisions come from the trusted membership table.
        if !Self::is_reviewer(&mut tx, ctx).await? {
            return Err(TinkerError::Forbidden(
                "only a reviewer may reject a draft".into(),
            ));
        }
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "UPDATE record_drafts SET state = 'rejected', updated_by = $3, updated_at = now() \
             WHERE organization_id = $1 AND draft_id = $2 RETURNING {DRAFT_COLUMNS}"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .bind(ctx.actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft =
            to_draft(row.ok_or_else(|| TinkerError::Internal("draft reject lost".into()))?)?;
        Self::supersede_draft_approvals(&mut tx, ctx, draft_id).await?;
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id: draft.object_id,
                record_id: draft.record_id,
                draft_id: Some(draft.draft_id),
                transition: "reject",
                before: &serde_json::json!({"state": "in_review"}),
                after: &serde_json::json!({"state": "rejected", "reason": reason}),
                approval_request_id: None,
            },
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(draft)
    }

    /// Revise: `rejected` → `draft`, back to the author for rework.
    /// Author-only.
    pub async fn revise(&self, ctx: &TenantContext, draft_id: Uuid) -> Result<Draft> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "SELECT {DRAFT_COLUMNS} FROM record_drafts \
             WHERE organization_id = $1 AND draft_id = $2 FOR UPDATE"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft = match row {
            Some(r) => to_draft(r)?,
            None => return Err(TinkerError::NotFound(format!("draft {draft_id}"))),
        };
        Self::require_lifecycle_by_id(&mut tx, draft.object_id).await?;
        if draft.created_by != ctx.actor_id {
            return Err(TinkerError::Forbidden(
                "only the draft author may revise it".into(),
            ));
        }
        if draft.state != LifecycleState::Rejected {
            return Err(TinkerError::Validation(format!(
                "cannot revise from state '{}'",
                draft.state.as_str()
            )));
        }
        let row: Option<DraftRow> = sqlx::query_as(&format!(
            "UPDATE record_drafts SET state = 'draft', updated_by = $3, updated_at = now() \
             WHERE organization_id = $1 AND draft_id = $2 RETURNING {DRAFT_COLUMNS}"
        ))
        .bind(ctx.organization_id.0)
        .bind(draft_id)
        .bind(ctx.actor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let draft =
            to_draft(row.ok_or_else(|| TinkerError::Internal("draft revise lost".into()))?)?;
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id: draft.object_id,
                record_id: draft.record_id,
                draft_id: Some(draft.draft_id),
                transition: "revise",
                before: &serde_json::json!({"state": "rejected"}),
                after: &serde_json::json!({"state": "draft"}),
                approval_request_id: None,
            },
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(draft)
    }

    /// Archive a published record: `published` → `archived`. Archived
    /// rows stay in the data table (history is preserved) but the
    /// default read path no longer resolves them. Consumes an M7
    /// approval — hiding published content is destructive-ish.
    pub async fn archive(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        record_id: Uuid,
        approval_request_id: Uuid,
    ) -> Result<()> {
        let desc = self.ontology.describe_object(ctx, object_id).await?;
        Self::require_lifecycle(&desc)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Bound to this record + action before consumption.
        Self::check_approval_binding(
            &mut tx,
            ctx,
            approval_request_id,
            "archive",
            "record_id",
            record_id,
        )
        .await?;
        consume_approval(&mut tx, ctx, true, Some(approval_request_id)).await?;
        let n = sqlx::query(&format!(
            "UPDATE {} SET lifecycle_state = 'archived', updated_at = now() \
             WHERE organization_id = $1 AND id = $2 AND lifecycle_state = 'published'",
            Self::table_slug(&desc.api_slug)
        ))
        .bind(ctx.organization_id.0)
        .bind(record_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        if n == 0 {
            return Err(TinkerError::NotFound(format!(
                "published record {record_id}"
            )));
        }
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id,
                record_id: Some(record_id),
                draft_id: None,
                transition: "archive",
                before: &serde_json::json!({"state": "published"}),
                after: &serde_json::json!({"state": "archived"}),
                approval_request_id: Some(approval_request_id),
            },
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Un-archive: `archived` → `published`. Consumes an M7 approval.
    pub async fn unarchive(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        record_id: Uuid,
        approval_request_id: Uuid,
    ) -> Result<()> {
        let desc = self.ontology.describe_object(ctx, object_id).await?;
        Self::require_lifecycle(&desc)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Bound to this record + action before consumption.
        Self::check_approval_binding(
            &mut tx,
            ctx,
            approval_request_id,
            "unarchive",
            "record_id",
            record_id,
        )
        .await?;
        consume_approval(&mut tx, ctx, true, Some(approval_request_id)).await?;
        let n = sqlx::query(&format!(
            "UPDATE {} SET lifecycle_state = 'published', updated_at = now() \
             WHERE organization_id = $1 AND id = $2 AND lifecycle_state = 'archived'",
            Self::table_slug(&desc.api_slug)
        ))
        .bind(ctx.organization_id.0)
        .bind(record_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        if n == 0 {
            return Err(TinkerError::NotFound(format!(
                "archived record {record_id}"
            )));
        }
        Self::audit_transition(
            &mut tx,
            ctx,
            TransitionAudit {
                object_id,
                record_id: Some(record_id),
                draft_id: None,
                transition: "unarchive",
                before: &serde_json::json!({"state": "archived"}),
                after: &serde_json::json!({"state": "published"}),
                approval_request_id: Some(approval_request_id),
            },
        )
        .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Immutable publish history, newest first.
    pub async fn list_versions(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        record_id: Uuid,
    ) -> Result<Vec<PublishedVersion>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, i64, serde_json::Value, Uuid, DateTime<Utc>)> = sqlx::query_as(
            "SELECT record_id, version_no, content, published_by, published_at \
             FROM record_versions \
             WHERE organization_id = $1 AND object_id = $2 AND record_id = $3 \
             ORDER BY version_no DESC",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .bind(record_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(rows
            .into_iter()
            .map(|r| PublishedVersion {
                record_id: r.0,
                version_no: r.1,
                content: r.2,
                published_by: r.3,
                published_at: r.4,
            })
            .collect())
    }

    /// Legal hold suspends ALL deletion for the object — drafts and
    /// versions included. The hold is keyed by the same object_key the
    /// M8 retention policy uses (the object's api_slug).
    async fn under_legal_hold(
        tx: &mut Transaction<'_, Postgres>,
        ctx: &TenantContext,
        api_slug: &str,
    ) -> Result<bool> {
        let held: Option<(bool,)> = sqlx::query_as(
            "SELECT legal_hold FROM retention_policies \
             WHERE organization_id = $1 AND object_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(api_slug)
        .fetch_optional(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(matches!(held, Some((true,))))
    }

    /// Draft retention: hard-delete drafts (any state) not touched for
    /// longer than `max_age`. Drafts are working copies, not records of
    /// value — the recommended default is 30 days
    /// ([`DEFAULT_DRAFT_RETENTION`]). Returns the number purged.
    pub async fn purge_stale_drafts(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        max_age: Duration,
    ) -> Result<u64> {
        let max_age = chrono::Duration::from_std(max_age)
            .map_err(|_| TinkerError::Validation("draft max_age out of range".into()))?;
        let desc = self.ontology.describe_object(ctx, object_id).await?;
        Self::require_lifecycle(&desc)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        if Self::under_legal_hold(&mut tx, ctx, &desc.api_slug).await? {
            tx.commit().await.map_err(TinkerError::Db)?;
            return Ok(0);
        }
        let n = sqlx::query(
            "DELETE FROM record_drafts \
             WHERE organization_id = $1 AND object_id = $2 AND updated_at < now() - $3::interval",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .bind(max_age)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(n)
    }

    /// Version-history hygiene for M8 retention: after
    /// `RetentionEngine::apply_core` deletes aged published rows, their
    /// version snapshots would dangle — remove versions whose record no
    /// longer has a data row. Returns the number purged.
    /// Version-history hygiene for M8 retention: after
    /// `RetentionEngine::apply_core` deletes aged published rows, their
    /// version snapshots would dangle — remove versions whose record no
    /// longer has a data row. Returns the number purged. Legal hold
    /// suspends this too: versions are retention-protected history.
    pub async fn purge_orphaned_versions(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
    ) -> Result<u64> {
        let desc = self.ontology.describe_object(ctx, object_id).await?;
        Self::require_lifecycle(&desc)?;
        let table = Self::table_slug(&desc.api_slug);
        let mut tx = self.core.tenant_tx(ctx).await?;
        if Self::under_legal_hold(&mut tx, ctx, &desc.api_slug).await? {
            tx.commit().await.map_err(TinkerError::Db)?;
            return Ok(0);
        }
        let n = sqlx::query(&format!(
            "DELETE FROM record_versions v \
             WHERE v.organization_id = $1 AND v.object_id = $2 \
               AND NOT EXISTS (SELECT 1 FROM {table} d \
                               WHERE d.organization_id = v.organization_id AND d.id = v.record_id)"
        ))
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(n)
    }
}
