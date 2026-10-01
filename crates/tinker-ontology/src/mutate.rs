//! Item 37 (C3): the governed mutation connector (M3 debt).
//!
//! The single production writer for ontology records. Every mutation runs
//! one pipeline:
//!
//! ```text
//! presets → validation → approval check → write → audit → hooks
//! ```
//!
//! - **Presets** ([`apply_presets`]): forced defaults from field metadata,
//!   applied *before* validation so a preset can satisfy `required`.
//! - **Validation** ([`validate_fields`]): server-side rule enforcement
//!   with field-level errors, fail-closed. These two functions are `pub`
//!   so any future write path reuses the exact same enforcement code —
//!   today the connector below is the only production writer of dynamic
//!   records (verified: no other `INSERT`/`UPDATE` against `data.*`
//!   tables exists outside this module), so no writer bypasses it.
//! - **Approval check**: when the request requires approval, an approved,
//!   unexpired `approval_requests` row must be presented; it is consumed
//!   (marked `executed`) in the same transaction as the write, so an
//!   approval can never authorize two mutations.
//! - **Write**: typed binds against the real columns. Unknown value keys
//!   are rejected — there are no sneaky columns.
//! - **Audit**: a `mutation_audit` row in the same transaction, so a
//!   committed write is never missing its audit trail.
//! - **Hooks** ([`MutationHooks`]): post-commit invalidation/signal fan-out
//!   through an injected hook. The connector never depends on tinker-live;
//!   a future caller (e.g. an HTTP record-write route) wires its own
//!   `SignalBus` implementation here. Hooks are not transactional — see
//!   the trait docs.
//!
//! Tenant isolation is structural: the object is resolved through the
//! caller's tenant context (a sibling org's object is `NotFound`, never
//! "exists elsewhere"), and every write carries an explicit
//! `organization_id` predicate under the table's RLS policy.
//!
//! Honest limits (v1): base-table fields only — evolved (extension-table)
//! fields are skipped on write; no cross-field rules; no async validators;
//! preset values are static data or the actor id, never expressions.

use crate::sensitive::{register_refs, seal_values, PiiSealer};
use std::collections::HashMap;
use std::sync::Arc;

use bigdecimal::BigDecimal;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{postgres::PgArguments, Postgres, Row, Transaction};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use super::{FieldDescription, Ontology, PresetMode, PresetValue};

// ---------------------------------------------------------------------------
// File-field validation (item 42, C7)
// ---------------------------------------------------------------------------

/// Validates `file`-typed field values on the record write path.
///
/// Implemented by `tinker_agents::files::FileStore` (which owns the
/// registry + backend); defined here so the mutation layer depends on the
/// *contract*, not the agents crate (tinker-agents already depends on
/// tinker-ontology — the reverse would be a dependency cycle).
///
/// For every `file` field present with a non-null value: the value must
/// be a UUID naming an active `stored_files` row in the writing org (a
/// missing, deleted, or other-org file all fail with the same error — no
/// existence oracle), the file's `pii_class` must not exceed the field's
/// `max_pii_class`, and the backend bytes' sha256 is re-verified against
/// the registry (a tampered backend fails the write closed).
#[async_trait::async_trait]
pub trait FileLinkValidator: Send + Sync {
    async fn validate_file_fields(
        &self,
        ctx: &TenantContext,
        fields: &[FieldDescription],
        values: &HashMap<String, serde_json::Value>,
    ) -> Result<()>;
}

// ---------------------------------------------------------------------------
// Shared enforcement: presets + validation (the single enforcement point)
// ---------------------------------------------------------------------------

/// Apply write presets to the incoming values, returning the merged map.
///
/// Pure function and the single place presets are applied — the connector
/// and any direct writer call this same code.
///
/// - `PresetMode::Always`: forced, overwrites whatever the writer sent.
/// - `PresetMode::WhenMissing`: on create, fills absent-or-null keys; on
///   update, absent means "don't touch", so only keys the writer
///   explicitly nulled are backfilled.
pub fn apply_presets(
    fields: &[FieldDescription],
    values: &HashMap<String, serde_json::Value>,
    actor_id: Uuid,
    is_create: bool,
) -> HashMap<String, serde_json::Value> {
    let mut out = values.clone();
    for f in fields {
        let Some(preset) = &f.preset else {
            continue;
        };
        let present = out.get(&f.api_name).filter(|v| !v.is_null());
        let fire = match preset.mode {
            PresetMode::Always => true,
            PresetMode::WhenMissing => {
                if is_create {
                    present.is_none()
                } else {
                    out.contains_key(&f.api_name) && present.is_none()
                }
            }
        };
        if fire {
            let v = match &preset.value {
                PresetValue::Static { value } => value.clone(),
                PresetValue::ActorId => serde_json::Value::String(actor_id.to_string()),
            };
            out.insert(f.api_name.clone(), v);
        }
    }
    out
}

fn is_textual_kind(kind: &str) -> bool {
    matches!(kind, "text" | "richtext" | "email" | "phone" | "url")
}

fn is_numeric_kind(kind: &str) -> bool {
    matches!(kind, "number" | "currency")
}

/// Validate merged values against field governance. Collects *all*
/// violations into one fail-closed error with field-level detail, so a
/// writer learns everything wrong in one round trip.
///
/// Pure function and the single enforcement point, shared by the
/// connector and the direct record-write path. Error strings name only
/// the caller's own fields — never anything cross-org.
pub fn validate_fields(
    fields: &[FieldDescription],
    values: &HashMap<String, serde_json::Value>,
    is_create: bool,
) -> Result<()> {
    let mut errors: Vec<String> = Vec::new();

    // Unknown keys fail closed: the writer may only address governed fields.
    let known: std::collections::HashSet<&str> =
        fields.iter().map(|f| f.api_name.as_str()).collect();
    let mut unknown: Vec<&str> = values
        .keys()
        .map(|k| k.as_str())
        .filter(|k| !known.contains(k))
        .collect();
    unknown.sort_unstable();
    for k in unknown {
        errors.push(format!("unknown field '{k}'"));
    }

    // Deterministic order: field definition order, not hash order.
    for f in fields {
        let v = values.get(&f.api_name).filter(|v| !v.is_null());
        let Some(v) = v else {
            if is_create && f.required {
                errors.push(format!("field '{}': required", f.api_name));
            }
            // On update, a required field explicitly nulled fails closed;
            // an absent required field means "don't touch".
            if !is_create && f.required && values.contains_key(&f.api_name) {
                errors.push(format!("field '{}': required", f.api_name));
            }
            continue;
        };
        // A sensitive field's stored (sealed) value was validated as
        // plaintext before sealing; here it only counts as present.
        // Callers can never supply this form: `sensitive::seal_values`
        // rejects any non-string caller value.
        if f.sensitive && crate::sensitive::parse_sealed(v).is_some() {
            continue;
        }
        // Required text-ish fields reject the empty string: "" is not a value.
        if f.required && is_textual_kind(&f.field_type) && v.as_str().is_some_and(|s| s.is_empty())
        {
            errors.push(format!("field '{}': required", f.api_name));
            continue;
        }
        // Type shape first: a value that cannot land in the column fails
        // here with a field-level error, not as a Postgres error.
        if let Err(e) = coerce(&f.field_type, v) {
            errors.push(format!("field '{}': {e}", f.api_name));
            continue;
        }
        // Rule checks, each fail-closed with the field named.
        let r = &f.validation;
        if is_numeric_kind(&f.field_type) {
            if let Some(n) = v.as_f64() {
                if let Some(min) = r.min {
                    if n < min {
                        errors.push(format!("field '{}': below min {min}", f.api_name));
                    }
                }
                if let Some(max) = r.max {
                    if n > max {
                        errors.push(format!("field '{}': above max {max}", f.api_name));
                    }
                }
            }
        } else if is_textual_kind(&f.field_type) {
            if let Some(s) = v.as_str() {
                let len = s.chars().count() as f64;
                if let Some(min) = r.min {
                    if len < min {
                        errors.push(format!(
                            "field '{}': shorter than min length {min}",
                            f.api_name
                        ));
                    }
                }
                if let Some(max) = r.max {
                    if len > max {
                        errors.push(format!(
                            "field '{}': longer than max length {max}",
                            f.api_name
                        ));
                    }
                }
                if let Some(pattern) = &r.pattern {
                    // Full-match semantics: the pattern must describe the
                    // whole value. Wrapped at validation time (not stored
                    // wrapped) so the stored rule stays readable.
                    let wrapped = format!("\\A(?:{pattern})\\z");
                    match regex::Regex::new(&wrapped) {
                        Ok(re) if re.is_match(s) => {}
                        _ => errors.push(format!("field '{}': does not match pattern", f.api_name)),
                    }
                }
            }
        }
        if let Some(options) = &r.options {
            let rendered = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            if !options.contains(&rendered) {
                errors.push(format!(
                    "field '{}': not one of the allowed values",
                    f.api_name
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(TinkerError::Validation(errors.join("; ")))
    }
}

// ---------------------------------------------------------------------------
// Typed coercion (JSON value -> physical column bind)
// ---------------------------------------------------------------------------

/// A value coerced to its physical column type. No Null variant: nulls are
/// omitted from the write (the column keeps its default/NULL).
#[derive(Debug, Clone)]
pub(crate) enum ColVal {
    Text(String),
    Json(serde_json::Value),
    Numeric(BigDecimal),
    Date(NaiveDate),
    Ts(DateTime<Utc>),
    Bool(bool),
    StrArray(Vec<String>),
    Uid(Uuid),
    /// Explicit SQL NULL: clears the column. Only produced for
    /// non-required fields (validate_fields rejects null on required ones),
    /// and only when no WhenMissing preset re-filled the value.
    Null,
}

/// Coerce a JSON value to the field's physical column type. Fails closed
/// with a human-readable reason; unknown field kinds can never be written.
pub(crate) fn coerce(kind: &str, v: &serde_json::Value) -> std::result::Result<ColVal, String> {
    use serde_json::Value as V;
    match kind {
        "text" | "email" | "phone" | "url" | "select" => match v {
            V::String(s) => Ok(ColVal::Text(s.clone())),
            _ => Err(format!("expected a string for {kind} field")),
        },
        // Item 42 (C7): a file field stores the `stored_files.id` UUID
        // string. It also accepts the structured `{id, sha256}` form so
        // a writer can pin the expected content hash; it normalizes to
        // the id string here, and the file-link validator (which runs
        // right after `validate_fields`) checks the expected hash
        // against the registry before anything is written.
        "file" => match v {
            V::String(s) => Ok(ColVal::Text(s.clone())),
            V::Object(m) => match m.get("id").and_then(|i| i.as_str()) {
                Some(id) => Ok(ColVal::Text(id.to_string())),
                None => Err("expected a string or {id, sha256} for file field".into()),
            },
            _ => Err("expected a string or {id, sha256} for file field".into()),
        },
        "richtext" => Ok(ColVal::Json(v.clone())),
        "number" | "currency" => match v {
            // Parse the number's decimal text directly: going through f64
            // first would smuggle binary-float artifacts (1.1 ->
            // 1.1000000000000000888) into NUMERIC columns.
            V::Number(n) => n
                .to_string()
                .parse::<BigDecimal>()
                .map(ColVal::Numeric)
                .map_err(|_| format!("number out of range for {kind} field")),
            _ => Err(format!("expected a number for {kind} field")),
        },
        "boolean" => match v {
            V::Bool(b) => Ok(ColVal::Bool(*b)),
            _ => Err("expected a boolean".into()),
        },
        "date" => match v {
            V::String(s) => NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .map(ColVal::Date)
                .map_err(|_| "expected YYYY-MM-DD".into()),
            _ => Err("expected a date string (YYYY-MM-DD)".into()),
        },
        "datetime" => match v {
            V::String(s) => s
                .parse::<DateTime<Utc>>()
                .map(ColVal::Ts)
                .map_err(|_| "expected an RFC 3339 datetime".into()),
            _ => Err("expected a datetime string (RFC 3339)".into()),
        },
        "multi_select" => match v {
            V::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        V::String(s) => out.push(s.clone()),
                        _ => return Err("multi_select items must be strings".into()),
                    }
                }
                Ok(ColVal::StrArray(out))
            }
            _ => Err("expected an array of strings".into()),
        },
        "relation" => match v {
            V::String(s) => s
                .parse::<Uuid>()
                .map(ColVal::Uid)
                .map_err(|_| "expected a UUID".into()),
            _ => Err("expected a UUID string for relation field".into()),
        },
        other => Err(format!("unknown field kind '{other}': cannot write")),
    }
}

/// Physical columns + bound values for a governed write, in field order.
/// Explicit null clears an optional column (validate_fields has already
/// rejected null on required fields). A sensitive field writes two
/// columns — the vault ref and its blind index — and must arrive in
/// sealed form: plaintext here means a caller skipped sealing, which
/// fails closed rather than landing in the row.
pub(crate) fn write_columns(
    fields: &[FieldDescription],
    values: &HashMap<String, serde_json::Value>,
) -> Result<(Vec<String>, Vec<ColVal>)> {
    let mut cols = Vec::new();
    let mut coerced = Vec::new();
    for f in fields {
        let Some(v) = values.get(&f.api_name) else {
            continue;
        };
        if f.sensitive {
            let bidx_col = crate::bidx_column(&f.physical_column);
            if v.is_null() {
                cols.extend([f.physical_column.clone(), bidx_col]);
                coerced.extend([ColVal::Null, ColVal::Null]);
                continue;
            }
            let (ref_id, bidx) = crate::sensitive::parse_sealed(v).ok_or_else(|| {
                TinkerError::Internal(format!(
                    "field '{}': sensitive value reached the write unsealed",
                    f.api_name
                ))
            })?;
            cols.extend([f.physical_column.clone(), bidx_col]);
            coerced.extend([ColVal::Uid(ref_id), ColVal::Text(bidx)]);
            continue;
        }
        if v.is_null() {
            cols.push(f.physical_column.clone());
            coerced.push(ColVal::Null);
            continue;
        }
        let cv = coerce(&f.field_type, v)
            .map_err(|e| TinkerError::Validation(format!("field '{}': {e}", f.api_name)))?;
        cols.push(f.physical_column.clone());
        coerced.push(cv);
    }
    Ok((cols, coerced))
}

pub(crate) fn bind_col<'q>(
    q: sqlx::query::Query<'q, Postgres, PgArguments>,
    v: &'q ColVal,
) -> sqlx::query::Query<'q, Postgres, PgArguments> {
    match v {
        ColVal::Text(s) => q.bind(s),
        ColVal::Json(v) => q.bind(v),
        ColVal::Numeric(n) => q.bind(n),
        ColVal::Date(d) => q.bind(d),
        ColVal::Ts(t) => q.bind(t),
        ColVal::Bool(b) => q.bind(b),
        ColVal::StrArray(a) => q.bind(a),
        ColVal::Uid(u) => q.bind(u),
        // Unknown-type NULL: Postgres infers the column type from the
        // SET target, so this clears any column kind.
        ColVal::Null => q.bind(None::<String>),
    }
}

// ---------------------------------------------------------------------------
// Requests, hooks, outcome
// ---------------------------------------------------------------------------

/// Post-commit fan-out. Called exactly once per committed mutation, after
/// the transaction commits — it must not fail the mutation, because the
/// write has already landed. Hooks are deliberately NOT transactional:
/// they run after commit, so a hook failure can never roll back a write
/// (and a crash between commit and hook can skip fan-out — callers that
/// need guaranteed delivery must reconcile from `mutation_audit`).
/// No production wiring exists yet; the seam is here for the caller that
/// needs cache invalidation or SSE signals.
pub trait MutationHooks: Send + Sync {
    fn after_commit(&self, org: Uuid, object: Uuid, record_ids: &[Uuid]);
}

/// No-op hooks, for tests and for callers that fan out themselves.
pub struct NoHooks;

impl MutationHooks for NoHooks {
    fn after_commit(&self, _org: Uuid, _object: Uuid, _record_ids: &[Uuid]) {}
}

/// A hook that records calls, for tests proving the connector fires
/// post-commit fan-out exactly once per mutation.
#[derive(Debug, Default)]
pub struct RecordingHooks {
    pub calls: std::sync::Mutex<Vec<(Uuid, Uuid, Vec<Uuid>)>>,
}

impl MutationHooks for RecordingHooks {
    fn after_commit(&self, org: Uuid, object: Uuid, record_ids: &[Uuid]) {
        self.calls
            .lock()
            .unwrap()
            .push((org, object, record_ids.to_vec()));
    }
}

#[derive(Debug, Clone)]
pub struct CreateRequest {
    pub object_id: Uuid,
    pub values: HashMap<String, serde_json::Value>,
    /// When true, the write requires a presented, approved approval
    /// request — the policy decision is the caller's; the connector only
    /// consumes approvals, never invents them.
    pub require_approval: bool,
    pub approval_request_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct UpdateRequest {
    pub object_id: Uuid,
    pub record_id: Uuid,
    pub values: HashMap<String, serde_json::Value>,
    /// Optimistic lock: when set, the write fails with `Conflict` unless
    /// the record is still at this version.
    pub expected_version: Option<i64>,
    pub require_approval: bool,
    pub approval_request_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct MutationOutcome {
    pub record_id: Uuid,
    pub version: i64,
}

// ---------------------------------------------------------------------------
// The connector
// ---------------------------------------------------------------------------

/// The governed mutation connector: the single production writer for
/// ontology records. Couples presets, validation, approval consumption,
/// the write itself, and the audit row in one transaction, then fires
/// post-commit hooks.
//
// Item 46 (`tinker-mcp serve`): `Clone` so the HTTP transport can hold
// one shared services triple and mint a per-session `FrontDoor` from
// it. All fields are already `Clone`; the impl changes nothing.
#[derive(Clone)]
pub struct MutationConnector {
    core: CoreDb,
    ontology: Ontology,
    file_validator: Option<Arc<dyn FileLinkValidator>>,
    pii: Option<PiiSealer>,
}

impl MutationConnector {
    pub fn new(core: CoreDb, ontology: Ontology) -> Self {
        Self {
            core,
            ontology,
            file_validator: None,
            pii: None,
        }
    }

    /// Attach the PII vault for sensitive fields. Without it, a write that
    /// carries a sensitive value fails closed (never stored in plaintext).
    pub fn with_pii(mut self, sealer: PiiSealer) -> Self {
        self.pii = Some(sealer);
        self
    }

    /// Attach file-field validation for the write path. When absent,
    /// `file` fields are stored as opaque UUID text with no reference
    /// checks (pre-item-42 behavior); callers that govern files attach
    /// the `FileStore`-backed validator.
    pub fn with_file_validator(mut self, v: Arc<dyn FileLinkValidator>) -> Self {
        self.file_validator = Some(v);
        self
    }

    /// Run file-field validation when a validator is attached. Called
    /// after presets + field validation, before the write transaction.
    async fn validate_file_links(
        &self,
        ctx: &TenantContext,
        fields: &[FieldDescription],
        values: &HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        if let Some(v) = &self.file_validator {
            v.validate_file_fields(ctx, fields, values).await?;
        }
        Ok(())
    }

    /// Base-table fields only in v1: evolved (extension-table) fields are
    /// skipped on write, never silently misdirected at the base table.
    pub(crate) fn writable(fields: &[FieldDescription]) -> Vec<FieldDescription> {
        fields
            .iter()
            .filter(|f| f.extension_table.is_none())
            .cloned()
            .collect()
    }

    fn table_slug(slug: &str) -> String {
        // api_slug is validated as a slug at define time; the physical
        // column names are generated `f_<hex>`. Quoting the columns is
        // defense in depth, matching the DDL runner's own style.
        format!("data.{slug}")
    }

    pub async fn create(
        &self,
        ctx: &TenantContext,
        req: &CreateRequest,
        hooks: &dyn MutationHooks,
    ) -> Result<MutationOutcome> {
        // Tenant-scoped resolution: a sibling org's object id is NotFound,
        // never "exists elsewhere".
        let desc = self.ontology.describe_object(ctx, req.object_id).await?;
        // Item 40 (C1): lifecycle-managed objects refuse direct writes —
        // records must go through the lifecycle engine's draft → review →
        // publish path. Fail closed, never silently forked into a draft.
        if desc.lifecycle_enabled {
            return Err(TinkerError::Forbidden(
                "object is lifecycle-managed; use the record lifecycle API".into(),
            ));
        }
        let fields = Self::writable(&desc.fields);

        let mut values = apply_presets(&fields, &req.values, ctx.actor_id, true);
        validate_fields(&fields, &values, true)?;
        // Item 42 (C7): file references resolve against the governed
        // file registry before the write — fail closed, no oracles.
        self.validate_file_links(ctx, &fields, &values).await?;
        // Sensitive values leave plaintext here: sealed into the vault
        // before any copy (row, audit) is made.
        let record_id = Uuid::now_v7();
        let sealed = seal_values(self.pii.as_ref(), ctx, &fields, record_id, &mut values).await?;

        let mut tx = self.core.tenant_tx(ctx).await?;
        consume_approval(&mut tx, ctx, req.require_approval, req.approval_request_id).await?;
        register_refs(&mut tx, ctx, &sealed).await?;

        let (cols, coerced) = write_columns(&fields, &values)?;
        if cols.is_empty() {
            return Err(TinkerError::Validation(
                "create has no values to write".into(),
            ));
        }

        let table = Self::table_slug(&desc.api_slug);
        let sql = format!(
            "INSERT INTO {table} (organization_id, id, version{}) VALUES ($1, $2, 1{}) RETURNING version",
            cols.iter()
                .map(|c| format!(", \"{c}\""))
                .collect::<String>(),
            (0..cols.len())
                .map(|i| format!(", ${}", i + 3))
                .collect::<String>(),
        );
        let mut q = sqlx::query(&sql)
            .bind(ctx.organization_id.0)
            .bind(record_id);
        for cv in &coerced {
            q = bind_col(q, cv);
        }
        let row = q.fetch_one(&mut *tx).await.map_err(TinkerError::Db)?;
        let version: i64 = row.try_get("version").map_err(TinkerError::Db)?;

        let after_json = serde_json::to_value(&values).map_err(TinkerError::Serde)?;
        sqlx::query(
            "INSERT INTO mutation_audit \
             (organization_id, actor_id, object_id, record_id, operation, before_json, after_json, approval_request_id) \
             VALUES ($1,$2,$3,$4,'create',NULL,$5,$6)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(desc.id)
        .bind(record_id)
        .bind(&after_json)
        .bind(req.approval_request_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;

        let changed: Vec<String> = values.keys().cloned().collect();
        record_automation_event(&mut tx, ctx, desc.id, record_id, "created", &changed).await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        hooks.after_commit(ctx.organization_id.0, desc.id, &[record_id]);
        Ok(MutationOutcome { record_id, version })
    }

    pub async fn update(
        &self,
        ctx: &TenantContext,
        req: &UpdateRequest,
        hooks: &dyn MutationHooks,
    ) -> Result<MutationOutcome> {
        let desc = self.ontology.describe_object(ctx, req.object_id).await?;
        // Item 40 (C1): lifecycle-managed objects refuse direct writes —
        // edits go through create_draft(record_id) on the lifecycle engine.
        if desc.lifecycle_enabled {
            return Err(TinkerError::Forbidden(
                "object is lifecycle-managed; use the record lifecycle API".into(),
            ));
        }
        let fields = Self::writable(&desc.fields);

        let mut values = apply_presets(&fields, &req.values, ctx.actor_id, false);
        validate_fields(&fields, &values, false)?;
        // Item 42 (C7): file references resolve against the governed
        // file registry before the write — fail closed, no oracles.
        self.validate_file_links(ctx, &fields, &values).await?;
        let sealed =
            seal_values(self.pii.as_ref(), ctx, &fields, req.record_id, &mut values).await?;

        let mut tx = self.core.tenant_tx(ctx).await?;
        consume_approval(&mut tx, ctx, req.require_approval, req.approval_request_id).await?;
        register_refs(&mut tx, ctx, &sealed).await?;

        let table = Self::table_slug(&desc.api_slug);
        // Lock the row first: precise NotFound vs Conflict, and the
        // before-image for the audit trail comes from the locked row.
        let current: Option<(i64,)> = sqlx::query_as(&format!(
            "SELECT version FROM {table} WHERE organization_id=$1 AND id=$2 FOR UPDATE"
        ))
        .bind(ctx.organization_id.0)
        .bind(req.record_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let Some((current_version,)) = current else {
            return Err(TinkerError::NotFound(format!(
                "record {} on {}",
                req.record_id, desc.api_slug
            )));
        };
        if let Some(expected) = req.expected_version {
            if current_version != expected {
                return Err(TinkerError::conflict(tinker_core::VersionConflict {
                    object: desc.api_slug.clone(),
                    record_id: req.record_id,
                    expected_version: expected,
                    current_version,
                }));
            }
        }

        let (cols, coerced) = write_columns(&fields, &values)?;
        if cols.is_empty() {
            return Err(TinkerError::Validation(
                "update has no values to write".into(),
            ));
        }

        // Before-image for the audit trail, from the locked row. The raw
        // row is keyed by physical column; remap to api_name so the audit
        // trail speaks the same language as after_json.
        let before_raw: Option<serde_json::Value> = sqlx::query_scalar(&format!(
            "SELECT to_jsonb(t) - 'organization_id' - 'id' - 'version' - 'lifecycle_state' - 'created_at' - 'updated_at' \
             FROM {table} t WHERE organization_id=$1 AND id=$2"
        ))
        .bind(ctx.organization_id.0)
        .bind(req.record_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let before: Option<serde_json::Value> = before_raw.map(|b| {
            let phys_to_api: HashMap<&str, &str> = fields
                .iter()
                .map(|f| (f.physical_column.as_str(), f.api_name.as_str()))
                .collect();
            let mut out = serde_json::Map::new();
            for (k, v) in b.as_object().cloned().unwrap_or_default() {
                if let Some(api) = phys_to_api.get(k.as_str()) {
                    out.insert(api.to_string(), v);
                }
            }
            serde_json::Value::Object(out)
        });

        let set_clause = cols
            .iter()
            .enumerate()
            .map(|(i, c)| format!("\"{c}\" = ${}", i + 3))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE {table} SET {set_clause}, version = version + 1, updated_at = now() \
             WHERE organization_id = $1 AND id = $2 RETURNING version"
        );
        let mut q = sqlx::query(&sql)
            .bind(ctx.organization_id.0)
            .bind(req.record_id);
        for cv in &coerced {
            q = bind_col(q, cv);
        }
        let row = q.fetch_one(&mut *tx).await.map_err(TinkerError::Db)?;
        let version: i64 = row.try_get("version").map_err(TinkerError::Db)?;

        let after_json = serde_json::to_value(&values).map_err(TinkerError::Serde)?;
        sqlx::query(
            "INSERT INTO mutation_audit \
             (organization_id, actor_id, object_id, record_id, operation, before_json, after_json, approval_request_id) \
             VALUES ($1,$2,$3,$4,'update',$5,$6,$7)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(desc.id)
        .bind(req.record_id)
        .bind(&before)
        .bind(&after_json)
        .bind(req.approval_request_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;

        // "changed" = fields whose stored value actually moved (a sealed
        // value always moves: a fresh seal is a new ref).
        let changed: Vec<String> = values
            .iter()
            .filter(|(k, v)| before.as_ref().and_then(|b| b.get(k.as_str())) != Some(*v))
            .map(|(k, _)| k.clone())
            .collect();
        record_automation_event(&mut tx, ctx, desc.id, req.record_id, "updated", &changed).await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        hooks.after_commit(ctx.organization_id.0, desc.id, &[req.record_id]);
        Ok(MutationOutcome {
            record_id: req.record_id,
            version,
        })
    }
}

/// Purpose prefix for writes made by an automation action
/// (`automation:<automation id>:<depth>`, docs/automations.md A8).
pub const AUTOMATION_PURPOSE_PREFIX: &str = "automation:";

/// Write the automation outbox row for a committed-together mutation:
/// called inside the mutation's transaction, so the event exists iff the
/// write does. The chain depth and causing automation come from the
/// context's purpose when an automation made the write.
pub async fn record_automation_event(
    tx: &mut Transaction<'_, Postgres>,
    ctx: &TenantContext,
    object_id: Uuid,
    record_id: Uuid,
    kind: &str,
    changed: &[String],
) -> Result<()> {
    let (caused_by, depth) = ctx
        .purpose
        .strip_prefix(AUTOMATION_PURPOSE_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .and_then(|(id, d)| Some((id.parse::<Uuid>().ok()?, d.parse::<i32>().ok()?)))
        .map(|(id, d)| (Some(id), d))
        .unwrap_or((None, 0));
    sqlx::query(
        "INSERT INTO automation_events \
         (organization_id, object_id, record_id, kind, changed, depth, caused_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(ctx.organization_id.0)
    .bind(object_id)
    .bind(record_id)
    .bind(kind)
    .bind(changed)
    .bind(depth)
    .bind(caused_by)
    .execute(&mut **tx)
    .await
    .map_err(TinkerError::Db)?;
    Ok(())
}

/// Consume one approval for a governed write, atomically with the mutation.
/// Mirrors `ApprovalEngine::mark_executed` semantics: lazily expire, then
/// consume approved-and-unexpired in a single UPDATE. Zero rows affected —
/// missing, pending, denied, already-executed, or expired — all fail closed
/// identically (no state oracle for attackers probing approval ids).
///
/// Item 40 (C1): shared with the lifecycle engine — submit_for_review and
/// publish consume M7 approvals through exactly this path.
pub async fn consume_approval(
    tx: &mut Transaction<'_, Postgres>,
    ctx: &TenantContext,
    require_approval: bool,
    approval_request_id: Option<Uuid>,
) -> Result<()> {
    if !require_approval {
        return Ok(());
    }
    let Some(id) = approval_request_id else {
        return Err(TinkerError::Forbidden(
            "mutation requires an approved approval request".into(),
        ));
    };
    sqlx::query(
        "UPDATE approval_requests SET status = 'expired' \
         WHERE organization_id = $1 AND id = $2 AND status = 'approved' \
           AND expires_at IS NOT NULL AND expires_at <= now()",
    )
    .bind(ctx.organization_id.0)
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(TinkerError::Db)?;
    let done = sqlx::query(
        "UPDATE approval_requests SET status = 'executed' \
         WHERE organization_id = $1 AND id = $2 AND status = 'approved' \
           AND (expires_at IS NULL OR expires_at > now())",
    )
    .bind(ctx.organization_id.0)
    .bind(id)
    .execute(&mut **tx)
    .await
    .map_err(TinkerError::Db)?;
    if done.rows_affected() != 1 {
        return Err(TinkerError::Forbidden(
            "approval request is not approved, already used, or expired".into(),
        ));
    }
    Ok(())
}
