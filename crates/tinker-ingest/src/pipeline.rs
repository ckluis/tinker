//! The ingest pipeline: extract → land → profile → model → promote.
//!
//! One [`IngestPipeline::run`] call processes a stream end-to-end:
//! pages are fetched from the connector, landed idempotently, profiled,
//! schema drift is checked, and (when activated mappings exist and drift
//! is non-breaking) landed rows promote to canonical tables through
//! identity resolution and survivorship.
//!
//! Every stage is measured: the report carries per-stage counts and
//! timings, so every source object has a *measured* route from mirror to
//! Tinker-primary (M6 exit).
//!
//! Failure semantics: the run row is created first; any error after that
//! marks the run `failed` (never stuck `running`). The durable cursor is
//! advanced per committed landing page, so a retry resumes incrementally
//! from the last committed page — landing upserts and identity links make
//! the replay converge instead of duplicating.
//!
//! Canonical writes are TYPED: targets are platform ontology objects and
//! every mapped api field resolves to its physical typed column through
//! the ontology. No EAV, no JSONB catch-all. All dynamic SQL fragments
//! (tables, columns) go through [`crate::ident`] validation.

use std::collections::HashMap;
use std::time::Instant;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::sensitive::{register_refs, PiiSealer, SealedRef};
use uuid::Uuid;

use crate::connector::SourceConnector;
use crate::control::{IngestControl, RunStatus};
use crate::ident;
use crate::identity::{IdentityEngine, IdentityOutcome, MatchCandidate};
use crate::landing::LandingWriter;
use crate::mapping::MappingEngine;
use crate::reconcile::Reconciler;
use crate::schema::drift_check;
use crate::survivorship::{FieldProposal, Survivorship};

/// One canonical target: a platform ontology object.
///
/// The physical table is resolved through the ontology at run time — the
/// caller names the object slug, never a table. External ids match through
/// the identity-link registry (per-org, cross-stream), not a canonical
/// column.
#[derive(Debug, Clone)]
pub struct CanonicalTarget {
    /// Platform object slug, e.g. "crm_contact".
    pub object_slug: String,
    /// Canonical api field holding the email (for matching), e.g. "email".
    pub email_api_field: Option<String>,
}

/// One resolved ontology field: api name → physical typed column.
#[derive(Debug, Clone)]
pub struct TypedField {
    pub api_name: String,
    pub physical: String,
    /// Ontology kind name: text, email, number, currency, boolean, date,
    /// datetime, select, multi_select, richtext, relation, phone, url, file.
    pub kind: String,
    /// `ontology_fields.id` — scopes the blind index of a sensitive field.
    pub field_id: Uuid,
    /// Vault-backed field (docs/pii-sensitive-fields.md): promotion seals
    /// the value, compares by blind index, and scrubs landing.
    pub sensitive: bool,
}

#[derive(Debug, Clone)]
struct ResolvedTarget {
    object_slug: String,
    table: String,
    fields: HashMap<String, TypedField>,
    email_api: Option<String>,
    email_physical: Option<String>,
}

/// Per-stage measurements for one pipeline run.
#[derive(Debug, Clone, Default)]
pub struct StageMeasure {
    pub landed: u64,
    pub promoted: u64,
    pub linked: u64,
    pub created: u64,
    pub queued_for_review: u64,
    pub millis: u64,
}

/// Column profile: null / non-null / distinct counts over landed rows.
#[derive(Debug, Clone, Default)]
pub struct ColumnProfile {
    pub nulls: i64,
    pub non_nulls: i64,
    pub distinct: i64,
}

#[derive(Debug, Clone)]
pub struct PipelineReport {
    pub run_id: Uuid,
    pub stream_id: Uuid,
    pub stages: HashMap<String, StageMeasure>,
    /// Per source field: null / non-null / distinct counts.
    pub profile: HashMap<String, ColumnProfile>,
    pub drift_breaking: bool,
    pub total_millis: u64,
    /// Deterministic reconciliation fingerprint: identical source data
    /// and mappings always produce the same fingerprint; any change in
    /// landed rows, canonical counts, or profile shifts it.
    pub fingerprint: String,
    /// Snapshot-diff outcome. `Some` only for streams with
    /// `cursor_kind == "snapshot"` (non-monotonic sources).
    pub snapshot_diff: Option<SnapshotDiff>,
}

/// Outcome of the snapshot-diff extract stage (one full-source scan).
#[derive(Debug, Clone, Default)]
pub struct SnapshotDiff {
    /// Records whose content hash differed from the mirror (new or
    /// changed): the rows actually written this run.
    pub changed: u64,
    /// Records whose content hash matched the mirror: skipped, not
    /// rewritten.
    pub unchanged: u64,
    /// Landed rows absent from the snapshot and marked `_deleted=true`.
    pub marked_deleted: u64,
    /// Source pages scanned.
    pub pages: u64,
}

/// A JSON value bound to a typed physical column.
#[derive(Debug, Clone)]
enum TypedBind {
    Text(Option<String>),
    Numeric(Option<String>),
    Bool(Option<bool>),
    Date(Option<String>),
    Timestamp(Option<String>),
    TextArray(Option<Vec<String>>),
    Json(Option<serde_json::Value>),
    Uuid(Option<Uuid>),
}

impl TypedBind {
    /// Back to JSON for survivorship comparison and provenance.
    fn to_json(&self) -> serde_json::Value {
        match self {
            TypedBind::Text(v) | TypedBind::Date(v) | TypedBind::Timestamp(v) => {
                v.clone().map(serde_json::Value::String).unwrap_or_default()
            }
            TypedBind::Numeric(v) => v
                .as_ref()
                .and_then(|s| canonical_decimal(s))
                .map(serde_json::Value::String)
                .unwrap_or_default(),
            TypedBind::Bool(v) => v.map(serde_json::Value::Bool).unwrap_or_default(),
            TypedBind::TextArray(v) => v
                .clone()
                .map(|a| {
                    serde_json::Value::Array(a.into_iter().map(serde_json::Value::String).collect())
                })
                .unwrap_or_default(),
            TypedBind::Json(v) => v.clone().unwrap_or_default(),
            TypedBind::Uuid(v) => v
                .map(|u| serde_json::Value::String(u.to_string()))
                .unwrap_or_default(),
        }
    }
}

/// Convert a JSON value to a typed bind for an ontology field kind.
/// Unconvertible values are a [`TinkerError::Validation`] — the caller
/// turns those into conflict review items, never silent drops.
/// Landing marker for a sensitive source value that has been promoted:
/// the plaintext is replaced by its blind-index digest.
const SEALED_MARKER: &str = "$tinker_sealed";

fn sealed_marker(digest: &str) -> serde_json::Value {
    serde_json::json!({ SEALED_MARKER: digest })
}

fn marker_digest(v: &serde_json::Value) -> Option<&str> {
    let m = v.as_object().filter(|m| m.len() == 1)?;
    m.get(SEALED_MARKER)?.as_str()
}

fn winners_or_proposal_digest(proposals: &[FieldProposal], field: &str) -> String {
    proposals
        .iter()
        .find(|p| p.field == field)
        .and_then(|p| p.value.as_str())
        .unwrap_or_default()
        .to_string()
}

fn to_typed_bind(kind: &str, v: &serde_json::Value) -> Result<TypedBind> {
    if v.is_null() {
        return Ok(match kind {
            "number" | "currency" => TypedBind::Numeric(None),
            "boolean" => TypedBind::Bool(None),
            "date" => TypedBind::Date(None),
            "datetime" => TypedBind::Timestamp(None),
            "multi_select" => TypedBind::TextArray(None),
            "richtext" => TypedBind::Json(None),
            "relation" => TypedBind::Uuid(None),
            _ => TypedBind::Text(None),
        });
    }
    match kind {
        "number" | "currency" => {
            let s = match v {
                serde_json::Value::Number(n) => Some(n.to_string()),
                serde_json::Value::String(s) if s.parse::<f64>().is_ok() => Some(s.clone()),
                _ => None,
            };
            s.map(|x| TypedBind::Numeric(Some(x)))
                .ok_or_else(|| TinkerError::Validation(format!("not numeric: {v}")))
        }
        "boolean" => {
            let b = match v {
                serde_json::Value::Bool(b) => Some(*b),
                serde_json::Value::String(s) => match s.to_ascii_lowercase().as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => None,
                },
                _ => None,
            };
            b.map(|x| TypedBind::Bool(Some(x)))
                .ok_or_else(|| TinkerError::Validation(format!("not boolean: {v}")))
        }
        "date" => match v.as_str() {
            Some(s) => Ok(TypedBind::Date(Some(s.to_string()))),
            None => Err(TinkerError::Validation(format!("not a date string: {v}"))),
        },
        "datetime" => match v.as_str() {
            Some(s) => Ok(TypedBind::Timestamp(Some(s.to_string()))),
            None => Err(TinkerError::Validation(format!(
                "not a datetime string: {v}"
            ))),
        },
        "multi_select" => match v.as_array() {
            Some(arr) => {
                let mut out = vec![];
                for item in arr {
                    match item.as_str() {
                        Some(s) => out.push(s.to_string()),
                        None => {
                            return Err(TinkerError::Validation(format!(
                                "multi_select item not a string: {item}"
                            )))
                        }
                    }
                }
                Ok(TypedBind::TextArray(Some(out)))
            }
            None => Err(TinkerError::Validation(format!("not an array: {v}"))),
        },
        "richtext" => Ok(TypedBind::Json(Some(v.clone()))),
        "relation" => match v.as_str().and_then(|s| Uuid::parse_str(s).ok()) {
            Some(u) => Ok(TypedBind::Uuid(Some(u))),
            None => Err(TinkerError::Validation(format!("not a uuid: {v}"))),
        },
        // text, email, phone, url, select, file: permissive text coercion.
        _ => {
            let s = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            Ok(TypedBind::Text(Some(s)))
        }
    }
}

/// SQL cast fragment for a typed bind placeholder.
fn bind_cast(kind: &str) -> &'static str {
    match kind {
        "number" | "currency" => "::numeric",
        "date" => "::date",
        "datetime" => "::timestamptz",
        _ => "",
    }
}

pub struct IngestPipeline {
    core: CoreDb,
    owner: OwnerDb,
    control: IngestControl,
    landing: LandingWriter,
    mappings: MappingEngine,
    identity: IdentityEngine,
    survivorship: Survivorship,
    pii: Option<PiiSealer>,
}

/// How a run treats the stream's durable checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Resume from the durable cursor; only new/changed source pages land.
    /// This is the normal mode — retries after failure pick up exactly
    /// where the last committed page left off.
    Incremental,
    /// Clear the checkpoint first, then run the full measured route.
    /// Landing is idempotent and identity links are cross-stream, so a
    /// full resync converges without duplicates.
    FullResync,
}

impl IngestPipeline {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self {
            core: core.clone(),
            owner: owner.clone(),
            control: IngestControl::new(core.clone()),
            landing: LandingWriter::new(core.clone(), owner.clone()),
            mappings: MappingEngine::new(core.clone(), owner),
            identity: IdentityEngine::new(core.clone()),
            survivorship: Survivorship::new(core),
            pii: None,
        }
    }

    /// Attach the PII vault so streams can promote into sensitive fields.
    /// Without it, a sensitive value fails closed as a conflict review.
    pub fn with_pii(mut self, sealer: PiiSealer) -> Self {
        self.pii = Some(sealer);
        self
    }

    pub fn control(&self) -> &IngestControl {
        &self.control
    }
    pub fn landing(&self) -> &LandingWriter {
        &self.landing
    }
    pub fn mappings(&self) -> &MappingEngine {
        &self.mappings
    }
    pub fn identity(&self) -> &IdentityEngine {
        &self.identity
    }

    /// A reconciler bound to this pipeline's pools, for the
    /// separate-cadence drift check (`Reconciler::reconcile`).
    pub fn reconciler(&self) -> Reconciler {
        Reconciler::new(
            self.core.clone(),
            LandingWriter::new(self.core.clone(), self.owner.clone()),
        )
    }

    /// Resolve a canonical target through the ontology (owner-backed
    /// metadata plane). The physical table and every mapped column come
    /// from the ontology — never from caller strings.
    async fn resolve_target(&self, target: &CanonicalTarget) -> Result<ResolvedTarget> {
        ident::ident("object_slug", &target.object_slug)?;
        if let Some(e) = &target.email_api_field {
            ident::ident("email_api_field", e)?;
        }
        let obj: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT id, api_slug FROM ontology_objects
             WHERE api_slug=$1 AND state='active' AND scope_kind='platform'",
        )
        .bind(&target.object_slug)
        .fetch_optional(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        let (object_id, slug) = obj.ok_or_else(|| {
            TinkerError::Validation(format!("unknown platform object: {}", target.object_slug))
        })?;
        // The slug came from our own metadata, but validate anyway: it is
        // interpolated into SQL below.
        let table = format!("data.{slug}");
        ident::data_table(&table)?;
        let rows: Vec<(String, String, String, Uuid, bool)> = sqlx::query_as(
            "SELECT api_name, physical_column, field_type, id, sensitive FROM ontology_fields
             WHERE object_id=$1 AND state='active'",
        )
        .bind(object_id)
        .fetch_all(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        let mut fields = HashMap::new();
        for (api_name, physical, kind, field_id, sensitive) in rows {
            ident::ident("physical_column", &physical)?;
            fields.insert(
                api_name.clone(),
                TypedField {
                    api_name,
                    physical,
                    kind,
                    field_id,
                    sensitive,
                },
            );
        }
        let email_physical = target
            .email_api_field
            .as_ref()
            .and_then(|api| fields.get(api))
            .map(|f| f.physical.clone());
        if target.email_api_field.is_some() && email_physical.is_none() {
            return Err(TinkerError::Validation(format!(
                "email api field {:?} not on object {}",
                target.email_api_field, target.object_slug
            )));
        }
        Ok(ResolvedTarget {
            object_slug: target.object_slug.clone(),
            table,
            fields,
            email_api: target.email_api_field.clone(),
            email_physical,
        })
    }

    /// Run one ingestion pass over a stream: extract → land → profile →
    /// model → promote. Any error after the run row is created marks the
    /// run `failed`; the durable cursor still points at the last committed
    /// page, so a retry resumes incrementally.
    pub async fn run(
        &self,
        ctx: &TenantContext,
        connector: &dyn SourceConnector,
        stream_id: Uuid,
        targets: &[CanonicalTarget],
        page_size: usize,
        mode: RunMode,
    ) -> Result<PipelineReport> {
        let stream = self
            .control
            .get_stream(ctx, stream_id)
            .await?
            .ok_or_else(|| TinkerError::NotFound(format!("stream {stream_id}")))?;
        // A previous run that died without finishing (crash, not Err)
        // would otherwise stay `running` forever. Supersede it before
        // the new run starts so the ledger is honest.
        self.control.fail_stale_runs(ctx, stream_id).await?;
        if mode == RunMode::FullResync {
            self.control
                .advance_cursor(ctx, stream_id, &serde_json::json!({}))
                .await?;
        }
        let mut resolved = Vec::with_capacity(targets.len());
        for t in targets {
            resolved.push(self.resolve_target(t).await?);
        }
        // Every activated mapping must name a known target object and a
        // real api field on it — fail fast on stale mappings.
        let mappings = self.mappings.mappings_for(ctx, stream_id).await?;
        for m in &mappings {
            let rt = resolved
                .iter()
                .find(|r| r.object_slug == m.target_object)
                .ok_or_else(|| {
                    TinkerError::Validation(format!(
                        "mapping {} targets unknown object {}",
                        m.source_field, m.target_object
                    ))
                })?;
            if !rt.fields.contains_key(&m.target_field) {
                return Err(TinkerError::Validation(format!(
                    "mapping {} targets unknown field {} on {}",
                    m.source_field, m.target_field, m.target_object
                )));
            }
        }

        let run_id = self
            .control
            .start_run(ctx, stream_id, stream.cursor_state.clone())
            .await?;
        match self
            .execute(
                ctx, connector, &stream, &resolved, &mappings, run_id, page_size,
            )
            .await
        {
            Ok(report) => Ok(report),
            Err(e) => {
                // Never leave a run stuck `running`: persist the failure so
                // operators (and the next retry) can see what happened.
                let _ = self
                    .control
                    .finish_run(
                        ctx,
                        run_id,
                        RunStatus::Failed,
                        None,
                        serde_json::json!({"error": e.to_string()}),
                    )
                    .await;
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        ctx: &TenantContext,
        connector: &dyn SourceConnector,
        stream: &crate::control::IngestStream,
        resolved: &[ResolvedTarget],
        mappings: &[crate::mapping::FieldMapping],
        run_id: Uuid,
        page_size: usize,
    ) -> Result<PipelineReport> {
        let t0 = Instant::now();
        let stream_id = stream.id;
        let mut stages: HashMap<String, StageMeasure> = HashMap::new();
        let mut total_landed = 0u64;
        let mut drift_breaking = false;

        // Discover schema once per run (cheap on the fake; real connectors
        // cache this).
        let objects = connector.discover().await?;
        let schema_fields: Vec<crate::connector::SourceField> = objects
            .iter()
            .find(|o| o.name == stream.source_object)
            .map(|o| o.fields.clone())
            .unwrap_or_default();
        let field_names: Vec<String> = schema_fields.iter().map(|f| f.name.clone()).collect();

        // Ensure the landing table exists.
        self.landing.ensure_table(stream_id, &field_names).await?;

        // Schema drift check (records the version; additive fields land).
        let (_fp, drift) = drift_check(&self.core, ctx, stream_id, &schema_fields).await?;
        if let Some(d) = drift {
            if !d.added.is_empty() {
                let added: Vec<String> = d.added.clone();
                self.landing.add_columns(stream_id, &added).await?;
            }
            if d.is_breaking() {
                drift_breaking = true;
                self.queue_drift_review(ctx, stream_id, &d).await?;
            }
        }

        // Extract → land. Two strategies, chosen by the stream's cursor
        // kind:
        //
        // * Incremental (`updated_at`/`id`): resume from the durable
        //   cursor; only new pages land. A crash replays from the last
        //   committed page; landing upserts converge.
        // * Snapshot (`snapshot`): the source is non-monotonic
        //   (out-of-order or rewritten history), so no cursor can resume
        //   safely. Every run scans the whole source, lands only records
        //   whose content hash differs from the mirror, and marks mirror
        //   rows absent from the snapshot as deleted.
        let mut cursor: Option<String> = stream
            .cursor_state
            .get("cursor")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let mut pages = 0u64;
        let mut snapshot_diff: Option<SnapshotDiff> = None;
        if stream.cursor_kind == "snapshot" {
            let diff = self
                .extract_land_snapshot(ctx, connector, stream, &field_names, run_id, page_size)
                .await?;
            total_landed = diff.changed;
            pages = diff.pages;
            snapshot_diff = Some(diff);
        } else {
            loop {
                let page = connector
                    .fetch_page(&stream.source_object, cursor.as_deref(), page_size)
                    .await?;
                let n = self
                    .landing
                    .write_batch(ctx, stream_id, &field_names, &page.records)
                    .await?;
                total_landed += n;
                pages += 1;
                match page.next_cursor {
                    Some(nc) => {
                        cursor = Some(nc.clone());
                        self.control
                            .advance_cursor(ctx, stream_id, &serde_json::json!({ "cursor": nc }))
                            .await?;
                    }
                    None => {
                        cursor = None;
                        self.control
                            .advance_cursor(ctx, stream_id, &serde_json::json!({}))
                            .await?;
                        break;
                    }
                }
                // Safety bound for runaway sources.
                if pages > 10_000 {
                    break;
                }
                // Liveness: a long run must never look crashed to the next
                // starter's stale-run sweep.
                self.control.heartbeat_run(ctx, run_id).await?;
            }
        }

        stages.insert(
            "extract_land".to_string(),
            StageMeasure {
                landed: total_landed,
                millis: t0.elapsed().as_millis() as u64,
                ..Default::default()
            },
        );

        // Profile: per-column null / non-null / distinct counts over the
        // landed rows. This is the "Profile" step of the measured route.
        let t_profile = Instant::now();
        let profile = self.profile_stream(ctx, stream_id, &field_names).await?;
        stages.insert(
            "profile".to_string(),
            StageMeasure {
                millis: t_profile.elapsed().as_millis() as u64,
                ..Default::default()
            },
        );

        // Model + promote: mapping application and identity matching are
        // measured as "model"; canonical writes + provenance as "promote".
        // Promotion runs only with activated mappings and non-breaking
        // drift.
        let mut promoted = 0u64;
        let mut linked = 0u64;
        let mut created = 0u64;
        let mut queued = 0u64;
        let mut model_millis = 0u64;
        let mut promote_millis = 0u64;
        if !drift_breaking && !mappings.is_empty() {
            let r = self
                .promote(ctx, stream_id, &field_names, resolved, mappings)
                .await?;
            promoted = r.0;
            linked = r.1;
            created = r.2;
            queued = r.3;
            model_millis = r.4;
            promote_millis = r.5;
        }
        stages.insert(
            "model".to_string(),
            StageMeasure {
                millis: model_millis,
                ..Default::default()
            },
        );
        stages.insert(
            "promote".to_string(),
            StageMeasure {
                promoted,
                linked,
                created,
                queued_for_review: queued,
                millis: promote_millis,
                ..Default::default()
            },
        );

        let total_millis = t0.elapsed().as_millis() as u64;
        let profile_json: HashMap<String, serde_json::Value> = profile
            .iter()
            .map(|(f, p)| {
                (
                    f.clone(),
                    serde_json::json!({
                        "nulls": p.nulls, "non_nulls": p.non_nulls, "distinct": p.distinct
                    }),
                )
            })
            .collect();
        let fingerprint = self
            .compute_fingerprint(ctx, stream_id, total_landed, resolved, &profile)
            .await?;
        let snapshot_diff_json = snapshot_diff.as_ref().map(|d| {
            serde_json::json!({
                "changed": d.changed,
                "unchanged": d.unchanged,
                "marked_deleted": d.marked_deleted,
            })
        });
        self.control
            .finish_run(
                ctx,
                run_id,
                RunStatus::Complete,
                // Snapshot mode has no resume cursor: the next run scans
                // the whole source again by design.
                if snapshot_diff.is_some() {
                    Some(serde_json::json!({ "mode": "snapshot" }))
                } else {
                    cursor.map(|c| serde_json::json!({ "cursor": c }))
                },
                serde_json::json!({
                    "landed": total_landed,
                    "promoted": promoted,
                    "linked": linked,
                    "created": created,
                    "queued_for_review": queued,
                    "pages": pages,
                    "drift_breaking": drift_breaking,
                    "profile": profile_json,
                    "millis": total_millis,
                    "fingerprint": fingerprint,
                    "snapshot_diff": snapshot_diff_json,
                }),
            )
            .await?;

        Ok(PipelineReport {
            run_id,
            stream_id,
            stages,
            profile,
            drift_breaking,
            total_millis,
            fingerprint,
            snapshot_diff,
        })
    }

    /// Snapshot-diff extract stage for non-monotonic sources
    /// (`cursor_kind == "snapshot"`).
    ///
    /// A monotonic cursor cannot capture out-of-order or rewritten history:
    /// a record whose `updated_at` moves backwards (or that simply arrives
    /// late relative to the cursor) is skipped forever. So snapshot mode
    /// ignores the durable cursor and scans the whole source every run,
    /// landing only what changed:
    ///
    /// 1. Page through the entire source from the beginning.
    /// 2. For each page, compare every record's content hash against the
    ///    mirror's stored hash; write only new/changed records (unchanged
    ///    rows are never rewritten).
    /// 3. After the full scan, mark mirror rows absent from the snapshot
    ///    as deleted — absence from a COMPLETE scan is evidence of
    ///    deletion.
    ///
    /// The scan heartbeats every page like the incremental path, and the
    /// same 10k-page safety bound applies.
    async fn extract_land_snapshot(
        &self,
        ctx: &TenantContext,
        connector: &dyn SourceConnector,
        stream: &crate::control::IngestStream,
        field_names: &[String],
        run_id: Uuid,
        page_size: usize,
    ) -> Result<SnapshotDiff> {
        use crate::landing::record_content_hash;
        let stream_id = stream.id;
        let mut diff = SnapshotDiff::default();
        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = connector
                .fetch_page(&stream.source_object, cursor.as_deref(), page_size)
                .await?;
            let ids: Vec<String> = page.records.iter().map(|r| r.source_id.clone()).collect();
            let stored = self.landing.record_hashes(ctx, stream_id, &ids).await?;
            let mut to_write: Vec<crate::connector::SourceRecord> = Vec::new();
            for r in &page.records {
                let h = record_content_hash(r);
                match stored.get(&r.source_id) {
                    // Stored hash matches: the mirror already has exactly
                    // this record. Skip the write entirely.
                    Some(Some(prev)) if *prev == h => diff.unchanged += 1,
                    // New record, changed content, or pre-hash row (NULL):
                    // land it and store the fresh hash.
                    _ => {
                        diff.changed += 1;
                        to_write.push(r.clone());
                    }
                }
            }
            let n = self
                .landing
                .write_batch(ctx, stream_id, field_names, &to_write)
                .await?;
            debug_assert_eq!(n as usize, to_write.len());
            seen.extend(ids);
            diff.pages += 1;
            match page.next_cursor {
                Some(nc) => cursor = Some(nc),
                None => break,
            }
            if diff.pages > 10_000 {
                break;
            }
            self.control.heartbeat_run(ctx, run_id).await?;
        }
        diff.marked_deleted = self
            .landing
            .mark_missing_deleted(ctx, stream_id, &seen)
            .await?;
        Ok(diff)
    }

    /// Deterministic reconciliation fingerprint: sha256 over the stream
    /// id, landed count, per-target canonical counts, and the
    /// canonicalized column profile. Two runs over identical data produce
    /// identical fingerprints; any data change shifts it.
    async fn compute_fingerprint(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        landed: u64,
        resolved: &[ResolvedTarget],
        profile: &HashMap<String, ColumnProfile>,
    ) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(stream_id.as_bytes());
        h.update(landed.to_le_bytes());
        let mut tx = self.core.tenant_tx(ctx).await?;
        for t in resolved {
            let (n,): (i64,) = sqlx::query_as(&format!(
                "SELECT COUNT(*) FROM {} WHERE organization_id=$1",
                t.table
            ))
            .bind(ctx.organization_id.0)
            .fetch_one(&mut *tx)
            .await?;
            h.update(t.object_slug.as_bytes());
            h.update(n.to_le_bytes());
        }
        tx.commit().await?;
        // Canonicalized profile: sorted field names, fixed field order.
        let mut names: Vec<&String> = profile.keys().collect();
        names.sort();
        for name in names {
            let p = &profile[name];
            h.update(name.as_bytes());
            h.update(p.nulls.to_le_bytes());
            h.update(p.non_nulls.to_le_bytes());
            h.update(p.distinct.to_le_bytes());
        }
        Ok(format!("{:x}", h.finalize()))
    }

    /// Profile landed columns: one pass, per-column null / non-null /
    /// distinct counts. Field names are validated before interpolation.
    async fn profile_stream(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        field_names: &[String],
    ) -> Result<HashMap<String, ColumnProfile>> {
        for f in field_names {
            ident::ident("landing field", f)?;
        }
        let table = LandingWriter::table_for(stream_id);
        let mut out = HashMap::new();
        if field_names.is_empty() {
            return Ok(out);
        }
        let mut select = vec!["count(*)".to_string()];
        for f in field_names {
            select.push(format!("count(\"{f}\")"));
            select.push(format!("count(DISTINCT \"{f}\")"));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: sqlx::postgres::PgRow = sqlx::query(&format!(
            "SELECT {} FROM {table} WHERE organization_id=$1",
            select.join(", ")
        ))
        .bind(ctx.organization_id.0)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        use sqlx::Row;
        let total: i64 = row.try_get(0).unwrap_or(0);
        for (i, f) in field_names.iter().enumerate() {
            let non_nulls: i64 = row.try_get(1 + i * 2).unwrap_or(0);
            let distinct: i64 = row.try_get(2 + i * 2).unwrap_or(0);
            out.insert(
                f.clone(),
                ColumnProfile {
                    nulls: total - non_nulls,
                    non_nulls,
                    distinct,
                },
            );
        }
        Ok(out)
    }

    /// Promote landed rows to canonical tables. Returns
    /// (promoted, linked, created, queued_for_review, model_millis, promote_millis).
    ///
    /// Each record promotes inside ONE tenant transaction: the identity
    /// decision, the canonical skeleton, the typed field writes, and the
    /// provenance rows commit atomically. A crash can never leave a link
    /// without its record or a record without provenance.
    ///
    /// Per-record failures are classified (`TinkerError::is_record_data_error`):
    /// data errors quarantine the record as a conflict review and the run
    /// continues; infrastructure errors fail the run loudly.
    async fn promote(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        field_names: &[String],
        resolved: &[ResolvedTarget],
        mappings: &[crate::mapping::FieldMapping],
    ) -> Result<(u64, u64, u64, u64, u64, u64)> {
        let mut promoted = 0u64;
        let mut linked = 0u64;
        let mut created = 0u64;
        let mut queued = 0u64;
        let mut model_millis = 0u64;
        let mut promote_millis = 0u64;
        // For M6, each stream promotes to its single target.
        let target = resolved
            .iter()
            .find(|t| mappings.iter().any(|m| m.target_object == t.object_slug))
            .ok_or_else(|| {
                TinkerError::Validation("no canonical target matches the activated mappings".into())
            })?;
        let mut after: Option<String> = None;
        loop {
            let rows = self
                .landing
                .fetch_page(ctx, stream_id, field_names, after.as_deref(), 200)
                .await?;
            if rows.is_empty() {
                break;
            }
            after = rows
                .last()
                .and_then(|r| r.get("_source_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            for row in rows {
                // ---- model: mapping application (identity matching is
                // inside promote_one_row's transaction) ----
                let source_id = row
                    .get("_source_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let triples = MappingEngine::apply(mappings, &row);
                if triples.is_empty() {
                    continue;
                }
                // The email value comes through the mapping for the email
                // api field (source field name is the mapping's business).
                let email = target
                    .email_api
                    .as_ref()
                    .and_then(|api| {
                        mappings.iter().find(|m| {
                            m.target_object == target.object_slug && m.target_field == *api
                        })
                    })
                    .and_then(|m| row.get(&m.source_field))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // One record, one transaction: identity decision, canonical
                // skeleton, typed writes, and provenance commit atomically.
                // A poisoned record rolls back entirely (no link, no
                // skeleton, no provenance) and becomes a conflict review
                // instead of failing the run.
                match self
                    .promote_one_row(
                        ctx,
                        stream_id,
                        target,
                        mappings,
                        &source_id,
                        &triples,
                        email.as_deref(),
                    )
                    .await
                {
                    Ok((l, c, q, p, mm, pm)) => {
                        linked += l;
                        created += c;
                        queued += q;
                        promoted += p;
                        model_millis += mm;
                        promote_millis += pm;
                    }
                    Err(e) => {
                        if matches!(e, TinkerError::DuplicateEffect(_)) {
                            // Idempotency: this record's write already
                            // landed under an earlier attempt. Nothing to
                            // review and nothing failed — continue.
                            continue;
                        }
                        if !e.is_record_data_error() {
                            // Infrastructure failure (pool exhaustion, lost
                            // connection, serialization failure, authz):
                            // quarantining the record would paint an outage
                            // as a green run with reviews pending. Fail the
                            // run loudly instead — run() marks it failed.
                            return Err(e);
                        }
                        let mut rtx = self.core.tenant_tx(ctx).await?;
                        self.queue_conflict_review_tx(
                            &mut rtx,
                            ctx,
                            stream_id,
                            &source_id,
                            "canonical_write",
                            &format!("canonical write failed and rolled back: {e}"),
                        )
                        .await?;
                        rtx.commit().await?;
                        queued += 1;
                    }
                }
            }
        }
        Ok((
            promoted,
            linked,
            created,
            queued,
            model_millis,
            promote_millis,
        ))
    }

    /// Promote one landed row inside a single tenant transaction.
    ///
    /// Returns (linked, created, queued_for_review, promoted,
    /// model_millis, promote_millis). On `Err` the transaction is dropped
    /// uncommitted — the caller classifies the error: data errors become a
    /// conflict review for the record (the run continues), infrastructure
    /// errors fail the run loudly.
    #[allow(clippy::too_many_arguments)]
    async fn promote_one_row(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        target: &ResolvedTarget,
        mappings: &[crate::mapping::FieldMapping],
        source_id: &str,
        triples: &[(String, String, serde_json::Value)],
        email: Option<&str>,
    ) -> Result<(u64, u64, u64, u64, u64, u64)> {
        let t_model = Instant::now();
        let mut tx = self.core.tenant_tx(ctx).await?;
        let candidates = self
            .find_candidates_tx(&mut tx, ctx, target, source_id, email)
            .await?;
        let outcome = self
            .identity
            .resolve_tx(
                &mut tx,
                ctx,
                stream_id,
                source_id,
                &candidates,
                Uuid::now_v7,
            )
            .await?;
        let model_millis = t_model.elapsed().as_millis() as u64;

        // ---- promote: canonical writes + provenance, same tx ----
        let t_promote = Instant::now();
        let (record_id, linked, created) = match outcome {
            IdentityOutcome::Linked { record_id, .. } => (record_id, 1, 0),
            IdentityOutcome::Created { record_id, .. } => {
                self.insert_canonical_skeleton_tx(&mut tx, ctx, target, record_id)
                    .await?;
                (record_id, 0, 1)
            }
            IdentityOutcome::QueuedForReview { .. } => {
                tx.commit().await?;
                let pm = t_promote.elapsed().as_millis() as u64;
                return Ok((0, 0, 1, 0, model_millis, pm));
            }
        };
        // Typed proposals; unconvertible values become conflict
        // review items (never silent drops, never poisoned runs).
        let mut proposals: Vec<FieldProposal> = vec![];
        // Sensitive fields (docs/pii-sensitive-fields.md): survivorship
        // runs on blind-index digests; the plaintext stays in this map
        // only until it is sealed, then landing is scrubbed to a marker.
        let mut plaintext: HashMap<String, String> = HashMap::new();
        for (obj, api_field, value) in triples {
            if *obj != target.object_slug {
                continue;
            }
            let tf = target.fields.get(api_field).ok_or_else(|| {
                TinkerError::Validation(format!(
                    "unknown api field {api_field} on {}",
                    target.object_slug
                ))
            })?;
            let source_field = mappings
                .iter()
                .find(|m| m.target_object == *obj && m.target_field == *api_field)
                .map(|m| m.source_field.clone())
                .unwrap_or_default();
            if tf.sensitive {
                let digest = if let Some(d) = marker_digest(value) {
                    Some(d.to_string())
                } else if value.is_null() {
                    None
                } else if let (Some(s), Some(p)) = (value.as_str(), &self.pii) {
                    plaintext.insert(api_field.clone(), s.to_string());
                    Some(
                        p.blind_index()
                            .digest(ctx.organization_id.0, tf.field_id, &tf.kind, s),
                    )
                } else {
                    // Never echo the value: the review item names the
                    // field and the rule only.
                    let why = if self.pii.is_none() {
                        "sensitive field, but this pipeline has no PII vault configured"
                    } else {
                        "sensitive fields take a string value (value withheld)"
                    };
                    self.queue_conflict_review_tx(
                        &mut tx, ctx, stream_id, source_id, api_field, why,
                    )
                    .await?;
                    continue;
                };
                proposals.push(FieldProposal {
                    field: api_field.clone(),
                    value: digest.map(serde_json::Value::String).unwrap_or_default(),
                    priority: 0,
                    stream_id,
                    source_id: source_id.to_string(),
                    source_field,
                });
                continue;
            }
            match to_typed_bind(&tf.kind, value) {
                Ok(bind) => proposals.push(FieldProposal {
                    field: api_field.clone(),
                    value: bind.to_json(),
                    priority: 0,
                    stream_id,
                    source_id: source_id.to_string(),
                    source_field,
                }),
                Err(e) => {
                    self.queue_conflict_review_tx(
                        &mut tx,
                        ctx,
                        stream_id,
                        source_id,
                        api_field,
                        &e.to_string(),
                    )
                    .await?;
                }
            }
        }
        let current = self
            .read_canonical_tx(&mut tx, ctx, target, record_id)
            .await?;
        let winners = Survivorship::winners(&proposals, &current);
        let mut promoted = 0u64;
        if !winners.is_empty() {
            self.write_canonical_tx(&mut tx, ctx, target, record_id, &winners, &plaintext)
                .await?;
            self.survivorship
                .record_provenance_tx(&mut tx, ctx, record_id, &winners)
                .await?;
            promoted = 1;
        }
        // Landing kept the source plaintext only until promotion: replace
        // each promoted sensitive value with its digest marker, in the
        // same transaction as the sealed write.
        for api_field in plaintext.keys() {
            let Some(m) = mappings
                .iter()
                .find(|m| m.target_object == target.object_slug && m.target_field == *api_field)
            else {
                continue;
            };
            let digest = winners_or_proposal_digest(&proposals, api_field);
            ident::ident("landing field", &m.source_field)?;
            sqlx::query(&format!(
                "UPDATE {} SET \"{}\" = $3 WHERE organization_id = $1 AND _source_id = $2",
                LandingWriter::table_for(stream_id),
                m.source_field
            ))
            .bind(ctx.organization_id.0)
            .bind(source_id)
            .bind(sealed_marker(&digest))
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        let promote_millis = t_promote.elapsed().as_millis() as u64;
        Ok((linked, created, 0, promoted, model_millis, promote_millis))
    }

    /// Candidate lookup inside the caller's transaction:
    /// 1. the identity-link registry — this source id linked before on any
    ///    stream of this org (the cross-stream external-id match);
    /// 2. exact email on the target's typed email column.
    async fn find_candidates_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        target: &ResolvedTarget,
        source_id: &str,
        email: Option<&str>,
    ) -> Result<Vec<MatchCandidate>> {
        let mut out = vec![];
        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT tinker_record_id FROM ingest_identity_link
             WHERE organization_id=$1 AND source_id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(source_id)
        .fetch_all(&mut **tx)
        .await?;
        for (id,) in rows {
            out.push(MatchCandidate {
                tinker_record_id: id,
                confidence: 1.0,
                reason: "external id linked on another stream".to_string(),
            });
        }
        if let (Some(phys), Some(email)) = (&target.email_physical, email) {
            let email_field = target.email_api.as_ref().and_then(|a| target.fields.get(a));
            // A sensitive email matches on its blind index (the column
            // holds a vault ref); without a vault there is nothing to
            // match against, so only the identity-link registry applies.
            let lookup = match email_field.filter(|f| f.sensitive) {
                Some(f) => self.pii.as_ref().map(|p| {
                    (
                        format!("\"{}\" = $2", tinker_ontology::bidx_column(phys)),
                        p.blind_index()
                            .digest(ctx.organization_id.0, f.field_id, &f.kind, email),
                    )
                }),
                None => Some((
                    format!("lower(\"{phys}\"::text)=lower($2)"),
                    email.to_string(),
                )),
            };
            if let (false, Some((pred, bind))) = (email.trim().is_empty(), lookup) {
                let rows: Vec<(Uuid,)> = sqlx::query_as(&format!(
                    "SELECT id FROM {} WHERE organization_id=$1 AND {pred}",
                    target.table
                ))
                .bind(ctx.organization_id.0)
                .bind(bind)
                .fetch_all(&mut **tx)
                .await?;
                for (id,) in rows {
                    if !out.iter().any(|c| c.tinker_record_id == id) {
                        out.push(MatchCandidate {
                            tinker_record_id: id,
                            confidence: 0.9,
                            reason: "exact email".to_string(),
                        });
                    }
                }
            }
        }
        Ok(out)
    }

    async fn insert_canonical_skeleton_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        target: &ResolvedTarget,
        record_id: Uuid,
    ) -> Result<()> {
        sqlx::query(&format!(
            "INSERT INTO {} (organization_id, id) VALUES ($1,$2)
             ON CONFLICT (organization_id, id) DO NOTHING",
            target.table
        ))
        .bind(ctx.organization_id.0)
        .bind(record_id)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Read mapped api fields back as JSON for survivorship comparison.
    /// Columns are selected as text and converted by field kind so the
    /// comparison is type-consistent with incoming values.
    async fn read_canonical_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        target: &ResolvedTarget,
        record_id: Uuid,
    ) -> Result<HashMap<String, serde_json::Value>> {
        use sqlx::Row;
        let mut cols: Vec<(&String, &TypedField)> = vec![];
        // Only mapped fields matter for survivorship; the caller passes
        // winners keyed by api field, so read the target's full mapped
        // field set deterministically.
        let mut names: Vec<&String> = target.fields.keys().collect();
        names.sort();
        for api in names {
            let tf = &target.fields[api];
            cols.push((api, tf));
        }
        let mut out = HashMap::new();
        if cols.is_empty() {
            return Ok(out);
        }
        // Sensitive fields compare by blind index, never by value.
        let select = cols
            .iter()
            .map(|(_, tf)| {
                if tf.sensitive {
                    format!("\"{}\"::text", tinker_ontology::bidx_column(&tf.physical))
                } else {
                    format!("\"{}\"::text", tf.physical)
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let row: Option<sqlx::postgres::PgRow> = sqlx::query(&format!(
            "SELECT {select} FROM {} WHERE organization_id=$1 AND id=$2",
            target.table
        ))
        .bind(ctx.organization_id.0)
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(row) = row {
            for (i, (api, tf)) in cols.iter().enumerate() {
                let raw: Option<String> = row.try_get(i).unwrap_or(None);
                let kind = if tf.sensitive {
                    "text"
                } else {
                    tf.kind.as_str()
                };
                if let Some(json) = text_to_json(kind, raw) {
                    out.insert((*api).clone(), json);
                }
            }
        }
        Ok(out)
    }

    /// Typed canonical write: each winner binds to its physical column
    /// with the kind's cast. All in the caller's transaction.
    async fn write_canonical_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        target: &ResolvedTarget,
        record_id: Uuid,
        winners: &[FieldProposal],
        plaintext: &HashMap<String, String>,
    ) -> Result<()> {
        for w in winners {
            let tf = target.fields.get(&w.field).ok_or_else(|| {
                TinkerError::Validation(format!(
                    "unknown api field {} on {}",
                    w.field, target.object_slug
                ))
            })?;
            if tf.sensitive {
                // A digest without plaintext came from a scrubbed landing
                // row while the canonical value moved on elsewhere: there
                // is nothing to seal, so the canonical value stands.
                let Some(value) = plaintext.get(&w.field) else {
                    continue;
                };
                let sealer = self.pii.as_ref().ok_or_else(|| {
                    TinkerError::Validation(format!(
                        "field '{}' is sensitive, but this pipeline has no PII vault configured",
                        w.field
                    ))
                })?;
                let class = format!("pii.{}", w.field);
                let ref_id = sealer.vault().seal(ctx, record_id, &class, value).await?;
                register_refs(
                    tx,
                    ctx,
                    &[SealedRef {
                        ref_id,
                        subject: record_id,
                        storage_class: class,
                    }],
                )
                .await?;
                sqlx::query(&format!(
                    "UPDATE {} SET \"{}\" = $3, \"{}\" = $4, version = version + 1, updated_at = now()
                     WHERE organization_id = $1 AND id = $2",
                    target.table,
                    tf.physical,
                    tinker_ontology::bidx_column(&tf.physical)
                ))
                .bind(ctx.organization_id.0)
                .bind(record_id)
                .bind(ref_id)
                .bind(w.value.as_str())
                .execute(&mut **tx)
                .await?;
                continue;
            }
            let bind = to_typed_bind(&tf.kind, &w.value)?;
            let cast = bind_cast(&tf.kind);
            let sql = format!(
                "UPDATE {} SET \"{}\"=$3{cast}, version=version+1, updated_at=now()
                 WHERE organization_id=$1 AND id=$2",
                target.table, tf.physical
            );
            let q = sqlx::query(&sql)
                .bind(ctx.organization_id.0)
                .bind(record_id);
            let q = match bind {
                TypedBind::Text(v) => q.bind(v),
                TypedBind::Numeric(v) => q.bind(v),
                TypedBind::Bool(v) => q.bind(v),
                TypedBind::Date(v) => q.bind(v),
                TypedBind::Timestamp(v) => q.bind(v),
                TypedBind::TextArray(v) => q.bind(v),
                TypedBind::Json(v) => q.bind(v),
                TypedBind::Uuid(v) => q.bind(v),
            };
            q.execute(&mut **tx).await?;
        }
        Ok(())
    }

    /// A value that cannot be coerced to its typed column is a conflict:
    /// queue a review item (idempotent per stream+source+field) and skip
    /// the field. The run continues; nothing is silently dropped.
    async fn queue_conflict_review_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_id: &str,
        api_field: &str,
        reason: &str,
    ) -> Result<()> {
        let existing: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM ingest_review_item
             WHERE organization_id=$1 AND stream_id=$2 AND kind='conflict'
               AND state='open' AND payload->>'source_id'=$3
               AND payload->>'field'=$4",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(source_id)
        .bind(api_field)
        .fetch_optional(&mut **tx)
        .await?;
        if existing.is_some() {
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO ingest_review_item
             (id, organization_id, stream_id, kind, payload)
             VALUES ($1,$2,$3,'conflict',$4)",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(serde_json::json!({
            "source_id": source_id,
            "field": api_field,
            "reason": reason,
        }))
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn queue_drift_review(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        drift: &crate::schema::SchemaDrift,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO ingest_review_item
             (id, organization_id, stream_id, kind, payload)
             VALUES ($1,$2,$3,'schema_drift',$4)",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(serde_json::json!({
            "removed": drift.removed,
            "type_changed": drift.type_changed,
        }))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

/// Convert a `::text`-selected column value back to JSON by field kind,
/// for survivorship comparison with incoming values.
fn text_to_json(kind: &str, raw: Option<String>) -> Option<serde_json::Value> {
    let s = raw?;
    Some(match kind {
        "number" | "currency" => canonical_decimal(&s)
            .map(serde_json::Value::String)
            .unwrap_or_else(|| serde_json::Value::String(s)),
        "boolean" => match s.as_str() {
            "t" | "true" => serde_json::Value::Bool(true),
            "f" | "false" => serde_json::Value::Bool(false),
            _ => serde_json::Value::String(s),
        },
        "multi_select" => parse_pg_text_array(&s),
        "richtext" | "jsonb" => serde_json::from_str(&s).unwrap_or(serde_json::Value::String(s)),
        _ => serde_json::Value::String(s),
    })
}

/// Canonical decimal string for numeric comparison: no f64 round-trip,
/// so "50000", "50000.0", and "5e4" all compare equal and a value that
/// survives one promotion compares equal on the next (no repeated
/// updates from normalization drift). Returns None for non-numeric input.
fn canonical_decimal(s: &str) -> Option<String> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (neg, rest) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let (mantissa, exp): (&str, i32) = match rest.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse().ok()?),
        None => (rest, 0),
    };
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mantissa, ""),
    };
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
        || (int_part.is_empty() && frac_part.is_empty())
    {
        return None;
    }
    // digits with the decimal point `point` digits from the left.
    let mut digits = format!("{int_part}{frac_part}");
    let mut point = int_part.len() as i32 + exp;
    // Strip leading zeros (they shift the point left).
    let leading = digits.len() - digits.trim_start_matches('0').len();
    digits = digits.trim_start_matches('0').to_string();
    point -= leading as i32;
    // Strip trailing fractional zeros.
    while digits.ends_with('0') && (digits.len() as i32) > point {
        digits.pop();
    }
    if digits.is_empty() {
        return Some("0".to_string());
    }
    let out = if point <= 0 {
        format!("0.{}{}", "0".repeat(-point as usize), digits)
    } else if point as usize >= digits.len() {
        format!("{}{}", digits, "0".repeat(point as usize - digits.len()))
    } else {
        let p = point as usize;
        format!("{}.{}", &digits[..p], &digits[p..])
    };
    Some(if neg { format!("-{out}") } else { out })
}

/// Minimal Postgres `{a,b,"c,d"}` text-array parser.
fn parse_pg_text_array(s: &str) -> serde_json::Value {
    let s = s.trim();
    if !(s.starts_with('{') && s.ends_with('}')) {
        return serde_json::Value::String(s.to_string());
    }
    let inner = &s[1..s.len() - 1];
    if inner.is_empty() {
        return serde_json::Value::Array(vec![]);
    }
    let mut items = vec![];
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if !in_quotes => in_quotes = true,
            '"' => {
                if chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            '\\' if in_quotes => {
                if let Some(e) = chars.next() {
                    cur.push(e);
                }
            }
            ',' if !in_quotes => {
                items.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    items.push(cur);
    serde_json::Value::Array(items.into_iter().map(serde_json::Value::String).collect())
}
