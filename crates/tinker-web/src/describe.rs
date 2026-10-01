//! Item 43 (agent front door, Part 1): the self-describing ontology.
//!
//! `tinker describe` is a READ PROJECTION over the real governance
//! sources — never a parallel hand-written registry that can drift:
//!
//! - objects/fields ......... `tinker_ontology::Ontology` (metadata plane)
//! - validation + presets ... item 37, ride on `FieldDescription`
//! - file PII ceilings ....... item 42, rides on `FieldDescription`
//! - row policies ............ item 38, `tinker_query::RowFilters`
//! - field projections ....... M3, `tinker_live::FieldGrants`
//! - lifecycle ............... item 40, `lifecycle_enabled` + the engine's
//!                             transition table (verified against
//!                             `tinker_ontology::lifecycle::LifecycleEngine`)
//!
//! Permission-awareness (spec design rule 1): the caller's role projects
//! the output exactly the way the query compiler projects rows. Hidden
//! fields are OMITTED (never named), foreign/missing objects are both
//! `NotFound` (never an existence oracle), and row policies are
//! summarized at a coarse level — never verbatim predicates, never
//! field names, operators, or values.
//!
//! Read-only (spec design rule 2): every query here runs inside
//! `tenant_tx` (RLS always applies) and no statement mutates.
//!
//! Canonical JSON (spec design rule 3): [`canonical_json`] sorts object
//! keys recursively and emits compact JSON — the item-39 approach,
//! applied to describe payloads so agents and tests can pin bytes.
//!
//! Version pinning (spec design rule 4): every payload carries
//! `tinker_version` and `ontology_version`. Callers may declare the
//! versions they were built against (`client_tinker_version` /
//! `client_ontology_version`); a mismatch fails closed with 409 and a
//! body naming both sides, never silent drift.
//!
//! Schema-only in v1 (approved decision 2): no synthetic example
//! records. Describe documents the ontology, not business meaning.

use std::collections::HashMap;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_live::FieldGrants;
use tinker_ontology::{FieldDescription, ObjectDescription, Ontology};
use tinker_query::{RowFilterValue, RowFilters};
use uuid::Uuid;

use crate::{
    live::{role_of, tenant_ctx, ApiError},
    RequestContext, SharedState,
};

// ---------------------------------------------------------------------------
// Versions
// ---------------------------------------------------------------------------

/// The server binary's version. Agents pin the skill against this.
pub fn tinker_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The ontology metadata-schema version: the highest core migration the
/// binary embeds, zero-padded (`0043`). Bumped by migration, never by
/// hand — describe can never claim a schema it doesn't understand.
pub fn ontology_version() -> String {
    let max = tinker_db::MIGRATOR_CORE
        .migrations
        .iter()
        .map(|m| m.version)
        .max()
        .unwrap_or(0);
    format!("{max:04}")
}

// ---------------------------------------------------------------------------
// Canonical JSON (item-39 approach)
// ---------------------------------------------------------------------------

fn canonical_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::with_capacity(m.len());
            for k in keys {
                out.insert(k.clone(), canonical_value(&m[k]));
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(canonical_value).collect())
        }
        _ => v.clone(),
    }
}

/// Compact JSON with object keys sorted recursively. Key insertion order
/// is normalized explicitly (not via a serde feature flag), so the byte
/// output is stable regardless of build configuration.
pub fn canonical_json(value: &serde_json::Value) -> Vec<u8> {
    // to_vec on the canonicalized value cannot fail: Value serializes
    // infallibly. A panic here would be a serde_json bug, not input.
    serde_json::to_vec(&canonical_value(value)).expect("canonical_json: Value serialization")
}

// ---------------------------------------------------------------------------
// Wire shapes (declaration order = stable key order pre-canonicalization)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ObjectSummary {
    pub api_slug: String,
    pub name: String,
    pub scope: String,
    pub lifecycle_enabled: bool,
    pub describe_href: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DescribeCatalog {
    pub tinker_version: String,
    pub ontology_version: String,
    pub objects: Vec<ObjectSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DescribedField {
    pub api_name: String,
    pub label: String,
    pub field_type: String,
    pub postgres_type: String,
    pub required: bool,
    /// Always true in v1: physical columns are created nullable and
    /// `required` is enforced by the governed mutation layer, never by
    /// a blocking table rewrite. Surfaced so agents don't infer
    /// NOT NULL from `required: true`.
    pub nullable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// Item 37: server-side validation rules (min/max/pattern/options).
    /// The rule language is data, never code.
    pub validation: tinker_ontology::ValidationRules,
    /// Item 37: forced default applied before validation, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<tinker_ontology::WritePreset>,
    /// Item 42: ceiling for PII classes of linked files.
    pub max_pii_class: String,
    /// Target object slug for relation fields, resolved live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation_target: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DescribedRelation {
    pub field: String,
    pub target_object: String,
    /// Relations are FK columns: many-to-one, always.
    pub cardinality: &'static str,
}

/// Coarse row-policy summary (item 38). Deliberately lossy: field names,
/// operators, and values NEVER appear — policy internals are not
/// documentation, and naming them would build an oracle.
#[derive(Debug, Clone, Serialize)]
pub struct DescribedRowPolicy {
    pub applies: bool,
    pub summary: String,
    pub filter_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct LifecycleTransition {
    pub name: String,
    /// Empty = creates a new draft/record rather than moving one.
    pub from: Vec<String>,
    pub to: String,
    /// Who may initiate, in plain words (verified against
    /// `LifecycleEngine`; roles are free-form org strings, so the
    /// reviewer gate is named, not enumerated).
    pub who: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_approval: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DescribedLifecycle {
    pub states: Vec<String>,
    pub storage_note: String,
    pub retention_note: String,
    pub transitions: Vec<LifecycleTransition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorClass {
    pub class: String,
    pub http_status: u16,
    pub meaning: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MutationContract {
    /// "governed" or "lifecycle".
    pub write_path: String,
    pub write_path_note: String,
    pub error_taxonomy: Vec<ErrorClass>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReadContract {
    pub query_endpoint: String,
    pub intent_shape: serde_json::Value,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DescribeObject {
    pub tinker_version: String,
    pub ontology_version: String,
    pub api_slug: String,
    pub name: String,
    pub scope: String,
    pub lifecycle_enabled: bool,
    pub fields: Vec<DescribedField>,
    pub relations: Vec<DescribedRelation>,
    pub row_policy: DescribedRowPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<DescribedLifecycle>,
    pub mutation: MutationContract,
    pub reads: ReadContract,
}

// ---------------------------------------------------------------------------
// The read projection
// ---------------------------------------------------------------------------

/// The describe read projection: ontology + grants + row filters over one
/// tenant context. Constructible without the full `AppState` so tests
/// and the CLI can drive it directly.
pub struct Describer {
    core: CoreDb,
    ontology: Ontology,
    grants: FieldGrants,
    row_filters: RowFilters,
}

impl Describer {
    pub fn new(
        core: CoreDb,
        ontology: Ontology,
        grants: FieldGrants,
        row_filters: RowFilters,
    ) -> Self {
        Self {
            core,
            ontology,
            grants,
            row_filters,
        }
    }

    pub fn from_state(state: &SharedState) -> Self {
        // FieldGrants and RowFilters are thin wrappers over CoreDb
        // (stateless); rebuild them from the shared pool instead of
        // cloning.
        let core = state.core.clone();
        Self {
            ontology: state.ontology.clone(),
            grants: FieldGrants::new(core.clone()),
            row_filters: RowFilters::new(core.clone()),
            core,
        }
    }

    /// Owner handle for operator tooling. The CLI builds its Describer
    /// from this; tenant reads still go through `core.tenant_tx`.
    pub fn for_cli(core: CoreDb, owner: OwnerDb) -> Self {
        let ontology = Ontology::new(core.clone(), owner);
        let grants = FieldGrants::new(core.clone());
        let row_filters = RowFilters::new(core.clone());
        Self::new(core, ontology, grants, row_filters)
    }

    /// Every object the caller may see: platform objects plus the
    /// caller's own organization overlay. RLS enforces this — the query
    /// runs inside `tenant_tx`, so sibling orgs' objects are invisible
    /// and there is no missing-vs-hidden distinction to leak.
    pub async fn catalog(&self, ctx: &TenantContext, _role: &str) -> Result<DescribeCatalog> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, String, String, String, bool)> = sqlx::query_as(
            "SELECT id, api_slug, name, scope_kind, lifecycle_enabled \
             FROM ontology_objects WHERE state='active' ORDER BY api_slug",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(DescribeCatalog {
            tinker_version: tinker_version().to_string(),
            ontology_version: ontology_version(),
            objects: rows
                .into_iter()
                .map(
                    |(_, api_slug, name, scope, lifecycle_enabled)| ObjectSummary {
                        describe_href: format!("/api/describe/{api_slug}"),
                        api_slug,
                        name,
                        scope,
                        lifecycle_enabled,
                    },
                )
                .collect(),
        })
    }

    /// Full documentation for one object, projected through the caller's
    /// role: hidden fields omitted, row policy summarized, lifecycle
    /// transitions documented. Unknown and foreign slugs are both
    /// `NotFound` — no oracle.
    pub async fn object(
        &self,
        ctx: &TenantContext,
        role: &str,
        slug: &str,
    ) -> Result<DescribeObject> {
        let desc = self.ontology.describe_object_by_slug(ctx, slug).await?;
        self.object_from_desc(ctx, role, desc).await
    }

    async fn object_from_desc(
        &self,
        ctx: &TenantContext,
        role: &str,
        desc: ObjectDescription,
    ) -> Result<DescribeObject> {
        // M3 field projection for this role: objects without grant rows
        // are unrestricted (default-open); hidden fields are omitted
        // from describe output entirely — never named.
        let projection = self.grants.load_projection(ctx, role, &[desc.id]).await?;
        let visible: Vec<&FieldDescription> = desc
            .fields
            .iter()
            .filter(|f| projection.allows(desc.id, &f.api_name))
            .collect();

        // Resolve relation targets to slugs (live, not cached). Targets
        // are same-scope by construction (add_field enforces it), so the
        // caller may always see them; an unresolvable target is corrupt
        // metadata and fails closed.
        let target_ids: Vec<Uuid> = visible
            .iter()
            .filter_map(|f| f.relation_target_id)
            .collect();
        let target_slugs: HashMap<Uuid, String> = self.ontology.slugs_for_ids(&target_ids).await?;

        let mut fields = Vec::with_capacity(visible.len());
        let mut relations = Vec::new();
        for f in visible {
            let relation_target = match f.relation_target_id {
                Some(tid) => Some(target_slugs.get(&tid).cloned().ok_or_else(|| {
                    TinkerError::Internal(format!(
                        "corrupt relation target on field '{}': {tid}",
                        f.api_name
                    ))
                })?),
                None => None,
            };
            if let Some(target) = relation_target.clone() {
                relations.push(DescribedRelation {
                    field: f.api_name.clone(),
                    target_object: target,
                    cardinality: "many-to-one",
                });
            }
            fields.push(DescribedField {
                api_name: f.api_name.clone(),
                label: f.label.clone(),
                field_type: f.field_type.clone(),
                postgres_type: kind_pg_type(&f.field_type).to_string(),
                required: f.required,
                nullable: true,
                options: select_options(&f.options_json),
                validation: f.validation.clone(),
                preset: f.preset.clone(),
                max_pii_class: f.max_pii_class.clone(),
                relation_target,
            });
        }
        fields.sort_by(|a, b| a.api_name.cmp(&b.api_name));
        relations.sort_by(|a, b| a.field.cmp(&b.field));

        // Item 38: the caller's row policy, summarized — never verbatim.
        let policy = self.row_filters.load_policy(ctx, desc.id, role).await?;
        let row_policy = summarize_row_policy(&policy.filters);

        let lifecycle = if desc.lifecycle_enabled {
            Some(describe_lifecycle())
        } else {
            None
        };

        Ok(DescribeObject {
            tinker_version: tinker_version().to_string(),
            ontology_version: ontology_version(),
            api_slug: desc.api_slug,
            name: desc.name,
            scope: desc.scope_kind,
            lifecycle_enabled: desc.lifecycle_enabled,
            fields,
            relations,
            row_policy,
            lifecycle,
            mutation: describe_mutation(desc.lifecycle_enabled),
            reads: describe_reads(),
        })
    }
}

/// The physical Postgres type per field kind. Mirrors
/// `FieldType::pg_type` in tinker-ontology; kept as a local match so
/// describe never depends on ontology internals beyond the kind name.
/// An unknown kind fails closed — describe must not invent types.
fn kind_pg_type(kind: &str) -> &'static str {
    match kind {
        "text" | "email" | "phone" | "url" | "select" | "file" => "TEXT",
        "richtext" => "JSONB",
        "number" | "currency" => "NUMERIC",
        "date" => "DATE",
        "datetime" => "TIMESTAMPTZ",
        "boolean" => "BOOLEAN",
        "multi_select" => "TEXT[]",
        "relation" => "UUID",
        _ => "UNKNOWN",
    }
}

/// Extract `options.options` for select-style fields. Anything else
/// shaped is corrupt metadata — fail closed rather than document a lie.
fn select_options(options_json: &serde_json::Value) -> Option<Vec<String>> {
    let arr = options_json.get("options")?.as_array()?;
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        out.push(v.as_str()?.to_string());
    }
    Some(out)
}

/// Coarse row-policy summary. The shapes are all describe may reveal:
/// whether any policy applies, how many filters, and whether scoping is
/// actor-based, constant-based, or mixed. Field names, operators, and
/// values never leave this function.
fn summarize_row_policy(filters: &[tinker_query::RowFilter]) -> DescribedRowPolicy {
    if filters.is_empty() {
        return DescribedRowPolicy {
            applies: false,
            summary: "default-open: no row policy for this role on this object".to_string(),
            filter_count: 0,
        };
    }
    let actor_scoped = filters
        .iter()
        .all(|f| matches!(f.value, RowFilterValue::ActorId));
    let summary = if actor_scoped {
        "rows are scoped to the calling actor by an administrator-defined policy"
    } else {
        "rows are restricted by an administrator-defined policy"
    }
    .to_string();
    DescribedRowPolicy {
        applies: true,
        summary,
        filter_count: filters.len(),
    }
}

/// The lifecycle transition table, verified against
/// `tinker_ontology::lifecycle::LifecycleEngine` (item 40). Static
/// because the engine's gating is code, not data: transitions and their
/// role/approval rules change only when the engine changes, and this
/// table is reviewed against it in the describe test.
fn describe_lifecycle() -> DescribedLifecycle {
    let t = |name: &str, from: &[&str], to: &str, who: &str, requires_approval: Option<&str>| {
        LifecycleTransition {
            name: name.to_string(),
            from: from.iter().map(|s| s.to_string()).collect(),
            to: to.to_string(),
            who: who.to_string(),
            requires_approval: requires_approval.map(|s| s.to_string()),
        }
    };
    DescribedLifecycle {
        states: ["draft", "in_review", "rejected", "published", "archived"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        storage_note: "draft, in_review, and rejected live in record_drafts; \
            published and archived live on the data row"
            .to_string(),
        retention_note: "M8 retention/legal-hold composition: purge of stale \
            drafts and orphaned versions is suspended while the object is \
            under legal hold"
            .to_string(),
        transitions: vec![
            t(
                "create_draft",
                &[],
                "draft",
                "any organization member",
                None,
            ),
            t(
                "update_draft",
                &["draft"],
                "draft",
                "the draft author only",
                None,
            ),
            t(
                "submit_for_review",
                &["draft", "rejected"],
                "in_review",
                "the draft author only",
                Some("a bound M7 approval for submit_for_review on this draft"),
            ),
            t(
                "publish",
                &["in_review"],
                "published",
                "any member presenting a bound M7 publish approval decided by \
                 someone other than the draft author (no self-approval)",
                Some("a bound M7 approval for publish on this draft, decided by a non-author"),
            ),
            t(
                "reject",
                &["in_review"],
                "rejected",
                "members with role reviewer, admin, or owner — never the draft author",
                None,
            ),
            t(
                "revise",
                &["rejected"],
                "draft",
                "the draft author only",
                None,
            ),
            t(
                "archive",
                &["published"],
                "archived",
                "any member presenting a bound M7 archive approval for the record",
                Some("a bound M7 approval for archive on this record"),
            ),
            t(
                "unarchive",
                &["archived"],
                "published",
                "any member presenting a bound M7 unarchive approval for the record",
                Some("a bound M7 approval for unarchive on this record"),
            ),
        ],
    }
}

fn describe_mutation(lifecycle_enabled: bool) -> MutationContract {
    let (write_path, write_path_note) = if lifecycle_enabled {
        (
            "lifecycle",
            "direct writes are refused for this object: records must travel \
             the lifecycle transitions documented above (draft → review → \
             publish). Every transition is audit-logged; published versions \
             are immutable"
                .to_string(),
        )
    } else {
        (
            "governed",
            "all record writes pass the governed mutation connector, in \
             order: write presets are applied first (a preset can satisfy \
             `required`), then server-side validation rules, then file-field \
             validation (the file must exist, be active, belong to this \
             organization, and fit the field's max_pii_class). No write \
             path bypasses this ordering"
                .to_string(),
        )
    };
    MutationContract {
        write_path: write_path.to_string(),
        write_path_note,
        error_taxonomy: vec![
            ErrorClass {
                class: "invalid".to_string(),
                http_status: 400,
                meaning: "the write violates a validation rule, names an \
                    unknown field, or attempts an illegal transition"
                    .to_string(),
            },
            ErrorClass {
                class: "forbidden".to_string(),
                http_status: 403,
                meaning: "the caller lacks permission; for objects or fields \
                    the caller cannot see this is indistinguishable from \
                    not_found — there is no existence oracle"
                    .to_string(),
            },
            ErrorClass {
                class: "not_found".to_string(),
                http_status: 404,
                meaning: "unknown object, field, or record — same response \
                    shape as hidden"
                    .to_string(),
            },
            ErrorClass {
                class: "conflict".to_string(),
                http_status: 409,
                meaning: "version or state conflict (e.g. a second in-flight \
                    draft for the same record), or a client version-pinning \
                    mismatch"
                    .to_string(),
            },
        ],
    }
}

fn describe_reads() -> ReadContract {
    ReadContract {
        query_endpoint: "POST /api/query".to_string(),
        intent_shape: serde_json::json!({
            "from": "<object id (uuid)>",
            "select": ["api_name", "relation_field.api_name"],
            "filters": [{"field": "api_name", "op": "eq|ne|lt|lte|gt|gte|in|contains|starts_with|is_null|is_not_null", "value": "<json>"}],
            "order": [{"field": "api_name", "descending": false}],
            "limit": 100,
            "schema_version": "active"
        }),
        notes: vec![
            "select uses field api_names; \"a.b\" traverses one declared relation hop".to_string(),
            "filters and sorts on fields hidden from the caller's role are rejected outright — \
             a boolean oracle on a hidden column would leak its values"
                .to_string(),
            "row policies (see row_policy above) AND with the tenant predicate at compile time: \
             policy before ranking"
                .to_string(),
            "query plans are cached per (organization, plan hash); the hash covers the row-policy \
             SQL and actor binds, so roles never share an unauthorized plan"
                .to_string(),
        ],
    }
}

// ---------------------------------------------------------------------------
// Version pinning (spec design rule 4)
// ---------------------------------------------------------------------------

/// Query params a client may use to declare the versions it was built
/// against. Absent = unpinned (lenient); present and mismatched =
/// 409 with both sides named.
#[derive(Debug, Deserialize)]
pub struct VersionPin {
    pub client_tinker_version: Option<String>,
    pub client_ontology_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMismatch {
    pub expected_tinker: String,
    pub expected_ontology: String,
    pub got_tinker: Option<String>,
    pub got_ontology: Option<String>,
}

/// Returns `Some` when a declared client version disagrees with the
/// server. Pure function so tests can pin the behavior without HTTP.
pub fn check_client_versions(pin: &VersionPin) -> Option<VersionMismatch> {
    let tinker_ok = pin
        .client_tinker_version
        .as_deref()
        .map(|v| v == tinker_version())
        .unwrap_or(true);
    let ontology_ok = pin
        .client_ontology_version
        .as_deref()
        .map(|v| v == ontology_version())
        .unwrap_or(true);
    if tinker_ok && ontology_ok {
        return None;
    }
    Some(VersionMismatch {
        expected_tinker: tinker_version().to_string(),
        expected_ontology: ontology_version(),
        got_tinker: pin.client_tinker_version.clone(),
        got_ontology: pin.client_ontology_version.clone(),
    })
}

fn mismatch_response(m: &VersionMismatch) -> Response {
    let body = serde_json::json!({
        "error": "version_mismatch",
        "message": "client was built against different Tinker versions; refusing to silently drift",
        "expected": { "tinker_version": m.expected_tinker, "ontology_version": m.expected_ontology },
        "got": { "tinker_version": m.got_tinker, "ontology_version": m.got_ontology },
        "hint": "re-run describe without version pins, or update the client/skill to the server versions",
    });
    (StatusCode::CONFLICT, Json(body)).into_response()
}

fn json_response(value: &serde_json::Value) -> Response {
    (
        StatusCode::OK,
        [("content-type", "application/json")],
        canonical_json(value),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

/// `GET /api/describe` — the catalog. Requires org membership
/// (`role_of` fails closed with 403); the object list itself is RLS'd.
pub async fn get_catalog(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Query(pin): Query<VersionPin>,
) -> std::result::Result<Response, ApiError> {
    if let Some(m) = check_client_versions(&pin) {
        return Ok(mismatch_response(&m));
    }
    let tenant = tenant_ctx(&ctx);
    let role = role_of(&state, &tenant).await?;
    let catalog = Describer::from_state(&state)
        .catalog(&tenant, &role)
        .await?;
    let value = serde_json::to_value(&catalog).map_err(TinkerError::Serde)?;
    Ok(json_response(&value))
}

/// `GET /api/describe/{slug}` — one object's documentation, projected
/// through the caller's role. Unknown and foreign slugs are both 404.
pub async fn get_object(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(slug): Path<String>,
    Query(pin): Query<VersionPin>,
) -> std::result::Result<Response, ApiError> {
    if let Some(m) = check_client_versions(&pin) {
        return Ok(mismatch_response(&m));
    }
    let tenant = tenant_ctx(&ctx);
    let role = role_of(&state, &tenant).await?;
    let object = Describer::from_state(&state)
        .object(&tenant, &role, &slug)
        .await?;
    let value = serde_json::to_value(&object).map_err(TinkerError::Serde)?;
    Ok(json_response(&value))
}

// ---------------------------------------------------------------------------
// Human-readable rendering (CLI default)
// ---------------------------------------------------------------------------

/// Plain-text rendering for `tinker describe` without `--json`.
/// Informational only: the canonical JSON is the contract.
pub fn render_catalog_text(c: &DescribeCatalog) -> String {
    let mut out = format!(
        "tinker {} · ontology {}\nobjects ({}):\n",
        c.tinker_version,
        c.ontology_version,
        c.objects.len()
    );
    for o in &c.objects {
        let lc = if o.lifecycle_enabled {
            " [lifecycle]"
        } else {
            ""
        };
        out.push_str(&format!(
            "  {} ({}){} -> {}\n",
            o.api_slug, o.scope, lc, o.describe_href
        ));
    }
    out
}

/// Plain-text rendering for `tinker describe <object>` without `--json`.
pub fn render_object_text(o: &DescribeObject) -> String {
    let mut out = format!(
        "{} ({}, scope: {})\nfields ({}):\n",
        o.api_slug,
        o.name,
        o.scope,
        o.fields.len()
    );
    for f in &o.fields {
        let req = if f.required { " required" } else { "" };
        let preset = if f.preset.is_some() { " preset" } else { "" };
        out.push_str(&format!(
            "  {} : {}{req}{preset} [{}]\n",
            f.api_name, f.field_type, f.postgres_type
        ));
    }
    if !o.relations.is_empty() {
        out.push_str("relations:\n");
        for r in &o.relations {
            out.push_str(&format!(
                "  {} -> {} ({})\n",
                r.field, r.target_object, r.cardinality
            ));
        }
    }
    out.push_str(&format!(
        "row policy: {} (applies: {})\n",
        o.row_policy.summary, o.row_policy.applies
    ));
    if let Some(lc) = &o.lifecycle {
        out.push_str("lifecycle transitions:\n");
        for t in &lc.transitions {
            let from = if t.from.is_empty() {
                "∅".to_string()
            } else {
                t.from.join("/")
            };
            out.push_str(&format!(
                "  {} : {} -> {} ({})\n",
                t.name, from, t.to, t.who
            ));
        }
    }
    out.push_str(&format!(
        "writes: {} — {}\n",
        o.mutation.write_path, o.mutation.write_path_note
    ));
    out.push_str(&format!("reads: {}\n", o.reads.query_endpoint));
    out
}
