//! M4: the visual schema builder. Server-rendered (Askama) with plain
//! POST/redirect/GET forms — no JavaScript required, so every action is
//! testable over HTTP. The JSON API in `schema.rs` remains the
//! programmatic interface; these form endpoints are thin wrappers that
//! redirect back to the builder.

use std::collections::HashMap;

use askama::Template;
use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use uuid::Uuid;

use tinker_core::TenantContext;
use tinker_evolve::{SchemaVersion, VersionRef};

use super::live::ApiError;
use super::schema::{self, FieldInput};
use super::SharedState;
use crate::RequestContext;

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
pub struct SchemaQuery {
    pub object: Option<Uuid>,
    pub version: Option<Uuid>,
    pub diff_from: Option<String>,
}

#[derive(Template)]
#[template(path = "schema.html")]
struct SchemaTemplate {
    host_name: String,
    can_evolve: bool,
    objects: Vec<ObjectRow>,
    selected: Option<SelectedObject>,
}

struct ObjectRow {
    id: Uuid,
    name: String,
    api_slug: String,
    fields: usize,
    versions: usize,
    active_version: Option<i32>,
}

struct SelectedObject {
    id: Uuid,
    name: String,
    api_slug: String,
    record_count: i64,
    referenced_by: Vec<String>,
    base_fields: Vec<FieldRow>,
    versions: Vec<VersionRow>,
    detail: Option<VersionDetail>,
}

struct FieldRow {
    api_name: String,
    field_type: String,
    physical_column: String,
    relation_target: Option<String>,
}

struct VersionRow {
    id: Uuid,
    version_number: i32,
    status: String,
    parent: Option<i32>,
    fields: usize,
    selected: bool,
}

struct VersionDetail {
    id: Uuid,
    version_number: i32,
    status: String,
    is_draft: bool,
    cohort: Vec<String>,
    evolved_fields: Vec<FieldRow>,
    diff_from: String,
    diff_added: Vec<String>,
    diff_removed: Vec<String>,
    diff_changed: Vec<String>,
    preview_cols: Vec<String>,
    preview_rows: Vec<Vec<String>>,
}

pub async fn schema_page(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Query(q): Query<SchemaQuery>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    let can_evolve = schema::require_schema_evolve(&state, &ctx).await.is_ok();

    let objects = visible_objects(&state, &tenant).await?;

    let selected = match q.object {
        None => None,
        Some(object_id) => {
            Some(selected_object(&state, &tenant, object_id, q.version, q.diff_from).await?)
        }
    };

    let tpl = SchemaTemplate {
        host_name: state.host_name.clone(),
        can_evolve,
        objects,
        selected,
    };
    let html = tpl
        .render()
        .map_err(|e| ApiError::from(tinker_core::TinkerError::Internal(e.to_string())))?;
    Ok(Html(html).into_response())
}

async fn visible_objects(
    state: &SharedState,
    tenant: &TenantContext,
) -> Result<Vec<ObjectRow>, ApiError> {
    // RLS on ontology_objects shows platform + own-org rows only.
    let mut tx = state.core.tenant_tx(tenant).await.map_err(ApiError::from)?;
    let ids: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM ontology_objects WHERE state='active'")
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| ApiError::from(tinker_core::TinkerError::Db(e)))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(tinker_core::TinkerError::Db(e)))?;

    let mut rows = vec![];
    for (id,) in ids {
        let desc = state
            .ontology
            .describe_object(tenant, id)
            .await
            .map_err(ApiError::from)?;
        let versions = state
            .evolver
            .list_versions(tenant, id)
            .await
            .map_err(ApiError::from)?;
        let active = versions
            .iter()
            .find(|v| v.status == "active")
            .map(|v| v.version_number);
        rows.push(ObjectRow {
            id,
            name: desc.name,
            api_slug: desc.api_slug,
            fields: desc.fields.len(),
            versions: versions.len(),
            active_version: active,
        });
    }
    rows.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(rows)
}

async fn selected_object(
    state: &SharedState,
    tenant: &TenantContext,
    object_id: Uuid,
    version_id: Option<Uuid>,
    diff_from: Option<String>,
) -> Result<SelectedObject, ApiError> {
    // Fail closed for invisible objects: describe_object -> NotFound -> 404.
    let desc = state
        .ontology
        .describe_object(tenant, object_id)
        .await
        .map_err(ApiError::from)?;
    let versions = state
        .evolver
        .list_versions(tenant, object_id)
        .await
        .map_err(ApiError::from)?;

    let num_of = |id: Uuid| {
        versions
            .iter()
            .find(|v| v.id == id)
            .map(|v| v.version_number)
    };
    let mut version_rows: Vec<VersionRow> = vec![];
    for v in &versions {
        let fields = state
            .evolver
            .spec_fields(tenant, v.id)
            .await
            .map(|s| s.len())
            .unwrap_or(0);
        version_rows.push(VersionRow {
            id: v.id,
            version_number: v.version_number,
            status: v.status.clone(),
            parent: v.parent_version_id.and_then(num_of),
            fields,
            selected: Some(v.id) == version_id,
        });
    }

    let record_count = count_records(state, tenant, &desc).await?;
    let referenced_by = incoming_relations(state, tenant, object_id).await?;

    let base_fields = desc
        .fields
        .iter()
        .map(|f| FieldRow {
            api_name: f.api_name.clone(),
            field_type: f.field_type.clone(),
            physical_column: f.physical_column.clone(),
            relation_target: None,
        })
        .collect();

    let detail = match version_id {
        None => None,
        Some(vid) => Some(version_detail(state, tenant, object_id, vid, diff_from).await?),
    };

    Ok(SelectedObject {
        id: desc.id,
        name: desc.name,
        api_slug: desc.api_slug,
        record_count,
        referenced_by,
        base_fields,
        versions: version_rows,
        detail,
    })
}

async fn version_detail(
    state: &SharedState,
    tenant: &TenantContext,
    object_id: Uuid,
    version_id: Uuid,
    diff_from: Option<String>,
) -> Result<VersionDetail, ApiError> {
    let v = state
        .evolver
        .get_version(tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    if v.object_id != object_id {
        return Err(ApiError::from(tinker_core::TinkerError::NotFound(
            "version does not belong to this object".into(),
        )));
    }
    let spec = state
        .evolver
        .spec_fields(tenant, version_id)
        .await
        .map_err(ApiError::from)?;

    // Resolve relation target names (sequential; builder page, not hot path).
    let mut target_names: HashMap<Uuid, String> = HashMap::new();
    for f in &spec {
        if let Some(tid) = f.relation_target_id {
            match target_names.entry(tid) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    let name = state
                        .ontology
                        .describe_object(tenant, tid)
                        .await
                        .map(|d| d.name)
                        .unwrap_or_else(|_| tid.to_string());
                    e.insert(name);
                }
                std::collections::hash_map::Entry::Occupied(_) => {}
            }
        }
    }
    let evolved_fields = spec
        .iter()
        .map(|f| FieldRow {
            api_name: f.api_name.clone(),
            field_type: f.field_type.clone(),
            physical_column: f.physical_column.clone(),
            relation_target: f
                .relation_target_id
                .and_then(|tid| target_names.get(&tid).cloned()),
        })
        .collect();

    // Diff: default from=base.
    let from_ref = match diff_from.as_deref() {
        None | Some("base") => VersionRef::Base,
        Some(s) => {
            let id = Uuid::parse_str(s).map_err(|_| {
                ApiError::from(tinker_core::TinkerError::Validation("bad diff_from".into()))
            })?;
            VersionRef::Version(id)
        }
    };
    let diff = state
        .evolver
        .diff(tenant, object_id, from_ref, VersionRef::Version(version_id))
        .await
        .map_err(ApiError::from)?;

    let (preview_cols, preview_rows) = preview_version(state, tenant, object_id, &v).await?;

    Ok(VersionDetail {
        id: v.id,
        version_number: v.version_number,
        status: v.status.clone(),
        is_draft: v.status == "draft",
        cohort: v
            .canary_cohort
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|u| u.to_string())
            .collect(),
        evolved_fields,
        diff_from: diff_from.unwrap_or_else(|| "base".into()),
        diff_added: diff.added,
        diff_removed: diff.removed,
        diff_changed: diff
            .changed
            .iter()
            .map(|(a, b, c)| format!("{a}: {b} -> {c}"))
            .collect(),
        preview_cols,
        preview_rows,
    })
}

async fn count_records(
    state: &SharedState,
    tenant: &TenantContext,
    desc: &tinker_ontology::ObjectDescription,
) -> Result<i64, ApiError> {
    // The schema page is visible to non-admin members, so the count must
    // respect the viewer's row policy (item 38): an unfiltered COUNT(*)
    // would leak the size of the hidden set to a restricted role.
    let role = role_of(state, tenant).await?;
    let policy = state
        .row_filters
        .load_policy(tenant, desc.id, &role)
        .await
        .map_err(ApiError::from)?;
    let mut sql = format!(
        "SELECT COUNT(*) FROM data.\"{}\" WHERE organization_id=$1",
        desc.api_slug
    );
    let mut params = vec![tinker_core::Param::Uuid(tenant.organization_id.0)];
    policy
        .append_predicates(tenant, desc, None, &mut sql, &mut params)
        .map_err(ApiError::from)?;
    // C1 (item 40): the schema-page count respects lifecycle too —
    // archived records are not counted for default readers.
    tinker_query::append_default_published_predicate(
        &policy,
        desc.lifecycle_enabled,
        &mut sql,
        &mut params,
        None,
        &|n| format!("${n}"),
    );
    let mut tx = state.core.tenant_tx(tenant).await.map_err(ApiError::from)?;
    let mut q = sqlx::query_as::<_, (i64,)>(&sql);
    for p in &params {
        q = tinker_query::bind_param_as(q, p);
    }
    let (n,) = q
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| ApiError::from(tinker_core::TinkerError::Db(e)))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(tinker_core::TinkerError::Db(e)))?;
    Ok(n)
}

/// The viewer's membership role — same trusted source as the query
/// endpoint (live.rs). Roles drive both field projections and row
/// policies; the schema page must not show counts the viewer cannot see.
async fn role_of(state: &SharedState, tenant: &TenantContext) -> Result<String, ApiError> {
    let mut tx = state.core.tenant_tx(tenant).await.map_err(ApiError::from)?;
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM memberships WHERE actor_id=$1 AND organization_id=$2")
            .bind(tenant.actor_id)
            .bind(tenant.organization_id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(tinker_core::TinkerError::Db)
            .map_err(ApiError::from)?;
    tx.commit()
        .await
        .map_err(tinker_core::TinkerError::Db)
        .map_err(ApiError::from)?;
    row.map(|(r,)| r)
        .ok_or(ApiError(axum::http::StatusCode::FORBIDDEN))
}

async fn incoming_relations(
    state: &SharedState,
    tenant: &TenantContext,
    object_id: Uuid,
) -> Result<Vec<String>, ApiError> {
    let mut tx = state.core.tenant_tx(tenant).await.map_err(ApiError::from)?;
    let ids: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM ontology_objects WHERE state='active' AND id <> $1")
            .bind(object_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| ApiError::from(tinker_core::TinkerError::Db(e)))?;
    tx.commit()
        .await
        .map_err(|e| ApiError::from(tinker_core::TinkerError::Db(e)))?;
    let mut refs = vec![];
    for (id,) in ids {
        let d = state
            .ontology
            .describe_object(tenant, id)
            .await
            .map_err(ApiError::from)?;
        for f in &d.fields {
            if f.field_type == "relation" && f.relation_target_id == Some(object_id) {
                refs.push(format!("{}.{}", d.name, f.api_name));
            }
        }
    }
    Ok(refs)
}

async fn preview_version(
    state: &SharedState,
    tenant: &TenantContext,
    object_id: Uuid,
    v: &SchemaVersion,
) -> Result<(Vec<String>, Vec<Vec<String>>), ApiError> {
    use tinker_query::QueryIntent;
    let schema_version = match v.status.as_str() {
        "canary" => Some("canary".to_string()),
        "preview" => Some("preview".to_string()),
        "active" => Some("active".to_string()),
        _ => None,
    };
    let desc = state
        .ontology
        .describe_object(tenant, object_id)
        .await
        .map_err(ApiError::from)?;
    let mut select: Vec<String> = desc
        .fields
        .iter()
        .take(6)
        .map(|f| f.api_name.clone())
        .collect();
    if schema_version.is_some() {
        let spec = state
            .evolver
            .spec_fields(tenant, v.id)
            .await
            .map_err(ApiError::from)?;
        for f in spec.iter().take(4) {
            if !select.contains(&f.api_name) {
                select.push(f.api_name.clone());
            }
        }
    }
    if select.is_empty() {
        return Ok((vec![], vec![]));
    }
    let intent = QueryIntent {
        from: object_id,
        select,
        filters: vec![],
        order: vec![],
        limit: Some(5),
        schema_version,
    };
    let plan = state
        .compiler
        .compile(tenant, &intent)
        .await
        .map_err(ApiError::from)?;
    let rows = state
        .executor
        .execute(tenant, &plan)
        .await
        .map_err(ApiError::from)?;
    let out: Vec<Vec<String>> = rows
        .into_iter()
        .map(|r| {
            plan.output_fields
                .iter()
                .map(|c| {
                    r.get(c)
                        .map(|val| match val {
                            serde_json::Value::Null => "—".to_string(),
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        })
                        .unwrap_or_default()
                })
                .collect()
        })
        .collect();
    Ok((plan.output_fields, out))
}

// ---------------------------------------------------------------------------
// Form actions (POST/redirect/GET)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct AddFieldForm {
    pub name: String,
    pub api_name: String,
    pub label: String,
    pub field_type: String,
}

#[derive(Deserialize)]
pub struct AddRelationForm {
    pub name: String,
    pub api_name: String,
    pub label: String,
    pub target_object_id: Uuid,
}

#[derive(Deserialize)]
pub struct CanaryForm {
    #[serde(default)]
    pub cohort: String, // comma-separated actor UUIDs; empty = no cohort
}

fn back(object_id: Uuid, version: Option<Uuid>) -> Redirect {
    let mut url = format!("/schema?object={object_id}");
    if let Some(v) = version {
        url.push_str(&format!("&version={v}"));
    }
    Redirect::to(&url)
}

pub async fn form_create_draft(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(object_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    schema::require_schema_evolve(&state, &ctx).await?;
    let v = state
        .evolver
        .create_draft(&tenant, object_id)
        .await
        .map_err(ApiError::from)?;
    Ok(back(object_id, Some(v.id)).into_response())
}

pub async fn form_add_field(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
    Form(f): Form<AddFieldForm>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    schema::require_schema_evolve(&state, &ctx).await?;
    let input = FieldInput {
        name: f.name,
        api_name: f.api_name,
        label: f.label,
        field_type: f.field_type,
        options: serde_json::json!({}),
        required: false,
        target_object_id: None,
        // Item 37 (C3): the HTML form does not collect governance metadata yet.
        validation: Default::default(),
        preset: None,
        max_pii_class: "restricted".to_string(),
        sensitive: false,
    };
    let def = schema::field_def_from(input, false)?;
    let v = state
        .evolver
        .get_version(&tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    state
        .evolver
        .add_field(&tenant, version_id, &def)
        .await
        .map_err(ApiError::from)?;
    Ok(back(v.object_id, Some(version_id)).into_response())
}

pub async fn form_add_relation(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
    Form(f): Form<AddRelationForm>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    schema::require_schema_evolve(&state, &ctx).await?;
    let input = FieldInput {
        name: f.name,
        api_name: f.api_name,
        label: f.label,
        field_type: "relation".into(),
        options: serde_json::json!({}),
        required: false,
        target_object_id: Some(f.target_object_id),
        // Item 37 (C3): the HTML form does not collect governance metadata yet.
        validation: Default::default(),
        preset: None,
        max_pii_class: "restricted".to_string(),
        sensitive: false,
    };
    let def = schema::field_def_from(input, true)?;
    let v = state
        .evolver
        .get_version(&tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    state
        .evolver
        .add_relation(&tenant, version_id, &def)
        .await
        .map_err(ApiError::from)?;
    Ok(back(v.object_id, Some(version_id)).into_response())
}

pub async fn form_mark_preview(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    schema::require_schema_evolve(&state, &ctx).await?;
    let v = state
        .evolver
        .get_version(&tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    state
        .evolver
        .mark_preview(&tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    Ok(back(v.object_id, Some(version_id)).into_response())
}

pub async fn form_mark_canary(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
    Form(f): Form<CanaryForm>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    schema::require_schema_evolve(&state, &ctx).await?;
    let cohort: Vec<Uuid> = f
        .cohort
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(Uuid::parse_str)
        .collect::<Result<_, _>>()
        .map_err(|_| {
            ApiError::from(tinker_core::TinkerError::Validation(
                "cohort must be comma-separated UUIDs".into(),
            ))
        })?;
    let v = state
        .evolver
        .get_version(&tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    state
        .evolver
        .mark_canary(
            &tenant,
            version_id,
            if cohort.is_empty() {
                None
            } else {
                Some(cohort)
            },
        )
        .await
        .map_err(ApiError::from)?;
    Ok(back(v.object_id, Some(version_id)).into_response())
}

pub async fn form_promote(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    schema::require_schema_evolve(&state, &ctx).await?;
    // Goes through the same governance as the JSON path: cached plans
    // drop and open SSE streams re-resolve the schema (post-M8 item 33).
    let v = schema::promote_and_broadcast(&state, &tenant, version_id).await?;
    Ok(back(v.object_id, Some(version_id)).into_response())
}

pub async fn form_rollback(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let tenant = schema::tenant_ctx(&ctx);
    schema::require_schema_evolve(&state, &ctx).await?;
    // Goes through the same governance as the JSON path: cached plans
    // drop and open SSE streams re-resolve the schema (post-M8 item 33).
    let (object_id, _) = schema::rollback_and_broadcast(&state, &tenant, version_id).await?;
    Ok(back(object_id, Some(version_id)).into_response())
}
