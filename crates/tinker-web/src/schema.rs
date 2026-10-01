//! M4: HTTP API for the schema builder (evolution).
//!
//! Every endpoint requires the `schema:evolve` grant at organization scope —
//! schema DDL is never available to ordinary members. The grant check runs
//! before any evolver call, so an unauthorized actor cannot even create a
//! draft version.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use tinker_auth::{AuthzDecision, AuthzScope};
use tinker_core::{TenantContext, TinkerError};
use tinker_evolve::{SchemaVersion, VersionRef};
use tinker_identity::authz_input;
use tinker_ontology::{FieldDef, FieldType};
use uuid::Uuid;

use crate::{live::ApiError, RequestContext, SharedState};

pub(crate) fn tenant_ctx(ctx: &RequestContext) -> TenantContext {
    TenantContext::new(
        tinker_core::OrganizationId(ctx.0.organization_id),
        ctx.0.actor_id,
        "schema-evolve",
    )
}

/// `schema:evolve` at organization scope, or 403. Runs before any DDL.
pub(crate) async fn require_schema_evolve(
    state: &SharedState,
    ctx: &RequestContext,
) -> Result<(), ApiError> {
    let tenant = tenant_ctx(ctx);
    let input = authz_input(
        &ctx.0,
        AuthzScope::Organization {
            organization_id: ctx.0.organization_id,
        },
        "schema:evolve",
        "schema",
        &ctx.0.organization_id.to_string(),
        "schema evolution",
    );
    let decision = state
        .authorizer
        .authorize(&input, ctx.0.assurance)
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR))?;
    if !matches!(decision, AuthzDecision::Allow) {
        return Err(ApiError(StatusCode::FORBIDDEN));
    }
    let _ = tenant;
    Ok(())
}

#[derive(Serialize)]
pub struct VersionResponse {
    id: Uuid,
    object_id: Uuid,
    version_number: i32,
    parent_version_id: Option<Uuid>,
    status: String,
    canary_cohort: Option<Vec<Uuid>>,
}

impl From<SchemaVersion> for VersionResponse {
    fn from(v: SchemaVersion) -> Self {
        Self {
            id: v.id,
            object_id: v.object_id,
            version_number: v.version_number,
            parent_version_id: v.parent_version_id,
            status: v.status,
            canary_cohort: v.canary_cohort,
        }
    }
}

pub async fn create_draft(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(object_id): Path<Uuid>,
) -> Result<Json<VersionResponse>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let v = state
        .evolver
        .create_draft(&tenant, object_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(v.into()))
}

#[derive(Deserialize)]
pub struct FieldInput {
    pub name: String,
    pub api_name: String,
    pub label: String,
    pub field_type: String,
    #[serde(default)]
    pub options: serde_json::Value,
    #[serde(default)]
    pub required: bool,
    pub target_object_id: Option<Uuid>,
    /// Item 37 (C3): validation rules for the field — data, never code.
    #[serde(default)]
    pub validation: tinker_ontology::ValidationRules,
    /// Item 37 (C3): forced default, applied before validation.
    #[serde(default)]
    pub preset: Option<tinker_ontology::WritePreset>,
    /// Item 42 (C7): ceiling for PII classes of files linked through a
    /// `file` field. Defaults to 'restricted' (permissive).
    #[serde(default = "default_max_pii_class")]
    pub max_pii_class: String,
}

/// Item 42 (C7): mirrors the ontology default — fields defined without
/// an explicit ceiling stay permissive until an operator tightens them.
fn default_max_pii_class() -> String {
    "restricted".to_string()
}

pub(crate) fn field_def_from(input: FieldInput, relation: bool) -> Result<FieldDef, ApiError> {
    let field_type = match input.field_type.as_str() {
        "text" => FieldType::Text,
        "richtext" => FieldType::RichText,
        "number" => FieldType::Number,
        "date" => FieldType::Date,
        "datetime" => FieldType::DateTime,
        "boolean" => FieldType::Boolean,
        "select" => FieldType::Select,
        "multi_select" => FieldType::MultiSelect,
        "currency" => FieldType::Currency,
        "email" => FieldType::Email,
        "phone" => FieldType::Phone,
        "url" => FieldType::Url,
        "file" => FieldType::File,
        "relation" => match input.target_object_id {
            Some(t) => FieldType::Relation {
                target_object_id: t,
            },
            None => {
                return Err(ApiError::from(TinkerError::Validation(
                    "relation fields need target_object_id".into(),
                )))
            }
        },
        other => {
            return Err(ApiError::from(TinkerError::Validation(format!(
                "unknown field_type: {other}"
            ))))
        }
    };
    if relation && !matches!(field_type, FieldType::Relation { .. }) {
        return Err(ApiError::from(TinkerError::Validation(
            "add_relation requires field_type=relation".into(),
        )));
    }
    Ok(FieldDef {
        // Item 37 (C3): governance metadata comes from the client payload;
        // definition-time sanity is enforced by validate_field_def.
        validation: input.validation,
        preset: input.preset,
        // Item 42 (C7): PII ceiling comes from the client payload;
        // add_field validates the vocabulary.
        max_pii_class: input.max_pii_class,
        name: input.name,
        api_name: input.api_name,
        label: input.label,
        field_type,
        options: input.options,
        required: input.required,
    })
}

#[derive(Serialize)]
pub struct FieldAddedResponse {
    api_name: String,
    field_type: String,
    physical_column: String,
}

pub async fn add_field(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
    Json(input): Json<FieldInput>,
) -> Result<Json<FieldAddedResponse>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let def = field_def_from(input, false)?;
    let f = state
        .evolver
        .add_field(&tenant, version_id, &def)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(FieldAddedResponse {
        api_name: f.api_name,
        field_type: f.field_type,
        physical_column: f.physical_column,
    }))
}

pub async fn add_relation(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
    Json(input): Json<FieldInput>,
) -> Result<Json<FieldAddedResponse>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let def = field_def_from(input, true)?;
    let f = state
        .evolver
        .add_relation(&tenant, version_id, &def)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(FieldAddedResponse {
        api_name: f.api_name,
        field_type: f.field_type,
        physical_column: f.physical_column,
    }))
}

pub async fn mark_preview(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
) -> Result<Json<VersionResponse>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let v = state
        .evolver
        .mark_preview(&tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(v.into()))
}

#[derive(Deserialize)]
pub struct CanaryInput {
    pub cohort: Option<Vec<Uuid>>,
}

pub async fn mark_canary(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
    Json(input): Json<CanaryInput>,
) -> Result<Json<VersionResponse>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let v = state
        .evolver
        .mark_canary(&tenant, version_id, input.cohort)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(v.into()))
}

pub async fn promote(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
) -> Result<Json<VersionResponse>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let v = promote_and_broadcast(&state, &tenant, version_id).await?;
    Ok(Json(v.into()))
}

/// Governance for every schema-change entry point (post-M8 item 33):
/// once the active schema changes, every open stream resolves against
/// a new version, so drop cached plans compiled against the old version
/// and tell SSE subscribers to re-resolve the schema (a row invalidation
/// might never come). The JSON and form handlers both go through this,
/// so neither can skip it.
pub(crate) async fn broadcast_schema_change(
    state: &SharedState,
    organization_id: Uuid,
    object_id: Uuid,
) {
    state.cache.invalidate(organization_id, object_id).await;
    // The governed-metadata cache shares the query cache's freshness
    // contract (item 47); every invalidation site covers both.
    state.meta.invalidate(organization_id, object_id).await;
    state
        .signals
        .publish_schema_version(organization_id, object_id)
        .await;
}

/// Promote a version, then broadcast the schema change (cache
/// invalidation + schema-version signal). Single source for the JSON
/// and form entry points, so neither can skip governance.
pub(crate) async fn promote_and_broadcast(
    state: &SharedState,
    tenant: &TenantContext,
    version_id: Uuid,
) -> Result<SchemaVersion, ApiError> {
    let v = state
        .evolver
        .promote(tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    broadcast_schema_change(state, tenant.organization_id.0, v.object_id).await;
    Ok(v)
}

/// Roll back, then broadcast the schema change (cache invalidation +
/// schema-version signal). Single source for the JSON and form entry
/// points, so neither can skip governance. Returns the object id
/// (needed for redirects whichever version ends up active) and the
/// restored version, if any.
pub(crate) async fn rollback_and_broadcast(
    state: &SharedState,
    tenant: &TenantContext,
    version_id: Uuid,
) -> Result<(Uuid, Option<SchemaVersion>), ApiError> {
    // The object id is needed for cache invalidation + the schema signal
    // whichever version ends up active, so read it before rolling back.
    let object_id = state
        .evolver
        .get_version(tenant, version_id)
        .await
        .map_err(ApiError::from)?
        .object_id;
    let restored = state
        .evolver
        .rollback(tenant, version_id)
        .await
        .map_err(ApiError::from)?;
    broadcast_schema_change(state, tenant.organization_id.0, object_id).await;
    Ok((object_id, restored))
}

#[derive(Serialize)]
pub struct RollbackResponse {
    rolled_back: Uuid,
    restored: Option<VersionResponse>,
}

pub async fn rollback(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(version_id): Path<Uuid>,
) -> Result<Json<RollbackResponse>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let (_, restored) = rollback_and_broadcast(&state, &tenant, version_id).await?;
    Ok(Json(RollbackResponse {
        rolled_back: version_id,
        restored: restored.map(VersionResponse::from),
    }))
}

pub async fn list_versions(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(object_id): Path<Uuid>,
) -> Result<Json<Vec<VersionResponse>>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let vs = state
        .evolver
        .list_versions(&tenant, object_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(vs.into_iter().map(VersionResponse::from).collect()))
}

#[derive(Deserialize)]
pub struct DiffQuery {
    /// "base" or a version UUID.
    pub from: String,
    /// a version UUID.
    pub to: String,
}

fn parse_ref(s: &str) -> Result<VersionRef, ApiError> {
    if s == "base" {
        Ok(VersionRef::Base)
    } else {
        s.parse::<Uuid>()
            .map(VersionRef::Version)
            .map_err(|_| ApiError::from(TinkerError::Validation(format!("bad version ref: {s}"))))
    }
}

pub async fn diff_versions(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(object_id): Path<Uuid>,
    Query(q): Query<DiffQuery>,
) -> Result<Json<tinker_evolve::SchemaDiff>, ApiError> {
    require_schema_evolve(&state, &ctx).await?;
    let tenant = tenant_ctx(&ctx);
    let d = state
        .evolver
        .diff(&tenant, object_id, parse_ref(&q.from)?, parse_ref(&q.to)?)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(d))
}
