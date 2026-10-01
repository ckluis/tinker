//! Governed reactivity loop: HTTP surface (PRD M2, projections M3).
//!
//! - `POST /api/query` — compile a typed intent, serve from the
//!   tenant-scoped cache when fresh, otherwise execute with a timeout and
//!   audit. Returns rows plus the plan hash for SSE subscription. M3: the
//!   caller's role (from their membership) loads an authorized field
//!   projection; hidden selected fields are dropped, hidden filter/sort
//!   fields are rejected, and the SQL never selects a hidden column.
//!   C2 (item 38): the same role loads a row-level policy, ANDed with the
//!   tenant predicate at compile time — policy before ranking. The plan
//!   hash covers the policy SQL and any actor.id binds, so cache entries
//!   never cross authorization boundaries.
//! - `GET /api/sse?object=<id>` — id-only invalidation stream for one
//!   object. The object id is authorized through the tenant-scoped
//!   ontology (`describe_object` fails closed); the signal subscription
//!   is per-organization, so colliding IDs in a sibling org are
//!   unreachable.
//!
//! Both endpoints require a session; the organization always comes from
//! the session, never from request parameters.

use std::convert::Infallible;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Json,
};
use serde::{Deserialize, Serialize};
use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_live::QueryExecutor;
use tinker_live::SignalKind;
use tinker_query::QueryIntent;
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use uuid::Uuid;

use crate::{RequestContext, SharedState};

#[derive(Debug, Serialize)]
pub struct QueryResponse {
    pub rows: Vec<serde_json::Value>,
    pub plan_hash: String,
    pub object_id: Uuid,
    pub cached: bool,
}

pub async fn api_query(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Json(intent): Json<QueryIntent>,
) -> Result<Json<QueryResponse>, ApiError> {
    let tenant = tenant_ctx(&ctx);
    // M3: the caller's role projects the query. The role comes from their
    // membership — never from the request body.
    let role = role_of(&state, &tenant).await?;
    // Item 47: the governed inputs (description, projection, row policy)
    // come from the metadata cache when warm — zero DB round trips on
    // the metadata path. Error behavior is unchanged (all raw).
    let inputs = crate::meta::query_inputs(
        &state,
        &tenant,
        &role,
        intent.from,
        intent.schema_version.as_deref(),
    )
    .await?;
    let plan = state
        .compiler
        .compile_with_inputs(
            &tenant,
            &intent,
            &inputs.projection,
            &inputs.policy,
            &inputs.desc,
            inputs.version_sel,
        )
        .await?;
    let hash = QueryExecutor::plan_hash(&plan);

    if let Some(rows) = state.cache.get(tenant.organization_id.0, &hash).await {
        return Ok(Json(QueryResponse {
            rows,
            plan_hash: hash,
            object_id: plan.object_id,
            cached: true,
        }));
    }
    let rows = state.executor.execute(&tenant, &plan).await?;
    state
        .cache
        .put(
            tenant.organization_id.0,
            &hash,
            plan.object_id,
            rows.clone(),
        )
        .await;
    Ok(Json(QueryResponse {
        rows,
        plan_hash: hash,
        object_id: plan.object_id,
        cached: false,
    }))
}

/// The caller's role in this organization, from their membership row.
/// No membership (or a revoked one) fails closed: the query endpoint
/// needs a role to project by.
pub(crate) async fn role_of(
    state: &SharedState,
    tenant: &TenantContext,
) -> Result<String, ApiError> {
    let mut tx = state.core.tenant_tx(tenant).await.map_err(ApiError::from)?;
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role FROM memberships WHERE actor_id=$1 AND organization_id=$2")
            .bind(tenant.actor_id)
            .bind(tenant.organization_id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)
            .map_err(ApiError::from)?;
    tx.commit()
        .await
        .map_err(TinkerError::Db)
        .map_err(ApiError::from)?;
    row.map(|(r,)| r).ok_or(ApiError(StatusCode::FORBIDDEN))
}

#[derive(Debug, Deserialize)]
pub struct SseParams {
    pub object: Uuid,
}

/// Id-only SSE stream. Each event carries `{seq, object_id, record_ids}` —
/// never row contents. The client refetches through `/api/query`, so
/// field-level authorization still applies on every render.
///
/// Schema-version changes (promotion/rollback) arrive as a distinct
/// `schema_version` event carrying `{seq, object_id}` and no record ids:
/// the client must re-resolve the schema (new fields may exist) rather
/// than merely refetching rows.
pub async fn api_sse(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Query(params): Query<SseParams>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let tenant = tenant_ctx(&ctx);
    // Authorize the object id through the tenant-scoped ontology. A
    // sibling org's object id fails here with NotFound — fail closed.
    state
        .ontology
        .describe_object(&tenant, params.object)
        .await?;

    let rx = state.signals.subscribe(tenant.organization_id.0).await;
    let object_id = params.object;
    let stream = BroadcastStream::new(rx).filter_map(move |msg| {
        let signal = match msg {
            Ok(s) => s,
            Err(_) => {
                // Lagged: we missed invalidations. Tell the client to
                // refetch now rather than waiting for the next write.
                return Some(Ok(Event::default()
                    .event("resync")
                    .data("{\"reason\":\"lagged\"}")));
            }
        };
        if signal.object_id != object_id {
            return None;
        }
        match signal.kind {
            SignalKind::Invalidate => {
                let payload = serde_json::json!({
                    "seq": signal.seq,
                    "object_id": signal.object_id,
                    "record_ids": signal.record_ids,
                });
                Some(Ok(Event::default()
                    .event("invalidate")
                    .data(payload.to_string())))
            }
            SignalKind::SchemaVersion => {
                let payload = serde_json::json!({
                    "seq": signal.seq,
                    "object_id": signal.object_id,
                });
                Some(Ok(Event::default()
                    .event("schema_version")
                    .data(payload.to_string())))
            }
        }
    });
    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    ))
}

pub(crate) fn tenant_ctx(ctx: &RequestContext) -> TenantContext {
    TenantContext::new(
        OrganizationId(ctx.0.organization_id),
        ctx.0.actor_id,
        "live-query",
    )
}

/// Minimal error mapping for the live API. Fail-closed codes only.
pub struct ApiError(pub(crate) StatusCode);

impl From<TinkerError> for ApiError {
    fn from(e: TinkerError) -> Self {
        let code = match e {
            TinkerError::Validation(_) => StatusCode::BAD_REQUEST,
            TinkerError::NotFound(_) => StatusCode::NOT_FOUND,
            TinkerError::Forbidden(_) => StatusCode::FORBIDDEN,
            TinkerError::Conflict { .. } => StatusCode::CONFLICT,
            TinkerError::Busy(_) => StatusCode::CONFLICT,
            TinkerError::DuplicateEffect(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self(code)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}
