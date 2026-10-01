//! C5 dashboard HTTP surface (item 41).
//!
//! JSON API over [`tinker_query::dashboard::DashboardService`]:
//! - `POST /api/dashboards` — create (panel queries validated at save)
//! - `GET /api/dashboards` — list this org's dashboards
//! - `GET /api/dashboards/{id}` — fetch one
//! - `PUT /api/dashboards/{id}` — replace name/description/panels
//! - `DELETE /api/dashboards/{id}` — delete
//! - `POST /api/dashboards/{id}/render` — render every panel under the
//!   VIEWER's permissions. The viewer's role comes from their membership
//!   row — never from the request — exactly like `/api/query`. Panel
//!   failures are per-panel; the dashboard always renders.
//!
//! Dashboard management itself is org-scoped (any member may manage);
//! the render path is what carries the no-escalation guarantee.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use uuid::Uuid;

use tinker_query::dashboard::{Dashboard, DashboardInput, DashboardSummary, RenderedDashboard};

use crate::{
    live::{role_of, tenant_ctx, ApiError},
    RequestContext, SharedState,
};

pub async fn create_dashboard(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Json(input): Json<DashboardInput>,
) -> Result<Json<Dashboard>, ApiError> {
    let tenant = tenant_ctx(&ctx);
    let dash = state.dashboards.create(&tenant, input).await?;
    Ok(Json(dash))
}

pub async fn list_dashboards(
    State(state): State<SharedState>,
    ctx: RequestContext,
) -> Result<Json<Vec<DashboardSummary>>, ApiError> {
    let tenant = tenant_ctx(&ctx);
    let list = state.dashboards.list(&tenant).await?;
    Ok(Json(list))
}

pub async fn get_dashboard(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(id): Path<Uuid>,
) -> Result<Json<Dashboard>, ApiError> {
    let tenant = tenant_ctx(&ctx);
    let dash = state.dashboards.get(&tenant, id).await?;
    Ok(Json(dash))
}

pub async fn update_dashboard(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(id): Path<Uuid>,
    Json(input): Json<DashboardInput>,
) -> Result<Json<Dashboard>, ApiError> {
    let tenant = tenant_ctx(&ctx);
    let dash = state.dashboards.update(&tenant, id, input).await?;
    Ok(Json(dash))
}

pub async fn delete_dashboard(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let tenant = tenant_ctx(&ctx);
    state.dashboards.delete(&tenant, id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn render_dashboard(
    State(state): State<SharedState>,
    ctx: RequestContext,
    Path(id): Path<Uuid>,
) -> Result<Json<RenderedDashboard>, ApiError> {
    let tenant = tenant_ctx(&ctx);
    // The viewer's role — from the membership table, never the request.
    // No membership fails closed (403), like /api/query.
    let role = role_of(&state, &tenant).await?;
    let rendered = state.dashboards.render(&tenant, &role, id).await?;
    Ok(Json(rendered))
}
