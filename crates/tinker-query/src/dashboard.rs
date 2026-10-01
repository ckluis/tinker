//! C5 dashboard composer (item 41).
//!
//! A dashboard is a governed object: org-scoped, RLS-isolated, CRUD'd
//! like any other tenant object. Panels are embedded in the dashboard's
//! `layout` JSONB column: each panel carries its saved query (a
//! [`QueryIntent`]), a visualization kind, and grid geometry. The server
//! accepts layout saves; drag-and-drop itself is client-side (DataStar).
//!
//! Security contract:
//! - Panel queries are VALIDATED at save time: every panel's query must
//!   compile under the author's own row policy and field projection.
//!   Unknown objects/fields, hidden fields, and bad operators fail the
//!   save — never render.
//! - Render ALWAYS executes each panel's query under the VIEWER's
//!   permissions: the viewer's role resolves their row policy (item 38),
//!   field projection (M3), and lifecycle visibility (item 40) at compile
//!   time. A dashboard shared from a privileged author to a restricted
//!   viewer shows the viewer only what they may see — there is no
//!   privilege escalation via shared dashboards.
//! - Panel failures are per-panel: one bad panel renders as an error
//!   card, never breaking the dashboard.
//! - Every panel execution is audit-logged (`query_audit`) under the
//!   viewing actor, exactly like a direct query execution.
//!
//! Honest limits (v1):
//! - No per-dashboard ACLs: any org member can CRUD dashboards. The
//!   render path is what carries the security property, not the
//!   management path.
//! - Panels reference embedded saved queries; there is no standalone
//!   saved-view library.
//! - Visualization kinds are `table` and a basic `chart` shape; the
//!   server returns rows, the client renders them.
//! - No real-time collaborative editing; no scheduled snapshots.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_ontology::Ontology;
use uuid::Uuid;

use crate::{bind_param, CompiledPlan, FieldProjection, QueryCompiler, QueryIntent, RowFilters};

/// Dashboards lay out on a 24-column grid.
pub const GRID_COLUMNS: u16 = 24;
/// Sanity caps: a dashboard is a screen, not a database.
pub const MAX_PANELS: usize = 64;
pub const MAX_GRID_Y: u16 = 1024;
pub const MAX_PANEL_ID_LEN: usize = 64;
/// Same statement timeout as direct query execution.
const QUERY_TIMEOUT_MS: u32 = 5_000;
/// Mirrors `tinker_live::grants::DENY_ALL_FIELDS`: an explicit deny-all
/// marker in `field_grants`. Kept in sync by contract; the table is the
/// source of truth and this module reads it, never writes it.
const DENY_ALL_FIELDS: &str = "__deny_all";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VisualizationKind {
    Table,
    Chart,
}

/// One panel: a saved query, how to show it, and where it sits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelDef {
    pub id: String,
    pub query: QueryIntent,
    pub visualization: VisualizationKind,
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardInput {
    pub name: String,
    pub description: Option<String>,
    pub panels: Vec<PanelDef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dashboard {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: String,
    pub panels: Vec<PanelDef>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSummary {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub description: String,
    pub panel_count: usize,
    pub updated_at: DateTime<Utc>,
}

/// One panel's render outcome. `Error` carries a sanitized message —
/// never SQL text or internal detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedPanel {
    pub panel_id: String,
    pub visualization: VisualizationKind,
    pub object_id: Option<Uuid>,
    #[serde(flatten)]
    pub outcome: PanelOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PanelOutcome {
    Ok { rows: Vec<serde_json::Value> },
    Error { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenderedDashboard {
    pub dashboard_id: Uuid,
    pub name: String,
    pub panels: Vec<RenderedPanel>,
}

pub struct DashboardService {
    core: CoreDb,
    ontology: Ontology,
    compiler: QueryCompiler,
    row_filters: RowFilters,
    keys: Option<std::sync::Arc<tinker_core::blind_index::BlindIndexKey>>,
}

impl DashboardService {
    /// Sensitive-field lookups in panels (blind index) and `field:key`
    /// selects (automation keys).
    pub fn with_blind_index(mut self, key: tinker_core::blind_index::BlindIndexKey) -> Self {
        self.compiler = self.compiler.with_blind_index(key.clone());
        self.keys = Some(std::sync::Arc::new(key));
        self
    }

    pub fn new(core: CoreDb, ontology: Ontology) -> Self {
        let compiler = QueryCompiler::new(ontology.clone());
        let row_filters = RowFilters::new(core.clone());
        Self {
            core,
            ontology,
            compiler,
            keys: None,
            row_filters,
        }
    }

    /// The caller's role in this organization, from their membership row.
    /// `None` (no membership) fails closed at the call sites that need a
    /// role — dashboards never render for role-less actors.
    pub async fn actor_role(&self, ctx: &TenantContext) -> Result<Option<String>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String,)> =
            sqlx::query_as("SELECT role FROM memberships WHERE actor_id=$1 AND organization_id=$2")
                .bind(ctx.actor_id)
                .bind(ctx.organization_id.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(row.map(|(r,)| r))
    }

    /// Load the field projection for `role` over a query's base object
    /// plus its one-level relation targets — the full set of objects the
    /// compiler can touch. Mirrors `tinker_live::FieldGrants`
    /// semantics against the same `field_grants` table (read-only here).
    async fn load_projection(
        &self,
        ctx: &TenantContext,
        role: &str,
        object_id: Uuid,
    ) -> Result<FieldProjection> {
        let base = self.ontology.describe_object(ctx, object_id).await?;
        let mut ids = vec![object_id];
        for f in &base.fields {
            if f.field_type == "relation" {
                if let Some(t) = f.relation_target_id {
                    if !ids.contains(&t) {
                        ids.push(t);
                    }
                }
            }
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT object_id, field_api_name FROM field_grants
             WHERE organization_id=$1 AND role=$2 AND object_id = ANY($3)",
        )
        .bind(ctx.organization_id.0)
        .bind(role)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let mut map: HashMap<Uuid, HashSet<String>> = HashMap::new();
        for (oid, field) in rows {
            if field == DENY_ALL_FIELDS {
                map.entry(oid).or_default();
            } else {
                map.entry(oid).or_default().insert(field);
            }
        }
        // An object with grant rows but zero listed fields is still a
        // projection (sees nothing); seed the entry so it isn't treated
        // as unrestricted.
        let with_rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT DISTINCT object_id FROM field_grants
             WHERE organization_id=$1 AND role=$2 AND object_id = ANY($3)",
        )
        .bind(ctx.organization_id.0)
        .bind(role)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        for (oid,) in with_rows {
            map.entry(oid).or_default();
        }
        Ok(FieldProjection::allowlist(map))
    }

    /// Validate the panel list shape (ids, geometry, caps) and compile
    /// every panel's saved query under the author's own policy and
    /// projection. Anything that would not render for the author fails
    /// the save here — never at render time.
    async fn validate_panels(
        &self,
        ctx: &TenantContext,
        role: &str,
        panels: &[PanelDef],
    ) -> Result<()> {
        if panels.len() > MAX_PANELS {
            return Err(TinkerError::Validation(format!(
                "too many panels: {} (max {MAX_PANELS})",
                panels.len()
            )));
        }
        let mut seen = HashSet::new();
        for p in panels {
            if p.id.is_empty() || p.id.len() > MAX_PANEL_ID_LEN {
                return Err(TinkerError::Validation("bad panel id".into()));
            }
            if !seen.insert(p.id.as_str()) {
                return Err(TinkerError::Validation(format!(
                    "duplicate panel id: {}",
                    p.id
                )));
            }
            if p.w == 0 || p.h == 0 || p.w > GRID_COLUMNS || p.x + p.w > GRID_COLUMNS {
                return Err(TinkerError::Validation(format!(
                    "panel {} has invalid grid geometry",
                    p.id
                )));
            }
            if p.y > MAX_GRID_Y {
                return Err(TinkerError::Validation(format!(
                    "panel {} is placed too far down",
                    p.id
                )));
            }
            // The save-time compile: unknown objects/fields, hidden
            // fields, and bad operators fail here, under the author's
            // own permissions. Policy/projection load failures are part
            // of validation too (e.g. a foreign object id fails the
            // tenant-scoped describe) — the save reports them as an
            // invalid panel query, never a raw lookup error.
            let policy = self
                .row_filters
                .load_policy(ctx, p.query.from, role)
                .await
                .map_err(|e| {
                    TinkerError::Validation(format!("panel {} query invalid: {e}", p.id))
                })?;
            let projection = self
                .load_projection(ctx, role, p.query.from)
                .await
                .map_err(|e| {
                    TinkerError::Validation(format!("panel {} query invalid: {e}", p.id))
                })?;
            self.compiler
                .compile_with_policy(ctx, &p.query, &projection, &policy)
                .await
                .map_err(|e| {
                    TinkerError::Validation(format!("panel {} query invalid: {e}", p.id))
                })?;
        }
        Ok(())
    }

    fn validate_input(input: &DashboardInput) -> Result<(String, String)> {
        let name = input.name.trim();
        if name.is_empty() || name.len() > 200 {
            return Err(TinkerError::Validation("bad dashboard name".into()));
        }
        let description = input.description.as_deref().unwrap_or("").trim();
        if description.len() > 2000 {
            return Err(TinkerError::Validation(
                "dashboard description too long".into(),
            ));
        }
        Ok((name.to_string(), description.to_string()))
    }

    fn decode_row(row: &sqlx::postgres::PgRow, id: Uuid) -> Result<Dashboard> {
        use sqlx::Row;
        let layout: serde_json::Value = row.try_get("layout").map_err(TinkerError::Db)?;
        let panels: Vec<PanelDef> = serde_json::from_value(layout).map_err(|e| {
            TinkerError::Internal(format!("corrupt dashboard layout for {id}: {e}"))
        })?;
        Ok(Dashboard {
            id,
            organization_id: row.try_get("organization_id").map_err(TinkerError::Db)?,
            name: row.try_get("name").map_err(TinkerError::Db)?,
            description: row.try_get("description").map_err(TinkerError::Db)?,
            panels,
            created_by: row.try_get("created_by").map_err(TinkerError::Db)?,
            created_at: row.try_get("created_at").map_err(TinkerError::Db)?,
            updated_at: row.try_get("updated_at").map_err(TinkerError::Db)?,
        })
    }

    /// Create a dashboard. The author's membership role validates every
    /// panel query at save time; role-less actors fail closed.
    pub async fn create(&self, ctx: &TenantContext, input: DashboardInput) -> Result<Dashboard> {
        let role = self
            .actor_role(ctx)
            .await?
            .ok_or_else(|| TinkerError::Forbidden("no membership in organization".into()))?;
        let (name, description) = Self::validate_input(&input)?;
        self.validate_panels(ctx, &role, &input.panels).await?;
        let layout = serde_json::to_value(&input.panels).map_err(TinkerError::Serde)?;
        let id = Uuid::now_v7();
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO dashboards (id, organization_id, name, description, layout, created_by)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(&name)
        .bind(&description)
        .bind(&layout)
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let row = sqlx::query(
            "SELECT id, organization_id, name, description, layout, created_by, created_at, updated_at
             FROM dashboards WHERE id=$1 AND organization_id=$2",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Self::decode_row(&row, id)
    }

    /// Fetch one dashboard. A foreign-org id returns NotFound — never an
    /// existence oracle (the org predicate is part of the lookup).
    pub async fn get(&self, ctx: &TenantContext, id: Uuid) -> Result<Dashboard> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row = sqlx::query(
            "SELECT id, organization_id, name, description, layout, created_by, created_at, updated_at
             FROM dashboards WHERE id=$1 AND organization_id=$2",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        match row {
            Some(r) => Self::decode_row(&r, id),
            None => Err(TinkerError::NotFound("dashboard".into())),
        }
    }

    pub async fn list(&self, ctx: &TenantContext) -> Result<Vec<DashboardSummary>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows = sqlx::query(
            "SELECT id, organization_id, name, description, layout, updated_at
             FROM dashboards WHERE organization_id=$1 ORDER BY updated_at DESC",
        )
        .bind(ctx.organization_id.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            use sqlx::Row;
            let id: Uuid = r.try_get("id").map_err(TinkerError::Db)?;
            let layout: serde_json::Value = r.try_get("layout").map_err(TinkerError::Db)?;
            let panels: Vec<PanelDef> = serde_json::from_value(layout).map_err(|e| {
                TinkerError::Internal(format!("corrupt dashboard layout for {id}: {e}"))
            })?;
            out.push(DashboardSummary {
                id,
                organization_id: r.try_get("organization_id").map_err(TinkerError::Db)?,
                name: r.try_get("name").map_err(TinkerError::Db)?,
                description: r.try_get("description").map_err(TinkerError::Db)?,
                panel_count: panels.len(),
                updated_at: r.try_get("updated_at").map_err(TinkerError::Db)?,
            });
        }
        Ok(out)
    }

    /// Replace a dashboard's name/description/panels. Panels re-validate
    /// under the author's current permissions, like create.
    pub async fn update(
        &self,
        ctx: &TenantContext,
        id: Uuid,
        input: DashboardInput,
    ) -> Result<Dashboard> {
        let role = self
            .actor_role(ctx)
            .await?
            .ok_or_else(|| TinkerError::Forbidden("no membership in organization".into()))?;
        let (name, description) = Self::validate_input(&input)?;
        self.validate_panels(ctx, &role, &input.panels).await?;
        let layout = serde_json::to_value(&input.panels).map_err(TinkerError::Serde)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let updated: Option<(DateTime<Utc>,)> = sqlx::query_as(
            "UPDATE dashboards SET name=$1, description=$2, layout=$3, updated_at=now()
             WHERE id=$4 AND organization_id=$5 RETURNING updated_at",
        )
        .bind(&name)
        .bind(&description)
        .bind(&layout)
        .bind(id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        if updated.is_none() {
            return Err(TinkerError::NotFound("dashboard".into()));
        }
        let row = sqlx::query(
            "SELECT id, organization_id, name, description, layout, created_by, created_at, updated_at
             FROM dashboards WHERE id=$1 AND organization_id=$2",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Self::decode_row(&row, id)
    }

    pub async fn delete(&self, ctx: &TenantContext, id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n: u64 = sqlx::query("DELETE FROM dashboards WHERE id=$1 AND organization_id=$2")
            .bind(id)
            .bind(ctx.organization_id.0)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?
            .rows_affected();
        tx.commit().await.map_err(TinkerError::Db)?;
        if n == 0 {
            return Err(TinkerError::NotFound("dashboard".into()));
        }
        Ok(())
    }

    /// Render a dashboard under the VIEWER's permissions. `role` is the
    /// viewer's membership role (resolved by the caller from the trusted
    /// memberships table — never from the request). Each panel compiles
    /// and executes under that role's row policy and field projection;
    /// lifecycle visibility (item 40) applies through the normal compile
    /// path. A panel that fails — at projection, policy, compile, or
    /// execute time — renders as an error card; the dashboard survives.
    pub async fn render(
        &self,
        ctx: &TenantContext,
        role: &str,
        id: Uuid,
    ) -> Result<RenderedDashboard> {
        let dash = self.get(ctx, id).await?;
        let mut panels = Vec::with_capacity(dash.panels.len());
        for panel in &dash.panels {
            panels.push(self.render_panel(ctx, role, panel).await);
        }
        Ok(RenderedDashboard {
            dashboard_id: dash.id,
            name: dash.name,
            panels,
        })
    }

    async fn render_panel(
        &self,
        ctx: &TenantContext,
        role: &str,
        panel: &PanelDef,
    ) -> RenderedPanel {
        let err_panel = |e: TinkerError| RenderedPanel {
            panel_id: panel.id.clone(),
            visualization: panel.visualization,
            object_id: None,
            outcome: PanelOutcome::Error {
                error: sanitize_panel_error(&e),
            },
        };
        let projection = match self.load_projection(ctx, role, panel.query.from).await {
            Ok(p) => p,
            Err(e) => return err_panel(e),
        };
        let policy = match self
            .row_filters
            .load_policy(ctx, panel.query.from, role)
            .await
        {
            Ok(p) => p,
            Err(e) => return err_panel(e),
        };
        let plan = match self
            .compiler
            .compile_with_policy(ctx, &panel.query, &projection, &policy)
            .await
        {
            Ok(p) => p,
            Err(e) => return err_panel(e),
        };
        let object_id = plan.object_id;
        match self.execute_plan(ctx, &plan).await {
            Ok(rows) => RenderedPanel {
                panel_id: panel.id.clone(),
                visualization: panel.visualization,
                object_id: Some(object_id),
                outcome: PanelOutcome::Ok { rows },
            },
            Err(e) => RenderedPanel {
                panel_id: panel.id.clone(),
                visualization: panel.visualization,
                object_id: Some(object_id),
                outcome: err_panel(e).outcome,
            },
        }
    }

    /// Execute a compiled panel plan as `ctx`: tenant transaction,
    /// statement timeout, typed binds, JSON row decoding — the same shape
    /// as direct query execution — plus one `query_audit` row attributed
    /// to the viewing actor.
    async fn execute_plan(
        &self,
        ctx: &TenantContext,
        plan: &CompiledPlan,
    ) -> Result<Vec<serde_json::Value>> {
        let started = std::time::Instant::now();
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(&format!(
            "SET LOCAL statement_timeout = '{QUERY_TIMEOUT_MS}'"
        ))
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let mut q = sqlx::query(&plan.sql);
        for p in &plan.params {
            q = bind_param(q, p);
        }
        let rows = q.fetch_all(&mut *tx).await.map_err(TinkerError::Db)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let mut row = row_to_json(&plan.output_fields, r);
            crate::finish_key_columns(&mut row, self.keys.as_deref());
            out.push(row);
        }
        let ms = started.elapsed().as_millis() as i32;
        let hash = plan_hash(plan);
        sqlx::query(
            "INSERT INTO query_audit
             (organization_id, actor_id, object_id, sql_hash, row_count, duration_ms)
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(plan.object_id)
        .bind(&hash)
        .bind(out.len() as i32)
        .bind(ms)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(out)
    }
}

/// Sanitize a panel failure for the render surface: caller-facing error
/// kinds keep their message; database and internal errors become a
/// generic marker — panel cards must not leak SQL text or internals.
fn sanitize_panel_error(e: &TinkerError) -> String {
    match e {
        TinkerError::NotFound(_)
        | TinkerError::Forbidden(_)
        | TinkerError::Validation(_)
        | TinkerError::Busy(_) => e.to_string(),
        _ => "panel query failed".to_string(),
    }
}

/// Plan identity for `query_audit`: sha256 over the SQL text and the
/// typed binds. Same scheme as the live query executor's plan hash.
fn plan_hash(plan: &CompiledPlan) -> String {
    use tinker_core::Param;
    let mut h = Sha256::new();
    h.update(plan.sql.as_bytes());
    for p in &plan.params {
        match p {
            Param::Text(s) => {
                h.update(b"T");
                h.update(s.as_bytes());
            }
            Param::Int(n) => {
                h.update(b"I");
                h.update(n.to_be_bytes());
            }
            Param::Float(f) => {
                h.update(b"F");
                h.update(f.to_be_bytes());
            }
            Param::Bool(b) => {
                h.update(b"B");
                h.update([*b as u8]);
            }
            Param::Uuid(u) => {
                h.update(b"U");
                h.update(u.as_bytes());
            }
            Param::Date(d) => {
                h.update(b"D");
                h.update(d.format("%Y-%m-%d").to_string().as_bytes());
            }
            Param::Timestamp(t) => {
                h.update(b"T");
                h.update(t.timestamp_nanos_opt().unwrap_or(0).to_be_bytes());
            }
            Param::Json(j) => {
                h.update(b"J");
                h.update(j.to_string().as_bytes());
            }
            Param::Null => {
                h.update(b"N");
            }
        }
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode one result row to a JSON object keyed by the plan's output
/// field names. Same decoding rules as the live query executor
/// (NUMERIC decodes exactly via BigDecimal; everything else falls back
/// through the natural JSON mapping to text).
fn row_to_json(output_fields: &[String], row: &sqlx::postgres::PgRow) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (i, name) in output_fields.iter().enumerate() {
        obj.insert(name.clone(), column_json(row, i));
    }
    if !output_fields.iter().any(|n| n == "__id") {
        obj.insert("__id".to_string(), column_json(row, output_fields.len()));
    }
    serde_json::Value::Object(obj)
}

fn column_json(row: &sqlx::postgres::PgRow, idx: usize) -> serde_json::Value {
    use sqlx::{Column, Row, TypeInfo, ValueRef};
    let type_name = row
        .columns()
        .get(idx)
        .map(|c| c.type_info().name().to_string())
        .unwrap_or_default();
    if type_name == "NUMERIC" {
        if let Ok(v) = row.try_get::<bigdecimal::BigDecimal, _>(idx) {
            let s = v.to_string();
            if let Ok(n) = s.parse::<i64>() {
                return serde_json::json!(n);
            }
            if let Ok(n) = s.parse::<f64>() {
                return serde_json::json!(n);
            }
            return serde_json::Value::String(s);
        }
        return serde_json::Value::Null;
    }
    let raw = row.try_get_raw(idx);
    let Ok(raw) = raw else {
        return serde_json::Value::Null;
    };
    if raw.is_null() {
        return serde_json::Value::Null;
    }
    if let Ok(v) = raw.as_str() {
        return serde_json::Value::String(v.to_string());
    }
    if let Ok(v) = row.try_get::<bool, _>(idx) {
        return serde_json::Value::Bool(v);
    }
    if let Ok(v) = row.try_get::<i32, _>(idx) {
        return serde_json::json!(v);
    }
    if let Ok(v) = row.try_get::<i64, _>(idx) {
        return serde_json::json!(v);
    }
    if let Ok(v) = row.try_get::<f64, _>(idx) {
        return serde_json::json!(v);
    }
    if let Ok(v) = row.try_get::<uuid::Uuid, _>(idx) {
        return serde_json::json!(v.to_string());
    }
    if let Ok(v) = row.try_get::<chrono::DateTime<chrono::Utc>, _>(idx) {
        return serde_json::json!(v.to_rfc3339());
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDate, _>(idx) {
        return serde_json::json!(v.to_string());
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDateTime, _>(idx) {
        return serde_json::json!(v.to_string());
    }
    if let Ok(v) = row.try_get::<Vec<String>, _>(idx) {
        return serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect());
    }
    if let Ok(v) = row.try_get::<serde_json::Value, _>(idx) {
        return v;
    }
    serde_json::Value::Null
}
