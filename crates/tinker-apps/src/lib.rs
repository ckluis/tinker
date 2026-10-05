//! App registry (M1): versioned, immutable app definitions rendered
//! server-side.
//!
//! An app is layout + components + tokens. Content lives in `app_versions`;
//! once a version leaves `draft` the database trigger freezes it.
//! Publishing creates a new version row — history is never rewritten.
//!
//! The five M1 components: `rt-text`, `rt-stat`, `rt-select`, `rt-grid`,
//! `rt-form`. Each has a [`ComponentSpec`] (tag, required props, signals,
//! events) enforced at draft-save time, so a published version always
//! renders.

use askama::Template;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use tinker_core::{OrganizationId, Result, TenantContext, TinkerError};

// ---------------------------------------------------------------------------
// Component registry
// ---------------------------------------------------------------------------

/// Static spec for one component type. Internal shadow-DOM structure may
/// change; public props, events, signals, and patch targets are stable.
#[derive(Debug, Clone)]
pub struct ComponentSpec {
    pub tag: &'static str,
    /// Props that must be present for the component to render.
    pub required_props: &'static [&'static str],
    /// Documented signals the component reads/writes.
    pub signals: &'static [&'static str],
    /// Events the component may emit.
    pub events: &'static [&'static str],
}

pub const RT_TEXT: ComponentSpec = ComponentSpec {
    tag: "rt-text",
    required_props: &["content"],
    signals: &["value"],
    events: &[],
};

pub const RT_STAT: ComponentSpec = ComponentSpec {
    tag: "rt-stat",
    required_props: &["label", "value"],
    signals: &["value"],
    events: &[],
};

pub const RT_SELECT: ComponentSpec = ComponentSpec {
    tag: "rt-select",
    required_props: &["label", "options"],
    signals: &["value"],
    events: &["change"],
};

pub const RT_GRID: ComponentSpec = ComponentSpec {
    tag: "rt-grid",
    required_props: &["columns"],
    signals: &[
        "pageIndex",
        "pageSize",
        "selectedRow",
        "rowCount",
        "loading",
        "error",
    ],
    events: &["rowSelect", "pageChange", "sortChange"],
};

pub const RT_FORM: ComponentSpec = ComponentSpec {
    tag: "rt-form",
    required_props: &["fields"],
    signals: &["values", "errors", "submitting"],
    events: &["submit"],
};

/// The five M1 components.
pub const COMPONENTS: &[ComponentSpec] = &[RT_TEXT, RT_STAT, RT_SELECT, RT_GRID, RT_FORM];

pub fn spec_for(tag: &str) -> Option<&'static ComponentSpec> {
    COMPONENTS.iter().find(|s| s.tag == tag)
}

// ---------------------------------------------------------------------------
// App definition model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GridLayout {
    #[serde(rename = "type")]
    pub layout_type: String,
    pub columns: u32,
    #[serde(rename = "rowHeight")]
    pub row_height: u32,
    pub gap: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellLayout {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBinding {
    pub on: String,
    pub action: String,
    #[serde(default)]
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentInstance {
    pub id: String,
    #[serde(rename = "type")]
    pub component_type: String,
    #[serde(default)]
    pub props: serde_json::Value,
    pub layout: CellLayout,
    #[serde(default)]
    pub events: Vec<EventBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppDefinition {
    pub layout: GridLayout,
    pub components: Vec<ComponentInstance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppTokens {
    #[serde(default)]
    pub brand: String,
    #[serde(default)]
    pub accent: String,
}

/// Event actions the renderer will wire. Closed set: unknown actions fail
/// draft validation instead of rendering dead controls.
const ALLOWED_ACTIONS: &[&str] = &["runQuery", "setSignal", "navigate", "submitForm"];

fn validate_definition(def: &AppDefinition) -> Result<()> {
    if def.layout.columns == 0 || def.layout.columns > 24 {
        return Err(TinkerError::Validation(
            "layout.columns out of range".into(),
        ));
    }
    let mut ids = std::collections::HashSet::new();
    for c in &def.components {
        if !ids.insert(c.id.clone()) {
            return Err(TinkerError::Validation(format!(
                "duplicate component id {}",
                c.id
            )));
        }
        let spec = spec_for(&c.component_type).ok_or_else(|| {
            TinkerError::Validation(format!("unknown component {}", c.component_type))
        })?;
        for req in spec.required_props {
            if c.props.get(req).is_none() {
                return Err(TinkerError::Validation(format!(
                    "component {} missing required prop {}",
                    c.id, req
                )));
            }
        }
        if c.layout.x + c.layout.w > def.layout.columns {
            return Err(TinkerError::Validation(format!(
                "component {} overflows grid columns",
                c.id
            )));
        }
        for e in &c.events {
            if !spec.events.contains(&e.on.as_str()) {
                return Err(TinkerError::Validation(format!(
                    "component {} cannot emit {}",
                    c.id, e.on
                )));
            }
            if !ALLOWED_ACTIONS.contains(&e.action.as_str()) {
                return Err(TinkerError::Validation(format!(
                    "unknown event action {}",
                    e.action
                )));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

async fn tenant_tx(
    pool: &PgPool,
    organization_id: Uuid,
    actor_id: Uuid,
    purpose: &str,
) -> Result<Transaction<'static, Postgres>> {
    let ctx = TenantContext::new(OrganizationId(organization_id), actor_id, purpose);
    let mut tx = pool.begin().await.map_err(TinkerError::Db)?;
    for stmt in ctx.set_local_statements() {
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
    }
    Ok(tx)
}

#[derive(Debug, Clone)]
pub struct AppSummary {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub published_version: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct PublishedApp {
    pub app_id: Uuid,
    pub slug: String,
    pub name: String,
    pub version_number: i32,
    pub definition: AppDefinition,
    pub tokens: AppTokens,
}

pub struct AppRegistry {
    pool: PgPool,
}

impl AppRegistry {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create_app(
        &self,
        organization_id: Uuid,
        workspace_id: Uuid,
        actor_id: Uuid,
        slug: &str,
        name: &str,
    ) -> Result<Uuid> {
        let mut tx = tenant_tx(&self.pool, organization_id, actor_id, "app.create").await?;
        let row = sqlx::query!(
            r#"INSERT INTO apps (organization_id, workspace_id, slug, name, created_by)
               VALUES ($1, $2, $3, $4, $5) RETURNING id"#,
            organization_id,
            workspace_id,
            slug,
            name,
            actor_id,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(row.id)
    }

    /// Save a new draft version. Validation runs here so published
    /// versions always render.
    pub async fn save_draft(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        app_id: Uuid,
        definition: &AppDefinition,
        tokens: &AppTokens,
    ) -> Result<i32> {
        validate_definition(definition)?;
        let def_json =
            serde_json::to_value(definition).map_err(|e| TinkerError::Validation(e.to_string()))?;
        let tok_json =
            serde_json::to_value(tokens).map_err(|e| TinkerError::Validation(e.to_string()))?;
        let mut tx = tenant_tx(&self.pool, organization_id, actor_id, "app.draft").await?;
        let max: Option<i32> = sqlx::query!(
            "SELECT MAX(version_number) AS max FROM app_versions WHERE app_id = $1",
            app_id
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .max;
        let next = max.unwrap_or(0) + 1;
        sqlx::query!(
            r#"INSERT INTO app_versions
               (organization_id, app_id, version_number, status, definition, tokens, created_by)
               VALUES ($1, $2, $3, 'draft', $4, $5, $6)"#,
            organization_id,
            app_id,
            next,
            def_json,
            tok_json,
            actor_id,
        )
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(next)
    }

    /// Publish a draft version. The old published version is archived in
    /// the same transaction; the new row becomes the one published version.
    pub async fn publish(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        app_id: Uuid,
        version_number: i32,
    ) -> Result<()> {
        let mut tx = tenant_tx(&self.pool, organization_id, actor_id, "app.publish").await?;
        let row = sqlx::query!(
            "SELECT id FROM app_versions WHERE app_id = $1 AND version_number = $2",
            app_id,
            version_number
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound("app version".into()))?;
        sqlx::query("SELECT publish_app_version($1)")
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }

    pub async fn get_published(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        app_slug: &str,
    ) -> Result<Option<PublishedApp>> {
        let mut tx = tenant_tx(&self.pool, organization_id, actor_id, "app.render").await?;
        let row = sqlx::query!(
            r#"SELECT a.id AS app_id, a.slug, a.name, v.version_number,
                      v.definition, v.tokens
               FROM apps a
               JOIN app_versions v ON v.app_id = a.id AND v.status = 'published'
               WHERE a.slug = $1"#,
            app_slug
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        let Some(row) = row else { return Ok(None) };
        Ok(Some(PublishedApp {
            app_id: row.app_id,
            slug: row.slug,
            name: row.name,
            version_number: row.version_number,
            definition: serde_json::from_value(row.definition)
                .map_err(|e| TinkerError::Internal(e.to_string()))?,
            tokens: serde_json::from_value(row.tokens)
                .map_err(|e| TinkerError::Internal(e.to_string()))?,
        }))
    }

    pub async fn list_apps(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
    ) -> Result<Vec<AppSummary>> {
        let mut tx = tenant_tx(&self.pool, organization_id, actor_id, "app.list").await?;
        let rows = sqlx::query!(
            r#"SELECT a.id, a.slug, a.name,
                      (SELECT v.version_number FROM app_versions v
                       WHERE v.app_id = a.id AND v.status = 'published') AS published_version
               FROM apps a ORDER BY a.name"#,
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(rows
            .into_iter()
            .map(|r| AppSummary {
                id: r.id,
                slug: r.slug,
                name: r.name,
                published_version: r.published_version,
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// One component, pre-rendered to its inner HTML by the server. The custom
/// element upgrades it client-side; without JS the server HTML still reads.
struct RenderedComponent {
    id: String,
    tag: String,
    layout_style: String,
    inner_html: String,
    events_json: String,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn render_component(c: &ComponentInstance) -> RenderedComponent {
    let inner_html = match c.component_type.as_str() {
        "rt-text" => {
            let content = c
                .props
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            format!("<p>{}</p>", escape_html(content))
        }
        "rt-stat" => {
            let label = c.props.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let value = c.props.get("value").and_then(|v| v.as_str()).unwrap_or("");
            format!(
                "<div class=\"stat-label\">{}</div><div class=\"stat-value\">{}</div>",
                escape_html(label),
                escape_html(value)
            )
        }
        "rt-select" => {
            let label = c.props.get("label").and_then(|v| v.as_str()).unwrap_or("");
            let options = c
                .props
                .get("options")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut opts = String::new();
            for o in options {
                let v = o.as_str().unwrap_or("");
                opts.push_str(&format!("<option>{}</option>", escape_html(v)));
            }
            format!(
                "<label>{}<select data-signal=\"value\">{}</select></label>",
                escape_html(label),
                opts
            )
        }
        "rt-grid" => {
            let columns = c
                .props
                .get("columns")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut head = String::new();
            // data-field carries the row JSON key per column for the
            // client-side connector; defaults to the label's slug.
            let mut fields = Vec::new();
            for col in &columns {
                let label = col.get("label").and_then(|v| v.as_str()).unwrap_or("");
                let field = col
                    .get("field")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| label.to_string());
                fields.push(field);
                head.push_str(&format!("<th>{}</th>", escape_html(label)));
            }
            let fields_attr = escape_html(&serde_json::to_string(&fields).unwrap_or_default());
            // M2: an optional `query` prop (a QueryIntent) turns the grid
            // live. The server renders the shell; the client POSTs the
            // intent to /api/query and subscribes to /api/sse.
            let query_attr = c
                .props
                .get("query")
                .map(|q| {
                    format!(
                        " data-query=\"{}\"",
                        escape_html(&serde_json::to_string(q).unwrap_or_default())
                    )
                })
                .unwrap_or_default();
            format!(
                "<table{query_attr}><thead><tr>{head}</tr></thead>\
                 <tbody data-patch-target=\"tbody\" data-fields=\"{fields_attr}\">\
                 <tr><td colspan=\"{colspan}\">Loading…</td></tr></tbody></table>",
                query_attr = query_attr,
                head = head,
                fields_attr = fields_attr,
                colspan = columns.len().max(1),
            )
        }
        "rt-form" => {
            let fields = c
                .props
                .get("fields")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut inputs = String::new();
            for f in fields {
                let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("field");
                let label = f.get("label").and_then(|v| v.as_str()).unwrap_or(name);
                let ftype = f.get("type").and_then(|v| v.as_str()).unwrap_or("text");
                inputs.push_str(&format!(
                    "<label>{}<input name=\"{}\" type=\"{}\" data-signal=\"values.{}\" /></label>",
                    escape_html(label),
                    escape_html(name),
                    escape_html(ftype),
                    escape_html(name)
                ));
            }
            format!(
                "<form data-on:submit=\"@post('/api/forms/{}')\">{}\
                 <button type=\"submit\">Submit</button></form>",
                escape_html(&c.id),
                inputs
            )
        }
        _ => format!(
            "<!-- unknown component {} -->",
            escape_html(&c.component_type)
        ),
    };
    let layout_style = format!(
        "grid-column: {} / span {}; grid-row: {} / span {}",
        c.layout.x + 1,
        c.layout.w,
        c.layout.y + 1,
        c.layout.h
    );
    RenderedComponent {
        id: c.id.clone(),
        tag: c.component_type.clone(),
        layout_style,
        inner_html,
        events_json: serde_json::to_string(&c.events).unwrap_or_else(|_| "[]".into()),
    }
}

#[derive(Template)]
#[template(path = "app.html")]
struct AppTemplate {
    app_name: String,
    org_slug: String,
    brand: String,
    accent: String,
    version_number: i32,
    grid_style: String,
    components: Vec<RenderedComponentView>,
}

struct RenderedComponentView {
    id: String,
    tag: String,
    layout_style: String,
    inner_html: String,
    events_json: String,
}

/// Render a published app to a full HTML page. Pure function of the
/// version — the same version bytes always produce the same page.
pub fn render_app(app: &PublishedApp, org_slug: &str, host_name: &str) -> Result<String> {
    let _ = host_name;
    let components = app
        .definition
        .components
        .iter()
        .map(render_component)
        .map(|r| RenderedComponentView {
            id: r.id,
            tag: r.tag,
            layout_style: r.layout_style,
            inner_html: r.inner_html,
            events_json: r.events_json,
        })
        .collect();
    let layout = &app.definition.layout;
    let tpl = AppTemplate {
        app_name: app.name.clone(),
        org_slug: org_slug.to_string(),
        brand: if app.tokens.brand.is_empty() {
            "Tinker".into()
        } else {
            app.tokens.brand.clone()
        },
        accent: if app.tokens.accent.is_empty() {
            "#2563eb".into()
        } else {
            app.tokens.accent.clone()
        },
        version_number: app.version_number,
        // The grid honors the version's own layout — never a hardcoded
        // column count.
        grid_style: format!(
            "grid-template-columns: repeat({}, 1fr); grid-auto-rows: {}px; gap: {}px;",
            layout.columns, layout.row_height, layout.gap
        ),
        components,
    };
    tpl.render()
        .map_err(|e| TinkerError::Internal(format!("template render: {e}")))
}
