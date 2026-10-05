//! Actor-parameterized unfurl: one card template, per-reader truth.
//!
//! `render_thread_card` takes the thread's organization tenant context, the
//! viewer's actor id + role, and returns a [`ThreadCard`] where every field
//! value has already passed the semantic access layer:
//!
//! - Tenant scope (RLS) decides whether the thread/messages exist at all.
//! - [`FieldGrants`][tinker_live::FieldGrants] decide which fields the
//!   viewer's role may see; anything else renders as [`MASKED`]. There is
//!   no role branch in the template — the projection made the decision.
//! - Message authors render as their display name only with a live
//!   identity disclosure (per-thread opt-in or org-wide override);
//!   otherwise a stable handle. Identity disclosure is an act, versioned
//!   and revocable.
//! - `tinker:<slug>:<uuid>` refs inside bodies unfurl through the same
//!   tenant + grant path, so a notification or message that references PII
//!   masks it for ungranted actors.

use std::collections::HashMap;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_live::FieldGrants;
use tinker_ontology::Ontology;
use tinker_query::FieldProjection;
use uuid::Uuid;

use crate::disclose::is_disclosed;
use crate::install::InstalledComms;

/// Rendered in place of any value the viewer's grants hide.
pub const MASKED: &str = "▪▪▪";

#[derive(Debug, Clone, serde::Serialize)]
pub struct UnfurledRef {
    pub slug: String,
    pub id: Uuid,
    pub fields: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CardMessage {
    pub id: Uuid,
    pub author: String,
    pub author_actor_id: String,
    pub body: serde_json::Value,
    pub created_at: String,
    pub unfurls: Vec<UnfurledRef>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ThreadCard {
    pub thread_id: Uuid,
    pub subject: serde_json::Value,
    pub status: serde_json::Value,
    pub messages: Vec<CardMessage>,
}

pub struct UnfurlRenderer {
    core: CoreDb,
    ontology: Ontology,
    grants: FieldGrants,
}

impl Clone for UnfurlRenderer {
    fn clone(&self) -> Self {
        Self::new(self.core.clone(), self.ontology.clone())
    }
}

impl UnfurlRenderer {
    pub fn new(core: CoreDb, ontology: Ontology) -> Self {
        let grants = FieldGrants::new(core.clone());
        Self {
            core,
            ontology,
            grants,
        }
    }

    /// Render the thread card for one viewer. `ctx` is the THREAD's
    /// organization tenant context (cross-plane callers resolve it after
    /// their grant check); `viewer_role` drives field masking.
    pub async fn render_thread_card(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        thread_id: Uuid,
        viewer_actor_id: Uuid,
        viewer_role: &str,
    ) -> Result<ThreadCard> {
        let thread_obj = installed.objects[crate::install::THREAD_SLUG];
        let message_obj = installed.objects[crate::install::MESSAGE_SLUG];
        let projection = self
            .grants
            .load_projection(ctx, viewer_role, &[thread_obj, message_obj])
            .await?;

        let thread = self
            .read_row(ctx, &installed.thread_table, thread_obj, thread_id)
            .await?
            .ok_or_else(|| TinkerError::NotFound(format!("thread {thread_id}")))?;
        let subject = visible(&projection, thread_obj, &thread, "subject");
        let status = visible(&projection, thread_obj, &thread, "status");

        let message_ids = self
            .message_ids(ctx, &installed.message_table, message_obj, thread_id)
            .await?;
        let mut messages = Vec::with_capacity(message_ids.len());
        for mid in message_ids {
            let row = self
                .read_row(ctx, &installed.message_table, message_obj, mid)
                .await?
                .ok_or_else(|| TinkerError::Internal(format!("message {mid} vanished")))?;
            let body = visible(&projection, message_obj, &row, "body");
            let author_actor: String = row
                .get("author_actor_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let created_at = row
                .get("__created_at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let author = self
                .author_display(ctx, thread_id, &author_actor, viewer_actor_id)
                .await?;
            let mut unfurls = Vec::new();
            // Extract refs from the RAW body, not the masked one: a viewer
            // who cannot read the body still sees the references it
            // contains. Each unfurl's fields are governed by the referenced
            // object's own field projection — never the message's — so the
            // masked body text itself never leaks through the unfurl.
            let raw_text: &str = row.get("body").and_then(|v| v.as_str()).unwrap_or("");
            for (slug, rid) in extract_refs(raw_text) {
                if let Some(u) = self.unfurl_ref(ctx, viewer_role, &slug, rid).await? {
                    unfurls.push(u);
                }
            }
            messages.push(CardMessage {
                id: mid,
                author,
                author_actor_id: author_actor,
                body,
                created_at,
                unfurls,
            });
        }

        Ok(ThreadCard {
            thread_id,
            subject,
            status,
            messages,
        })
    }

    /// Display name only with a live disclosure; otherwise a stable
    /// handle. The viewer always sees their own name.
    async fn author_display(
        &self,
        ctx: &TenantContext,
        thread_id: Uuid,
        author_actor_id: &str,
        viewer_actor_id: Uuid,
    ) -> Result<String> {
        let author_uuid = author_actor_id.parse::<Uuid>().unwrap_or(Uuid::nil());
        if author_uuid == viewer_actor_id {
            return self.display_name(ctx, author_uuid).await;
        }
        if is_disclosed(&self.core, ctx, Some(thread_id), author_uuid).await? {
            Ok(self.display_name(ctx, author_uuid).await?)
        } else {
            Ok(stable_handle(author_uuid))
        }
    }

    async fn display_name(&self, ctx: &TenantContext, actor_id: Uuid) -> Result<String> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let name: Option<String> = sqlx::query_scalar(
            "SELECT display_name FROM actors WHERE id=$1 AND organization_id=$2",
        )
        .bind(actor_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(name.unwrap_or_else(|| stable_handle(actor_id)))
    }

    async fn message_ids(
        &self,
        ctx: &TenantContext,
        table: &str,
        message_obj: Uuid,
        thread_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        let desc = self.ontology.describe_object(ctx, message_obj).await?;
        let thread_col = desc
            .fields
            .iter()
            .find(|f| f.api_name == "thread")
            .map(|f| f.physical_column.clone())
            .ok_or_else(|| TinkerError::Internal("message.thread column missing".into()))?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid,)> = sqlx::query_as(&format!(
            "SELECT id FROM {table} WHERE organization_id=$1 AND \"{thread_col}\"=$2 ORDER BY created_at, id"
        ))
        .bind(ctx.organization_id.0)
        .bind(thread_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().map(|(id,)| id).collect())
    }

    /// Read one row as api_name -> JSON value, tenant-scoped. Returns None
    /// when the row is not visible (sibling id -> no oracle).
    async fn read_row(
        &self,
        ctx: &TenantContext,
        table: &str,
        object_id: Uuid,
        id: Uuid,
    ) -> Result<Option<HashMap<String, serde_json::Value>>> {
        let desc = self.ontology.describe_object(ctx, object_id).await?;
        let mut select = vec![
            "\"id\"".to_string(),
            "\"created_at\"::text AS \"__created_at\"".to_string(),
        ];
        for f in &desc.fields {
            let col = &f.physical_column;
            if f.field_type == "richtext" {
                select.push(format!("\"{col}\" AS \"{}\"", f.api_name));
            } else {
                select.push(format!("\"{col}\"::text AS \"{}\"", f.api_name));
            }
        }
        let sql = format!(
            "SELECT {} FROM {table} WHERE organization_id=$1 AND id=$2",
            select.join(", ")
        );
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<sqlx::postgres::PgRow> = sqlx::query(&sql)
            .bind(ctx.organization_id.0)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        let Some(row) = row else { return Ok(None) };
        let mut out = HashMap::new();
        {
            use sqlx::Row;
            for f in &desc.fields {
                let v: Option<serde_json::Value> = if f.field_type == "richtext" {
                    row.try_get::<Option<serde_json::Value>, _>(f.api_name.as_str())
                        .unwrap_or(None)
                } else {
                    row.try_get::<Option<String>, _>(f.api_name.as_str())
                        .unwrap_or(None)
                        .map(serde_json::Value::String)
                };
                out.insert(f.api_name.clone(), v.unwrap_or(serde_json::Value::Null));
            }
            let created: Option<String> = row.try_get("__created_at").unwrap_or(None);
            out.insert(
                "__created_at".into(),
                created
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
            );
        }
        Ok(Some(out))
    }

    /// Unfurl one `tinker:<slug>:<uuid>` ref through the viewer's grants
    /// for THAT object. Unknown slugs or invisible records resolve to
    /// None (no oracle).
    async fn unfurl_ref(
        &self,
        ctx: &TenantContext,
        viewer_role: &str,
        slug: &str,
        record_id: Uuid,
    ) -> Result<Option<UnfurledRef>> {
        if !valid_ref_slug(slug) {
            return Ok(None);
        }
        let desc = match self.ontology.describe_object_by_slug(ctx, slug).await {
            Ok(d) => d,
            Err(_) => return Ok(None), // sibling/unknown slug: no oracle
        };
        // The ref's own object grants govern its fields — not the
        // message's projection.
        let projection = self
            .grants
            .load_projection(ctx, viewer_role, &[desc.id])
            .await?;
        let table = format!("data.{slug}");
        let Some(row) = self.read_row(ctx, &table, desc.id, record_id).await? else {
            return Ok(None);
        };
        let mut fields = HashMap::new();
        for f in &desc.fields {
            // Denied fields are omitted from the unfurl entirely (not
            // masked): a compact card shows only what the reader may see.
            if projection.allows(desc.id, &f.api_name) {
                fields.insert(
                    f.api_name.clone(),
                    visible(&projection, desc.id, &row, &f.api_name),
                );
            }
        }
        Ok(Some(UnfurledRef {
            slug: slug.to_string(),
            id: record_id,
            fields,
        }))
    }
}

fn visible(
    projection: &FieldProjection,
    object_id: Uuid,
    row: &HashMap<String, serde_json::Value>,
    api_name: &str,
) -> serde_json::Value {
    if projection.allows(object_id, api_name) {
        row.get(api_name)
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    } else {
        serde_json::Value::String(MASKED.into())
    }
}

/// A stable, non-identifying handle for an undisclosed participant.
pub fn stable_handle(actor_id: Uuid) -> String {
    format!("actor-{}", &actor_id.simple().to_string()[..8])
}

/// `tinker:<slug>:<uuid>` — the catalog object-reference syntax from the
/// PRD. Malformed refs are ignored, never rendered.
pub fn extract_refs(body: &str) -> Vec<(String, Uuid)> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find("tinker:") {
        let after = &rest[start + 7..];
        let mut parts = after.splitn(3, ':');
        let slug = parts.next().unwrap_or("");
        let id_part = parts.next().unwrap_or("");
        let id_str: String = id_part
            .chars()
            .take_while(|c| c.is_ascii_hexdigit() || *c == '-')
            .collect();
        if valid_ref_slug(slug) {
            if let Ok(id) = id_str.parse::<Uuid>() {
                // Avoid duplicates within one body.
                if !out.iter().any(|(s, i)| s == slug && i == &id) {
                    out.push((slug.to_string(), id));
                }
            }
        }
        rest = after;
    }
    out
}

fn valid_ref_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}
