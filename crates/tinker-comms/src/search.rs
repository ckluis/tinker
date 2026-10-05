//! Permission-aware message search (item 32, M5 launch scope).
//!
//! Messages are indexed into the shared [`tinker_search::SearchBackend`]
//! contract on post (see [`crate::write`]); this module is the read path.
//!
//! Security posture:
//! - Tenant scope decides whether a record exists. The backend scopes
//!   every match/rank statement to the caller's organization and RLS on
//!   `search_index` is the fail-closed backstop, so org B can never see
//!   org A's hits.
//! - Row visibility: the caller's row policy (item 38, C2) is compiled
//!   into the match/rank statement — policy before ranking — so hidden
//!   rows never influence rank, snippets, or counts. A hit whose message
//!   row is not visible in the caller's tenant (stale index row, or
//!   anything that slipped the tenant predicate) is additionally dropped,
//!   never surfaced.
//! - Field visibility: the body snippet follows the caller's field
//!   projection over `comm_message` — exactly the rule the thread card
//!   uses. A caller whose projection hides `body` gets the [`MASKED`]
//!   sentinel, never the raw text.

use std::collections::HashMap;
use std::sync::Arc;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_live::FieldGrants;
use tinker_ontology::Ontology;
use tinker_query::RowFilters;
use tinker_search::{SearchBackend, SearchPlan};
use uuid::Uuid;

use crate::install::InstalledComms;
use crate::unfurl::MASKED;

/// One message hit from [`MessageSearch::search_messages`].
#[derive(Debug, Clone)]
pub struct MessageSearchHit {
    pub message_id: Uuid,
    pub thread_id: Uuid,
    /// ts_headline fragment when the caller may read the body;
    /// [`MASKED`] when their field projection hides it.
    pub snippet: String,
    pub rank: f32,
}

/// The indexed text for one message: the body plus the thread subject as
/// cheap context (item 32 brief: "plus thread/subject context if cheap").
/// Both are non-PII storage classes (see the SECURITY note in
/// [`crate::write`]); the subject is already visible to anyone who can
/// read the thread.
pub(crate) fn index_text(body: &str, subject: &str) -> String {
    let subject = subject.trim();
    if subject.is_empty() {
        body.to_string()
    } else {
        format!("{body}\nThread: {subject}")
    }
}

pub struct MessageSearch {
    core: CoreDb,
    ontology: Ontology,
    backend: Arc<dyn SearchBackend>,
    grants: FieldGrants,
    row_filters: RowFilters,
}

impl MessageSearch {
    pub fn new(core: CoreDb, ontology: Ontology, backend: Arc<dyn SearchBackend>) -> Self {
        let grants = FieldGrants::new(core.clone());
        let row_filters = RowFilters::new(core.clone());
        Self {
            core,
            ontology,
            backend,
            grants,
            row_filters,
        }
    }

    /// Search the caller's tenant for messages matching `query`.
    /// `role` is the caller's membership role in the tenant org and drives
    /// snippet masking. Never surfaces a message the caller cannot read.
    pub async fn search_messages(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        role: &str,
        query: &str,
        limit: u32,
    ) -> Result<Vec<MessageSearchHit>> {
        if query.trim().is_empty() {
            return Err(TinkerError::Validation("empty search query".into()));
        }
        let message_obj = installed.objects[crate::install::MESSAGE_SLUG];
        // The caller's field projection decides snippet visibility — the
        // same rule the thread card applies to the body field.
        let projection = self
            .grants
            .load_projection(ctx, role, &[message_obj])
            .await?;
        let body_visible = projection.allows(message_obj, "body");
        // C2 row policy (item 38): the role's filters on comm_message are
        // compiled into the SAME statement that matches and ranks, so
        // hidden rows never influence rank, snippets, or counts. The
        // post-rank visibility check below stays as defense-in-depth for
        // stale index rows.
        let policy = self.row_filters.load_policy(ctx, message_obj, role).await?;
        let message_desc = self.ontology.describe_object(ctx, message_obj).await?;
        let row_policies = policy
            .compile_for_search(ctx, &message_desc)?
            .into_iter()
            .collect::<Vec<_>>();
        let page = self
            .backend
            .search(
                ctx,
                &SearchPlan {
                    text_query: query.to_string(),
                    object_id: Some(message_obj),
                    limit,
                    row_policies,
                },
            )
            .await?;
        if page.hits.is_empty() {
            return Ok(Vec::new());
        }
        // Row visibility, defense in depth: drop any hit whose message row
        // is not readable in this tenant (stale index rows included), and
        // resolve each surviving hit's thread in one batched query.
        let ids: Vec<Uuid> = page.hits.iter().map(|h| h.record_id).collect();
        let threads = self
            .message_threads(ctx, installed, message_obj, &ids)
            .await?;
        Ok(page
            .hits
            .into_iter()
            .filter_map(|h| {
                threads.get(&h.record_id).map(|thread_id| MessageSearchHit {
                    message_id: h.record_id,
                    thread_id: *thread_id,
                    snippet: if body_visible {
                        h.snippet
                    } else {
                        MASKED.into()
                    },
                    rank: h.rank,
                })
            })
            .collect())
    }

    /// (message_id -> thread_id) for the given ids, tenant-scoped. A hit
    /// id with no visible message row is absent from the map, and the
    /// caller drops it.
    async fn message_threads(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        message_obj: Uuid,
        ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Uuid>> {
        let desc = self.ontology.describe_object(ctx, message_obj).await?;
        let thread_col = desc
            .fields
            .iter()
            .find(|f| f.api_name == "thread")
            .map(|f| f.physical_column.clone())
            .ok_or_else(|| TinkerError::Internal("comm_message missing thread field".into()))?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(&format!(
            "SELECT id, \"{thread_col}\" FROM {} WHERE organization_id=$1 AND id = ANY($2)",
            installed.message_table
        ))
        .bind(ctx.organization_id.0)
        .bind(ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::index_text;

    #[test]
    fn index_text_combines_body_and_subject() {
        assert_eq!(
            index_text("hello", "Launch plan"),
            "hello\nThread: Launch plan"
        );
        assert_eq!(index_text("hello", ""), "hello");
        assert_eq!(index_text("hello", "   "), "hello");
    }
}
