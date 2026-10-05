//! Typed write path for communications objects.
//!
//! Chat is a view over the messages dataset: every post goes through here,
//! is tenant-scoped by RLS, and publishes an id-only [`Signal`][tinker_live]
//! so SSE subscribers refetch through their own grants. (The governed
//! mutation connector is still M4-backlog; this writer is the narrow,
//! audited mutation surface for comms.)

use std::collections::HashMap;
use std::sync::Arc;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_live::SignalBus;
use tinker_ontology::Ontology;
use tinker_search::{IndexChange, SearchBackend};
use uuid::Uuid;

use crate::install::InstalledComms;
use crate::search::index_text;

/// api_name -> physical column for one object, resolved once per writer.
#[derive(Debug, Clone)]
pub struct ColumnMap {
    pub table: String,
    pub cols: HashMap<String, String>,
    pub types: HashMap<String, String>,
}

impl ColumnMap {
    fn col(&self, api_name: &str) -> Result<&str> {
        self.cols
            .get(api_name)
            .map(String::as_str)
            .ok_or_else(|| TinkerError::Internal(format!("comms object missing field {api_name}")))
    }
}

use crate::mentions::MentionNotifier;

#[derive(Clone)]
pub struct CommsWriter {
    core: CoreDb,
    ontology: Ontology,
    signals: SignalBus,
    mention_notify: Option<MentionNotifier>,
    search_backend: Option<Arc<dyn SearchBackend>>,
}

impl CommsWriter {
    pub fn new(core: CoreDb, ontology: Ontology, signals: SignalBus) -> Self {
        Self {
            core,
            ontology,
            signals,
            mention_notify: None,
            search_backend: None,
        }
    }

    /// Enable @-mention extraction + notification routing on
    /// [`CommsWriter::post_message`]. Without this, posts store the body
    /// but route no mention notifications.
    pub fn with_mention_notifier(mut self, notifier: MentionNotifier) -> Self {
        self.mention_notify = Some(notifier);
        self
    }

    /// Enable search indexing on [`CommsWriter::post_message`]: after the
    /// durable write, the body (+ thread subject) is indexed through
    /// `backend`. Without this, posts are stored but never indexed.
    /// Indexing is best-effort — see the SECURITY note in
    /// [`CommsWriter::post_message`].
    pub fn with_search_backend(mut self, backend: Arc<dyn SearchBackend>) -> Self {
        self.search_backend = Some(backend);
        self
    }

    pub async fn columns(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        table: &str,
    ) -> Result<ColumnMap> {
        let desc = self.ontology.describe_object(ctx, object_id).await?;
        let mut cols = HashMap::new();
        let mut types = HashMap::new();
        for f in &desc.fields {
            cols.insert(f.api_name.clone(), f.physical_column.clone());
            types.insert(f.api_name.clone(), f.field_type.clone());
        }
        Ok(ColumnMap {
            table: table.to_string(),
            cols,
            types,
        })
    }

    pub async fn create_channel(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        name: &str,
        kind: &str,
    ) -> Result<Uuid> {
        if name.trim().is_empty() || name.len() > 120 {
            return Err(TinkerError::Validation(
                "channel name must be 1-120 chars".into(),
            ));
        }
        if !matches!(kind, "channel" | "shared_inbox") {
            return Err(TinkerError::Validation(format!("bad channel kind: {kind}")));
        }
        let object_id = installed.objects[crate::install::CHANNEL_SLUG];
        let map = self
            .columns(ctx, object_id, &installed.channel_table)
            .await?;
        let id = self
            .insert_row(
                ctx,
                &map,
                &[
                    ("name", serde_json::Value::String(name.to_string())),
                    ("kind", serde_json::Value::String(kind.to_string())),
                ],
            )
            .await?;
        self.signals
            .publish(ctx.organization_id.0, object_id, vec![id])
            .await;
        Ok(id)
    }

    pub async fn create_thread(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        channel_id: Uuid,
        subject: &str,
    ) -> Result<Uuid> {
        if subject.trim().is_empty() || subject.len() > 200 {
            return Err(TinkerError::Validation(
                "thread subject must be 1-200 chars".into(),
            ));
        }
        // The channel must exist in the caller's org: RLS makes a foreign
        // id simply not exist (NotFound, no oracle).
        self.assert_row_visible(ctx, &installed.channel_table, channel_id, "channel")
            .await?;
        let object_id = installed.objects[crate::install::THREAD_SLUG];
        let map = self
            .columns(ctx, object_id, &installed.thread_table)
            .await?;
        let id = self
            .insert_row(
                ctx,
                &map,
                &[
                    ("subject", serde_json::Value::String(subject.to_string())),
                    ("channel", serde_json::Value::String(channel_id.to_string())),
                    ("status", serde_json::Value::String("open".to_string())),
                ],
            )
            .await?;
        self.signals
            .publish(ctx.organization_id.0, object_id, vec![id])
            .await;
        Ok(id)
    }

    pub async fn post_message(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        thread_id: Uuid,
        author_actor_id: Uuid,
        body: &str,
    ) -> Result<Uuid> {
        self.post_message_classified(ctx, installed, thread_id, author_actor_id, body, "text")
            .await
    }

    /// Post with an explicit storage class for the body. The class is
    /// what the item-32 PII guard keys on: `"text"` for ordinary bodies,
    /// `"pii"`/`"restricted"` when the producer classified the content
    /// as PII. `SearchBackend::index_change` runs `reject_pii` first and
    /// fails CLOSED on a PII/secret class — the change is skipped (logged)
    /// and never touches `search_index`, while the message row itself is
    /// still durably stored (same fail-closed shape as item 32: the
    /// security invariant is that PII-classed content never enters the
    /// core index, not that the write is rejected). Used by the inbound
    /// email path, which classifies received bodies from the provider's
    /// own `pii_class` flag — we make no content-scanning claims.
    pub async fn post_message_classified(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        thread_id: Uuid,
        author_actor_id: Uuid,
        body: &str,
        storage_class: &str,
    ) -> Result<Uuid> {
        if body.trim().is_empty() || body.len() > 20_000 {
            return Err(TinkerError::Validation(
                "message body must be 1-20000 chars".into(),
            ));
        }
        self.assert_row_visible(ctx, &installed.thread_table, thread_id, "thread")
            .await?;
        let object_id = installed.objects[crate::install::MESSAGE_SLUG];
        let map = self
            .columns(ctx, object_id, &installed.message_table)
            .await?;
        let id = self
            .insert_row(
                ctx,
                &map,
                &[
                    ("thread", serde_json::Value::String(thread_id.to_string())),
                    (
                        "author_actor_id",
                        serde_json::Value::String(author_actor_id.to_string()),
                    ),
                    ("body", serde_json::Value::String(body.to_string())),
                ],
            )
            .await?;
        // Id-only envelope: subscribers refetch the message (and its card)
        // through their own tenant context and field grants.
        self.signals
            .publish(ctx.organization_id.0, object_id, vec![id])
            .await;
        // @-mentions: best-effort notification routing AFTER the message
        // is durably posted. A routing failure must never lose the post
        // (or fail it): the message row is the source of truth, the
        // notification is a courtesy. Failures are logged, not raised.
        if let Some(notifier) = &self.mention_notify {
            if let Err(e) = notifier
                .notify_mentions(&self.core, ctx, id, author_actor_id, body)
                .await
            {
                tracing::warn!(
                    message_id = %id,
                    error = %e,
                    "mention routing failed for posted message"
                );
            }
        }
        // Search indexing (item 32): best-effort, AFTER the durable write.
        //
        // SECURITY — the storage-class decision, documented here and in
        // STATUS.md (item 32), not ad hoc: the core search index NEVER
        // receives PII plaintext. `comm_message.body` is a plain
        // `RichText` field with no PII classification — the `pii.*` /
        // `secret.*` storage classes exist only in the PII vault store
        // (`pii_refs`) and can never be produced by the chat write path,
        // so that path indexes under the non-PII class "text". Callers
        // that DO carry a producer classification (inbound email) pass it
        // explicitly; `SearchBackend::index_change` runs `reject_pii`
        // first and fails CLOSED on any `pii.*`/`secret.*` class: such a
        // change is rejected and never touches `search_index`. On ANY
        // indexing failure we log and keep the post — the message row is
        // the source of truth, and making chat availability depend on the
        // search backend would invert the reliability hierarchy (same
        // rationale as @-mention routing above). The security invariant
        // is preserved because a rejected change is never written.
        //
        // Honest caveat: chat bodies are free text and a user CAN type
        // PII into one; the guard operates on storage-class
        // classification, not content scanning — we do not claim PII
        // detection in free text. The guarantee is structural: nothing
        // carrying a PII/secret storage class can reach the core index,
        // fail-closed.
        if let Some(backend) = &self.search_backend {
            let subject = self
                .thread_subject(ctx, installed, thread_id)
                .await
                .unwrap_or_default();
            let change = IndexChange {
                object_id,
                record_id: id,
                text: index_text(body, &subject),
                field_versions: serde_json::json!({"body": 1, "thread_subject": 1}),
                storage_classes: vec![storage_class.into()],
            };
            if let Err(e) = backend.index_change(ctx, &change).await {
                tracing::warn!(
                    message_id = %id,
                    error = %e,
                    "search indexing failed for posted message"
                );
            }
        }
        Ok(id)
    }

    /// Fail closed unless the row is visible in the caller's tenant.
    async fn assert_row_visible(
        &self,
        ctx: &TenantContext,
        table: &str,
        id: Uuid,
        what: &str,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let found: Option<Uuid> = sqlx::query_scalar(&format!(
            "SELECT id FROM {table} WHERE organization_id=$1 AND id=$2"
        ))
        .bind(ctx.organization_id.0)
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        found
            .map(|_| ())
            .ok_or_else(|| TinkerError::NotFound(format!("{what} {id}")))
    }

    /// Cheap context for the search index: the thread subject is one
    /// single-row SELECT in the caller's tenant. A missing subject degrades
    /// to no context (never an indexing failure).
    async fn thread_subject(
        &self,
        ctx: &TenantContext,
        installed: &InstalledComms,
        thread_id: Uuid,
    ) -> Result<String> {
        let map = self
            .columns(
                ctx,
                installed.objects[crate::install::THREAD_SLUG],
                &installed.thread_table,
            )
            .await?;
        let col = map.col("subject")?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let subject: Option<String> = sqlx::query_scalar(&format!(
            "SELECT \"{col}\" FROM {} WHERE organization_id=$1 AND id=$2",
            map.table
        ))
        .bind(ctx.organization_id.0)
        .bind(thread_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(subject.unwrap_or_default())
    }

    /// Insert one row into a `data.*` table. Column names come from the
    /// ontology description (validated identifiers at DDL time); values are
    /// bound. Relation (UUID) columns bind from their string form.
    async fn insert_row(
        &self,
        ctx: &TenantContext,
        map: &ColumnMap,
        values: &[(&str, serde_json::Value)],
    ) -> Result<Uuid> {
        let mut cols = Vec::new();
        for (api_name, _) in values {
            let col = map.col(api_name)?;
            cols.push(format!("\"{col}\""));
        }
        let placeholders: Vec<String> = (1..=values.len()).map(|i| format!("${}", i + 1)).collect();
        let sql = format!(
            "INSERT INTO {} (organization_id, {}) VALUES ($1, {}) RETURNING id",
            map.table,
            cols.join(", "),
            placeholders.join(", ")
        );
        let mut tx = self.core.tenant_tx(ctx).await?;
        let mut q = sqlx::query_scalar::<_, Uuid>(&sql).bind(ctx.organization_id.0);
        for (api_name, v) in values {
            let ftype = map
                .types
                .get(*api_name)
                .map(String::as_str)
                .unwrap_or("text");
            q = bind_field(q, ftype, v);
        }
        let id: Uuid = q.fetch_one(&mut *tx).await?;
        tx.commit().await?;
        Ok(id)
    }
}

fn bind_field<'q>(
    q: sqlx::query::QueryScalar<'q, sqlx::Postgres, Uuid, sqlx::postgres::PgArguments>,
    field_type: &str,
    v: &'q serde_json::Value,
) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, Uuid, sqlx::postgres::PgArguments> {
    match field_type {
        // Relation columns are UUID; values arrive as strings.
        "relation" => match v.as_str().and_then(|s| s.parse::<Uuid>().ok()) {
            Some(u) => q.bind(u),
            None => q.bind(None::<Uuid>),
        },
        // RichText is JSONB: the body travels as a JSON string.
        "richtext" => q.bind(v),
        _ => match v.as_str() {
            Some(s) => q.bind(s),
            None => q.bind(v.to_string()),
        },
    }
}
