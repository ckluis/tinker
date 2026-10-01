//! Search backends behind one contract (PRD §40).
//!
//! [`SearchBackend`] is the only interface callers use. The portable
//! baseline is [`NativeSearchBackend`] (tsvector/GIN + pg_trgm), which every
//! deployment has. [`tin::TinSearchBackend`] implements the same contract
//! against PlanetScale's TIN extension where it is installed; its adoption
//! is gated by extension availability (see [`tin`]).

use serde::{Deserialize, Serialize};
use tinker_core::{CompiledRowPolicy, Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

pub mod semantic;
pub mod tin;

pub use semantic::{SemanticReport, SemanticSearchBackend};

/// A change to the search index. Produced by durable indexing steps.
#[derive(Debug, Clone)]
pub struct IndexChange {
    pub object_id: Uuid,
    pub record_id: Uuid,
    /// Plain text to index. MUST NOT contain PII plaintext: enforced below.
    pub text: String,
    pub field_versions: serde_json::Value,
    /// Storage classes of the indexed fields, e.g. "text", "pii.name".
    pub storage_classes: Vec<String>,
}

/// A search request. The compiler injects tenant and row policy into the
/// same statement that performs matching and ranking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPlan {
    pub text_query: String,
    pub object_id: Option<Uuid>,
    pub limit: u32,
    /// C2 row policies, compiler-built ([`CompiledRowPolicy`]). Each is
    /// ANDed into the match/rank statement as
    /// `(object_id <> $N OR (<record passes the role's filters>))`, so a
    /// row the caller's role cannot see never influences ranking,
    /// snippets, or counts. Empty = no row policies (default-open).
    #[serde(default)]
    pub row_policies: Vec<CompiledRowPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub object_id: Uuid,
    pub record_id: Uuid,
    pub snippet: String,
    pub rank: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchPage {
    pub hits: Vec<SearchHit>,
    pub backend: String,
    /// Semantic-ranking provenance (item 48). `None` for lexical backends.
    /// The semantic decorator ALWAYS returns `Some` — it errors instead of
    /// silently degrading — so a page from the semantic backend without a
    /// report is impossible by construction, and callers can tell ranked
    /// from unranked without trusting the backend name string.
    #[serde(default)]
    pub semantic: Option<SemanticReport>,
}

#[async_trait::async_trait]
pub trait SearchBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Index (or re-index) one record. Rejects PII plaintext by policy.
    async fn index_change(&self, ctx: &TenantContext, change: &IndexChange) -> Result<()>;

    /// Search within the caller's tenant. Implementations MUST scope every
    /// statement to the tenant; the trait test suite verifies this.
    async fn search(&self, ctx: &TenantContext, plan: &SearchPlan) -> Result<SearchPage>;
}

/// PII guard shared by all backends: the core search index never receives
/// PII plaintext. PII search runs inside the PII store and returns opaque
/// references instead.
pub fn reject_pii(change: &IndexChange) -> Result<()> {
    for class in &change.storage_classes {
        let c = class.to_ascii_lowercase();
        if c.starts_with("pii.") || c.starts_with("secret.") || c == "pii" {
            return Err(TinkerError::Forbidden(format!(
                "search index must not receive PII plaintext (storage class {class})"
            )));
        }
    }
    Ok(())
}

/// Portable baseline: tsvector/GIN ranking plus pg_trgm similarity.
/// Correctness-identical contract to TIN; latency may differ.
#[derive(Debug)]
pub struct NativeSearchBackend {
    core: CoreDb,
}

impl NativeSearchBackend {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }
}

/// C2 row-policy WHERE suffix, shared by both backends. Each policy is
/// ANDed as its compiler-built fragment with `{{pK}}` markers substituted
/// to positional `$N` starting at `first_bind` (both backends bind
/// org/object/query/limit as $1..$4, so callers pass 5). The policy is
/// part of the same statement as matching and ranking — hidden rows never
/// influence rank, snippets, or counts.
fn policy_where(plan: &SearchPlan, first_bind: usize) -> String {
    let mut sql = String::new();
    let mut next = first_bind;
    for p in &plan.row_policies {
        sql.push_str(&format!(" AND {}", p.substitute(next)));
        next += p.params.len();
    }
    sql
}

/// Bind all row-policy params of a plan, in order, after the backend's own
/// binds.
fn bind_policies<'q, O>(
    mut q: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    plan: &'q SearchPlan,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
    for p in &plan.row_policies {
        for bp in &p.params {
            q = tinker_query::bind_param_as(q, bp);
        }
    }
    q
}

#[async_trait::async_trait]
impl SearchBackend for NativeSearchBackend {
    fn name(&self) -> &'static str {
        "native"
    }

    async fn index_change(&self, ctx: &TenantContext, change: &IndexChange) -> Result<()> {
        reject_pii(change)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            r#"INSERT INTO search_index
               (organization_id, object_id, record_id, field_versions, text_content, updated_at)
               VALUES ($1,$2,$3,$4,$5,now())
               ON CONFLICT (organization_id, object_id, record_id) DO UPDATE
               SET text_content = EXCLUDED.text_content,
                   field_versions = EXCLUDED.field_versions,
                   updated_at = now()"#,
        )
        .bind(ctx.organization_id.0)
        .bind(change.object_id)
        .bind(change.record_id)
        .bind(&change.field_versions)
        .bind(&change.text)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn search(&self, ctx: &TenantContext, plan: &SearchPlan) -> Result<SearchPage> {
        if plan.text_query.trim().is_empty() {
            return Err(TinkerError::Validation("empty search query".into()));
        }
        let limit = plan.limit.clamp(1, 100) as i64;
        // Tenant predicate is part of the same statement as matching and
        // ranking; RLS on search_index is the fail-closed backstop. C2 row
        // policies are ANDed into the same WHERE — policy before ranking.
        let sql = format!(
            "SELECT object_id, record_id,
                      ts_headline('english', text_content,
                          plainto_tsquery('english', $3),
                          'MaxWords=24, MinWords=10') AS snippet,
                      ts_rank(tsv, plainto_tsquery('english', $3)) AS rank
               FROM search_index
               WHERE organization_id = $1
                 AND ($2::uuid IS NULL OR object_id = $2)
                 AND tsv @@ plainto_tsquery('english', $3){}
               ORDER BY rank DESC
               LIMIT $4",
            policy_where(plan, 5)
        );
        let mut tx = self.core.tenant_tx(ctx).await?;
        let mut q = sqlx::query_as::<_, (Uuid, Uuid, String, f32)>(&sql);
        q = q.bind(ctx.organization_id.0);
        q = q.bind(plan.object_id);
        q = q.bind(&plan.text_query);
        q = q.bind(limit);
        q = bind_policies(q, plan);
        let rows: Vec<(Uuid, Uuid, String, f32)> = q.fetch_all(&mut *tx).await?;
        tx.commit().await?;
        Ok(SearchPage {
            hits: rows
                .into_iter()
                .map(|(object_id, record_id, snippet, rank)| SearchHit {
                    object_id,
                    record_id,
                    snippet,
                    rank,
                })
                .collect(),
            backend: self.name().into(),
            semantic: None,
        })
    }
}
