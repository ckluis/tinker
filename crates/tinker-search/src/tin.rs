//! TIN adapter (PRD §40: "TIN preferred; native Postgres baseline").
//!
//! Status (verified 2026-09-24): TIN is GA on PlanetScale Postgres and Neki
//! only. PlanetScale publishes `planetscale/lead`, an AGPL-licensed,
//! deliberately non-production extension exposing TIN-compatible SQL
//! (the `tin` access method, `==>` operator, TINQL, `tin.score`) for
//! development/CI — but it targets Postgres 17/18 and performs no real
//! indexing. There is currently no installable production TIN for
//! self-hosted Postgres.
//!
//! This adapter implements [`crate::SearchBackend`] against TIN's documented
//! SQL surface and fails closed when the extension is absent. The day a
//! production TIN can be installed, the M0 benchmark gates adoption and the
//! same permission test suite runs unchanged.

use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use crate::{reject_pii, IndexChange, SearchBackend, SearchHit, SearchPage, SearchPlan};

#[derive(Debug)]
pub struct TinSearchBackend {
    core: CoreDb,
}

impl TinSearchBackend {
    /// Returns an error unless `CREATE EXTENSION tin` has been run.
    /// Adoption is gated by the M0 compatibility/workload benchmark.
    pub async fn connect(core: CoreDb) -> Result<Self> {
        let present: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'tin')")
                .fetch_one(&core.0)
                .await?;
        if !present {
            return Err(TinkerError::Validation(
                "TIN extension is not installed; using the native baseline. \
                 See tinker_search::tin for the adoption gate."
                    .into(),
            ));
        }
        Ok(Self { core })
    }

    /// Create the TIN index for a caller-managed documents table. Kept as a
    /// helper (not used by the default search_index table) so deployments
    /// that adopt TIN get the documented DDL in one place.
    pub async fn ensure_tin_index(&self, table: &str, column: &str) -> Result<()> {
        if !table
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
            || !column
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(TinkerError::Validation("bad table/column".into()));
        }
        sqlx::query(&format!(
            "CREATE INDEX IF NOT EXISTS {table}_{column}_tin_idx ON {table} USING tin({column})"
        ))
        .execute(&self.core.0)
        .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SearchBackend for TinSearchBackend {
    fn name(&self) -> &'static str {
        "tin"
    }

    async fn index_change(&self, ctx: &TenantContext, change: &IndexChange) -> Result<()> {
        // Same PII guard as every backend: no exceptions for accelerators.
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
        // TIN surface (per PlanetScale's launch article): `==>` match
        // operator, `tin.score(ctid)` BM25 ranking. Tenant predicate stays
        // in the same statement; RLS remains the backstop. C2 row policies
        // are ANDed into the same WHERE — policy before ranking, so TIN
        // carries the same authorization semantics as the native backend.
        let sql = format!(
            "SELECT object_id, record_id,
                      left(text_content, 160) AS snippet,
                      tin.score(ctid) AS rank
               FROM search_index
               WHERE organization_id = $1
                 AND ($2::uuid IS NULL OR object_id = $2)
                 AND text_content ==> $3{}
               ORDER BY rank DESC
               LIMIT $4",
            super::policy_where(plan, 5)
        );
        let mut tx = self.core.tenant_tx(ctx).await?;
        let mut q = sqlx::query_as::<_, (Uuid, Uuid, String, f32)>(&sql);
        q = q.bind(ctx.organization_id.0);
        q = q.bind(plan.object_id);
        q = q.bind(&plan.text_query);
        q = q.bind(limit);
        q = super::bind_policies(q, plan);
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
