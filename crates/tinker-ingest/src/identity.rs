//! Identity resolution: match, link, or queue for review.
//!
//! A merge creates an identity decision, not destructive row collapse.
//! Source links and prior values remain recoverable.
//!
//! Rules:
//! - Exact match on a stable external id (or email) with a single
//!   candidate above the auto threshold -> auto-link.
//! - Zero candidates -> new canonical record.
//! - Multiple candidates, or a single candidate below the auto threshold
//!   -> review item (`ambiguous_identity`). NEVER auto-merged.
//! - LLMs may propose; deterministic policy or a human approves the link.

use tinker_core::{Result, TenantContext};
use tinker_db::CoreDb;
use uuid::Uuid;

/// One match candidate: a canonical record id plus confidence in [0,1].
#[derive(Debug, Clone)]
pub struct MatchCandidate {
    pub tinker_record_id: Uuid,
    pub confidence: f64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityOutcome {
    /// Linked to an existing record (auto or human).
    Linked { record_id: Uuid, link_id: Uuid },
    /// Created a fresh canonical record.
    Created { record_id: Uuid, link_id: Uuid },
    /// Ambiguous: queued for human review, nothing linked.
    QueuedForReview { review_id: Uuid },
}

pub struct IdentityEngine {
    core: CoreDb,
    /// Confidence at or above which a single candidate auto-links.
    pub auto_threshold: f64,
}

/// Bundled parameters for a single identity-link write (keeps the
/// transactional write under clippy's argument-count lint).
struct InsertLinkParams<'a> {
    tx: &'a mut sqlx::Transaction<'static, sqlx::Postgres>,
    ctx: &'a TenantContext,
    stream_id: Uuid,
    source_id: &'a str,
    record_id: Uuid,
    confidence: f64,
    decided_by: &'a str,
}

impl IdentityEngine {
    /// Associate a params bundle with the engine for the transactional
    /// identity-link write (keeps the write under clippy's arg-count lint).
    pub fn new(core: CoreDb) -> Self {
        Self {
            core,
            auto_threshold: 0.95,
        }
    }

    /// Resolve one landed source record against candidates produced by the
    /// caller (matching strategy is pluggable; the pipeline builds
    /// candidates from the identity-link registry plus typed matchers).
    ///
    /// This is the transactional core: the caller owns `tx`, so identity
    /// decisions commit atomically with the canonical writes and
    /// provenance they describe. A crashed promotion can never leave a
    /// link without its record, or a record without its link.
    pub async fn resolve_tx(
        &self,
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_id: &str,
        candidates: &[MatchCandidate],
        new_record: impl FnOnce() -> Uuid,
    ) -> Result<IdentityOutcome> {
        // Already linked? Converge (idempotent replay).
        if let Some((link_id, record_id)) =
            Self::existing_link_tx(tx, ctx, stream_id, source_id).await?
        {
            return Ok(IdentityOutcome::Linked { record_id, link_id });
        }
        match candidates {
            [] => {
                let record_id = new_record();
                let link_id = self
                    .insert_link_tx(InsertLinkParams {
                        tx,
                        ctx,
                        stream_id,
                        source_id,
                        record_id,
                        confidence: 1.0,
                        decided_by: "auto",
                    })
                    .await?;
                Ok(IdentityOutcome::Created { record_id, link_id })
            }
            [c] if c.confidence >= self.auto_threshold => {
                let link_id = self
                    .insert_link_tx(InsertLinkParams {
                        tx,
                        ctx,
                        source_id,
                        stream_id,
                        record_id: c.tinker_record_id,
                        confidence: c.confidence,
                        decided_by: "auto",
                    })
                    .await?;
                Ok(IdentityOutcome::Linked {
                    record_id: c.tinker_record_id,
                    link_id,
                })
            }
            _ => {
                // Ambiguous: never auto-merge. Queue for human review.
                let review_id =
                    Self::queue_review_tx(tx, ctx, stream_id, source_id, candidates).await?;
                Ok(IdentityOutcome::QueuedForReview { review_id })
            }
        }
    }

    /// Non-transactional convenience: resolve inside its own transaction.
    /// Prefer [`resolve_tx`](Self::resolve_tx) when the decision must be
    /// atomic with surrounding writes.
    pub async fn resolve(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_id: &str,
        candidates: &[MatchCandidate],
        new_record: impl FnOnce() -> Uuid,
    ) -> Result<IdentityOutcome> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let outcome = self
            .resolve_tx(&mut tx, ctx, stream_id, source_id, candidates, new_record)
            .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    /// Record a human's decision on a review item: link or reject.
    pub async fn human_decide(
        &self,
        ctx: &TenantContext,
        review_id: Uuid,
        link_to: Option<Uuid>,
    ) -> Result<IdentityOutcome> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(Uuid, String, serde_json::Value)> = sqlx::query_as(
            "SELECT stream_id, kind, payload FROM ingest_review_item
             WHERE organization_id=$1 AND id=$2 AND state='open'",
        )
        .bind(ctx.organization_id.0)
        .bind(review_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (stream_id, kind, payload) = row.ok_or_else(|| {
            tinker_core::TinkerError::NotFound(format!("open review {review_id}"))
        })?;
        if kind != "ambiguous_identity" {
            return Err(tinker_core::TinkerError::Validation(format!(
                "review {review_id} is not an identity decision"
            )));
        }
        let source_id = payload
            .get("source_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                tinker_core::TinkerError::Internal("review payload missing source_id".into())
            })?;
        let outcome = match link_to {
            Some(record_id) => {
                let link_id = self
                    .insert_link_tx(InsertLinkParams {
                        tx: &mut tx,
                        ctx,
                        stream_id,
                        source_id,
                        record_id,
                        confidence: 1.0,
                        decided_by: "human",
                    })
                    .await?;
                IdentityOutcome::Linked { record_id, link_id }
            }
            None => {
                // Rejected: no link. The source record stays unlinked until
                // a future run or a new decision.
                IdentityOutcome::QueuedForReview { review_id }
            }
        };
        let new_state = if link_to.is_some() {
            "resolved"
        } else {
            "rejected"
        };
        sqlx::query(
            "UPDATE ingest_review_item SET state=$3, resolved_at=now()
             WHERE organization_id=$1 AND id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(review_id)
        .bind(new_state)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    pub async fn open_reviews(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
    ) -> Result<Vec<(Uuid, String, serde_json::Value)>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
            "SELECT id, kind, payload FROM ingest_review_item
             WHERE organization_id=$1 AND stream_id=$2 AND state='open'
             ORDER BY created_at",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows)
    }

    async fn existing_link_tx(
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_id: &str,
    ) -> Result<Option<(Uuid, Uuid)>> {
        let row: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, tinker_record_id FROM ingest_identity_link
             WHERE organization_id=$1 AND stream_id=$2 AND source_id=$3",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(source_id)
        .fetch_optional(&mut **tx)
        .await?;
        Ok(row)
    }

    async fn insert_link_tx(&self, p: InsertLinkParams<'_>) -> Result<Uuid> {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO ingest_identity_link
             (id, organization_id, stream_id, source_id, tinker_record_id, confidence, decided_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7)
             ON CONFLICT (organization_id, stream_id, source_id)
             DO UPDATE SET tinker_record_id=EXCLUDED.tinker_record_id,
                           confidence=EXCLUDED.confidence,
                           decided_by=EXCLUDED.decided_by,
                           decided_at=now()
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(p.ctx.organization_id.0)
        .bind(p.stream_id)
        .bind(p.source_id)
        .bind(p.record_id)
        .bind(p.confidence)
        .bind(p.decided_by)
        .fetch_one(&mut **p.tx)
        .await?;
        Ok(row.0)
    }

    async fn queue_review_tx(
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_id: &str,
        candidates: &[MatchCandidate],
    ) -> Result<Uuid> {
        // Idempotent: one open review per (stream, source).
        let existing: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM ingest_review_item
             WHERE organization_id=$1 AND stream_id=$2 AND kind='ambiguous_identity'
               AND state='open' AND payload->>'source_id'=$3",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(source_id)
        .fetch_optional(&mut **tx)
        .await?;
        if let Some((id,)) = existing {
            return Ok(id);
        }
        let payload = serde_json::json!({
            "source_id": source_id,
            "candidates": candidates.iter().map(|c| serde_json::json!({
                "tinker_record_id": c.tinker_record_id,
                "confidence": c.confidence,
                "reason": c.reason,
            })).collect::<Vec<_>>(),
        });
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO ingest_review_item
             (id, organization_id, stream_id, kind, payload)
             VALUES ($1,$2,$3,'ambiguous_identity',$4)
             RETURNING id",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(payload)
        .fetch_one(&mut **tx)
        .await?;
        Ok(id)
    }
}
