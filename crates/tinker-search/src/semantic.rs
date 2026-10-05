//! Embedding-based semantic ranking for record search (item 48).
//!
//! [`SemanticSearchBackend`] decorates any [`SearchBackend`]. The fusion
//! order is load-bearing:
//!
//! 1. The inner backend runs FIRST with its full permission filtering —
//!    tenant scope and the item-38 row policies are ANDed into the same
//!    match/rank statement, exactly as without this decorator. The
//!    candidate set is that permission-filtered page (a lexical
//!    prefilter with headroom: `min(limit*4, 200)`, further bounded by
//!    the inner backend's own limit clamp).
//! 2. The decorator loads indexed texts ONLY for the returned record
//!    ids, looks up cached vectors in `record_embeddings`, embeds the
//!    query text plus any cache misses in ONE batched gateway call,
//!    and stable-sorts the candidates by cosine similarity to the
//!    query. `hit.rank` is rewritten to the similarity score.
//!
//! Security properties:
//! - Permissions BEFORE ranking, never after. A record invisible to the
//!   caller never enters the candidate set, so it never reaches the
//!   embedder and never appears in output (no oracle). The fake
//!   adapter's `seen_texts` pins this in tests.
//! - Scores are never exposed beyond the resulting order, and order
//!   only ever permutes the already-authorized set. Snippets pass
//!   through untouched, so downstream field-projection masking
//!   (e.g. `MessageSearch`'s body masking) still applies.
//! - Embedding bytes are prompt bytes: the gateway re-checks placement
//!   against the provider row before any text leaves the process — a
//!   `hosted` adapter is rejected for org-controlled record text.
//! - Failure is LOUD, never silent. When semantic ranking cannot run
//!   (no provider row, provider unavailable, placement rejection,
//!   embed failure) the decorator returns a teaching error, never an
//!   unranked page presented as ranked. Plain lexical search stays
//!   untouched and always available; semantic ranking is opt-in per
//!   call path, so its failure modes cannot take down search.
//!
//! Vector storage (no pgvector — the vendored PG16 has no vector
//! extension and the self-healing DB story forbids non-vendored ones):
//! `record_embeddings`, a durable PG cache keyed by
//! `(organization_id, object_id, record_id, provider_name)` plus the
//! model id. The cache fills lazily at query time — never on the write
//! path, so post latency never pays provider round trips. Staleness is
//! exact: a row is reused only when its `text_sha256` matches the
//! current indexed text AND its dimensions match the provider's
//! current output; otherwise it is re-embedded and upserted. The cache
//! survives restarts, so there is no boot-time re-embedding storm.

use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tinker_agents::gateway::{cosine_similarity, ModelGateway};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use uuid::Uuid;

use super::{SearchBackend, SearchPage, SearchPlan};

/// Per-query semantic-ranking provenance, attached to [`SearchPage`].
/// `None` on pages from lexical backends. The semantic decorator ALWAYS
/// returns `Some` — it errors instead of silently degrading — so a page
/// from the semantic backend without a report is impossible by
/// construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticReport {
    pub provider: String,
    pub model: String,
    /// Candidate pool size that was similarity-ranked.
    pub candidates: u32,
    /// Candidates served from the `record_embeddings` cache.
    pub cache_hits: u32,
    /// Candidates embedded on this query (cold cache or stale text).
    pub cache_misses: u32,
    /// Wall time for the query-time embedding call(s).
    pub embed_ms: u64,
    /// Wall time for cache fetch + cosine + reorder.
    pub rank_ms: u64,
    /// Total added by the semantic path (embed + rank).
    pub total_ms: u64,
}

/// Upper bound on the lexical prefilter pool. One batched embed call
/// covers the query text plus every cache miss, so this also bounds
/// the provider payload per query.
const MAX_CANDIDATE_POOL: u32 = 200;

/// Decorator: permission-filtered search first, embedding rerank second.
pub struct SemanticSearchBackend {
    inner: Arc<dyn SearchBackend>,
    core: CoreDb,
    gateway: ModelGateway,
    provider_name: String,
}

impl SemanticSearchBackend {
    pub fn new(
        inner: Arc<dyn SearchBackend>,
        core: CoreDb,
        gateway: ModelGateway,
        provider_name: impl Into<String>,
    ) -> Self {
        Self {
            inner,
            core,
            gateway,
            provider_name: provider_name.into(),
        }
    }

    /// Teaching error for every semantic-ranking failure mode. Names the
    /// provider and the env-var prefix to configure — never any secret
    /// value — and points at the non-semantic alternative.
    fn unavailable(&self, source: impl std::fmt::Display) -> TinkerError {
        let sanitized: String = self
            .provider_name
            .to_ascii_uppercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        TinkerError::Internal(format!(
            "semantic ranking unavailable for provider '{}': {source}. \
             To fix: register an available embedding provider named '{}' in model_providers \
             (kind fake|hosted|private, placement_boundary honoring your policy) with its \
             TINKER_PROVIDER_{sanitized}_* environment configured; \
             or search without semantic ranking.",
            self.provider_name, self.provider_name,
        ))
    }
}

impl std::fmt::Debug for SemanticSearchBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemanticSearchBackend")
            .field("inner", &self.inner.name())
            .field("provider_name", &self.provider_name)
            .finish()
    }
}

/// sha256 hex of the exact text that was embedded. The cache row is
/// valid only while this matches the current indexed text.
fn text_hash(text: &str) -> String {
    let mut h = Sha256::new();
    h.update(text.as_bytes());
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn encode_vec(v: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 4);
    for x in v {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

fn decode_vec(bytes: &[u8], dimensions: usize) -> Option<Vec<f32>> {
    if bytes.len() != dimensions * 4 {
        return None;
    }
    let (chunks, _) = bytes.as_chunks::<4>();
    Some(chunks.iter().map(|c| f32::from_le_bytes(*c)).collect())
}

/// L2-normalize. Idempotent for already-normalized vectors (the fake
/// adapter); required for real providers before `cosine_similarity`,
/// which assumes normalized inputs.
fn normalize(v: &[f32]) -> Vec<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 0.0 {
        v.iter().map(|x| x / norm).collect()
    } else {
        v.to_vec()
    }
}

#[async_trait::async_trait]
impl SearchBackend for SemanticSearchBackend {
    fn name(&self) -> &'static str {
        "semantic"
    }

    async fn index_change(&self, ctx: &TenantContext, change: &super::IndexChange) -> Result<()> {
        // Deliberately lazy: the vector cache fills at query time. The
        // write path never pays provider latency, and records that are
        // never searched are never embedded.
        self.inner.index_change(ctx, change).await
    }

    async fn search(&self, ctx: &TenantContext, plan: &SearchPlan) -> Result<SearchPage> {
        let t0 = Instant::now();
        let backend_label = format!("{}+semantic", self.inner.name());

        // 1. Permission-filtered candidate set FIRST. Tenant scope + row
        //    policies run inside the inner backend's statement; this
        //    decorator only ever reorders what comes back.
        let pool_limit = plan
            .limit
            .max(1)
            .saturating_mul(4)
            .min(MAX_CANDIDATE_POOL)
            .max(plan.limit);
        let cand_plan = SearchPlan {
            text_query: plan.text_query.clone(),
            object_id: plan.object_id,
            limit: pool_limit,
            row_policies: plan.row_policies.clone(),
        };
        let mut page = self.inner.search(ctx, &cand_plan).await?;
        page.backend.clone_from(&backend_label);

        // Resolve the model id through the same enforcement as the embed
        // call itself: a missing/unavailable/placement-rejected provider
        // fails HERE with the teaching error, before any text moves — and
        // even for an empty candidate pool, so a broken provider can never
        // hide behind "no results".
        let model = self
            .gateway
            .embedding_model_id(ctx, &self.provider_name)
            .await
            .map_err(|e| self.unavailable(e))?;
        if page.hits.is_empty() {
            page.semantic = Some(SemanticReport {
                provider: self.provider_name.clone(),
                model,
                candidates: 0,
                cache_hits: 0,
                cache_misses: 0,
                embed_ms: 0,
                rank_ms: 0,
                total_ms: t0.elapsed().as_millis() as u64,
            });
            return Ok(page);
        }

        // 2. Indexed texts for EXACTLY the candidate record ids. No id is
        //    ever added: invisible records cannot enter the pool, so they
        //    cannot reach the embedder (no oracle).
        let t_rank = Instant::now();
        let ids: Vec<Uuid> = page.hits.iter().map(|h| h.record_id).collect();
        let mut tx = self.core.tenant_tx(ctx).await?;
        let texts: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT object_id, record_id, text_content FROM search_index \
             WHERE organization_id = $1 AND record_id = ANY($2)",
        )
        .bind(ctx.organization_id.0)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut text_of: std::collections::HashMap<Uuid, (Uuid, String)> =
            std::collections::HashMap::with_capacity(texts.len());
        for (object_id, record_id, text) in texts {
            text_of.insert(record_id, (object_id, text));
        }

        // 3. Cache lookup. A row is valid only for the current model,
        //    current dimensions, and byte-identical text.
        let mut tx = self.core.tenant_tx(ctx).await?;
        let cached: Vec<(Uuid, String, i32, String, Vec<u8>)> = sqlx::query_as(
            "SELECT record_id, model, dimensions, text_sha256, embedding \
             FROM record_embeddings \
             WHERE organization_id = $1 AND provider_name = $2 AND record_id = ANY($3)",
        )
        .bind(ctx.organization_id.0)
        .bind(&self.provider_name)
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut cache: std::collections::HashMap<Uuid, Vec<f32>> =
            std::collections::HashMap::with_capacity(cached.len());
        for (record_id, row_model, row_dims, row_hash, row_bytes) in cached {
            if row_model != model {
                continue;
            }
            let dims = row_dims as usize;
            let Some((_, text)) = text_of.get(&record_id) else {
                continue;
            };
            if row_hash != text_hash(text) {
                continue; // stale: text changed since embedding
            }
            if let Some(v) = decode_vec(&row_bytes, dims) {
                cache.insert(record_id, v);
            }
        }
        // Hits served from cache, captured BEFORE the upsert below mutates
        // `cache` (misses are inserted there as they are embedded).
        let cache_hits = page
            .hits
            .iter()
            .filter(|h| cache.contains_key(&h.record_id))
            .count() as u32;

        // 4. One batched embed call: the query text plus every cache
        //    miss. Gateway placement enforcement runs inside embed_texts;
        //    ANY failure is the teaching error, never a silent fallback.
        let t_embed = Instant::now();
        let mut miss_ids: Vec<Uuid> = Vec::new();
        let mut miss_texts: Vec<&str> = Vec::new();
        for h in &page.hits {
            if !cache.contains_key(&h.record_id) {
                if let Some((_, text)) = text_of.get(&h.record_id) {
                    miss_ids.push(h.record_id);
                    miss_texts.push(text.as_str());
                }
            }
        }
        let mut embed_inputs: Vec<&str> = Vec::with_capacity(1 + miss_texts.len());
        embed_inputs.push(plan.text_query.as_str());
        embed_inputs.extend(miss_texts.iter().copied());
        let vectors = self
            .gateway
            .embed_texts(ctx, &self.provider_name, &embed_inputs)
            .await
            .map_err(|e| self.unavailable(e))?;
        let embed_ms = t_embed.elapsed().as_millis() as u64;
        let (query_vec_raw, miss_vecs) = vectors
            .split_first()
            .ok_or_else(|| self.unavailable("provider returned no vectors"))?;
        if miss_vecs.len() != miss_ids.len() {
            return Err(self.unavailable(format!(
                "provider returned {} vectors for {} inputs",
                miss_vecs.len(),
                miss_ids.len()
            )));
        }
        let query_vec = normalize(query_vec_raw);
        let query_dims = query_vec.len();

        // Upsert the fresh vectors (normalized form is unnecessary to
        // store; keep provider output verbatim, normalize at rank time).
        if !miss_ids.is_empty() {
            let mut tx = self.core.tenant_tx(ctx).await?;
            for (i, record_id) in miss_ids.iter().enumerate() {
                let (object_id, text) = text_of
                    .get(record_id)
                    .ok_or_else(|| self.unavailable("candidate text vanished mid-query"))?;
                let v = &miss_vecs[i];
                if v.len() != query_dims {
                    return Err(self.unavailable(format!(
                        "provider returned {} dimensions for input {i}, expected {query_dims}",
                        v.len()
                    )));
                }
                sqlx::query(
                    "INSERT INTO record_embeddings \
                     (organization_id, object_id, record_id, provider_name, model, \
                      dimensions, text_sha256, embedding, embedded_at) \
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now()) \
                     ON CONFLICT (organization_id, object_id, record_id, provider_name) \
                     DO UPDATE SET model = EXCLUDED.model, \
                                   dimensions = EXCLUDED.dimensions, \
                                   text_sha256 = EXCLUDED.text_sha256, \
                                   embedding = EXCLUDED.embedding, \
                                   embedded_at = now()",
                )
                .bind(ctx.organization_id.0)
                .bind(object_id)
                .bind(record_id)
                .bind(&self.provider_name)
                .bind(&model)
                .bind(query_dims as i32)
                .bind(text_hash(text))
                .bind(encode_vec(v))
                .execute(&mut *tx)
                .await?;
                cache.insert(*record_id, v.clone());
            }
            tx.commit().await?;
        }

        // 5. Cosine-rank the authorized set. Stable sort: ties keep the
        //    inner backend's deterministic order. A candidate whose indexed
        //    text vanished between the inner search and the text fetch
        //    (concurrent delete) is dropped — the same stale-index rule
        //    MessageSearch applies downstream — never ranked, never
        //    surfaced.
        let cache_misses = miss_ids.len() as u32;
        let mut scored: Vec<(f32, usize)> = Vec::with_capacity(page.hits.len());
        for (i, h) in page.hits.iter().enumerate() {
            let Some(v) = cache.get(&h.record_id) else {
                continue;
            };
            if v.len() != query_dims {
                return Err(self.unavailable(format!(
                    "cached vector for record {} has {} dimensions, expected {query_dims}",
                    h.record_id,
                    v.len()
                )));
            }
            scored.push((cosine_similarity(&query_vec, &normalize(v)), i));
        }
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let mut ordered = Vec::with_capacity(page.hits.len());
        let mut indexed: Vec<Option<super::SearchHit>> = std::mem::take(&mut page.hits)
            .into_iter()
            .map(Some)
            .collect();
        for (sim, i) in scored {
            if let Some(mut hit) = indexed[i].take() {
                hit.rank = sim;
                ordered.push(hit);
            }
        }
        page.hits = ordered;
        let candidates = page.hits.len() as u32;
        page.hits.truncate(plan.limit as usize);
        let rank_ms = t_rank.elapsed().as_millis() as u64;
        page.semantic = Some(SemanticReport {
            provider: self.provider_name.clone(),
            model,
            candidates,
            cache_hits,
            cache_misses,
            embed_ms,
            rank_ms,
            total_ms: t0.elapsed().as_millis() as u64,
        });
        Ok(page)
    }
}
