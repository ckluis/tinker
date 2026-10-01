//! Budgeted graph expansion (§17 "Adaptive semantic expansion").
//!
//! Agents start with the smallest useful virtual record, then expand along
//! DECLARED ontology relation edges. The planner:
//!   1. resolves the root to a canonical record + policy snapshot;
//!   2. lists eligible relation types from ontology metadata + the
//!      attachment scope + the context profile;
//!   3. FILTERS every candidate edge/target by authorization BEFORE
//!      scoring — models may only rank authorized candidates;
//!   4. ranks the authorized set across the record's edges:
//!      deterministically by default, or — when a `SemanticRanker` is
//!      attached — by embedding similarity to a focus text via the model
//!      gateway (placement-enforced; a `hosted` provider is rejected).
//!      Ranking only reorders the authorized set, never enlarges it;
//!      embedder failure degrades to deterministic order;
//!   5. emits files plus a MANIFEST of traversed and truncated edges.
//!
//! Bounds: attachment max_depth, profile relation_depth, per-relation
//! fan-out caps, record cap, token budget. Cycles are deduped by
//! canonical (object, record) id; high-cardinality branches return
//! explicit truncation counts and continuation handles.

use std::collections::{HashMap, HashSet, VecDeque};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::{ObjectDescription, Ontology};
use uuid::Uuid;

use crate::budgets::ExpansionBudget;
use crate::gateway::{cosine_similarity, ModelGateway};
use crate::profiles::ContextProfile;
use crate::transforms::TransformEngine;

/// Per-relation fan-out cap: a single relation hop never fans out
/// unboundedly; the rest is truncated with a continuation handle.
pub const FANOUT_CAP: i64 = 25;

/// Per-relation candidate pool cap for semantic ranking: up to this many
/// targets are authorization-gated per edge. The ranker then orders the
/// record's whole AUTHORIZED set (across its edges) by similarity;
/// traversal still honors per-edge FANOUT_CAP and the budgets. Ranking
/// never enlarges the authorized set — it only reorders it.
pub const RANK_POOL_CAP: usize = 100;

#[derive(Debug, Clone)]
pub struct TraversedEdge {
    pub from_object: String,
    pub from_id: Uuid,
    pub edge: String,
    pub to_object: String,
    pub to_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct TruncatedEdge {
    pub from_object: String,
    pub from_id: Uuid,
    pub edge: String,
    pub truncated_count: i64,
    /// Opaque continuation: {object, record, edge, offset}.
    pub continuation: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ExpansionManifest {
    pub id: Uuid,
    pub root_object: String,
    pub root_record: Uuid,
    pub traversed: Vec<TraversedEdge>,
    pub truncated: Vec<TruncatedEdge>,
    pub records: u32,
    pub tokens: u64,
    pub depth_reached: u32,
    /// Present when a semantic ranker was attached: which provider ranked,
    /// and how many source records were similarity-ranked vs fell back
    /// to deterministic order.
    pub ranking: Option<RankingRecord>,
}

/// Audit record for semantic ranking on one expansion.
#[derive(Debug, Clone)]
pub struct RankingRecord {
    pub provider: String,
    /// Source records whose authorized candidate set was similarity-ranked.
    pub ranked_records: u32,
    /// Source records where the embedder failed and deterministic order
    /// was used instead.
    pub fallback_records: u32,
}

/// Opt-in semantic ranker for graph expansion. Candidates are ranked by
/// cosine similarity between their rendered text and a focus text
/// (default: the root record's rendered markdown) using embeddings from
/// the named provider through the model gateway — with the gateway's
/// full placement enforcement (a `hosted` provider is rejected for
/// org-controlled record text).
///
/// INVARIANT: ranking only ever REORDERS the authorization-filtered
/// candidate set. Unreadable targets never reach the embedder — the
/// authorization gate runs first, per edge, before any ranking.
pub struct SemanticRanker {
    gateway: ModelGateway,
    provider_name: String,
    focus: Option<String>,
}

impl SemanticRanker {
    pub fn new(gateway: ModelGateway, provider_name: impl Into<String>) -> Self {
        Self {
            gateway,
            provider_name: provider_name.into(),
            focus: None,
        }
    }

    /// Override the similarity focus. When unset, expansion uses the root
    /// record's rendered text.
    pub fn with_focus(mut self, focus: impl Into<String>) -> Self {
        self.focus = Some(focus.into());
        self
    }
}

/// An authorization-gated expansion candidate: the target passed the
/// policy render, so its (already policy-masked) text may be ranked.
struct ExpansionCandidate {
    target_id: Uuid,
    target_slug: String,
    tpath: String,
    rendered: String,
}

/// One relation edge's authorized candidates for a single source record.
struct EdgePool {
    api_name: String,
    total: i64,
    candidates: Vec<ExpansionCandidate>,
}

/// Fields for one persisted expansion manifest. Bundled so
/// `persist_manifest` stays under the argument-count lint.
struct ManifestFields<'a> {
    root_object: &'a str,
    root_record: Uuid,
    traversed: &'a [TraversedEdge],
    truncated: &'a [TruncatedEdge],
    records: u32,
    tokens: u64,
    depth_reached: u32,
    ranking: Option<&'a RankingRecord>,
}

pub struct ExpansionEngine<'a> {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
    ontology: &'a Ontology,
    engine: &'a TransformEngine,
    ranker: Option<SemanticRanker>,
}

impl<'a> ExpansionEngine<'a> {
    pub fn new(
        core: CoreDb,
        owner: OwnerDb,
        ontology: &'a Ontology,
        engine: &'a TransformEngine,
    ) -> Self {
        Self {
            core,
            owner,
            ontology,
            engine,
            ranker: None,
        }
    }

    /// Attach an opt-in semantic ranker. Without it, expansion keeps the
    /// milestone's deterministic candidate order.
    pub fn with_semantic_ranker(mut self, ranker: SemanticRanker) -> Self {
        self.ranker = Some(ranker);
        self
    }

    /// Expand from a root record within the attachment scope, the context
    /// profile, and the expansion budget. Returns rendered files (path →
    /// markdown) plus the persisted manifest.
    pub async fn expand(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        profile: &ContextProfile,
        root_object: &str,
        root_record: Uuid,
        budget: &ExpansionBudget,
    ) -> Result<(HashMap<String, String>, ExpansionManifest)> {
        // 1. Resolve root + policy snapshot: the attachment scope.
        let scope = self.attachment_scope(ctx, attachment_id).await?;
        let allowed: Option<HashSet<String>> = scope
            .get("allowed_relation_types")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            });
        let scope_max_depth = scope
            .get("max_depth")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);
        let max_depth = scope_max_depth
            .unwrap_or(u32::MAX)
            .min(profile.relation_depth())
            .min(budget.depth);

        // The root itself must be readable through the caller's policy;
        // otherwise the expansion is empty (fail closed, no oracle).
        let root_path = format!("/tinker/{root_object}/{root_record}/index.md");
        let (root_fields, _) = self
            .engine
            .render_record(
                ctx,
                root_object,
                root_record,
                Some(attachment_id),
                &root_path,
            )
            .await
            .map_err(|_| TinkerError::Forbidden("root record not readable".into()))?;
        // Default ranking focus: the root record's rendered text. Only
        // built when a ranker is attached.
        let root_text = self
            .ranker
            .as_ref()
            .map(|_| render_fields(root_object, &root_record, &root_fields));

        // 2/3. BFS over declared edges, authorization-filtered first.
        let mut files: HashMap<String, String> = HashMap::new();
        let mut traversed: Vec<TraversedEdge> = Vec::new();
        let mut truncated: Vec<TruncatedEdge> = Vec::new();
        let mut visited: HashSet<(String, Uuid)> = HashSet::new();
        let mut queue: VecDeque<(String, Uuid, u32)> = VecDeque::new();
        visited.insert((root_object.to_string(), root_record));
        queue.push_back((root_object.to_string(), root_record, 0));

        let mut records: u32 = 1; // root counts
        let mut tokens: u64 = 0;
        let mut depth_reached: u32 = 0;
        let mut ranked_records: u32 = 0;
        let mut fallback_records: u32 = 0;

        // Cache object descriptions (metadata; owner handle).
        let mut descs: HashMap<String, ObjectDescription> = HashMap::new();
        let mut slugs_by_id: HashMap<Uuid, String> = HashMap::new();

        while let Some((obj_slug, rec_id, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }
            let desc = self.describe_cached(&mut descs, ctx, &obj_slug).await?;

            // Phase 1 — per edge: scope/profile filter, then authorization
            // filter FIRST. Each target is rendered through the caller's
            // policy; unreadable targets are skipped silently (no oracle,
            // no leak) and never reach the embedder. Only the authorized
            // set advances to ranking.
            //
            // Relation targets are single FKs, so one edge yields at most
            // a handful of candidates; ranking (phase 2) operates across
            // the record's edges, where the authorized set is plural.
            let mut edge_pools: Vec<EdgePool> = Vec::new();
            for f in desc.fields.iter().filter(|f| f.field_type == "relation") {
                let edge_key = format!("{obj_slug}.{}", f.api_name);
                // Scope filter BEFORE any data access or scoring.
                if let Some(allow) = &allowed {
                    if !allow.contains(&edge_key) {
                        continue;
                    }
                }
                // Profile permitted_fields can further narrow edges.
                if let Some(permitted) = profile.permitted_fields(&obj_slug) {
                    if !permitted.contains(&f.api_name) {
                        continue;
                    }
                }
                let targets = self
                    .relation_targets(ctx, &obj_slug, &f.physical_column, rec_id)
                    .await?;
                let total = targets.len() as i64;
                let mut candidates: Vec<ExpansionCandidate> = Vec::new();
                for target_id in targets.into_iter().take(RANK_POOL_CAP) {
                    // Without a ranker, keep the milestone's exact
                    // behavior: stop gating candidates once the record
                    // budget is hit. With a ranker the full pool is
                    // needed — ranking exists to choose the most relevant
                    // candidates under budget pressure.
                    if records >= budget.records && self.ranker.is_none() {
                        break;
                    }
                    let target_slug = self
                        .slug_for_target(&desc, &f.api_name, &mut slugs_by_id, ctx)
                        .await?;
                    if visited.contains(&(target_slug.clone(), target_id)) {
                        continue;
                    }
                    let tpath = format!("/tinker/{target_slug}/{target_id}/index.md");
                    let rendered = match self
                        .engine
                        .render_record(ctx, &target_slug, target_id, Some(attachment_id), &tpath)
                        .await
                    {
                        Ok((fields, _)) => render_fields(&target_slug, &target_id, &fields),
                        Err(_) => continue,
                    };
                    candidates.push(ExpansionCandidate {
                        target_id,
                        target_slug,
                        tpath,
                        rendered,
                    });
                }
                edge_pools.push(EdgePool {
                    api_name: f.api_name.clone(),
                    total,
                    candidates,
                });
            }

            // Phase 2 — ranking across the record's edges. Each edge
            // contributes at most FANOUT_CAP candidates (the existing
            // bound); the concatenated AUTHORIZED set is reordered by
            // embedding similarity to the focus, or keeps deterministic
            // edge order without a ranker. Ranking never enlarges the
            // authorized set — it only reorders it.
            let focus = self
                .ranker
                .as_ref()
                .and_then(|r| r.focus.clone())
                .or_else(|| root_text.clone());
            let mut flat: Vec<(usize, ExpansionCandidate)> = Vec::new();
            for (edge_idx, pool) in edge_pools.iter_mut().enumerate() {
                for cand in pool.candidates.drain(..).take(FANOUT_CAP as usize) {
                    flat.push((edge_idx, cand));
                }
            }
            let (ordered, was_ranked, was_fallback) = match (&self.ranker, focus) {
                (Some(ranker), Some(focus)) => {
                    self.rank_candidates(ctx, ranker, &focus, flat).await
                }
                _ => (flat, false, false),
            };
            if was_ranked {
                ranked_records += 1;
            }
            if was_fallback {
                fallback_records += 1;
            }

            // Phase 3 — traverse in (possibly ranked) order within budget,
            // attributing each traversal back to its edge for honest
            // per-edge truncation accounting. A token-budget break skips
            // the rest of that edge's candidates (as the milestone did)
            // but lets other edges' affordable candidates through.
            let mut took = vec![0i64; edge_pools.len()];
            let mut token_cut: HashSet<usize> = HashSet::new();
            for (edge_idx, cand) in ordered {
                if records >= budget.records {
                    break;
                }
                if token_cut.contains(&edge_idx) {
                    continue;
                }
                let edge_name = edge_pools[edge_idx].api_name.clone();
                let edge_total = edge_pools[edge_idx].total;
                let est_tokens = (cand.rendered.len() as u64) / 4;
                if tokens + est_tokens > budget.tokens {
                    truncated.push(TruncatedEdge {
                        from_object: obj_slug.clone(),
                        from_id: rec_id,
                        edge: edge_name.clone(),
                        truncated_count: edge_total - took[edge_idx],
                        continuation: serde_json::json!({
                            "object": obj_slug, "record": rec_id,
                            "edge": edge_name, "offset": took[edge_idx],
                        }),
                    });
                    token_cut.insert(edge_idx);
                    continue;
                }
                tokens += est_tokens;
                records += 1;
                depth_reached = depth_reached.max(depth + 1);
                visited.insert((cand.target_slug.clone(), cand.target_id));
                traversed.push(TraversedEdge {
                    from_object: obj_slug.clone(),
                    from_id: rec_id,
                    edge: edge_name,
                    to_object: cand.target_slug.clone(),
                    to_id: cand.target_id,
                });
                files.insert(cand.tpath, cand.rendered);
                queue.push_back((cand.target_slug, cand.target_id, depth + 1));
                took[edge_idx] += 1;
            }
            // Per-edge truncation for whatever was not traversed. The
            // continuation offset counts traversed candidates in ranked
            // order; a resume re-applies the same ranker to reproduce it.
            for (edge_idx, pool) in edge_pools.iter().enumerate() {
                if token_cut.contains(&edge_idx) {
                    continue; // already reported above
                }
                if pool.total > took[edge_idx] {
                    truncated.push(TruncatedEdge {
                        from_object: obj_slug.clone(),
                        from_id: rec_id,
                        edge: pool.api_name.clone(),
                        truncated_count: pool.total - took[edge_idx],
                        continuation: serde_json::json!({
                            "object": obj_slug, "record": rec_id,
                            "edge": pool.api_name, "offset": took[edge_idx],
                        }),
                    });
                }
            }
        }

        // 5. Persist the manifest.
        let ranking = self.ranker.as_ref().map(|r| RankingRecord {
            provider: r.provider_name.clone(),
            ranked_records,
            fallback_records,
        });
        let fields = ManifestFields {
            root_object,
            root_record,
            traversed: &traversed,
            truncated: &truncated,
            records,
            tokens,
            depth_reached,
            ranking: ranking.as_ref(),
        };
        let manifest = self.persist_manifest(ctx, attachment_id, &fields).await?;
        Ok((files, manifest))
    }

    async fn attachment_scope(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
    ) -> Result<serde_json::Value> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT scope FROM agent_attachments
             WHERE organization_id = $1 AND id = $2 AND status = 'active'",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(|(s,)| s)
            .ok_or_else(|| TinkerError::NotFound(format!("attachment {attachment_id}")))
    }

    async fn describe_cached(
        &self,
        cache: &mut HashMap<String, ObjectDescription>,
        ctx: &TenantContext,
        slug: &str,
    ) -> Result<ObjectDescription> {
        if let Some(d) = cache.get(slug) {
            return Ok(d.clone());
        }
        let d = self.ontology.describe_object_by_slug(ctx, slug).await?;
        cache.insert(slug.to_string(), d.clone());
        Ok(d)
    }

    /// Target object slug for a relation field (via relation_target_id).
    async fn slug_for_target(
        &self,
        desc: &ObjectDescription,
        api_name: &str,
        cache: &mut HashMap<Uuid, String>,
        ctx: &TenantContext,
    ) -> Result<String> {
        let field = desc
            .fields
            .iter()
            .find(|f| f.api_name == api_name)
            .ok_or_else(|| TinkerError::NotFound(format!("field {api_name}")))?;
        let target_id = field
            .relation_target_id
            .ok_or_else(|| TinkerError::Internal(format!("{api_name} is not a relation")))?;
        if let Some(s) = cache.get(&target_id) {
            return Ok(s.clone());
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Owner metadata lookup through the tenant tx is fine: the row is
        // portfolio metadata, and the slug alone reveals nothing.
        let row: Option<(String,)> =
            sqlx::query_as("SELECT api_slug FROM ontology_objects WHERE id = $1")
                .bind(target_id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        let (slug,) = row.ok_or_else(|| TinkerError::NotFound("relation target".into()))?;
        cache.insert(target_id, slug.clone());
        Ok(slug)
    }

    /// All target record ids for one relation hop. Single-valued relation
    /// columns hold at most one id; the query is uniform anyway.
    async fn relation_targets(
        &self,
        ctx: &TenantContext,
        object_slug: &str,
        physical_column: &str,
        record_id: Uuid,
    ) -> Result<Vec<Uuid>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let table = format!("data.{object_slug}");
        let sql = format!(
            "SELECT \"{physical_column}\" FROM {table}
             WHERE organization_id = $1 AND id = $2"
        );
        let row: Option<(Option<Uuid>,)> = sqlx::query_as(&sql)
            .bind(ctx.organization_id.0)
            .bind(record_id)
            .fetch_optional(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(row.and_then(|(v,)| v).into_iter().collect())
    }

    #[allow(clippy::too_many_arguments)]
    /// Rank the authorized candidate set by embedding similarity to the
    /// focus text. Returns (ordered candidates, was_ranked, was_fallback).
    /// Each item carries its edge index so traversal can attribute it
    /// back to its edge for truncation accounting.
    ///
    /// - `was_ranked`: the provider returned embeddings and the set was
    ///   reordered by similarity (stable: ties keep deterministic order).
    /// - `was_fallback`: the embedder failed (or was rejected by gateway
    ///   placement enforcement) and the set keeps its deterministic order.
    ///   Ranking failure NEVER fails the expansion — it degrades to the
    ///   milestone's deterministic order.
    ///
    /// The set passed authorization before this call: unreadable targets
    /// are not in it and never reach the embedder.
    async fn rank_candidates(
        &self,
        ctx: &TenantContext,
        ranker: &SemanticRanker,
        focus: &str,
        flat: Vec<(usize, ExpansionCandidate)>,
    ) -> (Vec<(usize, ExpansionCandidate)>, bool, bool) {
        if flat.is_empty() {
            return (flat, false, false);
        }
        // Focus first, then candidates — one batched embedding call.
        let texts: Vec<&str> = std::iter::once(focus)
            .chain(flat.iter().map(|(_, c)| c.rendered.as_str()))
            .collect();
        let vectors = match ranker
            .gateway
            .embed_texts(ctx, &ranker.provider_name, &texts)
            .await
        {
            Ok(v) => v,
            Err(_) => return (flat, false, true),
        };
        if vectors.len() != texts.len() {
            return (flat, false, true);
        }
        let focus_vec = &vectors[0];
        let mut scored: Vec<(f32, usize)> = vectors[1..]
            .iter()
            .enumerate()
            .map(|(i, v)| (cosine_similarity(focus_vec, v), i))
            .collect();
        // Stable sort: ties keep deterministic pool order.
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let mut indexed: Vec<Option<(usize, ExpansionCandidate)>> =
            flat.into_iter().map(Some).collect();
        let mut ordered = Vec::with_capacity(indexed.len());
        for (_, i) in scored {
            if let Some(item) = indexed[i].take() {
                ordered.push(item);
            }
        }
        (ordered, true, false)
    }

    async fn persist_manifest(
        &self,
        ctx: &TenantContext,
        attachment_id: Uuid,
        fields: &ManifestFields<'_>,
    ) -> Result<ExpansionManifest> {
        let traversed_json: Vec<serde_json::Value> = fields
            .traversed
            .iter()
            .map(|e| {
                serde_json::json!({
                    "from_object": e.from_object, "from_id": e.from_id,
                    "edge": e.edge, "to_object": e.to_object, "to_id": e.to_id,
                })
            })
            .collect();
        let truncated_json: Vec<serde_json::Value> = fields
            .truncated
            .iter()
            .map(|e| {
                serde_json::json!({
                    "from_object": e.from_object, "from_id": e.from_id,
                    "edge": e.edge, "truncated_count": e.truncated_count,
                    "continuation": e.continuation,
                })
            })
            .collect();
        let ranking_json = fields.ranking.map(|r| {
            serde_json::json!({
                "provider": r.provider,
                "ranked_records": r.ranked_records,
                "fallback_records": r.fallback_records,
            })
        });
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO expansion_manifests
                 (organization_id, attachment_id, root_object, root_record,
                  traversed, truncated, records, tokens, depth_reached, ranking)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(attachment_id)
        .bind(fields.root_object)
        .bind(fields.root_record)
        .bind(serde_json::Value::Array(traversed_json))
        .bind(serde_json::Value::Array(truncated_json))
        .bind(fields.records as i32)
        .bind(fields.tokens as i64)
        .bind(fields.depth_reached as i32)
        .bind(ranking_json)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ExpansionManifest {
            id,
            root_object: fields.root_object.to_string(),
            root_record: fields.root_record,
            traversed: fields.traversed.to_vec(),
            truncated: fields.truncated.to_vec(),
            records: fields.records,
            tokens: fields.tokens,
            depth_reached: fields.depth_reached,
            ranking: fields.ranking.cloned(),
        })
    }
}

fn render_fields(slug: &str, id: &Uuid, fields: &[(String, serde_json::Value)]) -> String {
    let mut md = format!("# {slug} {id}\n\n");
    for (name, value) in fields {
        let v = match value {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => "(empty)".to_string(),
            other => other.to_string(),
        };
        md.push_str(&format!("- **{name}**: {v}\n"));
    }
    md
}
