//! Embedding-based semantic ranking for graph expansion.
//!
//! Invariants pinned here:
//! 1. Authorization filtering happens BEFORE embedding: unreadable targets
//!    never reach the embedder (the fake records every text it embeds).
//! 2. Ranking only REORDERS the authorized set — it never enlarges it.
//! 3. Embedder failure (or placement rejection) degrades to deterministic
//!    order; expansion never fails because ranking failed.
//! 4. A `hosted` provider is rejected for org-controlled record text
//!    before any text leaves the process.

mod common;

use common::*;
use std::collections::HashMap;
use std::sync::Arc;
use tinker_agents::gateway::{EmbeddingAdapter, FakeEmbeddingAdapter, UnavailableEmbeddingAdapter};
use tinker_agents::{
    cosine_similarity, AuditWriter, ExpansionBudget, ExpansionEngine, ExpansionManifest,
    ModelGateway, ProfileEngine, SemanticRanker, TransformEngine,
};
use tinker_core::{TenantContext, TinkerError};
use uuid::Uuid;

async fn seed_embedding_provider(env: &AgentEnv, name: &str, kind: &str, status: &str) {
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO model_providers
             (organization_id, name, kind, placement_boundary, status)
         VALUES ($1, $2, $3, 'org-controlled', $4)
         ON CONFLICT (organization_id, name)
         DO UPDATE SET kind = EXCLUDED.kind, status = EXCLUDED.status",
    )
    .bind(env.org_id)
    .bind(name)
    .bind(kind)
    .bind(status)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

/// Expand from deal_d1 with an optional ranker. The gateway is the
/// caller's (it carries whatever embedding adapters were registered).
async fn expand_with(
    env: &AgentEnv,
    ctx: &TenantContext,
    gateway: ModelGateway,
    ranker: Option<SemanticRanker>,
) -> (HashMap<String, String>, ExpansionManifest) {
    let audit = AuditWriter::new(env.core.clone(), env.owner.clone());
    let engine = TransformEngine::new(
        env.core.clone(),
        env.owner.clone(),
        env.ontology.clone(),
        gateway,
        audit,
    );
    let expansion =
        ExpansionEngine::new(env.core.clone(), env.owner.clone(), &env.ontology, &engine);
    let expansion = match ranker {
        Some(r) => expansion.with_semantic_ranker(r),
        None => expansion,
    };
    let profiles = ProfileEngine::new(env.core.clone(), env.owner.clone());
    let profile = profiles
        .active(&env.exec_ctx, &env.profile_key)
        .await
        .unwrap();
    let budget = ExpansionBudget::default();
    expansion
        .expand(
            ctx,
            env.attachment_id,
            &profile,
            "crm_deal",
            env.deal_d1,
            &budget,
        )
        .await
        .unwrap()
}

/// (object slug, record id) traversed directly from the deal root, in
/// traversal order.
fn root_candidates(manifest: &ExpansionManifest, deal_id: Uuid) -> Vec<(String, Uuid)> {
    manifest
        .traversed
        .iter()
        .filter(|e| e.from_object == "crm_deal" && e.from_id == deal_id)
        .map(|e| (e.to_object.clone(), e.to_id))
        .collect()
}

fn file_text(files: &HashMap<String, String>, slug: &str, id: Uuid) -> String {
    files
        .get(&format!("/tinker/{slug}/{id}/index.md"))
        .unwrap_or_else(|| panic!("missing file for {slug}/{id}"))
        .clone()
}

/// Ranking reorders the authorized candidate set by embedding similarity
/// to the focus — and changes nothing about the SET.
#[tokio::test]
async fn ranking_reorders_authorized_candidates_by_similarity() {
    let env = setup().await;
    seed_embedding_provider(&env, "embed-fake", "fake", "available").await;

    let fake = Arc::new(FakeEmbeddingAdapter::new("embed-fake"));
    let mut gw = env.gateway.clone();
    gw.register_embedding("embed-fake", fake.clone());

    // Baseline: deterministic order, no ranker. The mere presence of a
    // registered embedding adapter must not change anything.
    let (base_files, base_manifest) = expand_with(&env, &env.exec_ctx, gw.clone(), None).await;
    assert!(
        base_manifest.ranking.is_none(),
        "no ranker -> no ranking provenance"
    );
    let base_pairs = root_candidates(&base_manifest, env.deal_d1);
    assert!(
        base_pairs.len() >= 2,
        "need >=2 candidates to observe reordering, got {}",
        base_pairs.len()
    );

    // Focus = the LAST baseline candidate's own rendered text: a text is
    // maximally similar to itself, so similarity ranking must put it
    // first — a self-calibrating inversion of the deterministic order.
    let (last_slug, last_id) = base_pairs.last().unwrap().clone();
    let focus = file_text(&base_files, &last_slug, last_id);

    let ranker = SemanticRanker::new(gw.clone(), "embed-fake").with_focus(focus.clone());
    let (rank_files, rank_manifest) = expand_with(&env, &env.exec_ctx, gw, Some(ranker)).await;
    let ranking = rank_manifest
        .ranking
        .clone()
        .expect("ranker attached -> ranking provenance recorded");
    assert_eq!(ranking.provider, "embed-fake");
    assert!(ranking.ranked_records >= 1, "at least the root was ranked");
    assert_eq!(ranking.fallback_records, 0, "fake embedder must not fail");

    let rank_pairs = root_candidates(&rank_manifest, env.deal_d1);

    // The SET is unchanged: ranking reorders, never enlarges or shrinks.
    let mut base_set: Vec<Uuid> = base_pairs.iter().map(|(_, id)| *id).collect();
    let mut rank_set: Vec<Uuid> = rank_pairs.iter().map(|(_, id)| *id).collect();
    base_set.sort();
    rank_set.sort();
    assert_eq!(
        base_set, rank_set,
        "ranking must not change the authorized candidate set"
    );

    // Expected order: candidates sorted by cosine similarity to the focus
    // (stable — ties keep deterministic order), computed with an
    // independent fake over the same texts.
    let probe = FakeEmbeddingAdapter::new("probe");
    let texts: Vec<String> = base_pairs
        .iter()
        .map(|(slug, id)| file_text(&base_files, slug, *id))
        .collect();
    let refs: Vec<&str> = std::iter::once(focus.as_str())
        .chain(texts.iter().map(|s| s.as_str()))
        .collect();
    let vecs = probe.embed(&refs, "test").await.unwrap();
    let focus_v = &vecs[0];
    let mut scored: Vec<(f32, usize)> = vecs[1..]
        .iter()
        .enumerate()
        .map(|(i, v)| (cosine_similarity(focus_v, v), i))
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let expected: Vec<Uuid> = scored.iter().map(|(_, i)| base_pairs[*i].1).collect();
    let actual: Vec<Uuid> = rank_pairs.iter().map(|(_, id)| *id).collect();
    let baseline: Vec<Uuid> = base_pairs.iter().map(|(_, id)| *id).collect();
    assert_eq!(
        actual, expected,
        "traversal must follow embedding-similarity order"
    );
    assert_ne!(
        actual, baseline,
        "ranking must actually reorder (focus was the last baseline candidate)"
    );
    assert_eq!(actual[0], last_id, "the self-similar candidate ranks first");
    // Files are identical — only the traversal order changed.
    assert_eq!(rank_files.len(), base_files.len());
}

/// Authorization runs BEFORE embedding: the embedder only ever sees
/// policy-masked text. The contractor's contact projection allows only
/// `name`, so the contact's email must never reach the embedder — even
/// though the ranker is attached and the embedder is available.
///
/// (Field grants are allowlists per (object, role); an object with no
/// grant rows for a role is documented default-open, so this test pins
/// the masking boundary with an explicit narrow grant.)
#[tokio::test]
async fn embedder_sees_only_policy_masked_text() {
    let env = setup().await;
    seed_embedding_provider(&env, "embed-fake", "fake", "available").await;

    // Contractor may see the contact's name and nothing else.
    {
        let row: (Uuid,) = sqlx::query_as(
            "SELECT id FROM ontology_objects WHERE api_slug = 'crm_contact' AND state = 'active'",
        )
        .fetch_one(&env.owner.0)
        .await
        .unwrap();
        let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
        sqlx::query(
            "INSERT INTO field_grants (organization_id, object_id, role, field_api_name)
             VALUES ($1, $2, 'contractor', 'name')
             ON CONFLICT DO NOTHING",
        )
        .bind(env.org_id)
        .bind(row.0)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    let fake = Arc::new(FakeEmbeddingAdapter::new("embed-fake"));
    let mut gw = env.gateway.clone();
    gw.register_embedding("embed-fake", fake.clone());

    let ranker = SemanticRanker::new(gw.clone(), "embed-fake");
    let (files, manifest) = expand_with(&env, &env.contractor_ctx, gw, Some(ranker)).await;

    let seen = fake.seen_texts();
    assert!(!seen.is_empty(), "the embedder ran on authorized text");
    // Authorized: the contact's name IS embedded (masked render).
    assert!(
        seen.iter().any(|t| t.contains("Alice Anderson")),
        "authorized name must be embedded: {seen:?}"
    );
    // Forbidden: values outside the contractor's projection never reach
    // the embedder — neither the contact email nor the deal amount.
    for forbidden in ["alice@acme.example", "50000"] {
        assert!(
            seen.iter().all(|t| !t.contains(forbidden)),
            "forbidden value {forbidden:?} must never be embedded: {seen:?}"
        );
    }

    // And nothing leaked into the emitted files either.
    let all_text = files.values().cloned().collect::<Vec<_>>().join("\n");
    assert!(
        !all_text.contains("alice@acme.example"),
        "contractor files must never reveal the masked email"
    );
    assert!(
        !all_text.contains("50000"),
        "contractor files must never reveal the raw amount"
    );

    // Ranking still ran (on the authorized subset) and is audited.
    let ranking = manifest.ranking.expect("ranking provenance recorded");
    assert_eq!(ranking.fallback_records, 0);
    assert!(ranking.ranked_records >= 1);
}

/// A dead embedder degrades to deterministic order: the expansion
/// succeeds, the manifest says fallback, and the traversal matches the
/// no-ranker baseline exactly.
#[tokio::test]
async fn embedder_failure_degrades_to_deterministic_order() {
    let env = setup().await;
    seed_embedding_provider(&env, "embed-down", "fake", "available").await;

    let mut gw = env.gateway.clone();
    gw.register_embedding(
        "embed-down",
        Arc::new(UnavailableEmbeddingAdapter::new("embed-down")),
    );

    let (base_files, base_manifest) = expand_with(&env, &env.exec_ctx, gw.clone(), None).await;
    let base_order: Vec<Uuid> = base_manifest.traversed.iter().map(|e| e.to_id).collect();

    let ranker = SemanticRanker::new(gw.clone(), "embed-down").with_focus("anything");
    let (files, manifest) = expand_with(&env, &env.exec_ctx, gw, Some(ranker)).await;
    let ranking = manifest.ranking.expect("ranking provenance recorded");
    assert_eq!(ranking.provider, "embed-down");
    assert_eq!(ranking.ranked_records, 0, "nothing was similarity-ranked");
    assert!(
        ranking.fallback_records >= 1,
        "dead embedder must be recorded as fallback"
    );

    let order: Vec<Uuid> = manifest.traversed.iter().map(|e| e.to_id).collect();
    assert_eq!(
        order, base_order,
        "fallback must reproduce deterministic traversal order"
    );
    assert_eq!(files.len(), base_files.len());
}

/// Placement policy for embeddings: org-controlled record text may not
/// go to a `hosted` provider. The gateway rejects it before any text
/// leaves the process; expansion degrades to deterministic order.
#[tokio::test]
async fn placement_policy_rejects_hosted_embedding_provider() {
    let env = setup().await;
    // A hosted provider under an org-controlled boundary: the row-level
    // placement check must reject it.
    seed_embedding_provider(&env, "public-embed", "hosted", "available").await;

    let fake = Arc::new(FakeEmbeddingAdapter::new("public-embed"));
    let mut gw = ModelGateway::new(env.core.clone(), env.owner.clone());
    gw.register_embedding("public-embed", fake.clone());

    // Direct gateway call fails closed with Forbidden...
    let err = gw
        .embed_texts(&env.exec_ctx, "public-embed", &["Acme Expansion"])
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "hosted endpoint rejected for org-controlled content: {err:?}"
    );
    assert!(
        fake.seen_texts().is_empty(),
        "no text may reach the rejected adapter"
    );

    // ...and expansion degrades instead of failing.
    let ranker = SemanticRanker::new(gw.clone(), "public-embed");
    let (_files, manifest) = expand_with(&env, &env.exec_ctx, gw, Some(ranker)).await;
    let ranking = manifest.ranking.expect("ranking provenance recorded");
    assert!(
        ranking.fallback_records >= 1,
        "placement rejection degrades to deterministic order"
    );
    assert_eq!(ranking.ranked_records, 0);
    assert!(
        fake.seen_texts().is_empty(),
        "placement rejection: adapter never saw any text"
    );
    assert!(
        !manifest.traversed.is_empty(),
        "expansion still traverses deterministically"
    );
}
