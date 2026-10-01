//! Item 48: embedding-based semantic ranking for record search.
//!
//! The decorator (`tinker_search::SemanticSearchBackend`) reranks the
//! permission-filtered candidate set by cosine similarity to the query
//! embedding. Invariants pinned here:
//!
//! 1. Relevance: a fixed corpus with a known-good top-1; the full hit
//!    order matches an independently recomputed cosine order.
//! 2. Permissions BEFORE ranking: a row-policy-hidden record that would
//!    be top-1 never surfaces AND its text never reaches the embedder
//!    (the fake records every text it embeds — no oracle).
//! 3. No silent fallback: an unconfigured provider is a teaching error,
//!    never an unranked page presented as ranked.
//! 4. Vector cache: second query serves from `record_embeddings`
//!    (no re-embed); changed text re-embeds exactly the stale row.
//! 5. Tenant isolation: org B sees nothing of org A's corpus or vectors.
//!
//! Everything runs against `FakeEmbeddingAdapter` (deterministic hashed
//! bag-of-words, documented in the gateway): no network, no API key,
//! suite green offline.

mod common;

use common::*;
use std::sync::Arc;
use tinker_agents::gateway::{
    cosine_similarity, EmbeddingAdapter, FakeEmbeddingAdapter, ModelGateway,
};
use tinker_core::{CompiledRowPolicy, Param, TenantContext};
use tinker_db::OwnerDb;
use tinker_search::{
    IndexChange, NativeSearchBackend, SearchBackend, SearchPlan, SemanticSearchBackend,
};
use uuid::Uuid;

fn change(object_id: Uuid, record_id: Uuid, text: &str) -> IndexChange {
    IndexChange {
        object_id,
        record_id,
        text: text.into(),
        field_versions: serde_json::json!({}),
        storage_classes: vec!["text".into()],
    }
}

// Every doc contains every query lexeme ("alpha", "report") so the
// lexical prefilter (plainto_tsquery AND) returns all three; they differ
// only in focus. Under the fake's bag-of-words cosine the most focused
// doc is unambiguously top-1. DOC_FOCUSED differs from QUERY so the
// no-oracle test can tell query-embedding apart from doc-embedding.
const QUERY: &str = "alpha report";
const DOC_FOCUSED: &str = "alpha report summary";
const DOC_MID: &str = "alpha report covering quarterly server migration timelines";
const DOC_LONG: &str = "alpha report covering quarterly server migration timelines \
    and database index rebuild procedures for the weekend maintenance window";

fn test_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

struct SemanticEnv {
    ctx: TenantContext,
    fake: Arc<FakeEmbeddingAdapter>,
    backend: SemanticSearchBackend,
    obj: Uuid,
    focused: Uuid,
    mid: Uuid,
    long: Uuid,
}

async fn seed_provider(env: &common::Env, ctx: &TenantContext) {
    // Same pattern as m7_expand_ranking: write through the tenant tx so
    // the model_providers RLS policy sees the org.
    let mut tx = env.core.tenant_tx(ctx).await.expect("tenant tx");
    sqlx::query(
        "INSERT INTO model_providers (organization_id, name, kind, placement_boundary, status) \
         VALUES ($1, 'embed-fake', 'fake', 'org-controlled', 'available') \
         ON CONFLICT (organization_id, name) DO UPDATE \
         SET kind = EXCLUDED.kind, status = EXCLUDED.status",
    )
    .bind(ctx.organization_id.0)
    .execute(&mut *tx)
    .await
    .expect("provider seed");
    tx.commit().await.expect("commit");
}

/// Fresh org + provider row + gateway with the fake registered + corpus
/// indexed through the DECORATOR (the real write path: lazy, no embed).
async fn setup_semantic(env: &common::Env, slug: &str) -> SemanticEnv {
    let ctx = new_org(env, &uniq(slug)).await;
    seed_provider(env, &ctx).await;
    let owner = OwnerDb::connect(&test_env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("owner connect");

    let fake = Arc::new(FakeEmbeddingAdapter::new("embed-fake"));
    let mut gateway = ModelGateway::new(env.core.clone(), owner);
    gateway.register_embedding("embed-fake", fake.clone());

    let inner = Arc::new(NativeSearchBackend::new(env.core.clone()));
    let backend = SemanticSearchBackend::new(inner, env.core.clone(), gateway, "embed-fake");

    let obj = Uuid::now_v7();
    let focused = Uuid::now_v7();
    let mid = Uuid::now_v7();
    let long = Uuid::now_v7();
    for (id, text) in [(focused, DOC_FOCUSED), (mid, DOC_MID), (long, DOC_LONG)] {
        backend
            .index_change(&ctx, &change(obj, id, text))
            .await
            .expect("index");
    }
    SemanticEnv {
        ctx,
        fake,
        backend,
        obj,
        focused,
        mid,
        long,
    }
}

async fn search_all(
    senv: &SemanticEnv,
    policies: Vec<CompiledRowPolicy>,
) -> tinker_search::SearchPage {
    senv.backend
        .search(
            &senv.ctx,
            &SearchPlan {
                text_query: QUERY.into(),
                object_id: Some(senv.obj),
                limit: 10,
                row_policies: policies,
            },
        )
        .await
        .expect("search")
}

/// The relevance probe: known-good top-1 (the focused doc) plus the full
/// order matching an independently recomputed cosine ranking.
#[tokio::test]
async fn semantic_top1_is_most_focused_doc() {
    let env = setup().await;
    let senv = setup_semantic(&env, "semprobe").await;
    let page = search_all(&senv, vec![]).await;

    assert_eq!(page.backend, "native+semantic");
    let rep = page
        .semantic
        .as_ref()
        .expect("semantic page must carry a report");
    assert_eq!(rep.candidates, 3);
    assert_eq!(rep.cache_misses, 3, "cold cache embeds every candidate");
    assert_eq!(rep.cache_hits, 0);
    eprintln!(
        "item48 probe: candidates={} hits={} misses={} embed_ms={} rank_ms={} total_ms={}",
        rep.candidates, rep.cache_hits, rep.cache_misses, rep.embed_ms, rep.rank_ms, rep.total_ms
    );

    // Known-good top-1.
    assert_eq!(page.hits.len(), 3);
    assert_eq!(page.hits[0].record_id, senv.focused);

    // Independent recomputation with a SEPARATE fake instance (so the
    // backend's fake keeps clean seen_texts accounting): same
    // deterministic algorithm, cosine order must match exactly.
    let probe = FakeEmbeddingAdapter::new("recompute");
    let docs = [DOC_FOCUSED, DOC_MID, DOC_LONG];
    let ids = [senv.focused, senv.mid, senv.long];
    let mut inputs: Vec<&str> = vec![QUERY];
    inputs.extend(docs);
    let vecs = probe.embed(&inputs, "probe").await.unwrap();
    let mut expected: Vec<(usize, f32)> = (0..3)
        .map(|i| (i, cosine_similarity(&vecs[0], &vecs[i + 1])))
        .collect();
    expected.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    for (pos, (doc_idx, score)) in expected.iter().enumerate() {
        assert_eq!(
            page.hits[pos].record_id, ids[*doc_idx],
            "hit {pos} order must match cosine order"
        );
        assert!(
            (page.hits[pos].rank - score).abs() < 1e-6,
            "hit rank must be the cosine score"
        );
    }
    // Scores strictly descend (no ties in this corpus).
    assert!(page.hits[0].rank > page.hits[1].rank);
    assert!(page.hits[1].rank > page.hits[2].rank);
}

/// Row-policy-hidden record: the would-be top-1 never surfaces via
/// ranking, and its text NEVER reaches the embedder (no oracle).
#[tokio::test]
async fn hidden_record_never_embedded_or_surfaced() {
    let env = setup().await;
    let senv = setup_semantic(&env, "semhidden").await;
    // Hide exactly the focused doc (the known top-1).
    let policy = CompiledRowPolicy {
        object_id: senv.obj,
        sql: "(object_id <> {{p1}} OR (record_id <> {{p2}}))".to_string(),
        params: vec![Param::Uuid(senv.obj), Param::Uuid(senv.focused)],
    };
    let page = search_all(&senv, vec![policy]).await;

    assert_eq!(page.hits.len(), 2, "hidden record must not surface");
    assert!(
        !page.hits.iter().any(|h| h.record_id == senv.focused),
        "hidden record id must be absent"
    );
    let seen = senv.fake.seen_texts();
    assert!(
        !seen.iter().any(|t| t == DOC_FOCUSED),
        "hidden record text must never reach the embedder; seen={seen:?}"
    );
    // The query itself and the two visible docs were embedded.
    assert!(seen.iter().any(|t| t == QUERY));
    assert!(seen.iter().any(|t| t == DOC_MID));
}

/// No provider configured: a teaching error, never a silently unranked
/// page presented as ranked.
#[tokio::test]
async fn unconfigured_provider_is_teaching_error() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("semnoteach")).await;
    let owner = OwnerDb::connect(&test_env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("owner connect");
    // No model_providers row at all.
    let gateway = ModelGateway::new(env.core.clone(), owner);
    let inner = Arc::new(NativeSearchBackend::new(env.core.clone()));
    let backend = SemanticSearchBackend::new(inner, env.core.clone(), gateway, "nope-missing");

    let obj = Uuid::now_v7();
    backend
        .index_change(&ctx, &change(obj, Uuid::now_v7(), "alpha report"))
        .await
        .unwrap();
    let err = backend
        .search(
            &ctx,
            &SearchPlan {
                text_query: QUERY.into(),
                object_id: Some(obj),
                limit: 10,
                row_policies: vec![],
            },
        )
        .await
        .expect_err("unconfigured provider must fail, not silently rank");
    let msg = err.to_string();
    assert!(
        msg.contains("semantic ranking unavailable"),
        "teaching error names the failure: {msg}"
    );
    assert!(
        msg.contains("TINKER_PROVIDER_NOPE_MISSING_"),
        "teaching error names the env prefix: {msg}"
    );
    assert!(
        !msg.contains("sk-") && !msg.contains("API_KEY="),
        "teaching error leaks no secret material: {msg}"
    );
}

/// Second identical query: vectors come from `record_embeddings`, the
/// embedder sees only the query text.
#[tokio::test]
async fn embeddings_cached_across_queries() {
    let env = setup().await;
    let senv = setup_semantic(&env, "semcache").await;

    let p1 = search_all(&senv, vec![]).await;
    let r1 = p1.semantic.as_ref().unwrap();
    assert_eq!((r1.cache_hits, r1.cache_misses), (0, 3));
    let seen_after_first = senv.fake.seen_texts().len();

    let p2 = search_all(&senv, vec![]).await;
    let r2 = p2.semantic.as_ref().unwrap();
    assert_eq!((r2.cache_hits, r2.cache_misses), (3, 0));
    eprintln!(
        "item48 cache: warm query embed_ms={} rank_ms={} total_ms={}",
        r2.embed_ms, r2.rank_ms, r2.total_ms
    );
    // Only the query text was embedded on the warm query — no candidate
    // text re-embedded.
    assert_eq!(
        senv.fake.seen_texts().len(),
        seen_after_first + 1,
        "warm query embeds the query text only"
    );
    // Same order, cache-backed.
    assert_eq!(
        p1.hits.iter().map(|h| h.record_id).collect::<Vec<_>>(),
        p2.hits.iter().map(|h| h.record_id).collect::<Vec<_>>()
    );
}

/// Changed text re-embeds exactly the stale row (exact staleness bound,
/// not TTL).
#[tokio::test]
async fn stale_cache_reembedded_on_text_change() {
    let env = setup().await;
    let senv = setup_semantic(&env, "semstale").await;
    search_all(&senv, vec![]).await; // warm the cache

    // Rewrite the mid doc (still lexically matching: keeps alpha+report).
    let new_mid = "alpha report rewritten to discuss only widget inventory counts";
    senv.backend
        .index_change(&senv.ctx, &change(senv.obj, senv.mid, new_mid))
        .await
        .unwrap();

    let page = search_all(&senv, vec![]).await;
    let rep = page.semantic.as_ref().unwrap();
    assert_eq!(
        (rep.cache_hits, rep.cache_misses),
        (2, 1),
        "exactly the changed record re-embeds"
    );
    let seen = senv.fake.seen_texts();
    assert!(seen.iter().any(|t| t == new_mid), "new text was embedded");
    assert_eq!(
        seen.iter().filter(|t| *t == DOC_MID).count(),
        1,
        "old text embedded exactly once (the initial warm), never re-embedded"
    );
}

/// Tenant isolation through the decorator: org B (own provider row, own
/// corpus) sees only its own hits; org C (provider row, no corpus) sees
/// empty — never org A's records or vectors.
#[tokio::test]
async fn tenant_isolation_holds_through_decorator() {
    let env = setup().await;
    let senv = setup_semantic(&env, "semtenanta").await;

    // Org B: own provider row + own corpus -> only its own hits.
    let senv_b = setup_semantic(&env, "semtenantb").await;
    let page_b = search_all(&senv_b, vec![]).await;
    assert_eq!(page_b.hits.len(), 3);
    for id in [senv.focused, senv.mid, senv.long] {
        assert!(
            !page_b.hits.iter().any(|h| h.record_id == id),
            "org A's record must never appear for org B"
        );
    }
    assert_eq!(page_b.hits[0].record_id, senv_b.focused);

    // Org C: provider row but no corpus -> empty page, not A's data, and
    // the vector-cache fetch (org-scoped) finds nothing.
    let ctx_c = new_org(&env, &uniq("semtenantc")).await;
    seed_provider(&env, &ctx_c).await;
    let owner = OwnerDb::connect(&test_env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("owner connect");
    let mut gateway_c = ModelGateway::new(env.core.clone(), owner);
    let fake_c = Arc::new(FakeEmbeddingAdapter::new("embed-fake"));
    gateway_c.register_embedding("embed-fake", fake_c);
    let backend_c = SemanticSearchBackend::new(
        Arc::new(NativeSearchBackend::new(env.core.clone())),
        env.core.clone(),
        gateway_c,
        "embed-fake",
    );
    let page_c = backend_c
        .search(
            &ctx_c,
            &SearchPlan {
                text_query: QUERY.into(),
                object_id: None,
                limit: 10,
                row_policies: vec![],
            },
        )
        .await
        .expect("empty-corpus search");
    assert!(page_c.hits.is_empty(), "org C must see no hits");
    assert_eq!(page_c.semantic.as_ref().unwrap().candidates, 0);
}
