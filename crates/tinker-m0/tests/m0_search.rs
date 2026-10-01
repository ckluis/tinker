//! M0 search exits: identical permission tests for every backend, PII
//! rejection at the index boundary, TIN failing closed when absent.

mod common;

use tinker_core::TinkerError;
use tinker_search::{
    tin::TinSearchBackend, IndexChange, NativeSearchBackend, SearchBackend, SearchPlan,
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

/// The permission contract EVERY backend must satisfy. New backends (TIN)
/// run this same suite; the M0 exit demands identical results.
async fn permission_suite<B: SearchBackend>(backend: &B, env: &common::Env) {
    let ctx_a = common::new_org(env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(env, &common::uniq("orgb")).await;
    let obj_a = Uuid::now_v7();
    let obj_b = Uuid::now_v7();
    let rec_a = Uuid::now_v7();
    let rec_b = Uuid::now_v7();

    // Same text indexed in both orgs.
    backend
        .index_change(&ctx_a, &change(obj_a, rec_a, "Acme renewal contract"))
        .await
        .unwrap();
    backend
        .index_change(&ctx_b, &change(obj_b, rec_b, "Acme renewal contract"))
        .await
        .unwrap();

    // Org A sees only its own hit.
    let page = backend
        .search(
            &ctx_a,
            &SearchPlan {
                text_query: "Acme renewal".into(),
                object_id: None,
                limit: 10,
                row_policies: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(page.hits.len(), 1, "backend {}", backend.name());
    assert_eq!(page.hits[0].record_id, rec_a);
    assert_eq!(page.hits[0].object_id, obj_a);

    // Org B sees only its own hit.
    let page = backend
        .search(
            &ctx_b,
            &SearchPlan {
                text_query: "Acme renewal".into(),
                object_id: None,
                limit: 10,
                row_policies: vec![],
            },
        )
        .await
        .unwrap();
    assert_eq!(page.hits.len(), 1, "backend {}", backend.name());
    assert_eq!(page.hits[0].record_id, rec_b);

    // Scoping to a foreign object id yields nothing.
    let page = backend
        .search(
            &ctx_a,
            &SearchPlan {
                text_query: "Acme renewal".into(),
                object_id: Some(obj_b),
                limit: 10,
                row_policies: vec![],
            },
        )
        .await
        .unwrap();
    assert!(page.hits.is_empty(), "backend {}", backend.name());

    // Empty query is rejected, not runaway.
    let err = backend
        .search(
            &ctx_a,
            &SearchPlan {
                text_query: "  ".into(),
                object_id: None,
                limit: 10,
                row_policies: vec![],
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
}

#[tokio::test]
async fn native_backend_passes_permission_suite() {
    let env = common::setup().await;
    let backend = NativeSearchBackend::new(env.core.clone());
    permission_suite(&backend, &env).await;
}

#[tokio::test]
async fn search_index_rejects_pii_plaintext() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let backend = NativeSearchBackend::new(env.core.clone());

    for class in ["pii.name", "PII.EMAIL", "secret.api_key", "pii"] {
        let mut c = change(Uuid::now_v7(), Uuid::now_v7(), "Maya Chen");
        c.storage_classes = vec![class.into()];
        let err = backend.index_change(&ctx, &c).await.unwrap_err();
        assert!(
            matches!(err, TinkerError::Forbidden(_)),
            "class {class} must be rejected"
        );
    }

    // Non-PII classes still index fine.
    backend
        .index_change(&ctx, &change(Uuid::now_v7(), Uuid::now_v7(), "public text"))
        .await
        .unwrap();
}

#[tokio::test]
async fn tin_backend_fails_closed_when_extension_absent() {
    let env = common::setup().await;
    // The TIN extension is not installed on this database; the adapter must
    // refuse to construct instead of silently degrading.
    let err = TinSearchBackend::connect(env.core.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));

    // And the core database provably has no tin access method.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_am WHERE amname='tin'")
        .fetch_one(&env.core_owner)
        .await
        .unwrap();
    assert_eq!(n, 0);
}
