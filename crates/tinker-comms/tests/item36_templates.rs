//! Item 36: governed templates — CRUD/versioning, scoping, sandbox,
//! template-send through the M5 provider trait.

mod common;

use common::*;
use tinker_comms::{FakeEmailProvider, TemplateSender, TemplateStore};

fn store_for(e: &common::Item36Env) -> TemplateStore {
    TemplateStore::new(e.core.clone())
}

#[tokio::test]
async fn template_crud_and_versioning() {
    let e = setup().await;
    let store = store_for(&e);

    let created = store
        .create(
            &e.ctx_a,
            "welcome",
            "Hi {{ user.name }}",
            "Dear {{ user.name }},",
        )
        .await
        .unwrap();
    assert_eq!(created.name, "welcome");
    assert_eq!(created.current_version, 1);
    assert_eq!(created.status, "active");

    let updated = store
        .update(
            &e.ctx_a,
            created.id,
            "Hi {{ user.name }}!",
            "Dear {{ user.name }}, welcome!",
        )
        .await
        .unwrap();
    assert_eq!(updated.current_version, 2);

    // Current version renders the new text; v1 is immutable.
    let cur = store.get(&e.ctx_a, "welcome").await.unwrap();
    assert_eq!(cur.version, 2);
    assert!(cur.body.contains("welcome!"));
    let v1 = store.get_version(&e.ctx_a, created.id, 1).await.unwrap();
    assert_eq!(v1.version, 1);
    assert!(!v1.body.contains("welcome!"));

    // Case-insensitive get.
    let ci = store.get(&e.ctx_a, "WELCOME").await.unwrap();
    assert_eq!(ci.template_id, created.id);

    let list = store.list(&e.ctx_a).await.unwrap();
    assert_eq!(list.len(), 1);

    // Archive: get fails closed, update rejected, list shows archived.
    store.archive(&e.ctx_a, created.id).await.unwrap();
    let err = store.get(&e.ctx_a, "welcome").await.unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::NotFound(_)));
    let err = store
        .update(&e.ctx_a, created.id, "s", "b")
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::Validation(_)));
    let list = store.list(&e.ctx_a).await.unwrap();
    assert_eq!(list[0].status, "archived");
}

#[tokio::test]
async fn template_names_scoped_per_org() {
    let e = setup().await;
    let store = store_for(&e);

    store.create(&e.ctx_a, "Welcome", "s", "b").await.unwrap();
    // Same org, different case: unavailable (generic message, no oracle
    // games needed within an org, but the message stays uniform).
    let err = store
        .create(&e.ctx_a, "welcome", "s", "b")
        .await
        .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::Validation(ref m) if m == "template name unavailable"),
        "got {err:?}"
    );
    // Other org: same name is fine, and invisible across the boundary.
    store.create(&e.ctx_b, "Welcome", "s", "b").await.unwrap();
    let err = store.get(&e.ctx_b, "nope").await.unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::NotFound(_)));
    // Org B cannot see org A's template rows at all.
    let list_b = store.list(&e.ctx_b).await.unwrap();
    assert_eq!(list_b.len(), 1);
    assert_eq!(list_b[0].name, "Welcome");
}

#[tokio::test]
async fn template_name_and_field_validation() {
    let e = setup().await;
    let store = store_for(&e);
    for bad in [
        "",
        "has space!",
        "slash/x",
        "-leading",
        ".leading",
        "semi;colon",
    ] {
        let err = store.create(&e.ctx_a, bad, "s", "b").await.unwrap_err();
        assert!(
            matches!(err, tinker_core::TinkerError::Validation(_)),
            "name {bad:?} should be rejected"
        );
    }
    for ok in ["a", "welcome-email", "order.confirm_v2", "A1_-x.y"] {
        store.create(&e.ctx_a, ok, "s", "b").await.unwrap();
    }
    let err = store
        .create(&e.ctx_a, "toolong-subject", &"s".repeat(501), "b")
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::Validation(_)));
    let err = store
        .create(&e.ctx_a, "empty-body", "s", "")
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::Validation(_)));
}

#[tokio::test]
async fn template_send_renders_and_dedupes() {
    let e = setup().await;
    let provider = FakeEmailProvider::new();
    let sender = TemplateSender::new(provider, e.core.clone());
    sender
        .store()
        .create(
            &e.ctx_a,
            "order-shipped",
            "Order {{ order.id }} shipped{% if order.express %} (express){% endif %}",
            "Hi {{ user.name }},{% for item in order.items %}\n- {{ item }}{% endfor %}",
        )
        .await
        .unwrap();

    let ctx = serde_json::json!({
        "user": {"name": "Ada"},
        "order": {"id": "A-42", "express": true, "items": ["book", "pen"]},
    });
    let receipt = sender
        .send(&e.ctx_a, "order-shipped", e.actor_a, &ctx)
        .await
        .unwrap();
    // Deterministic idempotency key: same context -> provider dedupes.
    let receipt2 = sender
        .send(&e.ctx_a, "order-shipped", e.actor_a, &ctx)
        .await
        .unwrap();
    assert_eq!(receipt, receipt2);
    assert_eq!(sender.provider().actual_sends(), 1);

    let key = receipt.provider_message_id.strip_prefix("fake-").unwrap();
    let body = sender.provider().body_for(key).unwrap();
    assert!(body.contains("Hi Ada,"), "body: {body}");
    assert!(body.contains("- book"), "body: {body}");
    assert!(body.contains("- pen"), "body: {body}");
    let subject = sender.provider().subject_for(key).unwrap();
    assert_eq!(subject, "Order A-42 shipped (express)");

    // Different context -> different key -> a real second send.
    let ctx2 = serde_json::json!({
        "user": {"name": "Bo"},
        "order": {"id": "A-43", "express": false, "items": []},
    });
    let receipt3 = sender
        .send(&e.ctx_a, "order-shipped", e.actor_a, &ctx2)
        .await
        .unwrap();
    assert_ne!(receipt3, receipt);
    assert_eq!(sender.provider().actual_sends(), 2);
    // The conditional rendered the non-express branch (no "(express)").
    let key3 = receipt3.provider_message_id.strip_prefix("fake-").unwrap();
    let subject3 = sender.provider().subject_for(key3).unwrap();
    assert_eq!(subject3, "Order A-43 shipped");
}

#[tokio::test]
async fn template_send_cross_org_fails_closed() {
    let e = setup().await;
    let provider = FakeEmailProvider::new();
    let sender = TemplateSender::new(provider, e.core.clone());
    sender
        .store()
        .create(&e.ctx_a, "private", "s {{ x }}", "b {{ x }}")
        .await
        .unwrap();

    // Org B's context cannot see (let alone send) org A's template.
    let err = sender
        .send(
            &e.ctx_b,
            "private",
            e.actor_b,
            &serde_json::json!({"x": "1"}),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::NotFound(_)),
        "got {err:?}"
    );
    assert_eq!(sender.provider().actual_sends(), 0);
}

#[tokio::test]
async fn template_send_malicious_template_fails_closed() {
    let e = setup().await;
    let provider = FakeEmailProvider::new();
    let sender = TemplateSender::new(provider, e.core.clone());
    // Stored fine (it's just text), but rendering fails closed: no
    // expression evaluation exists, so `1+1` is a BadTag, not math.
    sender
        .store()
        .create(
            &e.ctx_a,
            "evil",
            "{{ 1+1 }}",
            "{% for x in [1] %}y{% endfor %}",
        )
        .await
        .unwrap();

    let err = sender
        .send(&e.ctx_a, "evil", e.actor_a, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::Validation(_)),
        "got {err:?}"
    );
    assert_eq!(
        sender.provider().actual_sends(),
        0,
        "a template that fails to render must never send"
    );

    // Missing variable is also fail-closed at send time.
    sender
        .store()
        .create(&e.ctx_a, "needy", "Hi {{ user.name }}", "body")
        .await
        .unwrap();
    let err = sender
        .send(&e.ctx_a, "needy", e.actor_a, &serde_json::json!({}))
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::Validation(_)));
    assert_eq!(sender.provider().actual_sends(), 0);
}
