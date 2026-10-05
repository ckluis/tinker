//! AI-assisted mapping proposals (post-M8 item 25).
//!
//! The governed lifecycle (draft -> proposed -> approved -> activated) is
//! unchanged: the AI proposer feeds the SAME `proposed` state as the
//! deterministic proposer and can never activate. These tests pin:
//! - happy path: JSON suggestions become `proposed` rows, never activated;
//! - malformed model JSON fails closed with zero rows;
//! - per-suggestion validation: unknown sources/targets and out-of-range
//!   confidences are dropped individually;
//! - privacy: record VALUES never reach the model (only field names);
//! - placement: a `hosted` provider is rejected before any prompt bytes
//!   leave, exactly like record content;
//! - an unavailable provider fails closed with zero rows;
//! - operator mappings win: already-mapped fields are skipped.

mod common;

use common::{contact_target, IngestEnv};
use std::sync::Arc;
use tinker_agents::gateway::{FakeModelAdapter, ModelGateway};
use tinker_core::TinkerError;
use tinker_ingest::pipeline::RunMode;
use uuid::Uuid;

async fn create_contact_stream(env: &IngestEnv) -> Uuid {
    let control = env.pipeline.control();
    let conn = control
        .create_connection(
            &env.ctx,
            tinker_ingest::control::NewConnection {
                kind: "salesforce".to_string(),
                name: "salesforce".to_string(),
                credential_ref: None,
            },
        )
        .await
        .unwrap();
    control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Contact".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap()
        .id
}

async fn insert_schema(env: &IngestEnv, stream_id: Uuid, fields: &[&str]) {
    let schema: Vec<serde_json::Value> = fields
        .iter()
        .map(|f| serde_json::json!({"name": f, "type": "string"}))
        .collect();
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO ingest_schema_version
         (organization_id, stream_id, fingerprint, observed_schema)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .bind("ai-test-fingerprint")
    .bind(serde_json::to_value(&schema).unwrap())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn register_provider(env: &IngestEnv, name: &str, kind: &str, boundary: &str, status: &str) {
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO model_providers
         (organization_id, name, kind, placement_boundary, status)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (organization_id, name)
         DO UPDATE SET kind=EXCLUDED.kind,
                       placement_boundary=EXCLUDED.placement_boundary,
                       status=EXCLUDED.status",
    )
    .bind(env.org_id)
    .bind(name)
    .bind(kind)
    .bind(boundary)
    .bind(status)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

fn gateway_with(
    env: &IngestEnv,
    adapter: FakeModelAdapter,
) -> (ModelGateway, Arc<FakeModelAdapter>) {
    let mut gw = ModelGateway::new(env.core.clone(), env.owner.clone());
    let arc = Arc::new(adapter);
    gw.register("fake-map", arc.clone());
    (gw, arc)
}

async fn mapping_count(env: &IngestEnv, stream_id: Uuid) -> i64 {
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_mapping WHERE organization_id=$1 AND stream_id=$2",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    n
}

async fn proposer_tags(env: &IngestEnv, stream_id: Uuid) -> Vec<String> {
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let rows: Vec<(serde_json::Value,)> = sqlx::query_as(
        "SELECT proposal FROM ingest_mapping
         WHERE organization_id=$1 AND stream_id=$2",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    rows.into_iter()
        .map(|(p,)| {
            p.get("proposer")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

fn valid_canned() -> String {
    serde_json::json!({"mappings": [
        {"source": "Email", "target": "email", "confidence": 0.95, "reason": "same meaning"},
        {"source": "FullName", "target": "name", "confidence": 0.8, "reason": "full name"},
    ]})
    .to_string()
}

#[tokio::test]
async fn ai_proposer_creates_proposed_rows_never_activated() {
    let env = common::setup().await;
    let stream_id = create_contact_stream(&env).await;
    insert_schema(&env, stream_id, &["Email", "FullName", "NoMatchX"]).await;
    register_provider(&env, "fake-map", "private", "org-controlled", "available").await;
    let (gw, _seen) = gateway_with(
        &env,
        FakeModelAdapter::new("fake-map").with_response("map", &valid_canned()),
    );

    let proposals = env
        .pipeline
        .mappings()
        .propose_mappings_ai(&env.ctx, stream_id, "crm_contact", &gw, "fake-map")
        .await
        .unwrap();
    assert_eq!(proposals.len(), 2, "both suggestions accepted");

    // Rows are `proposed` — never activated. Promotion reads only
    // `activated`, so nothing the model suggested can flow yet.
    let proposed = env
        .pipeline
        .mappings()
        .mappings_in_state(&env.ctx, stream_id, "proposed")
        .await
        .unwrap();
    assert_eq!(proposed.len(), 2);
    assert!(env
        .pipeline
        .mappings()
        .mappings_for(&env.ctx, stream_id)
        .await
        .unwrap()
        .is_empty());

    // The proposer is recorded on the row: audit can tell AI from human.
    for tag in proposer_tags(&env, stream_id).await {
        assert!(
            tag.starts_with("ai:fake-map/"),
            "proposer tag must name the AI path: {tag}"
        );
    }

    // The approval gate is unchanged: approve then activate, same as the
    // deterministic proposer.
    let approved = env
        .pipeline
        .mappings()
        .approve_mapping(&env.ctx, proposals[0].mapping_id)
        .await
        .unwrap();
    assert_eq!(approved.state, "approved");
    let activated = env
        .pipeline
        .mappings()
        .activate_mapping(&env.ctx, proposals[0].mapping_id)
        .await
        .unwrap();
    assert_eq!(activated.state, "activated");
}

#[tokio::test]
async fn ai_proposer_rejects_malformed_json() {
    let env = common::setup().await;
    let stream_id = create_contact_stream(&env).await;
    insert_schema(&env, stream_id, &["Email", "FullName"]).await;
    register_provider(&env, "fake-map", "private", "org-controlled", "available").await;
    let (gw, _seen) = gateway_with(
        &env,
        FakeModelAdapter::new("fake-map").with_response("map", "definitely not json {{{"),
    );

    let err = env
        .pipeline
        .mappings()
        .propose_mappings_ai(&env.ctx, stream_id, "crm_contact", &gw, "fake-map")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "malformed model output must fail closed: {err:?}"
    );
    assert_eq!(mapping_count(&env, stream_id).await, 0);
}

#[tokio::test]
async fn ai_proposer_drops_bad_suggestions_individually() {
    let env = common::setup().await;
    let stream_id = create_contact_stream(&env).await;
    insert_schema(&env, stream_id, &["Email", "FullName"]).await;
    register_provider(&env, "fake-map", "private", "org-controlled", "available").await;
    let canned = serde_json::json!({"mappings": [
        {"source": "Email", "target": "email", "confidence": 0.9, "reason": "good"},
        {"source": "Email", "target": "nope_field", "confidence": 0.9, "reason": "unknown target"},
        {"source": "Ghost", "target": "phone", "confidence": 0.9, "reason": "unknown source"},
        {"source": "FullName", "target": "name", "confidence": 99.0, "reason": "bad confidence"},
        {"source": "FullName", "target": "title", "confidence": 0.5, "reason": ""},
    ]})
    .to_string();
    let (gw, _seen) = gateway_with(
        &env,
        FakeModelAdapter::new("fake-map").with_response("map", &canned),
    );

    let proposals = env
        .pipeline
        .mappings()
        .propose_mappings_ai(&env.ctx, stream_id, "crm_contact", &gw, "fake-map")
        .await
        .unwrap();
    assert_eq!(proposals.len(), 1, "only the valid suggestion lands");
    assert_eq!(proposals[0].source_field, "Email");
    assert_eq!(proposals[0].target_field, "email");
}

#[tokio::test]
async fn ai_proposer_never_sends_record_values() {
    let env = common::setup().await;
    common::seed_salesforce(&env);
    let stream_id = create_contact_stream(&env).await;
    // Land real records so distinctive VALUES exist in the database.
    env.pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[contact_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    register_provider(&env, "fake-map", "private", "org-controlled", "available").await;
    let (gw, seen) = gateway_with(
        &env,
        FakeModelAdapter::new("fake-map").with_response("map", &valid_canned()),
    );

    env.pipeline
        .mappings()
        .propose_mappings_ai(&env.ctx, stream_id, "crm_contact", &gw, "fake-map")
        .await
        .unwrap();

    let prompts = seen.seen_prompts();
    assert_eq!(prompts.len(), 1);
    for sentinel in [
        "Alice Anderson",
        "alice@acme.example",
        "Bob Baker",
        "bob@globex.example",
    ] {
        assert!(
            !prompts[0].contains(sentinel),
            "record value {sentinel:?} must never reach the model"
        );
    }
    // The prompt DOES carry the field names — that is the intended input.
    assert!(prompts[0].contains("FullName"));
    assert!(prompts[0].contains("Email"));
}

#[tokio::test]
async fn ai_proposer_placement_blocks_hosted() {
    let env = common::setup().await;
    let stream_id = create_contact_stream(&env).await;
    insert_schema(&env, stream_id, &["Email"]).await;
    // Hosted provider for org-controlled content: rejected at the gateway.
    register_provider(&env, "fake-map", "hosted", "org-controlled", "available").await;
    let (gw, seen) = gateway_with(
        &env,
        FakeModelAdapter::new("fake-map").with_response("map", &valid_canned()),
    );

    let err = env
        .pipeline
        .mappings()
        .propose_mappings_ai(&env.ctx, stream_id, "crm_contact", &gw, "fake-map")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "hosted provider must be rejected: {err:?}"
    );
    assert_eq!(mapping_count(&env, stream_id).await, 0);
    assert!(
        seen.seen_prompts().is_empty(),
        "no prompt bytes may leave on a placement rejection"
    );
}

#[tokio::test]
async fn ai_proposer_unavailable_provider_fails_closed() {
    let env = common::setup().await;
    let stream_id = create_contact_stream(&env).await;
    insert_schema(&env, stream_id, &["Email"]).await;
    register_provider(&env, "fake-map", "private", "org-controlled", "unavailable").await;
    let (gw, seen) = gateway_with(
        &env,
        FakeModelAdapter::new("fake-map").with_response("map", &valid_canned()),
    );

    let err = env
        .pipeline
        .mappings()
        .propose_mappings_ai(&env.ctx, stream_id, "crm_contact", &gw, "fake-map")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Internal(_)),
        "disabled provider must fail: {err:?}"
    );
    assert_eq!(mapping_count(&env, stream_id).await, 0);
    assert!(seen.seen_prompts().is_empty());
}

#[tokio::test]
async fn ai_proposer_skips_already_mapped_fields() {
    let env = common::setup().await;
    let stream_id = create_contact_stream(&env).await;
    insert_schema(&env, stream_id, &["Email", "FullName"]).await;
    register_provider(&env, "fake-map", "private", "org-controlled", "available").await;
    // Operator mapping wins: Email is already mapped before the AI runs.
    env.pipeline
        .mappings()
        .put_mapping(&env.ctx, stream_id, "Email", "crm_contact", "email")
        .await
        .unwrap();
    let (gw, seen) = gateway_with(
        &env,
        FakeModelAdapter::new("fake-map").with_response("map", &valid_canned()),
    );

    let proposals = env
        .pipeline
        .mappings()
        .propose_mappings_ai(&env.ctx, stream_id, "crm_contact", &gw, "fake-map")
        .await
        .unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].source_field, "FullName");
    // The already-mapped field is not even offered to the model.
    assert!(!seen.seen_prompts()[0].contains("\"Email\""));
}
