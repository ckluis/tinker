//! AI-assisted mapping proposals, suggestion-only (item 49).
//!
//! Unlike post-M8 item 25 (`propose_mappings_ai`: stream-bound, persists
//! `proposed` rows), `suggest_mappings` takes an ad-hoc source schema
//! (field names + sample values) and returns ranked proposals WITHOUT
//! persisting anything. These tests pin:
//! - happy path: ranked proposals (confidence desc, deterministic
//!   tiebreak) plus the accounted model call carried in the report;
//! - no writes: `ingest_mapping` / `ingest_schema_version` row counts for
//!   the org are unchanged (and zero), while the mandated M7 cost record
//!   DID land with the live token counts;
//! - teaching errors, never empty/confident lists: empty source schema,
//!   unknown target slug, and zero usable suggestions after
//!   per-suggestion validation all fail with the problem named;
//! - malformed model JSON fails closed (still accounted: the call
//!   happened, so the ledger must show it);
//! - placement: a `hosted` provider is rejected before any prompt bytes
//!   leave, and nothing is accounted because no call happened;
//! - sample values DO reach the model — that is the feature (they are
//!   prompt bytes, placement-gated) — bounded and truncated;
//! - accounting failure fails closed: a ledger write error never yields
//!   silent unaccounted proposals.
//!
//! All model access goes through `FakeModelAdapter` (or a tiny test-only
//! adapter): no network, no API key, green with no provider configured.

mod common;

use common::IngestEnv;
use std::sync::{Arc, Mutex};
use tinker_agents::gateway::{Completion, FakeModelAdapter, ModelAdapter, ModelGateway};
use tinker_core::TinkerError;
use tinker_ingest::mapping::{MappingSource, MappingSourceField};

fn field(name: &str, samples: &[serde_json::Value]) -> MappingSourceField {
    MappingSourceField {
        name: name.to_string(),
        field_type: Some("string".to_string()),
        samples: samples.to_vec(),
    }
}

fn src(fields: Vec<MappingSourceField>) -> MappingSource {
    MappingSource { fields }
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
    provider: &str,
    adapter: Arc<dyn ModelAdapter>,
) -> (ModelGateway, Arc<dyn ModelAdapter>) {
    let mut gw = ModelGateway::new(env.core.clone(), env.owner.clone());
    gw.register(provider, adapter.clone());
    (gw, adapter)
}

fn fake_gw(env: &IngestEnv, provider: &str, canned: &str) -> (ModelGateway, Arc<FakeModelAdapter>) {
    let adapter = Arc::new(FakeModelAdapter::new(provider).with_response("map-suggest", canned));
    let (gw, _) = gateway_with(env, provider, adapter.clone());
    (gw, adapter)
}

/// (mapping rows, schema-version rows) for this org.
async fn write_counts(env: &IngestEnv) -> (i64, i64, i64, i64) {
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (m,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM ingest_mapping WHERE organization_id=$1")
            .bind(env.org_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let (s,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM ingest_schema_version WHERE organization_id=$1")
            .bind(env.org_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    // Ontology is platform-scoped (owner DB): the proposer must not
    // create objects/fields as a side effect either.
    let (o,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ontology_objects")
        .fetch_one(&env.owner.0)
        .await
        .unwrap();
    let (f,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ontology_fields")
        .fetch_one(&env.owner.0)
        .await
        .unwrap();
    (m, s, o, f)
}

/// Cost rows for (org, model_ref): the mandated M7 accounting write.
async fn cost_rows(env: &IngestEnv, model_ref: &str) -> Vec<(i64, i64)> {
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let rows: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT input_tokens, output_tokens FROM cost_records
         WHERE organization_id=$1 AND model_ref=$2",
    )
    .bind(env.org_id)
    .bind(model_ref)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    rows
}

async fn suggest(
    env: &IngestEnv,
    gw: &ModelGateway,
    provider: &str,
    source: &MappingSource,
    target: &str,
) -> Result<tinker_ingest::mapping::MappingSuggestions, TinkerError> {
    env.pipeline
        .mappings()
        .suggest_mappings(&env.ctx, source, target, gw, provider)
        .await
}

fn ranked_canned() -> String {
    // Deliberately unordered; two entries tie at 0.8 to pin the
    // deterministic tiebreak (source name ascending).
    serde_json::json!({"mappings": [
        {"source": "Phone", "target": "phone", "confidence": 0.7, "reason": "both phone numbers"},
        {"source": "Email", "target": "email", "confidence": 0.95, "reason": "same meaning"},
        {"source": "FullName", "target": "name", "confidence": 0.8, "reason": "person name"},
        {"source": "JobTitle", "target": "title", "confidence": 0.8, "reason": "job title"},
    ]})
    .to_string()
}

fn ranked_source() -> MappingSource {
    src(vec![
        field("Email", &[serde_json::json!("a@acme.example")]),
        field("FullName", &[serde_json::json!("Alice Anderson")]),
        field("Phone", &[serde_json::json!("+1-555-0100")]),
        field("JobTitle", &[serde_json::json!("VP Sales")]),
    ])
}

#[tokio::test]
async fn suggest_happy_path_is_ranked_with_accounted_call() {
    let env = common::setup().await;
    let provider = "fake-sg-rank";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    let (gw, seen) = fake_gw(&env, provider, &ranked_canned());

    let report = suggest(&env, &gw, provider, &ranked_source(), "crm_contact")
        .await
        .unwrap();

    // Ranked: confidence desc, tie broken by source name ascending.
    let got: Vec<(&str, f64)> = report
        .proposals
        .iter()
        .map(|p| (p.source_field.as_str(), p.confidence))
        .collect();
    assert_eq!(
        got,
        vec![
            ("Email", 0.95),
            ("FullName", 0.8),
            ("JobTitle", 0.8),
            ("Phone", 0.7),
        ],
        "proposals must be confidence-desc with a deterministic tiebreak"
    );
    assert_eq!(report.proposals[0].target_field, "email");
    assert!(!report.proposals[0].reason.is_empty());
    assert_eq!(report.target_object, "crm_contact");
    assert_eq!(report.provider, provider);
    assert_eq!(report.model_ref, format!("fake/{provider}"));

    // The report carries the accounted call: live token counts from the
    // fake adapter (prompt.len()/4), not estimates.
    let prompts = seen.seen_prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(report.tokens_in, prompts[0].len() as u64 / 4);
    assert!(report.tokens_out > 0);

    // The report IS the CLI/API response schema — pin its JSON shape.
    let v = serde_json::to_value(&report).unwrap();
    for key in [
        "target_object",
        "provider",
        "model_ref",
        "tokens_in",
        "tokens_out",
        "proposals",
    ] {
        assert!(v.get(key).is_some(), "report JSON must carry {key}");
    }
    let p0 = &v["proposals"][0];
    for key in ["source_field", "target_field", "confidence", "reason"] {
        assert!(p0.get(key).is_some(), "proposal JSON must carry {key}");
    }
}

#[tokio::test]
async fn suggest_writes_nothing_but_the_cost_record() {
    let env = common::setup().await;
    let provider = "fake-sg-nowrite";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    let (gw, _) = fake_gw(&env, provider, &ranked_canned());

    let before = write_counts(&env).await;
    assert_eq!((before.0, before.1), (0, 0));

    let report = suggest(&env, &gw, provider, &ranked_source(), "crm_contact")
        .await
        .unwrap();

    // Zero writes to schema/record/ontology tables: the proposer has no
    // code path that persists mappings, schemas, ontology rows, or records.
    // (Ontology counts are nonzero from pack installs; the invariant is
    // zero DELTA.)
    let after = write_counts(&env).await;
    assert_eq!(
        after, before,
        "suggest must not write mappings, schemas, or ontology rows"
    );

    // The ONE mandated write: the M7 cost record with the live counts.
    let rows = cost_rows(&env, &format!("fake/{provider}")).await;
    assert_eq!(rows.len(), 1, "exactly one cost record for the call");
    assert_eq!(rows[0].0, report.tokens_in as i64);
    assert_eq!(rows[0].1, report.tokens_out as i64);
}

#[tokio::test]
async fn suggest_empty_source_schema_is_a_teaching_error() {
    let env = common::setup().await;
    let provider = "fake-sg-empty";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    let (gw, seen) = fake_gw(&env, provider, &ranked_canned());

    let err = suggest(&env, &gw, provider, &src(vec![]), "crm_contact")
        .await
        .unwrap_err();
    match &err {
        TinkerError::Validation(msg) => assert!(
            msg.contains("no fields"),
            "teaching error must name the problem: {msg}"
        ),
        other => panic!("empty schema must be a teaching error, got {other:?}"),
    }
    // No model call, no accounting: fail before anything leaves.
    assert!(seen.seen_prompts().is_empty());
    assert!(cost_rows(&env, &format!("fake/{provider}"))
        .await
        .is_empty());
}

#[tokio::test]
async fn suggest_unknown_target_is_a_teaching_error() {
    let env = common::setup().await;
    let provider = "fake-sg-unknown";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    let (gw, seen) = fake_gw(&env, provider, &ranked_canned());

    let err = suggest(&env, &gw, provider, &ranked_source(), "no_such_object_xyz")
        .await
        .unwrap_err();
    match &err {
        TinkerError::Validation(msg) => assert!(
            msg.contains("unknown target object") && msg.contains("no_such_object_xyz"),
            "teaching error must name the object: {msg}"
        ),
        other => panic!("unknown target must be a teaching error, got {other:?}"),
    }
    assert!(seen.seen_prompts().is_empty());
    assert!(cost_rows(&env, &format!("fake/{provider}"))
        .await
        .is_empty());
}

#[tokio::test]
async fn suggest_zero_usable_mappings_is_a_teaching_error_not_an_empty_list() {
    let env = common::setup().await;
    let provider = "fake-sg-zero";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    // Every suggestion is invalid: unknown target, unknown source, bad
    // confidence. All are dropped individually; zero survivors must be a
    // teaching error — never an empty Ok(vec![]) presented as confident.
    let canned = serde_json::json!({"mappings": [
        {"source": "Email", "target": "nope_field", "confidence": 0.9, "reason": "unknown target"},
        {"source": "Ghost", "target": "email", "confidence": 0.9, "reason": "unknown source"},
        {"source": "Phone", "target": "phone", "confidence": 9.0, "reason": "bad confidence"},
    ]})
    .to_string();
    let (gw, _) = fake_gw(&env, provider, &canned);

    let err = suggest(&env, &gw, provider, &ranked_source(), "crm_contact")
        .await
        .unwrap_err();
    match &err {
        TinkerError::Validation(msg) => assert!(
            msg.contains("no usable mappings"),
            "teaching error must name the problem: {msg}"
        ),
        other => panic!("zero survivors must be a teaching error, got {other:?}"),
    }
    // The call happened, so it must be accounted even though nothing was
    // returned: an unaccounted model call is never silent.
    assert_eq!(
        cost_rows(&env, &format!("fake/{provider}")).await.len(),
        1,
        "the failed call must still be cost-accounted"
    );
}

#[tokio::test]
async fn suggest_malformed_model_json_fails_closed() {
    let env = common::setup().await;
    let provider = "fake-sg-malformed";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    let (gw, _) = fake_gw(&env, provider, "definitely not json {{{");

    let err = suggest(&env, &gw, provider, &ranked_source(), "crm_contact")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "malformed model output must fail closed: {err:?}"
    );
    let (m, s, ..) = write_counts(&env).await;
    assert_eq!((m, s), (0, 0));
    assert_eq!(
        cost_rows(&env, &format!("fake/{provider}")).await.len(),
        1,
        "the failed call must still be cost-accounted"
    );
}

#[tokio::test]
async fn suggest_placement_blocks_hosted_before_any_byte_leaves() {
    let env = common::setup().await;
    let provider = "fake-sg-hosted";
    // Hosted provider for org-controlled content: rejected at the gateway
    // before the adapter is touched — sample values are prompt bytes.
    register_provider(&env, provider, "hosted", "org-controlled", "available").await;
    let (gw, seen) = fake_gw(&env, provider, &ranked_canned());

    let err = suggest(&env, &gw, provider, &ranked_source(), "crm_contact")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "hosted provider must be rejected: {err:?}"
    );
    assert!(
        seen.seen_prompts().is_empty(),
        "no prompt bytes may leave on a placement rejection"
    );
    // No call happened, so nothing to account.
    assert!(cost_rows(&env, &format!("fake/{provider}"))
        .await
        .is_empty());
}

#[tokio::test]
async fn suggest_sample_values_reach_the_model_bounded_and_truncated() {
    let env = common::setup().await;
    let provider = "fake-sg-samples";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    let (gw, seen) = fake_gw(&env, provider, &ranked_canned());

    let long = "x".repeat(500);
    let source = src(vec![field(
        "Email",
        &[
            serde_json::json!("alice.sentinel@acme.example"),
            serde_json::json!(long),
        ],
    )]);
    suggest(&env, &gw, provider, &source, "crm_contact")
        .await
        .unwrap();

    let prompts = seen.seen_prompts();
    assert_eq!(prompts.len(), 1);
    // Sample values ARE prompt bytes — that is the feature (unlike item
    // 25's names-only prompts): the model sees them to disambiguate.
    assert!(
        prompts[0].contains("alice.sentinel@acme.example"),
        "sample values must reach the model"
    );
    // ...but bounded: the 500-char value is truncated, never sent whole.
    assert!(
        prompts[0].contains("...[truncated]"),
        "oversized samples must be truncated"
    );
    assert!(
        !prompts[0].contains(&long),
        "the full 500-char sample must never leave the process"
    );
}

/// Test-only adapter that poisons the cost ledger: the completion carries
/// an empty model_ref, which `CostLedger::record_usage` refuses. This
/// deterministically exercises the fail-closed wiring — a ledger write
/// error must surface, never silent unaccounted proposals — with zero
/// global side effects (no DDL, no grants).
struct EmptyRefAdapter {
    seen: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl ModelAdapter for EmptyRefAdapter {
    fn name(&self) -> &str {
        "empty-ref"
    }

    fn available(&self) -> bool {
        true
    }

    async fn complete(&self, prompt: &str, _purpose: &str) -> tinker_core::Result<Completion> {
        self.seen.lock().unwrap().push(prompt.to_string());
        Ok(Completion {
            text: r#"{"mappings":[{"source":"Email","target":"email","confidence":0.9,"reason":"ok"}]}"#
                .to_string(),
            tokens_in: 10,
            tokens_out: 5,
            model_ref: String::new(),
        })
    }
}

#[tokio::test]
async fn suggest_accounting_failure_fails_closed() {
    let env = common::setup().await;
    let provider = "fake-sg-acctfail";
    register_provider(&env, provider, "private", "org-controlled", "available").await;
    let adapter = Arc::new(EmptyRefAdapter {
        seen: Mutex::new(vec![]),
    });
    let (gw, _) = gateway_with(&env, provider, adapter.clone());

    let err = suggest(&env, &gw, provider, &ranked_source(), "crm_contact")
        .await
        .unwrap_err();
    match &err {
        TinkerError::Validation(msg) => assert!(
            msg.contains("model_ref"),
            "accounting failure must surface: {msg}"
        ),
        other => panic!("accounting failure must fail closed, got {other:?}"),
    }
    // The model WAS called (one prompt seen) — the failure is at the
    // accounting step, and no proposals leak past it.
    assert_eq!(adapter.seen.lock().unwrap().len(), 1);
    let (m, s, ..) = write_counts(&env).await;
    assert_eq!((m, s), (0, 0));
}
