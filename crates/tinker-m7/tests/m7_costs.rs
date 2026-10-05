//! Item 21: cost records in currency (PRD §46).
//!
//! - Token→currency price list + per-window cost records computed at
//!   record time (cost at time of use).
//! - Unpriced models accumulate unpriced_tokens (flagged, never zero-priced).
//! - Provider-bill import + reconciliation with variance + tolerance.
//! - Real completion tokens flow from the transform engine into cost
//!   records (no longer dropped on the floor).

mod common;

use bigdecimal::BigDecimal;
use common::*;
use std::str::FromStr;
use tinker_agents::costs::{bd, CostLedger, ReconcileStatus};
use tinker_agents::vfile::VirtualFileReader;
use tinker_agents::{AuditWriter, TransformCache, TransformEngine};
use tinker_core::{OrganizationId, TenantContext};
use uuid::Uuid;

fn costs(env: &AgentEnv) -> CostLedger {
    CostLedger::new(env.core.clone(), env.owner.clone())
}

fn deal_path(env: &AgentEnv) -> String {
    format!("/tinker/crm_deal/{}/index.md", env.deal_d1)
}

fn stack(env: &AgentEnv) -> (TransformEngine, TransformCache) {
    let audit = AuditWriter::new(env.core.clone(), env.owner.clone());
    let engine = TransformEngine::new(
        env.core.clone(),
        env.owner.clone(),
        env.ontology.clone(),
        env.gateway.clone(),
        audit,
    );
    let cache = TransformCache::new(env.core.clone(), env.owner.clone());
    (engine, cache)
}

/// A second org + actor for tenant-isolation checks.
async fn second_org(env: &AgentEnv) -> (Uuid, TenantContext) {
    let owner_pool = &env.owner.0;
    let host_id = Uuid::now_v7();
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, 'costs-host2')")
        .bind(host_id)
        .execute(owner_pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organizations (id, host_id, slug, name) VALUES ($1,$2,$3,'costs org2')",
    )
    .bind(org_id)
    .bind(host_id)
    .bind(format!("costs2-{}", org_id.simple()))
    .execute(owner_pool)
    .await
    .unwrap();
    let actor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,'costs-actor2','costs-actor2')",
    )
    .bind(actor_id)
    .bind(org_id)
    .execute(owner_pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,'executive')",
    )
    .bind(actor_id)
    .bind(org_id)
    .execute(owner_pool)
    .await
    .unwrap();
    (
        org_id,
        TenantContext::new(OrganizationId(org_id), actor_id, "costs-test"),
    )
}

fn usd4(s: &str) -> BigDecimal {
    BigDecimal::from_str(s).unwrap()
}

/// Scale-proof decimal equality: NUMERIC round-trips can change scale.
fn assert_usd_eq(actual: &BigDecimal, expected: &BigDecimal, what: &str) {
    let diff = (actual - expected).abs();
    assert!(
        diff < BigDecimal::from_str("0.00001").unwrap(),
        "{what}: {actual} != {expected}"
    );
}

// ---------------------------------------------------------------------------
// Price list + cost recording
// ---------------------------------------------------------------------------

#[tokio::test]
async fn priced_usage_records_exact_split_cost() {
    let env = setup().await;
    let ledger = costs(&env);
    // $1.00/1k in, $3.00/1k out.
    ledger
        .set_model_price("fake/scribe", bd(1.0), bd(3.0))
        .await
        .unwrap();

    ledger
        .record_usage(&env.exec_ctx, "fake/scribe", 2000, 1000)
        .await
        .unwrap();

    let now = chrono::Utc::now();
    let summary = ledger
        .cost_summary(
            &env.exec_ctx,
            now - chrono::Duration::hours(2),
            now + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    assert_eq!(summary.lines.len(), 1);
    let line = &summary.lines[0];
    assert_eq!(line.model_ref, "fake/scribe");
    assert_eq!(line.input_tokens, 2000);
    assert_eq!(line.output_tokens, 1000);
    // 2000 * 1.00/1000 + 1000 * 3.00/1000 = 2.00 + 3.00 = 5.00
    assert_usd_eq(&line.cost_usd, &usd4("5.00"), "exact split cost");
    assert_eq!(line.unpriced_tokens, 0);
    assert_usd_eq(&summary.total_cost_usd, &usd4("5.00"), "summary total");
    assert_eq!(summary.total_unpriced_tokens, 0);
}

#[tokio::test]
async fn unpriced_model_flags_tokens_never_zero_priced() {
    let env = setup().await;
    let ledger = costs(&env);

    ledger
        .record_usage(&env.exec_ctx, "fake/ghost", 1500, 500)
        .await
        .unwrap();

    let now = chrono::Utc::now();
    let summary = ledger
        .cost_summary(
            &env.exec_ctx,
            now - chrono::Duration::hours(2),
            now + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    assert_eq!(summary.lines.len(), 1);
    let line = &summary.lines[0];
    assert_eq!(line.input_tokens, 1500);
    assert_eq!(line.output_tokens, 500);
    assert_usd_eq(
        &line.cost_usd,
        &BigDecimal::from(0),
        "unpriced cost stays zero",
    );
    assert_eq!(
        line.unpriced_tokens, 2000,
        "tokens flagged, not zero-priced"
    );
    assert_eq!(summary.total_unpriced_tokens, 2000);
}

#[tokio::test]
async fn price_change_applies_to_new_usage_only() {
    let env = setup().await;
    let ledger = costs(&env);
    ledger
        .set_model_price("fake/scribe", bd(1.0), bd(1.0))
        .await
        .unwrap();
    ledger
        .record_usage(&env.exec_ctx, "fake/scribe", 1000, 0)
        .await
        .unwrap();

    // Price doubles; the already-recorded $1.00 must not be rewritten.
    ledger
        .set_model_price("fake/scribe", bd(2.0), bd(2.0))
        .await
        .unwrap();
    ledger
        .record_usage(&env.exec_ctx, "fake/scribe", 1000, 0)
        .await
        .unwrap();

    let now = chrono::Utc::now();
    let summary = ledger
        .cost_summary(
            &env.exec_ctx,
            now - chrono::Duration::hours(2),
            now + chrono::Duration::hours(1),
        )
        .await
        .unwrap();
    // $1.00 (old price) + $2.00 (new price) = $3.00 — history untouched.
    assert_usd_eq(
        &summary.total_cost_usd,
        &usd4("3.00"),
        "old cost not rewritten",
    );
}

#[tokio::test]
async fn negative_price_rejected() {
    let env = setup().await;
    let ledger = costs(&env);
    let err = ledger
        .set_model_price("fake/scribe", bd(-1.0), bd(1.0))
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::Validation(_)));
}

// ---------------------------------------------------------------------------
// Provider bills + reconciliation
// ---------------------------------------------------------------------------

fn period() -> (chrono::NaiveDate, chrono::NaiveDate) {
    let today = chrono::Utc::now().date_naive();
    (today - chrono::Duration::days(30), today)
}

#[tokio::test]
async fn reconcile_matches_within_tolerance() {
    let env = setup().await;
    let ledger = costs(&env);
    ledger
        .set_model_price("fake/scribe", bd(1.0), bd(1.0))
        .await
        .unwrap();
    ledger
        .record_usage(&env.exec_ctx, "fake/scribe", 1000, 1000)
        .await
        .unwrap(); // $2.00

    let (start, end) = period();
    ledger
        .import_provider_bill(&env.exec_ctx, "fake", start, end, usd4("2.01"), None)
        .await
        .unwrap(); // within 2% tolerance

    let r = ledger
        .reconcile(&env.exec_ctx, "fake", start, end)
        .await
        .unwrap();
    assert_eq!(r.status, ReconcileStatus::Match);
    assert_usd_eq(&r.ledger_cost_usd, &usd4("2.00"), "ledger cost");
    assert_usd_eq(&r.billed_amount_usd, &usd4("2.01"), "billed amount");
    assert!(!r.provisional);
}

#[tokio::test]
async fn reconcile_detects_ledger_under_and_over() {
    let env = setup().await;
    let ledger = costs(&env);
    ledger
        .set_model_price("fake/scribe", bd(10.0), bd(10.0))
        .await
        .unwrap();
    ledger
        .record_usage(&env.exec_ctx, "fake/scribe", 1000, 0)
        .await
        .unwrap(); // $10.00

    let (start, end) = period();
    // Bill higher than the ledger: we are under-counting (or missing usage).
    ledger
        .import_provider_bill(&env.exec_ctx, "fake", start, end, usd4("50.00"), None)
        .await
        .unwrap();
    let r = ledger
        .reconcile(&env.exec_ctx, "fake", start, end)
        .await
        .unwrap();
    assert_eq!(r.status, ReconcileStatus::LedgerUnder);
    assert_usd_eq(&r.variance_usd, &usd4("-40.00"), "variance");

    // A second, cheaper bill for the same period: ledger now over the bill.
    ledger
        .import_provider_bill(&env.exec_ctx, "fake", start, end, usd4("1.00"), None)
        .await
        .unwrap();
    let r = ledger
        .reconcile(&env.exec_ctx, "fake", start, end)
        .await
        .unwrap();
    assert_eq!(r.status, ReconcileStatus::LedgerOver);
}

#[tokio::test]
async fn reconcile_fails_closed_without_bill() {
    let env = setup().await;
    let ledger = costs(&env);
    let (start, end) = period();
    let err = ledger
        .reconcile(&env.exec_ctx, "fake", start, end)
        .await
        .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::NotFound(_)),
        "missing bill is not a match: {err:?}"
    );
}

#[tokio::test]
async fn reconcile_flags_unpriced_tokens_as_provisional() {
    let env = setup().await;
    let ledger = costs(&env);
    // No price for fake/ghost: 500 unpriced tokens.
    ledger
        .record_usage(&env.exec_ctx, "fake/ghost", 300, 200)
        .await
        .unwrap();
    let (start, end) = period();
    ledger
        .import_provider_bill(&env.exec_ctx, "fake", start, end, usd4("0.00"), None)
        .await
        .unwrap();

    let r = ledger
        .reconcile(&env.exec_ctx, "fake", start, end)
        .await
        .unwrap();
    assert!(
        r.provisional,
        "unpriced tokens make reconciliation provisional"
    );
    assert_eq!(r.unpriced_tokens, 500);
}

#[tokio::test]
async fn reconcile_matches_provider_prefix() {
    let env = setup().await;
    let ledger = costs(&env);
    ledger
        .set_model_price("acme/ultra", bd(1.0), bd(1.0))
        .await
        .unwrap();
    ledger
        .record_usage(&env.exec_ctx, "acme/ultra", 1000, 0)
        .await
        .unwrap(); // $1.00 under provider 'acme'
    ledger
        .set_model_price("other/model", bd(1.0), bd(1.0))
        .await
        .unwrap();
    ledger
        .record_usage(&env.exec_ctx, "other/model", 999_000, 0)
        .await
        .unwrap(); // must NOT leak into acme's reconciliation

    let (start, end) = period();
    ledger
        .import_provider_bill(&env.exec_ctx, "acme", start, end, usd4("1.00"), None)
        .await
        .unwrap();
    let r = ledger
        .reconcile(&env.exec_ctx, "acme", start, end)
        .await
        .unwrap();
    assert_eq!(r.status, ReconcileStatus::Match);
    assert_usd_eq(
        &r.ledger_cost_usd,
        &usd4("1.00"),
        "provider-prefix ledger cost",
    );
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cost_records_are_tenant_isolated() {
    let env = setup().await;
    let (_org2, ctx2) = second_org(&env).await;
    let ledger = costs(&env);
    ledger
        .set_model_price("fake/scribe", bd(1.0), bd(1.0))
        .await
        .unwrap();
    ledger
        .record_usage(&env.exec_ctx, "fake/scribe", 1000, 0)
        .await
        .unwrap();

    let now = chrono::Utc::now();
    let from = now - chrono::Duration::hours(2);
    let to = now + chrono::Duration::hours(1);
    let mine = ledger.cost_summary(&env.exec_ctx, from, to).await.unwrap();
    assert_eq!(mine.lines.len(), 1);
    let theirs = ledger.cost_summary(&ctx2, from, to).await.unwrap();
    assert!(
        theirs.lines.is_empty(),
        "org2 must not see org1 cost records"
    );

    // And org2 cannot reconcile against org1's bill.
    let (start, end) = period();
    ledger
        .import_provider_bill(&env.exec_ctx, "fake", start, end, usd4("1.00"), None)
        .await
        .unwrap();
    let err = ledger
        .reconcile(&ctx2, "fake", start, end)
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::NotFound(_)));
}

// ---------------------------------------------------------------------------
// End-to-end: real completion tokens flow into cost records.
// One sequential test: model_prices is GLOBAL, so the priced and
// unpriced phases cannot run as parallel tests.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn transform_cost_flow_end_to_end() {
    let env = setup().await;
    let ledger = costs(&env);
    // Start with no price for the harness fake (model_ref "fake/notes-llm").
    sqlx::query("DELETE FROM model_prices WHERE model_ref = 'fake/notes-llm'")
        .execute(&env.owner.0)
        .await
        .unwrap();

    // Phase 1: no price — the transform still serves, usage is recorded
    // as unpriced (best-effort cost write never breaks the read path).
    let (engine, cache) = stack(&env);
    let reader = VirtualFileReader::new(&engine, &cache);
    let md = reader
        .read(&env.exec_ctx, &deal_path(&env), None)
        .await
        .unwrap();
    assert!(
        md.contains("Seats expansion"),
        "llm transform must have run:\n{md}"
    );
    let now = chrono::Utc::now();
    let from = now - chrono::Duration::hours(2);
    let to = now + chrono::Duration::hours(1);
    let summary = ledger.cost_summary(&env.exec_ctx, from, to).await.unwrap();
    let line = summary
        .lines
        .iter()
        .find(|l| l.model_ref == "fake/notes-llm")
        .expect("usage recorded even without a price");
    assert!(line.input_tokens > 0 && line.output_tokens > 0);
    assert!(
        line.unpriced_tokens > 0,
        "no price -> flagged, not zero-priced"
    );
    assert_usd_eq(
        &line.cost_usd,
        &BigDecimal::from(0),
        "unpriced cost stays zero",
    );

    // Phase 2: priced — real completion tokens are costed at the listed
    // price. Fresh cache so the model actually runs again.
    ledger
        .set_model_price("fake/notes-llm", bd(1.0), bd(4.0))
        .await
        .unwrap();
    let (engine2, cache2) = stack(&env);
    let reader2 = VirtualFileReader::new(&engine2, &cache2);
    let md2 = reader2
        .read(&env.exec_ctx, &deal_path(&env), None)
        .await
        .unwrap();
    assert!(md2.contains("Seats expansion"));

    let summary2 = ledger.cost_summary(&env.exec_ctx, from, to).await.unwrap();
    let line2 = summary2
        .lines
        .iter()
        .find(|l| l.model_ref == "fake/notes-llm")
        .expect("priced usage recorded");
    assert!(line2.cost_usd > 0);
    // Cost recomputed from the phase-2 token DELTAS at the listed price
    // (phase-1 tokens were unpriced and contributed zero).
    let priced_in = line2.input_tokens - line.input_tokens;
    let priced_out = line2.output_tokens - line.output_tokens;
    assert!(priced_in + priced_out > 0, "phase 2 must add priced tokens");
    let expected = BigDecimal::from(priced_in) * bd(1.0) / BigDecimal::from(1000)
        + BigDecimal::from(priced_out) * bd(4.0) / BigDecimal::from(1000);
    let diff = (&line2.cost_usd - &expected).abs();
    assert!(
        diff < BigDecimal::from_str("0.0001").unwrap(),
        "cost must match price x real tokens: {:?} vs {:?}",
        line2.cost_usd,
        expected
    );

    // Leave no global price behind for other tests.
    sqlx::query("DELETE FROM model_prices WHERE model_ref = 'fake/notes-llm'")
        .execute(&env.owner.0)
        .await
        .unwrap();
}
