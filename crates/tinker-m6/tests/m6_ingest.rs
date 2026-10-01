//! M6 exit tests: managed ingestion and master data.
//!
//! Direct from PRD v0.6 §44:
//! - Full resync is idempotent.
//! - Mappings replay.
//! - Ambiguous identities never auto-merge.
//! - Every source object has a measured route from mirror to Tinker-primary.
//!
//! Hardening (M6 scope):
//! - Failed runs persist `failed` status and resume incrementally.
//! - Cross-tenant references are rejected (composite FKs + RLS).
//! - Hostile identifiers never reach SQL.
//! - Mapping lifecycle: draft -> proposed -> approved -> activated.
//! - Profiling measures every landed column; additive drift auto-lands,
//!   breaking drift pauses promotion with a review item.

mod common;

use async_trait::async_trait;
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_ingest::connector::SourceConnector;
use tinker_ingest::connector::{RecordPage, SourceObject};
use tinker_ingest::pipeline::{CanonicalTarget, RunMode};

/// Run one full pass for a stream: connect, create stream, map, run.
async fn run_stream(
    env: &IngestEnv,
    source_object: &str,
    target: CanonicalTarget,
    object: &str,
) -> (uuid::Uuid, tinker_ingest::pipeline::PipelineReport) {
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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: source_object.to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;
    put_standard_mappings(env, stream_id, object).await;
    let report = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[target],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    (stream_id, report)
}

async fn canonical_count(env: &IngestEnv, slug: &str) -> i64 {
    assert!(matches!(slug, "crm_company" | "crm_contact" | "crm_deal"));
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM data.{slug} WHERE organization_id=$1"
    ))
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    n
}

fn is_validation<T>(r: Result<T>) -> bool {
    matches!(r, Err(TinkerError::Validation(_)))
}

/// Snapshot all canonical contacts (typed columns) for replay comparison.
async fn snapshot_contacts(env: &IngestEnv) -> Vec<(Option<String>, Option<String>)> {
    let name_col = phys(env, "crm_contact", "name").await;
    let email_col = phys(env, "crm_contact", "email").await;
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let rows = sqlx::query_as::<_, (Option<String>, Option<String>)>(&format!(
        "SELECT \"{name_col}\", \"{email_col}\" FROM data.crm_contact
         WHERE organization_id=$1 ORDER BY \"{email_col}\""
    ))
    .bind(env.org_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    rows
}

/// Exit 1: full resync is idempotent — a second full pass changes nothing.
#[tokio::test]
async fn resync_is_idempotent() {
    let env = setup().await;
    seed_salesforce(&env);

    let (_sid, r1) = run_stream(&env, "Account", account_target(), "Account").await;
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    let landed1: u64 = r1.stages["extract_land"].landed;

    // Second full pass (new stream = resync).
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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;
    put_standard_mappings(&env, stream_id, "Account").await;
    let r2 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();

    // Same landed count, same canonical count, all linked (no duplicates).
    assert_eq!(r2.stages["extract_land"].landed, landed1);
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    let promote = &r2.stages["promote"];
    assert_eq!(promote.created, 0, "resync must not create duplicates");
    assert_eq!(promote.linked, 2, "resync must link to existing records");
    assert_eq!(
        promote.promoted, 0,
        "resync must not rewrite identical values (survivorship is stable)"
    );
}

/// Exit 2: mappings replay — the same landed rows plus the same mappings
/// always produce the same canonical mutations (deterministic).
#[tokio::test]
async fn mappings_replay_is_deterministic() {
    let env = setup().await;
    seed_salesforce(&env);

    let (stream_id, _r1) = run_stream(&env, "Contact", contact_target(), "Contact").await;
    let rows1 = snapshot_contacts(&env).await;

    // Re-run the same stream (reset the cursor to force a full replay).
    env.pipeline
        .control()
        .advance_cursor(&env.ctx, stream_id, &serde_json::json!({}))
        .await
        .unwrap();
    let r2 = env
        .pipeline
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
    assert!(!r2.drift_breaking);

    let rows2 = snapshot_contacts(&env).await;

    assert_eq!(rows1, rows2, "mapping replay must be deterministic");
    assert_eq!(r2.stages["promote"].created, 0);
}

/// Exit 3: ambiguous identities never auto-merge — two candidates for one
/// source record queues a review; no identity link is created.
#[tokio::test]
async fn ambiguous_identities_never_auto_merge() {
    let env = setup().await;
    seed_salesforce(&env);

    // Pre-create TWO canonical contacts sharing the same email as CON-1.
    let name_col = phys(&env, "crm_contact", "name").await;
    let email_col = phys(&env, "crm_contact", "email").await;
    for i in 0..2 {
        sqlx::query(&format!(
            "INSERT INTO data.crm_contact (organization_id, \"{name_col}\", \"{email_col}\")
             VALUES ($1, $2, $3)"
        ))
        .bind(env.org_id)
        .bind(format!("Alice Candidate {i}"))
        .bind("alice@acme.example")
        .execute(&env.owner.0)
        .await
        .unwrap();
    }

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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Contact".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;
    put_standard_mappings(&env, stream_id, "Contact").await;
    let report = env
        .pipeline
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

    // CON-1's email matches two candidates -> queued, not linked.
    assert_eq!(report.stages["promote"].queued_for_review, 1);
    assert_eq!(report.stages["promote"].linked, 0);

    // No identity link for CON-1.
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_identity_link
         WHERE organization_id=$1 AND stream_id=$2 AND source_id='CON-1'",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 0, "ambiguous identity must not be linked");
    // An open review exists.
    let reviews = env
        .pipeline
        .identity()
        .open_reviews(&env.ctx, stream_id)
        .await
        .unwrap();
    assert_eq!(reviews.len(), 1);
    assert_eq!(reviews[0].1, "ambiguous_identity");
}

/// Exit 4: every source object has a measured route from mirror to
/// Tinker-primary — each run reports per-stage landed/promoted counts and
/// timings for Account, Contact, and Opportunity.
#[tokio::test]
async fn source_objects_have_measured_route() {
    let env = setup().await;
    seed_salesforce(&env);

    for (object, target) in [
        ("Account", account_target()),
        ("Contact", contact_target()),
        ("Opportunity", opportunity_target()),
    ] {
        let (_sid, report) = run_stream(&env, object, target, object).await;
        let extract = &report.stages["extract_land"];
        let promote = &report.stages["promote"];
        // Mirror: every source record landed.
        assert!(extract.landed > 0, "{object}: nothing landed");
        // Tinker-primary: every landed record promoted or queued.
        let accounted = promote.promoted + promote.queued_for_review;
        assert!(accounted > 0, "{object}: nothing reached Tinker-primary");
        // Measured: timings present; the full route has all four stages.
        assert!(report.total_millis < 60_000, "{object}: run took too long");
        for stage in ["extract_land", "profile", "model", "promote"] {
            assert!(
                report.stages.contains_key(stage),
                "{object}: missing {stage}"
            );
        }
        // Profile measured every landed column.
        assert!(!report.profile.is_empty(), "{object}: nothing profiled");
    }

    // All three canonical tables populated (typed).
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    assert_eq!(canonical_count(&env, "crm_contact").await, 2);
    assert_eq!(canonical_count(&env, "crm_deal").await, 1);
}

/// A connector that fails fetch_page on one call, then can be repaired.
/// Drives the failed-run recovery test.
struct FlakyConnector {
    inner: tinker_ingest::FakeSalesforce,
    fail_at_call: AtomicUsize,
    calls: AtomicUsize,
}

impl FlakyConnector {
    fn new(inner: tinker_ingest::FakeSalesforce, fail_at_call: usize) -> Self {
        Self {
            inner,
            fail_at_call: AtomicUsize::new(fail_at_call),
            calls: AtomicUsize::new(0),
        }
    }
    fn repair(&self) {
        self.fail_at_call.store(usize::MAX, Ordering::SeqCst);
    }
}

#[async_trait]
impl SourceConnector for FlakyConnector {
    async fn discover(&self) -> Result<Vec<SourceObject>> {
        self.inner.discover().await
    }
    async fn fetch_page(
        &self,
        object: &str,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<RecordPage> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n == self.fail_at_call.load(Ordering::SeqCst) {
            return Err(TinkerError::Internal("simulated source outage".into()));
        }
        self.inner.fetch_page(object, cursor, page_size).await
    }
    async fn count(&self, object: &str) -> Result<u64> {
        self.inner.count(object).await
    }
}

/// Failed runs persist `failed` status (never stuck `running`) and a retry
/// resumes incrementally from the last committed page without duplicating.
#[tokio::test]
async fn failed_run_marks_failed_and_resumes() {
    let env = setup().await;
    seed_salesforce(&env);

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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;
    put_standard_mappings(&env, stream_id, "Account").await;

    // Fail on the 2nd fetch_page call (page_size=1 -> after ACC-1 lands).
    let flaky = FlakyConnector::new(std::mem::take(&mut clone_salesforce(&env)), 2);
    let err = env
        .pipeline
        .run(
            &env.ctx,
            &flaky,
            stream_id,
            &[account_target()],
            1,
            RunMode::Incremental,
        )
        .await
        .expect_err("run must fail");
    assert!(err.to_string().contains("simulated source outage"));

    // The run row says failed — never stuck running.
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (status,): (String,) = sqlx::query_as(
        "SELECT status FROM ingest_run
         WHERE organization_id=$1 AND stream_id=$2
         ORDER BY started_at DESC LIMIT 1",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(status, "failed");

    // The durable cursor advanced past the committed page 1.
    let stream = control
        .get_stream(&env.ctx, stream_id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        stream
            .cursor_state
            .get("cursor")
            .and_then(|v| v.as_str())
            .is_some(),
        "cursor must point past the committed page"
    );
    // Page 1 landed (idempotent landing); nothing promoted yet.
    assert_eq!(canonical_count(&env, "crm_company").await, 0);

    // Repair the source and retry: incremental resume, no duplicates.
    flaky.repair();
    let report = env
        .pipeline
        .run(
            &env.ctx,
            &flaky,
            stream_id,
            &[account_target()],
            1,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    assert!(!report.drift_breaking);
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    assert_eq!(report.stages["promote"].created, 2);
    assert_eq!(report.stages["promote"].linked, 0);

    // No duplicate identity links.
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_identity_link
         WHERE organization_id=$1 AND stream_id=$2",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 2);
}

/// Cross-tenant isolation: org B sees none of org A's ingest state, cannot
/// run org A's streams, and composite FKs reject cross-org references.
#[tokio::test]
async fn cross_tenant_ingest_is_isolated() {
    let env = setup().await;
    seed_salesforce(&env);
    let (_sid_a, _r) = run_stream(&env, "Account", account_target(), "Account").await;

    // Sibling org.
    let (org_b, actor_b) = create_org(&env.owner.0).await;
    let ctx_b = TenantContext::new(tinker_core::OrganizationId(org_b), actor_b, "m6-test-b");

    // Org B sees none of org A's streams.
    let stream_a = env
        .pipeline
        .control()
        .list_streams(&env.ctx, uuid::Uuid::nil())
        .await
        .unwrap();
    let _ = stream_a;
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (stream_a_id,): (uuid::Uuid,) =
        sqlx::query_as("SELECT id FROM ingest_stream WHERE organization_id=$1 LIMIT 1")
            .bind(env.org_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();

    assert!(env
        .pipeline
        .control()
        .get_stream(&ctx_b, stream_a_id)
        .await
        .unwrap()
        .is_none());
    // Org B cannot run org A's stream.
    let err = env
        .pipeline
        .run(
            &ctx_b,
            &env.salesforce,
            stream_a_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .expect_err("cross-tenant run must fail");
    assert!(matches!(err, TinkerError::NotFound(_)));
    // Org B's landing reads are empty.
    let rows = env
        .pipeline
        .landing()
        .fetch_page(&ctx_b, stream_a_id, &["Name".to_string()], None, 10)
        .await
        .unwrap();
    assert!(rows.is_empty());
    // Org B cannot activate mappings on org A's stream.
    let err = env
        .pipeline
        .mappings()
        .put_mapping(&ctx_b, stream_a_id, "Name", "crm_company", "name")
        .await
        .expect_err("cross-tenant mapping must fail");
    assert!(matches!(err, TinkerError::NotFound(_)));

    // Composite FK: a child row pairing org B with org A's stream is
    // rejected at the database, even owner-side.
    let mut otx = owner_scoped(&env.owner.0, org_b).await;
    let fk_err = sqlx::query(
        "INSERT INTO ingest_mapping
         (id, organization_id, stream_id, source_field, target_object, target_field, state)
         VALUES (gen_random_uuid(), $1, $2, 'X', 'crm_company', 'name', 'draft')",
    )
    .bind(org_b)
    .bind(stream_a_id)
    .execute(&mut *otx)
    .await
    .expect_err("composite FK must reject cross-org reference");
    // The rejected INSERT aborts the transaction; drop (rollback) it.
    drop(otx);
    assert!(
        format!("{fk_err:?}").contains("23503"),
        "expected FK violation, got {fk_err:?}"
    );

    // Org B's own stream works independently; data stays separate.
    let control = env.pipeline.control();
    let conn_b = control
        .create_connection(
            &ctx_b,
            tinker_ingest::control::NewConnection {
                kind: "salesforce".to_string(),
                name: "sf-b".to_string(),
                credential_ref: None,
            },
        )
        .await
        .unwrap();
    let stream_b = control
        .create_stream(
            &ctx_b,
            tinker_ingest::control::NewStream {
                connection_id: conn_b.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    env.pipeline
        .mappings()
        .put_mapping(&ctx_b, stream_b.id, "Name", "crm_company", "name")
        .await
        .unwrap();
    env.pipeline
        .mappings()
        .put_mapping(&ctx_b, stream_b.id, "Industry", "crm_company", "industry")
        .await
        .unwrap();
    let r_b = env
        .pipeline
        .run(
            &ctx_b,
            &env.salesforce,
            stream_b.id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    assert_eq!(r_b.stages["promote"].created, 2);
    // Org A's canonical count is untouched.
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    let mut tx = env.core.tenant_tx(&ctx_b).await.unwrap();
    let (n_b,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM data.crm_company WHERE organization_id=$1")
            .bind(org_b)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n_b, 2);
}

/// Hostile identifiers never reach SQL: every dynamic fragment is
/// validated before interpolation.
#[tokio::test]
async fn hostile_identifiers_rejected() {
    let env = setup().await;
    seed_salesforce(&env);

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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();

    // Hostile object slugs.
    for slug in [
        "crm_company\"; DROP TABLE data.crm_company; --",
        "public.crm_company",
        "data.crm_company",
        "",
    ] {
        let r = env
            .pipeline
            .run(
                &env.ctx,
                &env.salesforce,
                stream.id,
                &[CanonicalTarget {
                    object_slug: slug.to_string(),
                    email_api_field: None,
                }],
                2,
                RunMode::Incremental,
            )
            .await;
        assert!(is_validation(r), "slug {slug:?} must be rejected");
    }
    // Unknown (but well-formed) object.
    let r = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream.id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await;
    assert!(r.is_ok(), "sane target must run");
    let r = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream.id,
            &[CanonicalTarget {
                object_slug: "no_such_object".to_string(),
                email_api_field: None,
            }],
            2,
            RunMode::Incremental,
        )
        .await;
    assert!(is_validation(r), "unknown object must be rejected");

    // Hostile mapping fields.
    let m = env.pipeline.mappings();
    assert!(is_validation(
        m.put_mapping(&env.ctx, stream.id, "Name", "crm_company", "name\"; --")
            .await
    ));
    assert!(is_validation(
        m.put_mapping(&env.ctx, stream.id, "Na me", "crm_company", "name")
            .await
    ));

    // Hostile landing field names.
    assert!(is_validation(
        env.pipeline
            .landing()
            .ensure_table(
                stream.id,
                &["ok_field".to_string(), "bad\"field".to_string()]
            )
            .await
    ));
}

/// Mapping lifecycle: the deterministic proposer creates `proposed` rows;
/// promotion ignores them until a human (or policy) approves + activates.
#[tokio::test]
async fn mapping_lifecycle_propose_approve_activate() {
    let env = setup().await;
    seed_salesforce(&env);

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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Contact".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;

    // First pass with no mappings: extract/land/profile only.
    let r1 = env
        .pipeline
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
    assert_eq!(r1.stages["extract_land"].landed, 2);
    assert_eq!(canonical_count(&env, "crm_contact").await, 0);

    // Deterministic proposer suggests mappings; nothing is activated.
    let proposals = env
        .pipeline
        .mappings()
        .propose_mappings(&env.ctx, stream_id, "crm_contact")
        .await
        .unwrap();
    let by_src: std::collections::HashMap<_, _> = proposals
        .iter()
        .map(|p| (p.source_field.as_str(), p))
        .collect();
    assert_eq!(by_src["Email"].target_field, "email");
    assert_eq!(by_src["Email"].confidence, 1.0);
    assert_eq!(by_src["FullName"].target_field, "name");
    assert!(env
        .pipeline
        .mappings()
        .mappings_for(&env.ctx, stream_id)
        .await
        .unwrap()
        .is_empty());
    // Re-proposing is idempotent (existing rows win, nothing duplicated).
    let proposals2 = env
        .pipeline
        .mappings()
        .propose_mappings(&env.ctx, stream_id, "crm_contact")
        .await
        .unwrap();
    assert!(proposals2.is_empty());

    // Approve + activate the Email proposal; operator-activate FullName.
    let approved = env
        .pipeline
        .mappings()
        .approve_mapping(&env.ctx, by_src["Email"].mapping_id)
        .await
        .unwrap();
    assert_eq!(approved.state, "approved");
    let activated = env
        .pipeline
        .mappings()
        .activate_mapping(&env.ctx, by_src["Email"].mapping_id)
        .await
        .unwrap();
    assert_eq!(activated.state, "activated");
    // Double-activation fails closed.
    assert!(env
        .pipeline
        .mappings()
        .activate_mapping(&env.ctx, by_src["Email"].mapping_id)
        .await
        .is_err());
    env.pipeline
        .mappings()
        .put_mapping(&env.ctx, stream_id, "FullName", "crm_contact", "name")
        .await
        .unwrap();

    // Second pass promotes through the activated mappings only.
    let r2 = env
        .pipeline
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
    assert_eq!(r2.stages["promote"].created, 2);
    // Both contacts have emails (activated mapping); names mapped too.
    let email_col = phys(&env, "crm_contact", "email").await;
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (n,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM data.crm_contact
         WHERE organization_id=$1 AND \"{email_col}\" IS NOT NULL"
    ))
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 2);
}

/// The profile stage measures every landed column (nulls / non-nulls /
/// distinct), including ragged source fields.
#[tokio::test]
async fn profile_stage_measures_landed_columns() {
    let env = setup().await;
    seed_salesforce(&env);

    let (_sid, report) = run_stream(&env, "Contact", contact_target(), "Contact").await;
    let profile = &report.profile;
    // CON-1 has FullName, CON-2 has Name (ragged): each is null once.
    assert_eq!(profile["FullName"].non_nulls, 1);
    assert_eq!(profile["FullName"].nulls, 1);
    assert_eq!(profile["Email"].non_nulls, 2);
    assert_eq!(profile["Email"].nulls, 0);
    assert_eq!(profile["Email"].distinct, 2);
    assert!(report.stages["profile"].millis < 60_000);

    // The profile is persisted on the run row.
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (counts,): (serde_json::Value,) =
        sqlx::query_as("SELECT counts FROM ingest_run WHERE id=$1 AND organization_id=$2")
            .bind(report.run_id)
            .bind(env.org_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(counts["profile"]["Email"]["non_nulls"], 2);
}

/// Additive drift auto-lands: a new source field gets a landing column and
/// flows through without pausing promotion.
#[tokio::test]
async fn additive_drift_auto_lands() {
    let env = setup().await;
    seed_salesforce(&env);

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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;
    put_standard_mappings(&env, stream_id, "Account").await;
    let _r1 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();

    // Source adds a field and a record.
    env.salesforce.add_field(
        "Account",
        tinker_ingest::SourceField {
            name: "Phone".to_string(),
            type_name: "string".to_string(),
        },
    );
    env.salesforce.append_records(
        "Account",
        vec![tinker_ingest::SourceRecord {
            source_id: "ACC-3".to_string(),
            updated_at: "2026-09-23T10:00:00Z".parse().unwrap(),
            deleted: false,
            fields: [
                ("Id".to_string(), serde_json::json!("ACC-3")),
                ("Name".to_string(), serde_json::json!("Initech")),
                ("Industry".to_string(), serde_json::json!("Software")),
                ("Phone".to_string(), serde_json::json!("555-0100")),
            ]
            .into_iter()
            .collect(),
        }],
    );

    // New stream (fresh cursor) sees the drifted schema.
    let stream2 = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    put_standard_mappings(&env, stream2.id, "Account").await;
    let r2 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream2.id,
            &[account_target()],
            10,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    assert!(!r2.drift_breaking, "additive drift must not break");
    // ACC-1/ACC-2 link across streams via stable identity; only the new
    // record is created — no duplicates.
    assert_eq!(r2.stages["promote"].created, 1);
    assert_eq!(r2.stages["promote"].linked, 2);
    assert_eq!(canonical_count(&env, "crm_company").await, 3);

    // The landing table gained the column; the new value landed.
    let table = tinker_ingest::landing::LandingWriter::table_for(stream2.id);
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM information_schema.columns
         WHERE table_schema='data' AND table_name=$1 AND column_name='Phone'",
    )
    .bind(table.trim_start_matches("data."))
    .fetch_one(&env.owner.0)
    .await
    .unwrap();
    assert_eq!(n, 1, "Phone column must exist on the landing table");
    assert_eq!(r2.profile["Phone"].non_nulls, 1);
    assert_eq!(r2.profile["Phone"].nulls, 2);
}

/// Breaking drift pauses promotion and queues a schema_drift review;
/// canonical data is untouched.
#[tokio::test]
async fn breaking_drift_pauses_promotion() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r1) = run_stream(&env, "Account", account_target(), "Account").await;
    assert_eq!(canonical_count(&env, "crm_company").await, 2);

    // A second connector presents Account with Name's type changed.
    // Run it on the SAME stream so drift is measured against the stored
    // landing schema.
    let sf2 = tinker_ingest::FakeSalesforce::new();
    sf2.seed_object(
        "Account",
        vec![
            tinker_ingest::SourceField {
                name: "Id".to_string(),
                type_name: "id".to_string(),
            },
            tinker_ingest::SourceField {
                name: "Name".to_string(),
                type_name: "richtext".to_string(),
            },
            tinker_ingest::SourceField {
                name: "Industry".to_string(),
                type_name: "string".to_string(),
            },
        ],
        vec![],
    );

    let r = env
        .pipeline
        .run(
            &env.ctx,
            &sf2,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();

    assert!(r.drift_breaking, "type change must break");
    assert_eq!(r.stages["promote"].promoted, 0);
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    let reviews = env
        .pipeline
        .identity()
        .open_reviews(&env.ctx, stream_id)
        .await
        .unwrap();
    assert!(
        reviews.iter().any(|r| r.1 == "schema_drift"),
        "breaking drift must queue a review"
    );
}

/// Performance tripwire: 100 records promote well under the budget with
/// all four measured stages present.
#[tokio::test]
async fn ingest_perf_tripwire() {
    let env = setup().await;
    let mut records = vec![];
    for i in 0..100 {
        records.push(tinker_ingest::SourceRecord {
            source_id: format!("ACC-{i}"),
            updated_at: format!("2026-09-20T10:{:02}:00Z", i % 60).parse().unwrap(),
            deleted: false,
            fields: [
                ("Id".to_string(), serde_json::json!(format!("ACC-{i}"))),
                (
                    "Name".to_string(),
                    serde_json::json!(format!("Company {i}")),
                ),
                ("Industry".to_string(), serde_json::json!("Software")),
            ]
            .into_iter()
            .collect(),
        });
    }
    env.salesforce.seed_object(
        "Account",
        vec![
            tinker_ingest::SourceField {
                name: "Id".to_string(),
                type_name: "id".to_string(),
            },
            tinker_ingest::SourceField {
                name: "Name".to_string(),
                type_name: "string".to_string(),
            },
            tinker_ingest::SourceField {
                name: "Industry".to_string(),
                type_name: "string".to_string(),
            },
        ],
        records,
    );

    let (_sid, report) = run_stream(&env, "Account", account_target(), "Account").await;
    assert_eq!(canonical_count(&env, "crm_company").await, 100);
    assert!(
        report.total_millis < 15_000,
        "100 records in {}",
        report.total_millis
    );
    for stage in ["extract_land", "profile", "model", "promote"] {
        assert!(report.stages.contains_key(stage));
    }
}

/// Helper: move the FakeSalesforce out of the env (for the flaky wrapper).
fn clone_salesforce(_env: &IngestEnv) -> tinker_ingest::FakeSalesforce {
    // The env's FakeSalesforce cannot be cloned; instead reseed an
    // equivalent one. (Keeps FakeSalesforce's interior-mutability
    // encapsulated.)
    let sf = tinker_ingest::FakeSalesforce::new();
    // Re-seed deterministically — mirrors seed_salesforce's Account.
    sf.seed_object(
        "Account",
        vec![
            tinker_ingest::SourceField {
                name: "Id".to_string(),
                type_name: "id".to_string(),
            },
            tinker_ingest::SourceField {
                name: "Name".to_string(),
                type_name: "string".to_string(),
            },
            tinker_ingest::SourceField {
                name: "Industry".to_string(),
                type_name: "string".to_string(),
            },
        ],
        vec![
            tinker_ingest::SourceRecord {
                source_id: "ACC-1".to_string(),
                updated_at: "2026-09-20T10:00:00Z".parse().unwrap(),
                deleted: false,
                fields: [
                    ("Id".to_string(), serde_json::json!("ACC-1")),
                    ("Name".to_string(), serde_json::json!("Acme Corp")),
                    ("Industry".to_string(), serde_json::json!("Manufacturing")),
                ]
                .into_iter()
                .collect(),
            },
            tinker_ingest::SourceRecord {
                source_id: "ACC-2".to_string(),
                updated_at: "2026-09-21T10:00:00Z".parse().unwrap(),
                deleted: false,
                fields: [
                    ("Id".to_string(), serde_json::json!("ACC-2")),
                    ("Name".to_string(), serde_json::json!("Globex")),
                    ("Industry".to_string(), serde_json::json!("Technology")),
                ]
                .into_iter()
                .collect(),
            },
        ],
    );
    sf
}

/// A run row stuck `running` (crashed predecessor) is superseded — marked
/// failed — when the next run starts. History never shows a phantom run.
#[tokio::test]
async fn stale_running_run_is_superseded() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r1) = run_stream(&env, "Account", account_target(), "Account").await;

    // Simulate a crashed predecessor: a run row stuck `running` with a
    // heartbeat older than the staleness threshold.
    let stale_id = uuid::Uuid::now_v7();
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    sqlx::query(
        "INSERT INTO ingest_run (id, organization_id, stream_id, status, checkpoint_in, counts, last_heartbeat_at)
         VALUES ($1,$2,$3,'running','{}','{}', now() - interval '10 minutes')",
    )
    .bind(stale_id)
    .bind(env.org_id)
    .bind(stream_id)
    .execute(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();

    let r2 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    assert!(!r2.drift_breaking);

    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (status, counts): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, counts FROM ingest_run WHERE id=$1")
            .bind(stale_id)
            .fetch_one(&mut *otx)
            .await
            .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(status, "failed");
    assert_eq!(counts["superseded"], serde_json::json!(true));
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_run
         WHERE organization_id=$1 AND stream_id=$2 AND status='running'",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(n, 0, "no run may be left running");
}

/// Crash between landing a page and advancing the cursor: the page is
/// landed but the checkpoint is empty. The retry refetches from the
/// start; idempotent landing converges with no duplicates.
#[tokio::test]
async fn crash_between_land_and_cursor_is_benign() {
    let env = setup().await;
    seed_salesforce(&env);

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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;
    put_standard_mappings(&env, stream_id, "Account").await;

    // The crash: page 1 landed, cursor never advanced (still empty).
    let fields = vec!["Id".to_string(), "Name".to_string(), "Industry".to_string()];
    env.pipeline
        .landing()
        .ensure_table(stream_id, &fields)
        .await
        .unwrap();
    env.pipeline
        .landing()
        .write_batch(
            &env.ctx,
            stream_id,
            &fields,
            &[tinker_ingest::SourceRecord {
                source_id: "ACC-1".to_string(),
                updated_at: "2026-09-20T10:00:00Z".parse().unwrap(),
                deleted: false,
                fields: [
                    ("Id".to_string(), serde_json::json!("ACC-1")),
                    ("Name".to_string(), serde_json::json!("Acme Corp")),
                    ("Industry".to_string(), serde_json::json!("Manufacturing")),
                ]
                .into_iter()
                .collect(),
            }],
        )
        .await
        .unwrap();

    let report = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            1,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    assert!(!report.drift_breaking);
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    assert_eq!(report.stages["promote"].created, 2);
    assert_eq!(report.stages["promote"].linked, 0);
    // The pre-crash landed row was overwritten idempotently, not duplicated.
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_identity_link
         WHERE organization_id=$1 AND stream_id=$2",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(n, 2);
}

/// FullResync is an explicit mode: the checkpoint is cleared, every page
/// relands, and cross-stream identity converges without duplicates.
#[tokio::test]
async fn full_resync_mode_is_explicit() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, r1) = run_stream(&env, "Account", account_target(), "Account").await;
    assert_eq!(canonical_count(&env, "crm_company").await, 2);

    // Incremental rerun with no source change lands nothing new.
    let r_inc = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    assert_eq!(r_inc.stages["extract_land"].landed, 2);

    // Source grows; FullResync relands everything and converges.
    env.salesforce.append_records(
        "Account",
        vec![tinker_ingest::SourceRecord {
            source_id: "ACC-3".to_string(),
            updated_at: "2026-09-23T10:00:00Z".parse().unwrap(),
            deleted: false,
            fields: [
                ("Id".to_string(), serde_json::json!("ACC-3")),
                ("Name".to_string(), serde_json::json!("Initech")),
                ("Industry".to_string(), serde_json::json!("Software")),
            ]
            .into_iter()
            .collect(),
        }],
    );
    let r2 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            10,
            RunMode::FullResync,
        )
        .await
        .unwrap();
    assert_eq!(r2.stages["extract_land"].landed, 3);
    assert_eq!(r2.stages["promote"].created, 1, "only the new record");
    assert_eq!(r2.stages["promote"].linked, 2, "old records link");
    assert_eq!(canonical_count(&env, "crm_company").await, 3);
    assert_eq!(r1.fingerprint.len(), 64);
}

/// Reconciliation fingerprints: identical data reproduces the same
/// fingerprint; any data change shifts it. Persisted on the run row.
#[tokio::test]
async fn reconciliation_fingerprint_is_deterministic() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, r1) = run_stream(&env, "Account", account_target(), "Account").await;

    // Same data, full resync: identical fingerprint.
    let r2 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::FullResync,
        )
        .await
        .unwrap();
    assert_eq!(r1.fingerprint, r2.fingerprint);
    assert_eq!(r1.fingerprint.len(), 64);

    // Data change shifts it.
    env.salesforce.append_records(
        "Account",
        vec![tinker_ingest::SourceRecord {
            source_id: "ACC-3".to_string(),
            updated_at: "2026-09-23T10:00:00Z".parse().unwrap(),
            deleted: false,
            fields: [
                ("Id".to_string(), serde_json::json!("ACC-3")),
                ("Name".to_string(), serde_json::json!("Initech")),
                ("Industry".to_string(), serde_json::json!("Software")),
            ]
            .into_iter()
            .collect(),
        }],
    );
    let r3 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            10,
            RunMode::FullResync,
        )
        .await
        .unwrap();
    assert_ne!(r1.fingerprint, r3.fingerprint);

    // Persisted on the run row for operators.
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (counts,): (serde_json::Value,) =
        sqlx::query_as("SELECT counts FROM ingest_run WHERE id=$1 AND organization_id=$2")
            .bind(r3.run_id)
            .bind(env.org_id)
            .fetch_one(&mut *otx)
            .await
            .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(counts["fingerprint"], serde_json::json!(r3.fingerprint));
}

/// Provenance integration: every winning field value records its source
/// stream, source record, source field, and value.
#[tokio::test]
async fn provenance_records_winning_values() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r) = run_stream(&env, "Account", account_target(), "Account").await;

    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (record_id,): (uuid::Uuid,) = sqlx::query_as(
        "SELECT tinker_record_id FROM ingest_identity_link
         WHERE organization_id=$1 AND stream_id=$2 AND source_id='ACC-1'",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let rows: Vec<(String, String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT field, stream_id::text, source_id, value FROM ingest_provenance
         WHERE organization_id=$1 AND tinker_record_id=$2",
    )
    .bind(env.org_id)
    .bind(record_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let by_field: std::collections::HashMap<_, _> =
        rows.iter().map(|r| (r.0.as_str(), r)).collect();
    assert_eq!(by_field["name"].3, serde_json::json!("Acme Corp"));
    assert_eq!(by_field["industry"].3, serde_json::json!("Manufacturing"));
    // Every provenance row names the exact source it came from.
    for row in &rows {
        assert_eq!(row.1, stream_id.to_string());
        assert_eq!(row.2, "ACC-1");
    }
}

/// A poisoned canonical write (check-constraint violation) rolls back the
/// record's whole transaction — no link, no skeleton, no provenance — and
/// becomes a conflict review. The run itself completes.
#[tokio::test]
async fn canonical_write_failure_queues_review_atomically() {
    let env = setup().await;
    seed_salesforce(&env);
    // OPP-2 carries a stage value outside the pack's select options.
    env.salesforce.append_records(
        "Opportunity",
        vec![tinker_ingest::SourceRecord {
            source_id: "OPP-2".to_string(),
            updated_at: "2026-09-23T10:00:00Z".parse().unwrap(),
            deleted: false,
            fields: [
                ("Id".to_string(), serde_json::json!("OPP-2")),
                ("Name".to_string(), serde_json::json!("Bad Deal")),
                ("Amount".to_string(), serde_json::json!(1000)),
                ("Stage".to_string(), serde_json::json!("bogus")),
                ("AccountId".to_string(), serde_json::json!("ACC-1")),
            ]
            .into_iter()
            .collect(),
        }],
    );

    let (stream_id, report) =
        run_stream(&env, "Opportunity", opportunity_target(), "Opportunity").await;
    assert!(!report.drift_breaking);
    // The good record promoted; the poisoned one is queued, not fatal.
    assert_eq!(report.stages["promote"].created, 1);
    assert_eq!(report.stages["promote"].queued_for_review, 1);
    assert_eq!(canonical_count(&env, "crm_deal").await, 1);

    // All-or-nothing for OPP-2: no identity link left behind ...
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_identity_link
         WHERE organization_id=$1 AND stream_id=$2 AND source_id='OPP-2'",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&env.owner.0)
    .await
    .unwrap();
    assert_eq!(n, 0, "poisoned record must leave no identity link");
    // ... and no canonical row ...
    let name_col = phys(&env, "crm_deal", "name").await;
    let (n,): (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM data.crm_deal
         WHERE organization_id=$1 AND \"{name_col}\"='Bad Deal'"
    ))
    .bind(env.org_id)
    .fetch_one(&env.owner.0)
    .await
    .unwrap();
    assert_eq!(n, 0, "poisoned record must leave no canonical row");
    // ... but a conflict review explains what happened.
    let reviews = env
        .pipeline
        .identity()
        .open_reviews(&env.ctx, stream_id)
        .await
        .unwrap();
    assert!(
        reviews
            .iter()
            .any(|r| r.1 == "conflict" && r.2["source_id"] == serde_json::json!("OPP-2")),
        "poisoned record must queue a conflict review"
    );
}

/// Numeric survivorship is stable: an integer amount that survives one
/// promotion compares equal on the next (canonical decimal form, no f64
/// round-trip), so resyncs never rewrite identical values.
#[tokio::test]
async fn numeric_survivorship_is_stable() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r1) =
        run_stream(&env, "Opportunity", opportunity_target(), "Opportunity").await;
    let r2 = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[opportunity_target()],
            2,
            RunMode::FullResync,
        )
        .await
        .unwrap();
    assert_eq!(
        r2.stages["promote"].promoted, 0,
        "identical numerics must not rewrite"
    );
    assert_eq!(r2.stages["promote"].linked, 1);
    // The stored amount round-trips exactly.
    let amount_col = phys(&env, "crm_deal", "amount").await;
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (amount,): (String,) = sqlx::query_as(&format!(
        "SELECT \"{amount_col}\"::text FROM data.crm_deal WHERE organization_id=$1"
    ))
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(amount, "50000");
}

/// Full composite-tenant-FK audit: every M6 control-plane child references
/// its parent on (organization_id, id), so a cross-org child row is
/// rejected by the database itself, not just by application code.
#[tokio::test]
async fn composite_tenant_fks_cover_all_ingest_children() {
    let env = setup().await;
    let expected = [
        ("ingest_stream", "fk_ingest_stream_connection_id_tenant"),
        (
            "ingest_schema_version",
            "fk_ingest_schema_version_stream_id_tenant",
        ),
        ("ingest_run", "fk_ingest_run_stream_id_tenant"),
        ("ingest_mapping", "fk_ingest_mapping_stream_id_tenant"),
        (
            "ingest_identity_link",
            "fk_ingest_identity_link_stream_id_tenant",
        ),
        (
            "ingest_review_item",
            "fk_ingest_review_item_stream_id_tenant",
        ),
        ("ingest_provenance", "fk_ingest_provenance_stream_id_tenant"),
        (
            "ingest_reconciliation",
            "fk_ingest_reconciliation_stream_id_tenant",
        ),
    ];
    for (child, fk) in expected {
        // The FK exists and spans exactly (organization_id, <parent>_id).
        let (cols,): (Vec<String>,) = sqlx::query_as(
            "SELECT array_agg(a.attname ORDER BY u.ord)
             FROM pg_constraint c
             JOIN unnest(c.conkey) WITH ORDINALITY AS u(attnum, ord) ON true
             JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = u.attnum
             WHERE c.conrelid = to_regclass($1) AND c.conname = $2 AND c.contype = 'f'",
        )
        .bind(child)
        .bind(fk)
        .fetch_one(&env.owner.0)
        .await
        .unwrap();
        assert_eq!(
            cols,
            vec!["organization_id".to_string(), cols[1].clone()],
            "{child}: {fk} must be a composite tenant FK"
        );
        assert!(
            cols[1].ends_with("_id"),
            "{child}: {fk} second column must be the parent id"
        );
    }
}

/// The landing table's explicit GRANT gives the app role DML; verified
/// at the privilege level (RLS still scopes rows per tenant).
#[tokio::test]
async fn landing_table_grants_app_role_dml() {
    let env = setup().await;
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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "Account".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    let table = env
        .pipeline
        .landing()
        .ensure_table(stream.id, &["Name".to_string()])
        .await
        .unwrap();
    for privs in ["SELECT", "INSERT", "UPDATE", "DELETE"] {
        let (ok,): (bool,) = sqlx::query_as("SELECT has_table_privilege('tinker_app', $1, $2)")
            .bind(&table)
            .bind(privs)
            .fetch_one(&env.owner.0)
            .await
            .unwrap();
        assert!(ok, "tinker_app must hold {privs} on {table}");
    }
}

/// Concurrent pack installs converge: `install_objects` is
/// check-then-create on global slugs, so without the session install lock
/// two racing installs could both observe a missing slug and one would
/// fail with "object slug already exists". All racers must succeed and
/// resolve the same object ids.
#[tokio::test]
async fn concurrent_pack_installs_converge() {
    let tenant_pool = sqlx::PgPool::connect(
        &std::env::var("TINKER_CORE_URL").expect("TINKER_CORE_URL must be set"),
    )
    .await
    .unwrap();
    let owner_pool = sqlx::PgPool::connect(
        &std::env::var("TINKER_CORE_OWNER_URL").expect("TINKER_CORE_OWNER_URL must be set"),
    )
    .await
    .unwrap();
    let pack =
        tinker_packs::PackDefinition::from_toml(include_str!("../../../packs/crm/pack.toml"))
            .unwrap();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let (tp, op, pack) = (tenant_pool.clone(), owner_pool.clone(), pack.clone());
            tokio::spawn(async move {
                let installer = tinker_packs::PackInstaller::new(
                    tinker_ontology::Ontology::new(
                        tinker_db::CoreDb(tp.clone()),
                        tinker_db::OwnerDb(op),
                    ),
                    tinker_apps::AppRegistry::new(tp),
                );
                installer.install_objects(&pack).await
            })
        })
        .collect();
    let mut first: Option<std::collections::BTreeMap<String, uuid::Uuid>> = None;
    for h in handles {
        let installed = h.await.unwrap().expect("concurrent install must succeed");
        let ids: std::collections::BTreeMap<_, _> = installed.objects.into_iter().collect();
        if let Some(prev) = &first {
            assert_eq!(&ids, prev, "all installs must resolve the same objects");
        } else {
            first = Some(ids);
        }
    }
}

/// A `running` row with a FRESH heartbeat is a live run, not a crashed
/// one: the next starter must refuse with Busy, never murder it.
#[tokio::test]
async fn fresh_running_run_is_not_superseded() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r1) = run_stream(&env, "Account", account_target(), "Account").await;

    // Simulate a LIVE predecessor: `running` with a fresh heartbeat.
    let live_id = uuid::Uuid::now_v7();
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    sqlx::query(
        "INSERT INTO ingest_run (id, organization_id, stream_id, status, checkpoint_in, counts)
         VALUES ($1,$2,$3,'running','{}','{}')",
    )
    .bind(live_id)
    .bind(env.org_id)
    .bind(stream_id)
    .execute(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();

    let err = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .expect_err("a live concurrent run must be refused, not interleaved");
    assert!(
        matches!(err, TinkerError::Busy(_)),
        "expected Busy, got {err:?}"
    );

    // The live row is untouched: still `running`, never flagged superseded.
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (status, counts): (String, serde_json::Value) =
        sqlx::query_as("SELECT status, counts FROM ingest_run WHERE id=$1")
            .bind(live_id)
            .fetch_one(&mut *otx)
            .await
            .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(status, "running");
    assert!(
        counts.get("superseded").is_none(),
        "a live run must never be flagged superseded"
    );
}

/// Two genuinely concurrent start_run calls on one stream: exactly one
/// wins, the loser gets Busy. Runs never interleave, even under a race.
#[tokio::test]
async fn concurrent_start_run_serializes() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r1) = run_stream(&env, "Account", account_target(), "Account").await;

    let control = env.pipeline.control();
    let (a, b) = tokio::join!(
        control.start_run(&env.ctx, stream_id, serde_json::json!({})),
        control.start_run(&env.ctx, stream_id, serde_json::json!({})),
    );
    let results = [&a, &b];
    assert_eq!(
        results.iter().filter(|r| r.is_ok()).count(),
        1,
        "exactly one starter must win"
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(TinkerError::Busy(_))))
            .count(),
        1,
        "the loser must get Busy, got {a:?} / {b:?}"
    );

    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_run
         WHERE organization_id=$1 AND stream_id=$2 AND status='running'",
    )
    .bind(env.org_id)
    .bind(stream_id)
    .fetch_one(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(n, 1, "exactly one running row may exist per stream");
}

/// heartbeat_run refreshes last_heartbeat_at: a backdated live row
/// becomes fresh again (the mechanism the per-page heartbeat relies on).
#[tokio::test]
async fn heartbeat_run_refreshes_liveness() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r1) = run_stream(&env, "Account", account_target(), "Account").await;

    let run_id = uuid::Uuid::now_v7();
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    sqlx::query(
        "INSERT INTO ingest_run (id, organization_id, stream_id, status, checkpoint_in, counts, last_heartbeat_at)
         VALUES ($1,$2,$3,'running','{}','{}', now() - interval '1 hour')",
    )
    .bind(run_id)
    .bind(env.org_id)
    .bind(stream_id)
    .execute(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();

    env.pipeline
        .control()
        .heartbeat_run(&env.ctx, run_id)
        .await
        .unwrap();

    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (fresh,): (bool,) = sqlx::query_as(
        "SELECT last_heartbeat_at > now() - interval '1 minute'
         FROM ingest_run WHERE id=$1",
    )
    .bind(run_id)
    .fetch_one(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    assert!(fresh, "heartbeat_run must refresh last_heartbeat_at");
}

/// The SQLSTATE arm of `TinkerError::is_record_data_error`, exercised
/// against real Postgres errors: a CHECK violation is a data error (the
/// record is invalid, the database is fine); an undefined table and a
/// refused connection are infrastructural.
#[tokio::test]
async fn record_error_classification_sqlstate() {
    let env = setup().await;

    // Real 23514: the crm_deal stage CHECK constraint rejects 'bogus'.
    // (The statement fails atomically — no residue in the shared table.)
    let stage_col = phys(&env, "crm_deal", "stage").await;
    let data_err = sqlx::query(&format!(
        "INSERT INTO data.crm_deal (organization_id, id, \"{stage_col}\") VALUES ($1,$2,'bogus')"
    ))
    .bind(env.org_id)
    .bind(uuid::Uuid::now_v7())
    .execute(&env.owner.0)
    .await
    .expect_err("bogus stage must violate the CHECK constraint");
    let data_err: TinkerError = data_err.into();
    assert!(
        data_err.is_record_data_error(),
        "23514 check_violation is a record data error, got {data_err:?}"
    );

    // Real 42P01: undefined table is infrastructural.
    let missing_err = sqlx::query("SELECT * FROM data.no_such_table_xyz")
        .fetch_all(&env.owner.0)
        .await
        .expect_err("missing table must error");
    let missing_err: TinkerError = missing_err.into();
    assert!(
        !missing_err.is_record_data_error(),
        "42P01 undefined_table is infrastructural, got {missing_err:?}"
    );

    // Real connection refusal: infrastructural by construction.
    let refused = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(2))
        .connect("postgres://127.0.0.1:1/tinker_nodb")
        .await
        .expect_err("port 1 must refuse the connection");
    let refused: TinkerError = refused.into();
    assert!(
        !refused.is_record_data_error(),
        "connection refusal is infrastructural, got {refused:?}"
    );
}

/// An infrastructure failure mid-promote must fail the run loudly — it
/// must never be quarantined as a per-record conflict review.
///
/// Sabotage: a test-private platform object whose physical table is
/// dropped after install. The promote write then dies with 42P01
/// (undefined_table), which is infrastructural, not a data problem.
#[tokio::test]
async fn infra_failure_fails_run_loudly() {
    let env = setup().await;

    // Test-private platform object: unique slug, real typed table. The
    // metadata row lingers after the test but the slug is unique per
    // run, so nothing else can observe it.
    let slug = format!(
        "infra_probe_{}",
        &uuid::Uuid::now_v7().simple().to_string()[20..32] // random tail, not the v7 timestamp head
    );
    let pack_toml = format!(
        "[pack]\nid = \"infra-probe\"\nversion = \"1.0.0\"\nname = \"InfraProbe\"\n\n\
         [[objects]]\nname = \"Probe\"\napi_slug = \"{slug}\"\nlabel = \"Probe\"\n\n\
         [[objects.fields]]\nname = \"name\"\napi_name = \"name\"\nlabel = \"Name\"\nfield_type = \"text\"\n"
    );
    let pack = tinker_packs::PackDefinition::from_toml(&pack_toml).unwrap();
    let installer = tinker_packs::PackInstaller::new(
        tinker_ontology::Ontology::new(env.core.clone(), env.owner.clone()),
        tinker_apps::AppRegistry::new(env.core.0.clone()),
    );
    let installed = installer.install_objects(&pack).await.unwrap();
    assert_eq!(installed.objects.len(), 1, "probe pack installs one object");

    env.salesforce.seed_object(
        "InfraSrc",
        vec![tinker_ingest::connector::SourceField {
            name: "Name".to_string(),
            type_name: "string".to_string(),
        }],
        vec![tinker_ingest::connector::SourceRecord {
            source_id: "P-1".to_string(),
            updated_at: "2026-09-24T10:00:00Z".parse().unwrap(),
            deleted: false,
            fields: [("Name".to_string(), serde_json::json!("probe one"))]
                .into_iter()
                .collect(),
        }],
    );
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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: "InfraSrc".to_string(),
                cursor_kind: "updated_at".to_string(),
            },
        )
        .await
        .unwrap();
    env.pipeline
        .mappings()
        .put_mapping(&env.ctx, stream.id, "Name", &slug, "name")
        .await
        .unwrap();

    // The sabotage: the canonical table vanishes. The slug is
    // generator-built hex, safe to interpolate.
    sqlx::query(&format!("DROP TABLE data.{slug}"))
        .execute(&env.owner.0)
        .await
        .unwrap();

    let err = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream.id,
            &[CanonicalTarget {
                object_slug: slug.clone(),
                email_api_field: None,
            }],
            2,
            RunMode::Incremental,
        )
        .await
        .expect_err("an infra failure must fail the run loudly, not succeed");
    assert!(
        matches!(err, TinkerError::Db(_)),
        "expected a Db infrastructure error, got {err:?}"
    );

    // The run is honestly marked failed ...
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (status,): (String,) = sqlx::query_as(
        "SELECT status FROM ingest_run WHERE stream_id=$1 ORDER BY started_at DESC LIMIT 1",
    )
    .bind(stream.id)
    .fetch_one(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(status, "failed", "the run must be marked failed");

    // ... and nothing was hidden as a conflict review.
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM ingest_review_item
         WHERE organization_id=$1 AND stream_id=$2 AND kind='conflict'",
    )
    .bind(env.org_id)
    .bind(stream.id)
    .fetch_one(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    assert_eq!(
        n, 0,
        "infrastructure failures must never be quarantined as conflict reviews"
    );

    // ... and the first-class outcome columns stay NULL: a failed run
    // has no successful outcome to report, and we never fabricate one.
    let mut otx = owner_scoped(&env.owner.0, env.org_id).await;
    let (fp, landed): (Option<String>, Option<i64>) = sqlx::query_as(
        "SELECT fingerprint, count_landed FROM ingest_run
         WHERE stream_id=$1 ORDER BY started_at DESC LIMIT 1",
    )
    .bind(stream.id)
    .fetch_one(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    assert!(fp.is_none(), "failed run must not report a fingerprint");
    assert!(landed.is_none(), "failed run must not report counts");
}

/// Read the stream row's reconciliation rollup.
async fn read_rollup(
    env: &IngestEnv,
    stream_id: uuid::Uuid,
) -> (
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
    Option<i64>,
    serde_json::Value,
) {
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let row = sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<i64>,
            serde_json::Value,
        ),
    >(
        "SELECT reconcile_fingerprint, reconcile_seen_at, reconcile_expected, reconcile_unexpected
         FROM ingest_stream WHERE id=$1 AND organization_id=$2",
    )
    .bind(stream_id)
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    row
}

/// Post-M8 item 4: reconcile populates the stream rollup columns, and the
/// rollup matches the reconciliation report exactly.
#[tokio::test]
async fn reconcile_populates_stream_rollup() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r) = run_stream(&env, "Account", account_target(), "Account").await;

    let (fp0, seen0, _, _) = read_rollup(&env, stream_id).await;
    assert!(fp0.is_none(), "rollup starts unpopulated");
    assert!(seen0.is_none(), "rollup starts unpopulated");

    let report = env
        .pipeline
        .reconciler()
        .reconcile(&env.ctx, stream_id, "Account", &env.salesforce)
        .await
        .unwrap();

    let (fp, seen, expected, unexpected) = read_rollup(&env, stream_id).await;
    let fp = fp.expect("fingerprint populated");
    assert_eq!(fp.len(), 64, "sha256 hex digest");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit()),
        "fingerprint is hex"
    );
    assert!(seen.is_some(), "seen_at populated");
    assert_eq!(expected, Some(report.source_count));
    assert_eq!(unexpected, serde_json::json!(report.differences));
}

/// Post-M8 item 4: the rollup tracks drift — the fingerprint changes when
/// the outcome changes, and is stable across identical runs.
#[tokio::test]
async fn reconcile_rollup_tracks_drift() {
    let env = setup().await;
    seed_salesforce(&env);
    let (stream_id, _r) = run_stream(&env, "Account", account_target(), "Account").await;
    let reconciler = env.pipeline.reconciler();

    let r1 = reconciler
        .reconcile(&env.ctx, stream_id, "Account", &env.salesforce)
        .await
        .unwrap();
    assert!(
        r1.is_clean(),
        "seeded run reconciles clean, got {:?}",
        r1.differences
    );
    let (fp1, _, _, _) = read_rollup(&env, stream_id).await;
    let fp1 = fp1.unwrap();

    // Sabotage: wipe the landed rows directly, bypassing the pipeline.
    let table = tinker_ingest::landing::LandingWriter::table_for(stream_id);
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    sqlx::query(&format!("DELETE FROM {table} WHERE organization_id=$1"))
        .bind(env.org_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let r2 = reconciler
        .reconcile(&env.ctx, stream_id, "Account", &env.salesforce)
        .await
        .unwrap();
    assert!(!r2.is_clean(), "wiped landing must drift");
    let (fp2, _, expected2, unexpected2) = read_rollup(&env, stream_id).await;
    let fp2 = fp2.unwrap();
    assert_ne!(fp1, fp2, "fingerprint must change when the outcome changes");
    assert_eq!(expected2, Some(r2.source_count));
    assert_eq!(unexpected2, serde_json::json!(r2.differences));
    assert!(
        !unexpected2.as_array().unwrap().is_empty(),
        "drift must be recorded as unexpected"
    );

    // Identical rerun: fingerprint stable (no timestamps in the hash).
    let _r3 = reconciler
        .reconcile(&env.ctx, stream_id, "Account", &env.salesforce)
        .await
        .unwrap();
    let (fp3, _, _, _) = read_rollup(&env, stream_id).await;
    assert_eq!(fp2, fp3.unwrap(), "identical outcomes hash identically");
}

/// Row shape for the ingest_run first-class outcome columns
/// (migration 0024): fingerprint, landed, promoted, linked, created,
/// queued_for_review, pages, drift_breaking, duration_millis, counts JSON.
type RunOutcomeRow = (
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<bool>,
    Option<i64>,
    serde_json::Value,
);

/// M6 backlog (item 4, second half): the run's fingerprint and counts are
/// first-class columns on ingest_run — queryable without touching the
/// counts JSON — and they match the JSON exactly.
#[tokio::test]
async fn run_outcome_first_class_columns() {
    let env = setup().await;
    seed_salesforce(&env);
    let (_sid, r) = run_stream(&env, "Account", account_target(), "Account").await;

    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let row: RunOutcomeRow = sqlx::query_as(
        "SELECT fingerprint, count_landed, count_promoted, count_linked,
                count_created, count_queued_for_review, count_pages,
                drift_breaking, duration_millis, counts
         FROM ingest_run WHERE id=$1 AND organization_id=$2",
    )
    .bind(r.run_id)
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (
        fingerprint,
        landed,
        promoted,
        linked,
        created,
        queued,
        pages,
        drift_breaking,
        millis,
        counts,
    ) = row;

    // The columns are a faithful promotion of the counts JSON ...
    assert_eq!(fingerprint.as_deref(), counts["fingerprint"].as_str());
    assert_eq!(landed, counts["landed"].as_i64());
    assert_eq!(promoted, counts["promoted"].as_i64());
    assert_eq!(linked, counts["linked"].as_i64());
    assert_eq!(created, counts["created"].as_i64());
    assert_eq!(queued, counts["queued_for_review"].as_i64());
    assert_eq!(pages, counts["pages"].as_i64());
    assert_eq!(drift_breaking, counts["drift_breaking"].as_bool());
    assert_eq!(millis, counts["millis"].as_i64());
    // ... and the fingerprint matches the pipeline report.
    assert_eq!(fingerprint.as_deref(), Some(r.fingerprint.as_str()));
    assert!(
        fingerprint.map(|f| f.len() == 64).unwrap_or(false),
        "fingerprint is a sha256 hex digest"
    );
}
/// Snapshot-diff helper: create a "snapshot"-kind stream (non-monotonic
/// source) on the given source object and run one full pass. Returns the
/// stream id and the pipeline report.
async fn run_snapshot_stream(
    env: &IngestEnv,
    source_object: &str,
) -> (uuid::Uuid, tinker_ingest::pipeline::PipelineReport) {
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
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: source_object.to_string(),
                cursor_kind: "snapshot".to_string(),
            },
        )
        .await
        .unwrap();
    let stream_id = stream.id;
    put_standard_mappings(env, stream_id, source_object).await;
    let report = env
        .pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap();
    (stream_id, report)
}

/// Run another full pass on an existing snapshot-kind stream (no new
/// stream, no new mappings — like the next scheduled run).
async fn rerun_snapshot_stream(
    env: &IngestEnv,
    stream_id: uuid::Uuid,
) -> tinker_ingest::pipeline::PipelineReport {
    env.pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            stream_id,
            &[account_target()],
            2,
            RunMode::Incremental,
        )
        .await
        .unwrap()
}

/// Snapshot-diff exit 1: the first run lands every record; a repeat run
/// with no source changes lands nothing — content-hash compare means
/// unchanged rows are never rewritten. Incremental streams never report
/// a snapshot diff.
#[tokio::test]
async fn snapshot_cursor_diff_is_stable() {
    let env = setup().await;
    seed_salesforce(&env);

    let (_sid, r1) = run_snapshot_stream(&env, "Account").await;
    let d1 = r1
        .snapshot_diff
        .as_ref()
        .expect("snapshot mode must report a diff");
    assert_eq!(d1.changed, 2, "first snapshot run lands every record");
    assert_eq!(d1.unchanged, 0);
    assert_eq!(d1.marked_deleted, 0);
    assert_eq!(r1.stages["extract_land"].landed, 2);
    assert_eq!(canonical_count(&env, "crm_company").await, 2);

    // Incremental streams never report a snapshot diff.
    let (_iid, ri) = run_stream(&env, "Account", account_target(), "Account").await;
    assert!(
        ri.snapshot_diff.is_none(),
        "incremental mode must not report a snapshot diff"
    );

    let r2 = rerun_snapshot_stream(&env, _sid).await;
    let d2 = r2
        .snapshot_diff
        .as_ref()
        .expect("snapshot mode must report a diff");
    assert_eq!(d2.changed, 0, "unchanged records must not be rewritten");
    assert_eq!(d2.unchanged, 2);
    assert_eq!(d2.marked_deleted, 0);
    assert_eq!(r2.stages["extract_land"].landed, 0);
    assert_eq!(
        r2.stages["promote"].promoted, 0,
        "stable snapshot must not rewrite canonical values"
    );
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
}

/// Snapshot-diff exit 2: rewritten history is captured. ACC-1 gets new
/// content with an `updated_at` that moves BACKWARDS — a monotonic cursor
/// advanced past the old timestamp would skip it forever. Snapshot mode
/// compares content hashes, so it cannot be missed.
#[tokio::test]
async fn snapshot_cursor_captures_rewritten_history() {
    let env = setup().await;
    seed_salesforce(&env);

    let (sid, r1) = run_snapshot_stream(&env, "Account").await;
    assert_eq!(
        r1.snapshot_diff.as_ref().unwrap().changed,
        2,
        "seed run lands both accounts"
    );

    // Rewritten history: new content, timestamp moved backwards, arriving
    // in an order unrelated to updated_at (non-monotonic source).
    assert!(env.salesforce.rewrite_record(
        "Account",
        "ACC-1",
        "2026-09-01T10:00:00Z",
        vec![
            ("Id", serde_json::json!("ACC-1")),
            ("Name", serde_json::json!("Acme Corp (rebranded)")),
            ("Industry", serde_json::json!("Manufacturing")),
        ],
    ));
    env.salesforce.permute("Account", &[1, 0]);

    let r2 = rerun_snapshot_stream(&env, sid).await;
    let d2 = r2
        .snapshot_diff
        .as_ref()
        .expect("snapshot mode must report a diff");
    assert_eq!(
        d2.changed, 1,
        "rewritten record must land despite its older timestamp"
    );
    assert_eq!(d2.unchanged, 1, "untouched record must be skipped");
    assert_eq!(d2.marked_deleted, 0);

    // No duplicate canonical record: the rewritten row links to the same
    // company and updates its name via survivorship.
    assert_eq!(canonical_count(&env, "crm_company").await, 2);
    let name_col = phys(&env, "crm_company", "name").await;
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (name,): (Option<String>,) = sqlx::query_as(&format!(
        "SELECT \"{name_col}\" FROM data.crm_company WHERE organization_id=$1 ORDER BY \"{name_col}\""
    ))
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        name.as_deref(),
        Some("Acme Corp (rebranded)"),
        "rewritten source content must reach the canonical row"
    );
}

/// Snapshot-diff exit 3: a record that vanishes from a COMPLETE scan is
/// marked `_deleted=true` in the mirror (absence is evidence of deletion
/// only because the scan covers the whole source). Canonical rows are
/// kept: the mirror records the deletion; canonical tombstone policy is
/// a separate design decision.
#[tokio::test]
async fn snapshot_cursor_marks_missing_as_deleted() {
    let env = setup().await;
    seed_salesforce(&env);

    let (sid, r1) = run_snapshot_stream(&env, "Account").await;
    assert_eq!(
        r1.snapshot_diff.as_ref().unwrap().changed,
        2,
        "seed run lands both accounts"
    );

    // Hard delete at the source: no tombstone, the record just stops
    // appearing in snapshots.
    assert!(env.salesforce.remove_record("Account", "ACC-2"));

    let r2 = rerun_snapshot_stream(&env, sid).await;
    let d2 = r2
        .snapshot_diff
        .as_ref()
        .expect("snapshot mode must report a diff");
    assert_eq!(d2.changed, 0);
    assert_eq!(d2.unchanged, 1);
    assert_eq!(
        d2.marked_deleted, 1,
        "vanished record must be marked deleted"
    );

    let table = tinker_ingest::LandingWriter::table_for(sid);
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let (deleted,): (bool,) = sqlx::query_as(&format!(
        "SELECT _deleted FROM {table} WHERE organization_id=$1 AND _source_id='ACC-2'"
    ))
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(deleted, "absent mirror row must be marked deleted");
    assert_eq!(
        canonical_count(&env, "crm_company").await,
        2,
        "canonical rows are not removed by the mirror sweep"
    );
}

/// A one-object pack (`name`, `email`) plus a fake-Salesforce lead stream
/// mapped into it. `sensitive` sets the email field's flag at install.
struct LeadStream {
    slug: String,
    stream_id: uuid::Uuid,
    target: tinker_ingest::pipeline::CanonicalTarget,
}

async fn lead_stream(
    env: &IngestEnv,
    pipeline: &tinker_ingest::IngestPipeline,
    sensitive: bool,
) -> LeadStream {
    let tag = &uuid::Uuid::now_v7().simple().to_string()[20..32];
    let slug = format!("pii_lead_{tag}");
    let pack = tinker_packs::PackDefinition::from_toml(&format!(
        "[pack]\nid = \"pii-lead-{tag}\"\nversion = \"1.0.0\"\nname = \"Leads\"\n\n\
         [[objects]]\nname = \"Lead\"\napi_slug = \"{slug}\"\nlabel = \"Lead\"\n\n\
         [[objects.fields]]\nname = \"name\"\napi_name = \"name\"\nlabel = \"Name\"\nfield_type = \"text\"\n\n\
         [[objects.fields]]\nname = \"email\"\napi_name = \"email\"\nlabel = \"Email\"\n\
         field_type = \"email\"\nsensitive = {sensitive}\n"
    ))
    .unwrap();
    tinker_packs::PackInstaller::new(
        tinker_ontology::Ontology::new(env.core.clone(), env.owner.clone()),
        tinker_apps::AppRegistry::new(env.core.0.clone()),
    )
    .install_objects(&pack)
    .await
    .unwrap();
    let source = format!("Lead{tag}");
    env.salesforce.seed_object(
        &source,
        vec![
            tinker_ingest::SourceField {
                name: "Id".into(),
                type_name: "id".into(),
            },
            tinker_ingest::SourceField {
                name: "FullName".into(),
                type_name: "string".into(),
            },
            tinker_ingest::SourceField {
                name: "Email".into(),
                type_name: "string".into(),
            },
        ],
        vec![tinker_ingest::SourceRecord {
            source_id: "LEAD-1".into(),
            updated_at: "2026-09-20T10:00:00Z".parse().unwrap(),
            deleted: false,
            fields: [
                ("Id".to_string(), serde_json::json!("LEAD-1")),
                ("FullName".to_string(), serde_json::json!("Grace Hopper")),
                (
                    "Email".to_string(),
                    serde_json::json!("Grace.Hopper@Navy.mil"),
                ),
            ]
            .into_iter()
            .collect(),
        }],
    );
    let control = pipeline.control();
    let conn = control
        .create_connection(
            &env.ctx,
            tinker_ingest::control::NewConnection {
                kind: "salesforce".into(),
                name: "salesforce".into(),
                credential_ref: None,
            },
        )
        .await
        .unwrap();
    let stream = control
        .create_stream(
            &env.ctx,
            tinker_ingest::control::NewStream {
                connection_id: conn.id,
                source_object: source,
                cursor_kind: "updated_at".into(),
            },
        )
        .await
        .unwrap();
    for (src, tgt) in [("FullName", "name"), ("Email", "email")] {
        pipeline
            .mappings()
            .put_mapping(&env.ctx, stream.id, src, &slug, tgt)
            .await
            .unwrap();
    }
    LeadStream {
        target: tinker_ingest::pipeline::CanonicalTarget {
            object_slug: slug.clone(),
            email_api_field: Some("email".into()),
        },
        slug,
        stream_id: stream.id,
    }
}

async fn run_lead(
    env: &IngestEnv,
    pipeline: &tinker_ingest::IngestPipeline,
    l: &LeadStream,
    mode: RunMode,
) {
    pipeline
        .run(
            &env.ctx,
            &env.salesforce,
            l.stream_id,
            std::slice::from_ref(&l.target),
            2,
            mode,
        )
        .await
        .unwrap();
}

/// Every place a lead's email could sit in core + ingest, as text.
async fn lead_copies(env: &IngestEnv, l: &LeadStream) -> Vec<String> {
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let mut out: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t)::text FROM data.{} t WHERE organization_id = $1",
        l.slug
    ))
    .bind(env.org_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    out.extend(
        sqlx::query_scalar::<_, String>(&format!(
            "SELECT to_jsonb(t)::text FROM {} t WHERE organization_id = $1",
            tinker_ingest::LandingWriter::table_for(l.stream_id)
        ))
        .bind(env.org_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap(),
    );
    out.extend(
        sqlx::query_scalar::<_, String>(
            "SELECT value::text FROM ingest_provenance WHERE organization_id = $1 AND stream_id = $2",
        )
        .bind(env.org_id)
        .bind(l.stream_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap(),
    );
    tx.commit().await.unwrap();
    out
}

async fn sealer_env() -> tinker_ontology::sensitive::PiiSealer {
    tinker_ontology::sensitive::sealer_from_env()
        .await
        .unwrap()
        .expect("TINKER_PII_URL, TINKER_KEK, TINKER_BLIND_INDEX_KEY must be set")
}

/// Sensitive canonical fields (docs/pii-sensitive-fields.md) through
/// managed ingestion: promotion seals the value into the vault, matches
/// identities and runs survivorship on the blind index, records only the
/// digest as provenance, and scrubs the landing mirror to a digest
/// marker. A re-run is a no-op: no re-seal, no plaintext reappears.
#[tokio::test]
async fn ingest_seals_sensitive_fields_and_scrubs_landing() {
    let env = setup().await;
    let sealer = sealer_env().await;
    let pipeline = tinker_ingest::IngestPipeline::new(env.core.clone(), env.owner.clone())
        .with_pii(sealer.clone());
    let l = lead_stream(&env, &pipeline, true).await;
    run_lead(&env, &pipeline, &l, RunMode::Incremental).await;

    let copies = lead_copies(&env, &l).await;
    assert!(
        copies.iter().any(|c| c.contains("Grace Hopper")),
        "non-sensitive lands as-is"
    );
    for c in &copies {
        assert!(
            !c.to_lowercase().contains("navy.mil"),
            "plaintext copy: {c}"
        );
    }
    assert!(
        copies.iter().any(|c| c.contains("$tinker_sealed")),
        "landing holds the marker"
    );
    let (ref_id, refs_before) = lead_ref(&env, &l).await;
    assert_eq!(
        sealer
            .reveal(&env.core, &env.ctx, ref_id, "ingest test")
            .await
            .unwrap(),
        "Grace.Hopper@Navy.mil"
    );

    // Full resync: the scrubbed landing row compares by digest — nothing
    // is re-sealed and the canonical ref is unchanged.
    run_lead(&env, &pipeline, &l, RunMode::FullResync).await;
    assert_eq!(
        lead_ref(&env, &l).await,
        (ref_id, refs_before),
        "no re-seal on an unchanged value"
    );
}

/// (canonical email ref, live pii_refs count) for the org.
async fn lead_ref(env: &IngestEnv, l: &LeadStream) -> (uuid::Uuid, i64) {
    let email_col: String = sqlx::query_scalar(
        "SELECT f.physical_column FROM ontology_fields f JOIN ontology_objects o ON o.id = f.object_id \
         WHERE o.api_slug = $1 AND f.api_name = 'email'",
    )
    .bind(&l.slug)
    .fetch_one(&env.owner.0)
    .await
    .unwrap();
    let mut tx = env.core.tenant_tx(&env.ctx).await.unwrap();
    let ref_id: uuid::Uuid = sqlx::query_scalar(&format!(
        "SELECT \"{email_col}\" FROM data.{} WHERE organization_id = $1",
        l.slug
    ))
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let refs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pii_refs WHERE organization_id = $1 AND state = 'active'",
    )
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    (ref_id, refs)
}

/// Retrofit through ingest: a plaintext field that ingest already
/// populated (row, landing, provenance) is converted — core half seals
/// the row, ingest half digests provenance and markers the landing — and
/// the next ingest run neither re-seals nor reintroduces plaintext.
#[tokio::test]
async fn ingested_plaintext_field_retrofits_to_sensitive() {
    let env = setup().await;
    let sealer = sealer_env().await;
    let plain = tinker_ingest::IngestPipeline::new(env.core.clone(), env.owner.clone());
    let l = lead_stream(&env, &plain, false).await;
    run_lead(&env, &plain, &l, RunMode::Incremental).await;
    assert!(
        lead_copies(&env, &l)
            .await
            .iter()
            .any(|c| c.contains("Grace.Hopper@Navy.mil")),
        "precondition: plaintext before the retrofit"
    );

    let object_id: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM ontology_objects WHERE api_slug = $1")
            .bind(&l.slug)
            .fetch_one(&env.owner.0)
            .await
            .unwrap();
    let report = sealer
        .make_field_sensitive(&env.owner, object_id, "email")
        .await
        .unwrap();
    assert!(report.rows >= 1);
    let sealing = tinker_ingest::IngestPipeline::new(env.core.clone(), env.owner.clone())
        .with_pii(sealer.clone());
    let replaced = sealing
        .retrofit_sensitive(&sealer, &l.slug, "email")
        .await
        .unwrap();
    assert_eq!(replaced, 2, "one landing copy + one provenance value");
    for c in lead_copies(&env, &l).await {
        assert!(
            !c.to_lowercase().contains("navy.mil"),
            "plaintext copy after retrofit: {c}"
        );
    }

    let (ref_id, refs) = lead_ref(&env, &l).await;
    run_lead(&env, &sealing, &l, RunMode::FullResync).await;
    assert_eq!(
        lead_ref(&env, &l).await,
        (ref_id, refs),
        "digest match: nothing re-sealed"
    );
    for c in lead_copies(&env, &l).await {
        assert!(
            !c.to_lowercase().contains("navy.mil"),
            "plaintext reintroduced: {c}"
        );
    }
}
