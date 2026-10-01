//! C1 record lifecycle (item 40): draft → review → publish, plus
//! rejected/archived, composed with M7 approvals and M8 retention.
//!
//! Storage truth: `data.*` holds ONLY the current published/archived
//! row; `record_drafts` holds in-flight work; `record_versions` holds an
//! immutable snapshot per publish. These tests prove the lifecycle is
//! enforced at every read path and that M7/M8 composition is honest.
//!
//! Adversarial coverage: draft privacy (direct fetch, query, counts),
//! unauthorized publish, approval bypass, version isolation, archive
//! visibility, retention + legal hold, tenant isolation, audit trail.

mod common;

use std::collections::HashMap;

use tinker_agents::audit::AuditWriter;
use tinker_agents::gateway::ModelGateway;
use tinker_agents::{ApprovalEngine, TransformEngine};
use tinker_core::{OrganizationId, Param, TenantContext, TinkerError};
use tinker_db::OwnerDb;
use tinker_ontology::lifecycle::{Draft, LifecycleEngine, PublishOutcome};
use tinker_ontology::mutate::{CreateRequest, MutationConnector, UpdateRequest};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use tinker_query::{
    append_default_published_predicate, bind_param_as, FieldProjection, QueryCompiler, QueryIntent,
    RowFilterDef, RowFilters,
};
use tinker_transfer::RetentionEngine;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

fn object_def(slug: &str) -> ObjectDef {
    ObjectDef {
        name: slug.into(),
        api_slug: slug.into(),
        label: slug.into(),
        scope: Scope::Organization,
        pack_id: None,
        pack_version: None,
    }
}

fn field(api_name: &str, field_type: FieldType, required: bool) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        sensitive: false,
        validation: Default::default(),
        preset: None,
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type,
        options: serde_json::json!({}),
        required,
    }
}

/// One org with a lifecycle-managed `article` object (title required,
/// body optional), plus author/reviewer/viewer contexts, a second org
/// for tenant isolation, and a scratch agent attachment backing the M7
/// approval requests (the attachment_id FK requires a real
/// `agent_attachments` row; the BINDING the engine verifies is
/// action_name + payload, not the attachment).
struct World {
    article: Uuid,
    article_slug: String,
    attachment: Uuid,
    ctx_owner: TenantContext,
    ctx_author: TenantContext,
    ctx_reviewer: TenantContext,
    ctx_viewer: TenantContext,
    ctx_b: TenantContext,
}

async fn member(env: &common::Env, org_id: Uuid, role: &str) -> TenantContext {
    let actor_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
    )
    .bind(actor_id)
    .bind(org_id)
    .bind(format!("{role}-{actor_id}"))
    .execute(&env.core_owner)
    .await
    .unwrap();
    sqlx::query("INSERT INTO memberships (organization_id, actor_id, role) VALUES ($1,$2,$3)")
        .bind(org_id)
        .bind(actor_id)
        .bind(role)
        .execute(&env.core_owner)
        .await
        .unwrap();
    TenantContext::new(
        OrganizationId(org_id),
        actor_id,
        format!("m0-lifecycle-{role}"),
    )
}

async fn setup_world(env: &common::Env) -> World {
    let ctx_a = common::new_org(env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(env, &common::uniq("orgb")).await;
    let org_a = ctx_a.organization_id.0;
    let org_b = ctx_b.organization_id.0;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));

    let slug = common::uniq("article");
    let article = ont.define_object(&ctx_a, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx_a, article.id, &field("title", FieldType::Text, true))
        .await
        .unwrap();
    ont.add_field(&ctx_a, article.id, &field("body", FieldType::Text, false))
        .await
        .unwrap();
    ont.set_lifecycle_enabled(&ctx_a, article.id, true)
        .await
        .unwrap();

    // Members first: the attachment FK needs a real (org, actor) pair.
    let ctx_author = member(env, org_a, "member").await;
    let ctx_reviewer = member(env, org_a, "reviewer").await;
    let ctx_viewer = member(env, org_a, "viewer").await;
    let ctx_b = member(env, org_b, "member").await;

    // Scratch agent attachment backing M7 approval requests. RLS on
    // agent_attachments requires the tenant session vars, so insert
    // through a tenant transaction (the approval engine's own path).
    let mut att_tx = env.core.tenant_tx(&ctx_author).await.unwrap();
    let attachment: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_attachments \
         (organization_id, actor_id, name, kind, scope, action_grants, \
          approval_policy, budgets, status) \
         VALUES ($1, $2, 'lifecycle-test', 'test', '{}', '[]', '{}', '{}', 'active') \
         RETURNING id",
    )
    .bind(org_a)
    .bind(ctx_author.actor_id)
    .fetch_one(&mut *att_tx)
    .await
    .unwrap();
    att_tx.commit().await.unwrap();

    World {
        article: article.id,
        article_slug: slug,
        attachment,
        ctx_owner: ctx_a,
        ctx_author,
        ctx_reviewer,
        ctx_viewer,
        ctx_b,
    }
}

fn engines(env: &common::Env) -> (Ontology, LifecycleEngine, ApprovalEngine, RetentionEngine) {
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let lc = LifecycleEngine::new(env.core.clone(), ont.clone());
    let ap = ApprovalEngine::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let rt = RetentionEngine::new(env.core.clone(), env.pii.clone());
    (ont, lc, ap, rt)
}

fn values(pairs: &[(&str, &str)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), serde_json::json!(v)))
        .collect()
}

/// Request an approval and (optionally) have the reviewer decide it.
/// The lifecycle binding contract: `action_name` + payload
/// `{subject_key: subject}` — e.g. ("submit_for_review", "draft_id",
/// draft.draft_id). Returns the approval request id.
#[allow(clippy::too_many_arguments)] // test helper: readability over arity
async fn request_approval(
    ap: &ApprovalEngine,
    w: &World,
    ctx_req: &TenantContext,
    ctx_decide: &TenantContext,
    subject_key: &str,
    subject: Uuid,
    action: &str,
    approve: Option<bool>,
) -> Uuid {
    // NB: `json!({ subject_key: ... })` would bake the LITERAL key
    // "subject_key" — the binding contract needs the variable's value
    // ("draft_id" / "record_id"), so build the map explicitly.
    let mut payload = serde_json::Map::new();
    payload.insert(
        subject_key.to_string(),
        serde_json::Value::String(subject.to_string()),
    );
    let req = ap
        .request(
            ctx_req,
            w.attachment,
            action,
            serde_json::Value::Object(payload),
            &format!("lc-{}-{}", action, Uuid::now_v7()),
        )
        .await
        .unwrap();
    if let Some(ok) = approve {
        ap.decide(ctx_decide, req.id, ok).await.unwrap();
    }
    req.id
}

/// Shorthand for draft-bound approvals ("draft_id").
async fn draft_approval(
    ap: &ApprovalEngine,
    w: &World,
    ctx_decide: &TenantContext,
    draft_id: Uuid,
    action: &str,
    approve: Option<bool>,
) -> Uuid {
    request_approval(
        ap,
        w,
        &w.ctx_author,
        ctx_decide,
        "draft_id",
        draft_id,
        action,
        approve,
    )
    .await
}

/// Shorthand for record-bound approvals ("record_id").
async fn record_approval(
    ap: &ApprovalEngine,
    w: &World,
    ctx_decide: &TenantContext,
    record_id: Uuid,
    action: &str,
    approve: Option<bool>,
) -> Uuid {
    request_approval(
        ap,
        w,
        &w.ctx_author,
        ctx_decide,
        "record_id",
        record_id,
        action,
        approve,
    )
    .await
}

/// Full happy-path flow: draft → submit → publish. Returns the published
/// record id.
async fn publish_new_record(
    lc: &LifecycleEngine,
    ap: &ApprovalEngine,
    w: &World,
    title: &str,
    body: &str,
) -> (Uuid, PublishOutcome) {
    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", title), ("body", body)]),
        )
        .await
        .unwrap();
    let sub = draft_approval(
        ap,
        w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();
    let publ = draft_approval(
        ap,
        w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let out = lc
        .publish(&w.ctx_author, draft.draft_id, publ)
        .await
        .unwrap();
    (out.record_id, out)
}

/// Compile a title-select query under an open policy and return titles.
async fn query_titles(
    env: &common::Env,
    ont: &Ontology,
    ctx: &TenantContext,
    object_id: Uuid,
) -> Vec<String> {
    let qc = QueryCompiler::new(ont.clone());
    let rf = RowFilters::new(env.core.clone());
    let policy = rf.load_policy(ctx, object_id, "viewer").await.unwrap();
    assert!(policy.is_open(), "test world has no row filters by default");
    let plan = qc
        .compile_with_policy(
            ctx,
            &QueryIntent {
                from: object_id,
                select: vec!["title".into()],
                filters: vec![],
                order: vec![],
                limit: Some(100),
                schema_version: None,
            },
            &FieldProjection::unrestricted(),
            &policy,
        )
        .await
        .unwrap();
    // The C1 default must be in the same WHERE as tenant + policy.
    assert!(
        plan.sql.contains("\"lifecycle_state\""),
        "query must carry the published-only predicate: {}",
        plan.sql
    );
    let mut tx = env.core.tenant_tx(ctx).await.unwrap();
    let mut q = sqlx::query_as::<_, (String,)>(&plan.sql);
    for p in &plan.params {
        q = bind_param_as(q, p);
    }
    let rows: Vec<(String,)> = q.fetch_all(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let mut names: Vec<String> = rows.into_iter().map(|(t,)| t).collect();
    names.sort();
    names
}

fn transform_engine(env: &common::Env, ont: &Ontology) -> TransformEngine {
    let owner_db = OwnerDb(env.core_owner.clone());
    TransformEngine::new(
        env.core.clone(),
        owner_db.clone(),
        ont.clone(),
        ModelGateway::new(env.core.clone(), owner_db.clone()),
        AuditWriter::new(env.core.clone(), owner_db),
    )
}

async fn render_title(
    engine: &TransformEngine,
    ctx: &TenantContext,
    slug: &str,
    record_id: Uuid,
) -> Result<String, TinkerError> {
    let (fields, _) = engine
        .render_record(ctx, slug, record_id, None, "/")
        .await?;
    Ok(fields
        .into_iter()
        .find(|(k, _)| k == "title")
        .map(|(_, v)| v.as_str().unwrap_or("").to_string())
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Lifecycle state machine
// ---------------------------------------------------------------------------

#[tokio::test]
async fn lifecycle_happy_path_new_record() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);

    let draft: Draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Hello"), ("body", "world")]),
        )
        .await
        .unwrap();
    assert!(
        draft.record_id.is_none(),
        "new-record draft has no record yet"
    );

    // Author cannot update someone else's draft (tenant isolation via
    // author check happens in update_draft; reviewer editing fails).
    let err = lc
        .update_draft(
            &w.ctx_reviewer,
            draft.draft_id,
            &values(&[("title", "Hijack")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");

    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit",
        Some(true),
    )
    .await;
    // Wrong action name on the approval must not submit.
    let err = lc
        .submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "approval action mismatch must fail closed, got {err:?}"
    );

    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    let d = lc
        .submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();
    assert_eq!(
        d.state,
        tinker_ontology::lifecycle::LifecycleState::InReview
    );

    // Draft frozen in review: author edits rejected.
    let err = lc
        .update_draft(
            &w.ctx_author,
            draft.draft_id,
            &values(&[("title", "Late edit")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");

    // Publish needs its own approval; the submit approval is consumed.
    let err = lc
        .publish(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "consumed approval must not publish, got {err:?}"
    );

    let publ = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let out = lc
        .publish(&w.ctx_author, draft.draft_id, publ)
        .await
        .unwrap();
    assert_eq!(out.version, 1);

    // Published record visible to readers via query and direct render.
    let titles = query_titles(&env, &ont, &w.ctx_viewer, w.article).await;
    assert_eq!(titles, vec!["Hello".to_string()]);
    let engine = transform_engine(&env, &ont);
    assert_eq!(
        render_title(&engine, &w.ctx_viewer, &w.article_slug, out.record_id)
            .await
            .unwrap(),
        "Hello"
    );

    // Version snapshot recorded.
    let versions = lc
        .list_versions(&w.ctx_viewer, w.article, out.record_id)
        .await
        .unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].version_no, 1);
    assert_eq!(versions[0].content["title"], serde_json::json!("Hello"));

    // Audit trail: one row per transition in the dedicated lifecycle_audit table.
    let mut tx = env.core.tenant_tx(&w.ctx_viewer).await.unwrap();
    let ops: Vec<(String,)> = sqlx::query_as(
        "SELECT transition FROM lifecycle_audit \
         WHERE organization_id = $1 \
         ORDER BY created_at",
    )
    .bind(w.ctx_viewer.organization_id.0)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let ops: Vec<String> = ops.into_iter().map(|(o,)| o).collect();
    assert_eq!(
        ops,
        vec!["create_draft", "submit_for_review", "publish"],
        "audit trail must record every transition"
    );
}

#[tokio::test]
async fn draft_invisible_across_read_paths() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, _ap, _rt) = engines(&env);

    // Draft for a NEW record: there is no record id to fetch, but the
    // query path must not see it.
    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Secret draft")]),
        )
        .await
        .unwrap();
    assert!(draft.record_id.is_none());

    let titles = query_titles(&env, &ont, &w.ctx_viewer, w.article).await;
    assert!(
        titles.is_empty(),
        "draft must not appear in queries: {titles:?}"
    );

    // Draft for an EXISTING record: publish first, then fork a draft.
    let (rid, _) = publish_new_record(&lc, &_ap, &w, "Public", "v1").await;
    let edit = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            Some(rid),
            &values(&[("title", "Public"), ("body", "secret v2")]),
        )
        .await
        .unwrap();
    assert_eq!(edit.record_id, Some(rid));

    // Reader still sees the published v1 — draft edits do not change it.
    let titles = query_titles(&env, &ont, &w.ctx_viewer, w.article).await;
    assert_eq!(titles, vec!["Public".to_string()]);
    let engine = transform_engine(&env, &ont);
    let (fields, _) = engine
        .render_record(&w.ctx_viewer, &w.article_slug, rid, None, "/")
        .await
        .unwrap();
    let body = fields
        .iter()
        .find(|(k, _)| k == "body")
        .map(|(_, v)| v.clone());
    assert_eq!(
        body,
        Some(serde_json::json!("v1")),
        "published body unchanged"
    );

    // The draft row itself is unreachable via the data table: no
    // lifecycle_state other than published/archived can be queried by
    // readers, because drafts never live in data.*.
    let mut tx = env.core.tenant_tx(&w.ctx_viewer).await.unwrap();
    let n: (i64,) = sqlx::query_as(&format!(
        "SELECT COUNT(*) FROM data.\"{}\" WHERE organization_id = $1 AND id = $2",
        w.article_slug
    ))
    .bind(w.ctx_viewer.organization_id.0)
    .bind(rid)
    .fetch_optional(&mut *tx)
    .await
    .unwrap()
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n.0, 1, "exactly one published row for the record");

    // The C1 default predicate is a typed bind, not interpolation.
    let mut sql = String::from("SELECT 1");
    let mut params: Vec<Param> = Vec::new();
    let policy = RowFilters::new(env.core.clone())
        .load_policy(&w.ctx_viewer, w.article, "viewer")
        .await
        .unwrap();
    append_default_published_predicate(&policy, true, &mut sql, &mut params, None, &|i| {
        format!("${i}")
    });
    assert!(sql.contains("\"lifecycle_state\" = $1"));
    assert!(!sql.contains("published'"), "value must be bound: {sql}");
    assert!(matches!(&params[0], Param::Text(s) if s == "published"));
}

#[tokio::test]
async fn illegal_transitions_rejected() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (_ont, lc, ap, _rt) = engines(&env);

    let draft = lc
        .create_draft(&w.ctx_author, w.article, None, &values(&[("title", "T")]))
        .await
        .unwrap();

    // Publish straight from draft: not in review.
    let publ = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let err = lc
        .publish(&w.ctx_author, draft.draft_id, publ)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");

    // Second in-flight draft for a new record is fine (no record id),
    // but an existing record allows only one.
    let (rid, _) = publish_new_record(&lc, &ap, &w, "Solo", "b").await;
    let d1 = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            Some(rid),
            &values(&[("title", "Solo")]),
        )
        .await
        .unwrap();
    let err = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            Some(rid),
            &values(&[("title", "Solo")]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");

    // Reject by the author: forbidden (only reviewers reject).
    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        d1.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, d1.draft_id, sub)
        .await
        .unwrap();
    let err = lc
        .reject(&w.ctx_author, d1.draft_id, "self-reject")
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");

    // Proper reject, then revise by a non-author: forbidden.
    lc.reject(&w.ctx_reviewer, d1.draft_id, "needs work")
        .await
        .unwrap();
    let err = lc.revise(&w.ctx_reviewer, d1.draft_id).await.unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");

    // Revise moves back to draft; publishing from rejected fails.
    let err = lc
        .publish(&w.ctx_author, d1.draft_id, publ)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");
    let d = lc.revise(&w.ctx_author, d1.draft_id).await.unwrap();
    assert_eq!(d.state, tinker_ontology::lifecycle::LifecycleState::Draft);

    // Update on a rejected draft: still author-only and allowed (author
    // owns it); update on someone else's rejected draft: forbidden.
    lc.update_draft(&w.ctx_author, d1.draft_id, &values(&[("title", "Solo v2")]))
        .await
        .unwrap();
}

#[tokio::test]
async fn reject_revise_resubmit_flow() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (_ont, lc, ap, _rt) = engines(&env);

    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Rough")]),
        )
        .await
        .unwrap();
    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();
    // Reject needs no approval: it is fail-safe (blocks publication).
    let d = lc
        .reject(&w.ctx_reviewer, draft.draft_id, "typo in title")
        .await
        .unwrap();
    assert_eq!(
        d.state,
        tinker_ontology::lifecycle::LifecycleState::Rejected
    );

    lc.revise(&w.ctx_author, draft.draft_id).await.unwrap();
    lc.update_draft(
        &w.ctx_author,
        draft.draft_id,
        &values(&[("title", "Polished")]),
    )
    .await
    .unwrap();
    let sub2 = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub2)
        .await
        .unwrap();
    let publ = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let out = lc
        .publish(&w.ctx_author, draft.draft_id, publ)
        .await
        .unwrap();
    assert_eq!(out.version, 1);

    let versions = lc
        .list_versions(&w.ctx_viewer, w.article, out.record_id)
        .await
        .unwrap();
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].content["title"], serde_json::json!("Polished"));
}

/// `approval_requests` is FORCE-RLS: read it through the tenant tx.
async fn approval_status(env: &common::Env, ctx: &TenantContext, id: Uuid) -> String {
    let mut tx = env.core.tenant_tx(ctx).await.unwrap();
    let status = sqlx::query_scalar("SELECT status FROM approval_requests WHERE id=$1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    status
}

/// An approval binds to (action, draft_id), not to content. A `publish`
/// approval decided while v1 was in review must not ship v2 after
/// reject → revise → edit → resubmit: rejection (and any content edit)
/// retires every live approval bound to the draft.
#[tokio::test]
async fn stale_publish_approval_does_not_survive_reject_and_edit() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (_ont, lc, ap, _rt) = engines(&env);

    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Reviewed")]),
        )
        .await
        .unwrap();
    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();
    // Reviewer approves publishing v1 ... then rejects for another reason.
    let stale = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    lc.reject(&w.ctx_reviewer, draft.draft_id, "one more fix")
        .await
        .unwrap();

    // Author revises to content the reviewer never saw, and resubmits.
    lc.revise(&w.ctx_author, draft.draft_id).await.unwrap();
    lc.update_draft(
        &w.ctx_author,
        draft.draft_id,
        &values(&[("title", "Unreviewed")]),
    )
    .await
    .unwrap();
    let sub2 = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub2)
        .await
        .unwrap();

    let err = lc
        .publish(&w.ctx_author, draft.draft_id, stale)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "stale approval must not publish, got {err:?}"
    );
    assert_eq!(approval_status(&env, &w.ctx_author, stale).await, "expired");

    // A fresh decision on the current content still publishes.
    let fresh = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let out = lc
        .publish(&w.ctx_author, draft.draft_id, fresh)
        .await
        .unwrap();
    let versions = lc
        .list_versions(&w.ctx_viewer, w.article, out.record_id)
        .await
        .unwrap();
    assert_eq!(
        versions[0].content["title"],
        serde_json::json!("Unreviewed")
    );
}

/// A draft edit also retires approvals requested against the old content.
#[tokio::test]
async fn draft_edit_retires_pending_and_approved_approvals() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (_ont, lc, ap, _rt) = engines(&env);

    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "First")]),
        )
        .await
        .unwrap();
    let approved = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    let pending = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        None,
    )
    .await;
    lc.update_draft(
        &w.ctx_author,
        draft.draft_id,
        &values(&[("title", "Second")]),
    )
    .await
    .unwrap();
    for id in [approved, pending] {
        assert_eq!(approval_status(&env, &w.ctx_author, id).await, "expired");
    }
    let err = lc
        .submit_for_review(&w.ctx_author, draft.draft_id, approved)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");
}

/// Sensitive fields through the lifecycle (docs/pii-sensitive-fields.md):
/// draft content, version history and the published row only ever hold
/// the sealed form; an edit forks the sealed value out of the row and
/// republishes it intact; an engine without a vault refuses the value.
#[tokio::test]
async fn sensitive_fields_stay_sealed_through_drafts_and_versions() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, _lc, ap, _rt) = engines(&env);
    let email = FieldDef {
        name: "Email".into(),
        api_name: "contact_email".into(),
        label: "Email".into(),
        field_type: FieldType::Email,
        options: serde_json::json!({}),
        required: false,
        validation: Default::default(),
        preset: None,
        max_pii_class: "restricted".into(),
        sensitive: true,
    };
    ont.add_field(&w.ctx_owner, w.article, &email)
        .await
        .unwrap();
    let sealer = tinker_ontology::sensitive::sealer_from_env()
        .await
        .unwrap()
        .expect("TINKER_PII_URL, TINKER_KEK, TINKER_BLIND_INDEX_KEY must be set");
    let lc = LifecycleEngine::new(env.core.clone(), ont.clone()).with_pii(sealer.clone());

    let plaintext = "Ada.Lovelace@Example.org";
    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Notes"), ("contact_email", plaintext)]),
        )
        .await
        .unwrap();
    let sealed = draft.content["contact_email"].clone();
    assert!(
        tinker_ontology::sensitive::parse_sealed(&sealed).is_some(),
        "{sealed}"
    );
    assert!(!draft.content.to_string().contains("Lovelace"));
    // Editing another field keeps the sealed value as-is.
    let draft = lc
        .update_draft(
            &w.ctx_author,
            draft.draft_id,
            &values(&[("title", "Notes v2")]),
        )
        .await
        .unwrap();
    assert_eq!(draft.content["contact_email"], sealed);

    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();
    let publ = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let out = lc
        .publish(&w.ctx_author, draft.draft_id, publ)
        .await
        .unwrap();
    let versions = lc
        .list_versions(&w.ctx_viewer, w.article, out.record_id)
        .await
        .unwrap();
    assert!(!versions[0].content.to_string().contains("Lovelace"));
    assert_eq!(versions[0].content["contact_email"], sealed);

    // Fork the published record: the sealed value comes back out of the
    // ref + blind-index columns and republishes unchanged.
    let edit = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            Some(out.record_id),
            &values(&[("title", "Notes v3")]),
        )
        .await
        .unwrap();
    assert_eq!(edit.content["contact_email"], sealed);
    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        edit.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, edit.draft_id, sub)
        .await
        .unwrap();
    let publ = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        edit.draft_id,
        "publish",
        Some(true),
    )
    .await;
    lc.publish(&w.ctx_author, edit.draft_id, publ)
        .await
        .unwrap();
    let (ref_id, _) = tinker_ontology::sensitive::parse_sealed(&sealed).unwrap();
    assert_eq!(
        sealer
            .reveal(&env.core, &w.ctx_owner, ref_id, "lifecycle test")
            .await
            .unwrap(),
        plaintext
    );

    // Erasure reaches the value through the row and version history:
    // the ref no longer resolves anywhere.
    let desc = ont.describe_object(&w.ctx_owner, w.article).await.unwrap();
    assert_eq!(
        sealer
            .erase_record(&env.core, &w.ctx_owner, &desc, out.record_id)
            .await
            .unwrap(),
        1
    );
    let err = sealer
        .reveal(&env.core, &w.ctx_owner, ref_id, "after erasure")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("tombstoned"), "{err}");

    // An engine without the vault fails closed on a sensitive value.
    let bare = LifecycleEngine::new(env.core.clone(), ont);
    let err = bare
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "x"), ("contact_email", "a@b.co")]),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no PII vault configured"), "{err}");
}

// ---------------------------------------------------------------------------
// Versions and archive
// ---------------------------------------------------------------------------

#[tokio::test]
async fn readers_see_latest_published_while_draft_in_flight() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);
    let engine = transform_engine(&env, &ont);

    let (rid, _) = publish_new_record(&lc, &ap, &w, "Doc", "v1").await;

    // Fork an edit draft and change the body twice.
    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            Some(rid),
            &values(&[("title", "Doc")]),
        )
        .await
        .unwrap();
    lc.update_draft(
        &w.ctx_author,
        draft.draft_id,
        &values(&[("body", "v2-draft")]),
    )
    .await
    .unwrap();

    // Readers still see v1 while the draft is in flight — via query AND
    // direct render. Draft edits do not touch published content.
    let titles = query_titles(&env, &ont, &w.ctx_viewer, w.article).await;
    assert_eq!(titles, vec!["Doc".to_string()]);
    let (fields, _) = engine
        .render_record(&w.ctx_viewer, &w.article_slug, rid, None, "/")
        .await
        .unwrap();
    let body = fields
        .iter()
        .find(|(k, _)| k == "body")
        .map(|(_, v)| v.clone());
    assert_eq!(body, Some(serde_json::json!("v1")));

    // Publish v2: readers now see v2, and a new version is appended.
    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();
    let publ = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let out = lc
        .publish(&w.ctx_author, draft.draft_id, publ)
        .await
        .unwrap();
    assert_eq!(out.version, 2);

    let (fields, _) = engine
        .render_record(&w.ctx_viewer, &w.article_slug, rid, None, "/")
        .await
        .unwrap();
    let body = fields
        .iter()
        .find(|(k, _)| k == "body")
        .map(|(_, v)| v.clone());
    assert_eq!(body, Some(serde_json::json!("v2-draft")));

    let versions = lc
        .list_versions(&w.ctx_viewer, w.article, rid)
        .await
        .unwrap();
    assert_eq!(versions.len(), 2, "every publish appends a version");
    // Newest first.
    assert_eq!(versions[0].version_no, 2);
    assert_eq!(versions[0].content["body"], serde_json::json!("v2-draft"));
    assert_eq!(versions[1].version_no, 1);
    assert_eq!(versions[1].content["body"], serde_json::json!("v1"));
}

#[tokio::test]
async fn archive_hides_unarchive_restores() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);
    let engine = transform_engine(&env, &ont);

    let (rid, _) = publish_new_record(&lc, &ap, &w, "Ephemeral", "b").await;

    let arc = record_approval(&ap, &w, &w.ctx_reviewer, rid, "archive", Some(true)).await;
    lc.archive(&w.ctx_author, w.article, rid, arc)
        .await
        .unwrap();

    // Archived: gone from query and direct render for default readers.
    let titles = query_titles(&env, &ont, &w.ctx_viewer, w.article).await;
    assert!(
        titles.is_empty(),
        "archived record must not resolve: {titles:?}"
    );
    let err = engine
        .render_record(&w.ctx_viewer, &w.article_slug, rid, None, "/")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_)),
        "archived record must be NotFound, got {err:?}"
    );

    // Archive needs its own approval bound to the archive action: a
    // publish-bound approval must not archive.
    let (rid2, _) = publish_new_record(&lc, &ap, &w, "Second", "b").await;
    let publ2 = record_approval(&ap, &w, &w.ctx_reviewer, rid2, "publish", Some(true)).await;
    let err = lc
        .archive(&w.ctx_author, w.article, rid2, publ2)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");

    // Unarchive restores visibility.
    let unarc = record_approval(&ap, &w, &w.ctx_reviewer, rid, "unarchive", Some(true)).await;
    lc.unarchive(&w.ctx_author, w.article, rid, unarc)
        .await
        .unwrap();
    let titles = query_titles(&env, &ont, &w.ctx_viewer, w.article).await;
    assert_eq!(titles, vec!["Ephemeral".to_string(), "Second".to_string()]);
}

#[tokio::test]
async fn lifecycle_state_is_a_policy_dimension() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);

    let (rid, _) = publish_new_record(&lc, &ap, &w, "Old", "b").await;
    let arc = record_approval(&ap, &w, &w.ctx_reviewer, rid, "archive", Some(true)).await;
    lc.archive(&w.ctx_author, w.article, rid, arc)
        .await
        .unwrap();

    // An archivist policy explicitly allowing archived rows OVERRIDES the
    // C1 default (no silent merge of predicates).
    let rf = RowFilters::new(env.core.clone());
    let desc = ont.describe_object(&w.ctx_viewer, w.article).await.unwrap();
    rf.set_filters(
        &w.ctx_viewer,
        &desc,
        "archivist",
        &[RowFilterDef {
            field: "lifecycle_state".into(),
            op: "in".into(),
            value: Some(serde_json::json!(["published", "archived"])),
        }],
    )
    .await
    .unwrap();
    let ctx_archivist = member(&env, w.ctx_viewer.organization_id.0, "member").await;

    let policy = rf
        .load_policy(&ctx_archivist, w.article, "archivist")
        .await
        .unwrap();
    assert!(policy.has_lifecycle_filter());
    let qc = QueryCompiler::new(ont.clone());
    let plan = qc
        .compile_with_policy(
            &ctx_archivist,
            &QueryIntent {
                from: w.article,
                select: vec!["title".into()],
                filters: vec![],
                order: vec![],
                limit: Some(100),
                schema_version: None,
            },
            &FieldProjection::unrestricted(),
            &policy,
        )
        .await
        .unwrap();
    // Explicit policy wins: exactly ONE lifecycle predicate (the
    // policy's), no default appended.
    assert_eq!(
        plan.sql.matches("\"lifecycle_state\"").count(),
        1,
        "default must be suppressed by explicit filter: {}",
        plan.sql
    );
    let mut tx = env.core.tenant_tx(&ctx_archivist).await.unwrap();
    let mut q = sqlx::query_as::<_, (String,)>(&plan.sql);
    for p in &plan.params {
        q = bind_param_as(q, p);
    }
    let rows: Vec<(String,)> = q.fetch_all(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(rows.len(), 1, "archivist sees the archived row");
    assert_eq!(rows[0].0, "Old");

    // Default readers still cannot see it.
    let titles = query_titles(&env, &ont, &w.ctx_viewer, w.article).await;
    assert!(titles.is_empty());
}

// ---------------------------------------------------------------------------
// Direct-write blocking and tenant isolation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn direct_mutation_connector_refuses_lifecycle_objects() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);
    let mc = MutationConnector::new(env.core.clone(), ont.clone());

    let err = mc
        .create(
            &w.ctx_author,
            &CreateRequest {
                object_id: w.article,
                values: values(&[("title", "Sneaky")]),
                require_approval: false,
                approval_request_id: None,
            },
            &tinker_ontology::mutate::NoHooks,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "direct create must fail closed, got {err:?}"
    );

    let (rid, _) = publish_new_record(&lc, &ap, &w, "Real", "b").await;
    let err = mc
        .update(
            &w.ctx_author,
            &UpdateRequest {
                object_id: w.article,
                record_id: rid,
                values: values(&[("title", "Sneaky edit")]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &tinker_ontology::mutate::NoHooks,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "direct update must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn drafts_are_tenant_and_author_scoped() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (_ont, lc, ap, _rt) = engines(&env);

    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Mine")]),
        )
        .await
        .unwrap();

    // Sibling org: the draft does not exist (RLS + author/org scoping).
    let err = lc.get_draft(&w.ctx_b, draft.draft_id).await.unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_) | TinkerError::Forbidden(_)),
        "cross-tenant draft access must fail, got {err:?}"
    );
    let err = lc
        .update_draft(&w.ctx_b, draft.draft_id, &values(&[("title", "Theirs")]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_) | TinkerError::Forbidden(_)),
        "got {err:?}"
    );

    // Same-org reviewer can SEE the draft once in review (reviewer role
    // comes from the membership table, trusted by the engine).
    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();
    let seen = lc.get_draft(&w.ctx_reviewer, draft.draft_id).await.unwrap();
    assert_eq!(seen.draft_id, draft.draft_id);

    // Same-org non-reviewer cannot see it.
    let err = lc
        .get_draft(&w.ctx_viewer, draft.draft_id)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_) | TinkerError::Forbidden(_)),
        "non-reviewer must not see in-review drafts, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// M7 approval edges
// ---------------------------------------------------------------------------

#[tokio::test]
async fn publish_rejects_self_approval_and_bad_approval_states() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (_ont, lc, ap, _rt) = engines(&env);

    // Pending (undecided) approval: cannot submit.
    let draft = lc
        .create_draft(&w.ctx_author, w.article, None, &values(&[("title", "P")]))
        .await
        .unwrap();
    let pending = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        None,
    )
    .await;
    let err = lc
        .submit_for_review(&w.ctx_author, draft.draft_id, pending)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");

    // Denied approval: cannot submit.
    let denied = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(false),
    )
    .await;
    let err = lc
        .submit_for_review(&w.ctx_author, draft.draft_id, denied)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");

    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();

    // Self-approval: the AUTHOR deciding the publish approval must be
    // rejected, even though the request is otherwise valid.
    let self_appr = draft_approval(
        &ap,
        &w,
        &w.ctx_author,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let err = lc
        .publish(&w.ctx_author, draft.draft_id, self_appr)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "self-approval must be rejected, got {err:?}"
    );

    // Approval for a DIFFERENT draft: rejected (payload binding).
    let draft2 = lc
        .create_draft(&w.ctx_author, w.article, None, &values(&[("title", "Q")]))
        .await
        .unwrap();
    let other = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft2.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let err = lc
        .publish(&w.ctx_author, draft.draft_id, other)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "cross-draft approval must be rejected, got {err:?}"
    );
}

#[tokio::test]
async fn engine_refuses_non_lifecycle_objects() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, _ap, _rt) = engines(&env);

    // A second object WITHOUT the lifecycle flag: the engine fails
    // closed instead of running drafts against it.
    let slug = common::uniq("plain");
    let plain = ont
        .define_object(&w.ctx_owner, &object_def(&slug))
        .await
        .unwrap();
    ont.add_field(
        &w.ctx_owner,
        plain.id,
        &field("title", FieldType::Text, true),
    )
    .await
    .unwrap();

    let err = lc
        .create_draft(&w.ctx_owner, plain.id, None, &values(&[("title", "x")]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "engine must refuse non-lifecycle objects, got {err:?}"
    );

    // Direct writes still work there — there is no lifecycle to bypass.
    let mc = MutationConnector::new(env.core.clone(), ont.clone());
    let out = mc
        .create(
            &w.ctx_owner,
            &CreateRequest {
                object_id: plain.id,
                values: values(&[("title", "direct")]),
                require_approval: false,
                approval_request_id: None,
            },
            &tinker_ontology::mutate::NoHooks,
        )
        .await
        .unwrap();
    assert_ne!(out.record_id, Uuid::nil());
}

// ---------------------------------------------------------------------------
// M8 retention composition
// ---------------------------------------------------------------------------

#[tokio::test]
async fn retention_composes_with_lifecycle() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (_ont, lc, ap, rt) = engines(&env);

    // A stale draft (40 days old) is purged by the draft policy.
    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Stale")]),
        )
        .await
        .unwrap();
    let mut tx = env.core.tenant_tx(&w.ctx_author).await.unwrap();
    sqlx::query(
        "UPDATE record_drafts SET updated_at = now() - interval '40 days' WHERE draft_id = $1",
    )
    .bind(draft.draft_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let n = lc
        .purge_stale_drafts(
            &w.ctx_author,
            w.article,
            std::time::Duration::from_secs(30 * 24 * 3600),
        )
        .await
        .unwrap();
    assert_eq!(n, 1, "40-day-old draft must be purged by the 30-day policy");
    let err = lc
        .get_draft(&w.ctx_author, draft.draft_id)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));

    // Publish a record, then age it past the M8 window: apply_core
    // deletes the published row, and the orphaned versions follow.
    let (rid, _) = publish_new_record(&lc, &ap, &w, "Aged", "b").await;
    rt.set_policy(&w.ctx_author, &w.article_slug, 30)
        .await
        .unwrap();
    let mut tx = env.core.tenant_tx(&w.ctx_author).await.unwrap();
    sqlx::query(&format!(
        "UPDATE data.\"{}\" SET updated_at = now() - interval '40 days' WHERE id = $1",
        w.article_slug
    ))
    .bind(rid)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let outcome = rt
        .apply_core(
            &w.ctx_author,
            &w.article_slug,
            &format!("data.{}", w.article_slug),
            "updated_at",
            "organization_id",
        )
        .await
        .unwrap();
    assert_eq!(outcome.deleted, 1, "M8 must delete the aged published row");
    assert!(!outcome.skipped_legal_hold);
    let n = lc
        .purge_orphaned_versions(&w.ctx_author, w.article)
        .await
        .unwrap();
    assert_eq!(n, 1, "orphaned version history must be cleaned up");
    assert!(lc
        .list_versions(&w.ctx_viewer, w.article, rid)
        .await
        .unwrap()
        .is_empty());

    // Legal hold suspends deletion: the row and its versions survive.
    let (rid2, _) = publish_new_record(&lc, &ap, &w, "Held", "b").await;
    let mut tx = env.core.tenant_tx(&w.ctx_author).await.unwrap();
    sqlx::query(&format!(
        "UPDATE data.\"{}\" SET updated_at = now() - interval '40 days' WHERE id = $1",
        w.article_slug
    ))
    .bind(rid2)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    rt.set_legal_hold(&w.ctx_author, &w.article_slug, true)
        .await
        .unwrap();
    let outcome = rt
        .apply_core(
            &w.ctx_author,
            &w.article_slug,
            &format!("data.{}", w.article_slug),
            "updated_at",
            "organization_id",
        )
        .await
        .unwrap();
    assert_eq!(outcome.deleted, 0);
    assert!(
        outcome.skipped_legal_hold,
        "legal hold must suspend deletion"
    );
    let n = lc
        .purge_orphaned_versions(&w.ctx_author, w.article)
        .await
        .unwrap();
    assert_eq!(n, 0, "no versions orphaned while the row is held");
    assert_eq!(
        lc.list_versions(&w.ctx_viewer, w.article, rid2)
            .await
            .unwrap()
            .len(),
        1
    );

    // Legal hold also suspends draft purging: a stale draft survives
    // while the hold is on, and is purged once the hold lifts.
    let draft3 = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Held draft")]),
        )
        .await
        .unwrap();
    let mut tx = env.core.tenant_tx(&w.ctx_author).await.unwrap();
    sqlx::query(
        "UPDATE record_drafts SET updated_at = now() - interval '40 days' WHERE draft_id = $1",
    )
    .bind(draft3.draft_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let n = lc
        .purge_stale_drafts(
            &w.ctx_author,
            w.article,
            std::time::Duration::from_secs(30 * 24 * 3600),
        )
        .await
        .unwrap();
    assert_eq!(n, 0, "legal hold must suspend draft purging");
    lc.get_draft(&w.ctx_author, draft3.draft_id).await.unwrap();
    rt.set_legal_hold(&w.ctx_author, &w.article_slug, false)
        .await
        .unwrap();
    let n = lc
        .purge_stale_drafts(
            &w.ctx_author,
            w.article,
            std::time::Duration::from_secs(30 * 24 * 3600),
        )
        .await
        .unwrap();
    assert_eq!(n, 1, "draft purge resumes after the hold lifts");
}

// ---------------------------------------------------------------------------
// Search composition
// ---------------------------------------------------------------------------

#[tokio::test]
async fn search_excludes_archived_rows() {
    use tinker_search::{IndexChange, NativeSearchBackend, SearchBackend, SearchPlan};

    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);
    let backend = NativeSearchBackend::new(env.core.clone());

    let (rid, _) = publish_new_record(&lc, &ap, &w, "Archivable doc", "b").await;
    // Index the row directly (the v1 indexer path): content is in the
    // index, exactly as a production feed would place it.
    backend
        .index_change(
            &w.ctx_author,
            &IndexChange {
                object_id: w.article,
                record_id: rid,
                text: "Archivable doc about zephyrs".into(),
                field_versions: serde_json::json!({"title": 1}),
                storage_classes: vec!["text".into()],
            },
        )
        .await
        .unwrap();

    let desc = ont.describe_object(&w.ctx_viewer, w.article).await.unwrap();
    let rf = RowFilters::new(env.core.clone());
    let policy = rf
        .load_policy(&w.ctx_viewer, w.article, "viewer")
        .await
        .unwrap();
    let compiled = policy
        .compile_for_search(&w.ctx_viewer, &desc)
        .unwrap()
        .unwrap();

    // Before archive: the row is found.
    let page = backend
        .search(
            &w.ctx_viewer,
            &SearchPlan {
                text_query: "zephyrs".into(),
                object_id: Some(w.article),
                limit: 10,
                row_policies: vec![compiled.clone()],
            },
        )
        .await
        .unwrap();
    assert_eq!(page.hits.len(), 1, "published row must be searchable");

    // Archive: the row must vanish from search even though its content
    // is still in the index — the lifecycle guard is in the match
    // statement, not a post-filter.
    let arc = record_approval(&ap, &w, &w.ctx_reviewer, rid, "archive", Some(true)).await;
    lc.archive(&w.ctx_author, w.article, rid, arc)
        .await
        .unwrap();
    let page = backend
        .search(
            &w.ctx_viewer,
            &SearchPlan {
                text_query: "zephyrs".into(),
                object_id: Some(w.article),
                limit: 10,
                row_policies: vec![compiled],
            },
        )
        .await
        .unwrap();
    assert!(
        page.hits.is_empty(),
        "archived row must not surface in search: {:?}",
        page.hits.iter().map(|h| h.record_id).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// C4 snapshot composition
// ---------------------------------------------------------------------------

#[tokio::test]
async fn snapshot_round_trips_lifecycle_flag() {
    use ed25519_dalek::SigningKey;
    use tinker_evolve::SchemaEvolver;
    use tinker_query::{sign_snapshot, SnapshotService};

    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, _lc, _ap, _rt) = engines(&env);
    let evolver = SchemaEvolver::new(
        env.core.clone(),
        OwnerDb(env.core_owner.clone()),
        ont.clone(),
    );
    let svc = SnapshotService::new(
        env.core.clone(),
        ont.clone(),
        evolver,
        RowFilters::new(env.core.clone()),
    );

    // Capture: the lifecycle flag is in the snapshot document.
    let doc = svc
        .build_snapshot(&w.ctx_owner, "lc-test-vendor", 1, &[w.article])
        .await
        .unwrap();
    let obj = doc
        .objects
        .iter()
        .find(|o| o.api_slug == w.article_slug)
        .unwrap();
    assert!(
        obj.lifecycle_enabled,
        "snapshot must capture the lifecycle flag"
    );

    // Flip the flag off behind the snapshot's back: the diff must
    // surface the flip, and re-applying the snapshot must converge the
    // flag back on. A restore that silently dropped the flag would
    // re-open direct writes on the object.
    sqlx::query("UPDATE ontology_objects SET lifecycle_enabled = false WHERE id = $1")
        .bind(w.article)
        .execute(&env.core_owner)
        .await
        .unwrap();
    let doc_off = svc
        .build_snapshot(&w.ctx_owner, "lc-test-vendor", 2, &[w.article])
        .await
        .unwrap();
    let off = doc_off
        .objects
        .iter()
        .find(|o| o.api_slug == w.article_slug)
        .unwrap();
    assert!(!off.lifecycle_enabled);
    let diff = tinker_query::diff_snapshots(&doc_off, &doc);
    let od = diff
        .objects
        .iter()
        .find(|o| o.api_slug == w.article_slug)
        .unwrap();
    assert_eq!(od.lifecycle_changed, Some(true));

    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let envelope = sign_snapshot(&doc, &signing).unwrap();
    svc.apply_snapshot(
        &w.ctx_owner,
        &envelope,
        "lc-test-vendor",
        &signing.verifying_key().to_bytes(),
    )
    .await
    .unwrap();
    let desc = ont.describe_object(&w.ctx_owner, w.article).await.unwrap();
    assert!(
        desc.lifecycle_enabled,
        "apply must restore the lifecycle flag"
    );
}

// ---------------------------------------------------------------------------
// Count path + approval expiry
// ---------------------------------------------------------------------------

#[tokio::test]
async fn count_excludes_drafts_and_archived() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);

    // One published record that stays visible.
    let (rid_visible, _) = publish_new_record(&lc, &ap, &w, "Visible", "v").await;
    // One published record we then archive.
    let (rid_archived, _) = publish_new_record(&lc, &ap, &w, "Gone", "g").await;
    let arc = record_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        rid_archived,
        "archive",
        Some(true),
    )
    .await;
    lc.archive(&w.ctx_author, w.article, rid_archived, arc)
        .await
        .unwrap();
    // A draft for a brand-new record: no row in data.* at all.
    let _draft_new = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "DraftOnly"), ("body", "d")]),
        )
        .await
        .unwrap();
    // An edit draft on the visible record: the published row stays.
    let _draft_edit = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            Some(rid_visible),
            &values(&[("title", "Visible v2"), ("body", "v")]),
        )
        .await
        .unwrap();

    // Replicate the schema-page count path: tenant + C2 policy + the C1
    // default published predicate, composed in the same order.
    let desc = ont.describe_object(&w.ctx_viewer, w.article).await.unwrap();
    let rf = RowFilters::new(env.core.clone());
    let policy = rf
        .load_policy(&w.ctx_viewer, w.article, "viewer")
        .await
        .unwrap();
    let mut sql = format!(
        "SELECT COUNT(*) FROM data.\"{}\" WHERE organization_id=$1",
        w.article_slug
    );
    let mut params = vec![Param::Uuid(w.ctx_viewer.organization_id.0)];
    policy
        .append_predicates(&w.ctx_viewer, &desc, None, &mut sql, &mut params)
        .unwrap();
    append_default_published_predicate(&policy, true, &mut sql, &mut params, None, &|n| {
        format!("${n}")
    });
    let mut tx = env.core.tenant_tx(&w.ctx_viewer).await.unwrap();
    let mut q = sqlx::query_as::<_, (i64,)>(&sql);
    for p in &params {
        q = bind_param_as(q, p);
    }
    let (n,) = q.fetch_one(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        n, 1,
        "count must see only the published, non-archived record"
    );
}

#[tokio::test]
async fn publish_rejects_expired_approval() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let (ont, lc, ap, _rt) = engines(&env);
    let _ = ont;

    // Get a draft to in_review.
    let draft = lc
        .create_draft(
            &w.ctx_author,
            w.article,
            None,
            &values(&[("title", "Expiring"), ("body", "e")]),
        )
        .await
        .unwrap();
    let sub = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "submit_for_review",
        Some(true),
    )
    .await;
    lc.submit_for_review(&w.ctx_author, draft.draft_id, sub)
        .await
        .unwrap();

    // Approve a publish, then let the deadline pass behind its back.
    let publ = draft_approval(
        &ap,
        &w,
        &w.ctx_reviewer,
        draft.draft_id,
        "publish",
        Some(true),
    )
    .await;
    let mut tx = env.core.tenant_tx(&w.ctx_author).await.unwrap();
    sqlx::query(
        "UPDATE approval_requests SET expires_at = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(publ)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let err = lc
        .publish(&w.ctx_author, draft.draft_id, publ)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "expired approval must not authorize publish, got {err:?}"
    );
    // And the draft is untouched: still in_review, still unpublished.
    let d = lc.get_draft(&w.ctx_author, draft.draft_id).await.unwrap();
    assert_eq!(d.state.as_str(), "in_review");
}
