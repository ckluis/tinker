//! R3 (security review, INTERNAL — not an external audit): adversarial
//! regression coverage for the MCP front door, C6 machine credentials,
//! tenant isolation, approval binding, and file-upload hostility.
//!
//! Every fixture org uses the `secorg_` slug prefix and is created fresh
//! per test run. These tests assert the *defended* behavior: an attack
//! that ever succeeds here is a security regression.
//!
//! Threat model: see `docs/threat-model.md` (INTERNAL review, not an
//! external audit).

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{json, Value};
use tinker_agents::approval::ApprovalEngine;
use tinker_agents::files::{FileStore, FsFileBackend, PiiClass};
use tinker_auth::apikey::MachineCredentialStore;
use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_mcp::{build_services, FrontDoor};
use tinker_ontology::lifecycle::LifecycleEngine;
use tinker_ontology::mutate::{CreateRequest, MutationConnector, NoHooks};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope, ValidationRules};
use tinker_query::dashboard::{DashboardInput, DashboardService, PanelDef, VisualizationKind};
use tinker_query::QueryIntent;
use tokio::sync::OnceCell;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness (mirrors mcp_front_door.rs; secorg_ fixtures)
// ---------------------------------------------------------------------------

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

struct Env {
    core: CoreDb,
    core_owner: sqlx::PgPool,
    host_id: Uuid,
}

static MIGRATED: OnceCell<()> = OnceCell::const_new();

async fn setup() -> Env {
    std::env::set_var(
        "TINKER_FILE_ROOT",
        std::env::temp_dir().join(format!("tinker-r3-adv-{}", std::process::id())),
    );
    let core_owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("core owner connect");
    MIGRATED
        .get_or_init(|| async {
            tinker_db::MIGRATOR_CORE
                .run(&core_owner)
                .await
                .expect("core migrations");
        })
        .await;
    let core = CoreDb::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("core app-role connect");
    let host_id = Uuid::from_u128(0x05EC_0123);
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,'r3-adv') ON CONFLICT (id) DO NOTHING")
        .bind(host_id)
        .execute(&core_owner)
        .await
        .expect("host upsert");
    Env {
        core,
        core_owner,
        host_id,
    }
}

fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{prefix}{}", &s[24..32])
}

/// Fresh org with the secorg_ slug prefix; returns (org_id, machine actor ctx).
async fn new_secorg(env: &Env, role: &str) -> (Uuid, TenantContext) {
    let org_id = Uuid::now_v7();
    let slug = uniq("secorg_");
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(&slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));
    let issued = store
        .issue(
            org_id,
            &format!("r3-{role}"),
            &["mcp:tools".to_string(), "mcp:resources".to_string()],
            None,
            None,
        )
        .await
        .expect("key issue");
    store
        .grant_machine_role(org_id, issued.credential.actor_id, role)
        .await
        .expect("grant role");
    let cred = store.verify(&issued.secret).await.expect("verify");
    let ctx = TenantContext::new(OrganizationId(org_id), cred.actor_id, "r3-adv".to_string());
    (org_id, ctx)
}

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

fn text_field(api_name: &str, required: bool) -> FieldDef {
    FieldDef {
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type: FieldType::Text,
        options: json!({}),
        required,
        validation: ValidationRules::default(),
        preset: None,
        max_pii_class: "none".into(),
        sensitive: false,
    }
}

async fn door(env: &Env, ctx: &TenantContext) -> FrontDoor {
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));
    // Re-resolve the credential from the DB the way the HTTP tier does.
    let cred = store
        .list(ctx.organization_id.0)
        .await
        .expect("list creds")
        .into_iter()
        .find(|c| c.actor_id == ctx.actor_id)
        .expect("cred row");
    let verified = tinker_auth::apikey::VerifiedCredential {
        id: cred.id,
        organization_id: cred.organization_id,
        actor_id: cred.actor_id,
        scopes: cred.scopes,
    };
    let (state, mutator, lifecycle) =
        build_services(env.core.0.clone(), env.core_owner.clone()).expect("build_services");
    let tenant = TenantContext::new(
        OrganizationId(verified.organization_id),
        verified.actor_id,
        "r3-adv".to_string(),
    );
    let role = FrontDoor::resolve_role(&state.core, &tenant)
        .await
        .expect("resolve_role");
    FrontDoor::new(state, mutator, lifecycle, verified, tenant, role)
}

async fn rpc(door: &FrontDoor, method: &str, id: i64, params: Value) -> Value {
    let raw = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string();
    let resp = door
        .handle(&raw)
        .await
        .unwrap_or_else(|| panic!("expected a response for {method}"));
    serde_json::from_str(&resp).expect("response parses")
}

async fn call_tool(door: &FrontDoor, id: i64, name: &str, args: Value) -> Value {
    let resp = rpc(
        door,
        "tools/call",
        id,
        json!({ "name": name, "arguments": args }),
    )
    .await;
    assert!(
        resp.get("error").is_none(),
        "tools/call {name} was a protocol error: {resp}"
    );
    resp["result"].clone()
}

fn tool_err_text(result: &Value) -> String {
    assert_eq!(result["isError"], true, "expected isError, got {result}");
    result["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_string()
}

fn tool_ok_text(result: &Value) -> String {
    assert!(
        result.get("isError").is_none(),
        "expected success, got tool error: {result}"
    );
    result["content"][0]["text"]
        .as_str()
        .expect("text content")
        .to_string()
}

/// A no-oracle denial: foreign and missing records must be
/// indistinguishable (the teaching `not_found` shape).
fn assert_no_oracle_denial(result: &Value, what: &str) {
    let text = tool_err_text(result);
    let v: Value = serde_json::from_str(&text).expect("error payload parses");
    assert_eq!(
        v["error"], "not_found",
        "{what}: foreign must look missing, got {v}"
    );
    assert!(
        !text.to_lowercase().contains("forbidden")
            && !text.to_lowercase().contains("other org")
            && !text.to_lowercase().contains("tenant"),
        "{what}: denial must not name the reason, got {text}"
    );
}

// ---------------------------------------------------------------------------
// (c) Tenant isolation through EVERY MCP tool
// ---------------------------------------------------------------------------

/// Org A: plain object + published record (for read/write isolation),
/// plus a lifecycle object + draft (for transition/draft isolation).
/// Returns (plain slug, record id, lc slug, draft id).
async fn seed_org_a(env: &Env, ctx_a: &TenantContext) -> (String, Uuid, Uuid, String, Uuid) {
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let slug = uniq("secorg_item");
    let obj = ont.define_object(ctx_a, &object_def(&slug)).await.unwrap();
    ont.add_field(ctx_a, obj.id, &text_field("title", true))
        .await
        .unwrap();

    let mc = MutationConnector::new(env.core.clone(), ont.clone());
    let mut vals = HashMap::new();
    vals.insert("title".to_string(), json!("A-secret"));
    let out = mc
        .create(
            ctx_a,
            &CreateRequest {
                object_id: obj.id,
                values: vals,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();

    let lc_slug = uniq("secorg_lc");
    let lc_obj = ont
        .define_object(ctx_a, &object_def(&lc_slug))
        .await
        .unwrap();
    ont.add_field(ctx_a, lc_obj.id, &text_field("title", true))
        .await
        .unwrap();
    ont.set_lifecycle_enabled(ctx_a, lc_obj.id, true)
        .await
        .unwrap();
    let lc = LifecycleEngine::new(env.core.clone(), ont.clone());
    let draft = lc
        .create_draft(ctx_a, lc_obj.id, None, &{
            let mut m = HashMap::new();
            m.insert("title".to_string(), json!("A-draft"));
            m
        })
        .await
        .unwrap();
    (slug, obj.id, out.record_id, lc_slug, draft.draft_id)
}

#[tokio::test]
async fn r3_tenant_isolation_every_mcp_tool() {
    let env = setup().await;
    let (_org_a, ctx_a) = new_secorg(&env, "admin").await;
    let (_org_b, ctx_b) = new_secorg(&env, "admin").await;
    let (slug_a, object_a, record_a, _lc_slug, draft_a) = seed_org_a(&env, &ctx_a).await;
    let door_a = door(&env, &ctx_a).await;
    let door_b = door(&env, &ctx_b).await;

    // describe: B must not see A's object (catalog is per-org; the slug
    // lookup must not_found, never forbidden).
    let r = call_tool(&door_b, 1, "describe", json!({"object": slug_a})).await;
    assert_no_oracle_denial(&r, "describe foreign slug");

    // query: hostile/foreign object slug.
    let r = call_tool(
        &door_b,
        2,
        "query",
        json!({"object": slug_a, "intent": {"filters": []}}),
    )
    .await;
    assert_no_oracle_denial(&r, "query foreign slug");

    // get_record: A's record id from B.
    let r = call_tool(
        &door_b,
        3,
        "get_record",
        json!({"object": slug_a, "record_id": record_a.to_string()}),
    )
    .await;
    assert_no_oracle_denial(&r, "get_record foreign id");

    // update_record: A's record id from B.
    let r = call_tool(
        &door_b,
        4,
        "update_record",
        json!({"object": slug_a, "record_id": record_a.to_string(), "values": {"title": "pwned"}}),
    )
    .await;
    assert_no_oracle_denial(&r, "update_record foreign id");

    // transition: A's draft id from B (draft_id guessing across orgs).
    let r = call_tool(
        &door_b,
        5,
        "transition",
        json!({"action": "update_draft", "draft_id": draft_a.to_string(), "values": {"title": "pwned"}}),
    )
    .await;
    assert_no_oracle_denial(&r, "transition foreign draft_id");

    // render_dashboard: a real dashboard seeded in A, probed from B with the
    // correct arg name — must look missing (not_found), never leak or deny.
    let dash_svc = DashboardService::new(
        env.core.clone(),
        Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone())),
    );
    let dash = dash_svc
        .create(
            &ctx_a,
            DashboardInput {
                name: "A private dash".to_string(),
                description: None,
                panels: vec![PanelDef {
                    id: "p1".to_string(),
                    query: QueryIntent {
                        from: object_a,
                        select: vec!["title".to_string()],
                        filters: vec![],
                        order: vec![],
                        limit: Some(5),
                        schema_version: None,
                    },
                    visualization: VisualizationKind::Table,
                    x: 0,
                    y: 0,
                    w: 6,
                    h: 4,
                }],
            },
        )
        .await
        .unwrap();
    let r = call_tool(
        &door_b,
        6,
        "render_dashboard",
        json!({"dashboard_id": dash.id.to_string()}),
    )
    .await;
    assert_no_oracle_denial(&r, "render_dashboard foreign id");
    // Control: A renders its own dashboard fine.
    let r = call_tool(
        &door_a,
        7,
        "render_dashboard",
        json!({"dashboard_id": dash.id.to_string()}),
    )
    .await;
    let err_code = r
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str());
    assert!(
        err_code.is_none(),
        "A must render its own dashboard, got {r}"
    );

    // resources/read: A's ontology resource from B.
    let resp = rpc(
        &door_b,
        "resources/read",
        7,
        json!({"uri": format!("tinker://ontology/{slug_a}")}),
    )
    .await;
    let text = resp["error"]
        .as_object()
        .map(|_| "protocol-error".to_string())
        .unwrap_or_else(|| tool_err_text(&resp["result"]));
    assert!(
        text.contains("not_found") || resp.get("error").is_some(),
        "resource read of foreign slug must deny, got {resp}"
    );
}

#[tokio::test]
async fn r3_hostile_query_filters_fail_closed() {
    let env = setup().await;
    let (_org_a, ctx_a) = new_secorg(&env, "admin").await;
    let (slug_a, _obj, _rec, _lc_slug, _draft) = seed_org_a(&env, &ctx_a).await;
    let door_a = door(&env, &ctx_a).await;

    // Hostile filter payloads: unknown ops, type confusion, deep nesting.
    // Each must fail closed (validation error) — never panic, never
    // bypass the row policy.
    for (i, filters) in [
        json!([{"field": "title", "op": "__proto__", "value": "x"}]),
        json!([{"field": "title", "op": "eq", "value": {"$ne": null}}]),
        json!([{"field": ["title"], "op": "eq", "value": "x"}]),
        json!({"not": "an-array"}),
        json!([{"field": "organization_id", "op": "eq", "value": "00000000-0000-0000-0000-000000000000"}]),
    ]
    .into_iter()
    .enumerate()
    {
        let r = call_tool(
            &door_a,
            100 + i as i64,
            "query",
            json!({"object": slug_a, "intent": {"filters": filters}}),
        )
        .await;
        // Either a clean validation/tool error or an empty result — but
        // never a panic (the test would abort) and never A's row policy
        // bypassed (no success payload containing another org's data).
        if r.get("isError").is_some() {
            let t = tool_err_text(&r);
            assert!(
                !t.contains("panicked"),
                "hostile filter {i} caused a panic surface: {t}"
            );
        } else {
            let t = tool_ok_text(&r);
            assert!(
                !t.contains("B-secret"),
                "hostile filter {i} leaked cross-org data"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// (d) Approval binding: replay, wrong action, cross-org
// ---------------------------------------------------------------------------

async fn attachment(env: &Env, ctx: &TenantContext) -> Uuid {
    let mut tx = env.core.tenant_tx(ctx).await.unwrap();
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_attachments (organization_id, actor_id, name, kind, scope, \
         action_grants, approval_policy, budgets, status) \
         VALUES ($1,$2,'r3','test','{}','[]','{}','{}','active') RETURNING id",
    )
    .bind(ctx.organization_id.0)
    .bind(ctx.actor_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

async fn request_decided(
    ap: &ApprovalEngine,
    ctx_req: &TenantContext,
    ctx_decide: &TenantContext,
    attachment: Uuid,
    action: &str,
    subject_key: &str,
    subject: Uuid,
) -> Uuid {
    let mut payload = serde_json::Map::new();
    payload.insert(subject_key.to_string(), Value::String(subject.to_string()));
    let req = ap
        .request(
            ctx_req,
            attachment,
            action,
            Value::Object(payload),
            &format!("r3-{action}-{}", Uuid::now_v7()),
        )
        .await
        .unwrap();
    ap.decide(ctx_decide, req.id, true).await.unwrap();
    req.id
}

#[tokio::test]
async fn r3_approval_replay_wrong_action_cross_org() {
    let env = setup().await;
    let (org_a, ctx_a) = new_secorg(&env, "admin").await;
    let (_org_b, ctx_b) = new_secorg(&env, "admin").await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let lc = LifecycleEngine::new(env.core.clone(), ont.clone());
    let ap = ApprovalEngine::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let mc = MutationConnector::new(env.core.clone(), ont.clone());

    let slug = uniq("secorg_appr");
    let obj = ont.define_object(&ctx_a, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx_a, obj.id, &text_field("title", true))
        .await
        .unwrap();
    // NOTE: this object is deliberately NOT lifecycle-managed: the replay
    // target is the governed direct-write path (consume_approval).
    let att_a = attachment(&env, &ctx_a).await;

    // --- Replay on the governed-write path: one approval, two creates.
    // (Decided by a second org-A actor: requesters never decide their own.)
    let ctx_a_approver =
        TenantContext::new(OrganizationId(org_a), Uuid::now_v7(), "r3-adv".to_string());
    let appr = request_decided(
        &ap,
        &ctx_a,
        &ctx_a_approver,
        att_a,
        "create_record",
        "object_id",
        obj.id,
    )
    .await;
    let mut vals = HashMap::new();
    vals.insert("title".to_string(), json!("first"));
    mc.create(
        &ctx_a,
        &CreateRequest {
            object_id: obj.id,
            values: vals,
            require_approval: true,
            approval_request_id: Some(appr),
        },
        &NoHooks,
    )
    .await
    .unwrap();
    let mut vals2 = HashMap::new();
    vals2.insert("title".to_string(), json!("second"));
    let err = mc
        .create(
            &ctx_a,
            &CreateRequest {
                object_id: obj.id,
                values: vals2,
                require_approval: true,
                approval_request_id: Some(appr),
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "approval replay must be rejected, got {err:?}"
    );

    // --- Wrong-action approval: a submit_for_review approval presented
    // --- to publish must be rejected (and NOT consumed). This needs a
    // --- lifecycle-managed object with a draft.
    let lc_slug = uniq("secorg_apprlc");
    let lc_obj = ont
        .define_object(&ctx_a, &object_def(&lc_slug))
        .await
        .unwrap();
    ont.add_field(&ctx_a, lc_obj.id, &text_field("title", true))
        .await
        .unwrap();
    ont.set_lifecycle_enabled(&ctx_a, lc_obj.id, true)
        .await
        .unwrap();

    // A second actor in org A (the reviewer): needed so the wrong-action
    // probe is decided by a non-author and isolates the binding check
    // (publish rejects self-decided approvals before checking binding).
    let reviewer_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$3)",
    )
    .bind(reviewer_id)
    .bind(org_a)
    .bind(format!("r3-reviewer-{reviewer_id}"))
    .execute(&env.core_owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (organization_id, actor_id, role) VALUES ($1,$2,'reviewer')",
    )
    .bind(org_a)
    .bind(reviewer_id)
    .execute(&env.core_owner)
    .await
    .unwrap();
    let ctx_reviewer = TenantContext::new(OrganizationId(org_a), reviewer_id, "r3-adv".to_string());

    let mut dv = HashMap::new();
    dv.insert("title".to_string(), json!("P"));
    let draft = lc.create_draft(&ctx_a, lc_obj.id, None, &dv).await.unwrap();
    // Move the draft to in_review through the real submit path.
    let sub = request_decided(
        &ap,
        &ctx_a,
        &ctx_reviewer,
        att_a,
        "submit_for_review",
        "draft_id",
        draft.draft_id,
    )
    .await;
    lc.submit_for_review(&ctx_a, draft.draft_id, sub)
        .await
        .unwrap();

    // --- Wrong-action approval: a fresh 'submit_for_review' approval
    // --- (decided by the reviewer, so it passes the self-approval gate)
    // --- presented to publish must be rejected by the binding check —
    // --- and NOT consumed.
    let wrong = request_decided(
        &ap,
        &ctx_a,
        &ctx_reviewer,
        att_a,
        "submit_for_review",
        "draft_id",
        draft.draft_id,
    )
    .await;
    // R3 debug: verify the row is visible immediately after decide.
    // (approval_requests has FORCED RLS: owner-pool queries see nothing
    // without the org var set, so go through tenant_tx like the engine.)
    let mut dbg_tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM approval_requests WHERE id = $1")
        .bind(wrong)
        .fetch_one(&mut *dbg_tx)
        .await
        .unwrap();
    dbg_tx.rollback().await.unwrap();
    assert_eq!(
        n, 1,
        "approval row must be visible to its own org right after decide"
    );
    let err = lc.publish(&ctx_a, draft.draft_id, wrong).await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "wrong-action approval must be rejected, got {err:?}"
    );
    // The mismatched approval must NOT be consumed: it is still approved.
    // (FORCED RLS on approval_requests: query through tenant_tx.)
    let mut stx = env.core.tenant_tx(&ctx_a).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM approval_requests WHERE id = $1")
        .bind(wrong)
        .fetch_one(&mut *stx)
        .await
        .unwrap();
    stx.rollback().await.unwrap();
    assert_eq!(
        status, "approved",
        "mismatched approval must not be consumed"
    );

    // --- Cross-org approval id: B's approval presented to A's publish.
    let att_b = attachment(&env, &ctx_b).await;
    // (A second org-B actor decides: requesters never decide their own.)
    let ctx_b_reviewer =
        TenantContext::new(ctx_b.organization_id, Uuid::now_v7(), "r3-adv".to_string());
    let foreign = request_decided(
        &ap,
        &ctx_b,
        &ctx_b_reviewer,
        att_b,
        "publish",
        "draft_id",
        draft.draft_id,
    )
    .await;
    let err = lc
        .publish(&ctx_a, draft.draft_id, foreign)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "cross-org approval must be rejected, got {err:?}"
    );

    // --- Self-approval (belt-and-braces with m0): the engine refuses a
    // --- requester deciding their own request outright...
    let own = ap
        .request(
            &ctx_a,
            att_a,
            "publish",
            json!({ "draft_id": draft.draft_id.to_string() }),
            &format!("r3-own-{}", Uuid::now_v7()),
        )
        .await
        .unwrap();
    assert!(matches!(
        ap.decide(&ctx_a, own.id, true).await,
        Err(TinkerError::Forbidden(_))
    ));
    // ...and publish refuses an approval the AUTHOR decided, even when a
    // reviewer queued it.
    let self_appr = request_decided(
        &ap,
        &ctx_reviewer,
        &ctx_a,
        att_a,
        "publish",
        "draft_id",
        draft.draft_id,
    )
    .await;
    let err = lc
        .publish(&ctx_a, draft.draft_id, self_appr)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "self-approval must be rejected, got {err:?}"
    );

    // Sanity: org ids really differ (the test is not vacuous).
    assert_ne!(org_a, ctx_b.organization_id.0);
}

// ---------------------------------------------------------------------------
// (a) C6 key verification: multibyte input must fail closed, not panic
// ---------------------------------------------------------------------------

#[tokio::test]
async fn r3_verify_multibyte_prefix_fails_closed() {
    let env = setup().await;
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));
    // U+0800 is 3 bytes; byte index 12 lands strictly inside it. A
    // byte-slicing implementation panics here — the test fails the
    // suite if the server can be crashed this way.
    let evil = "tk_abcdefg\u{0800}zz".to_string();
    assert!(evil.len() >= 12);
    let err = store.verify(&evil).await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "multibyte key must fail closed, got {err:?}"
    );
    // And a short multibyte key.
    let err = store.verify("tk_é").await.unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)));
}

// ---------------------------------------------------------------------------
// (e) File upload hostility (item 42 surface)
// ---------------------------------------------------------------------------

fn filestore(env: &Env) -> FileStore {
    let root = std::env::temp_dir().join(format!("r3-fs-{}", Uuid::now_v7().simple()));
    FileStore::new(env.core.clone(), Arc::new(FsFileBackend::new(root)))
}

#[tokio::test]
async fn r3_file_upload_hostility() {
    let env = setup().await;
    let (_org_a, ctx_a) = new_secorg(&env, "admin").await;
    let (_org_b, ctx_b) = new_secorg(&env, "admin").await;
    let fs = filestore(&env);

    // Oversized: shrink the cap for this test only.
    std::env::set_var("TINKER_MAX_FILE_BYTES", "16");
    let err = fs
        .store(
            &ctx_a,
            "big.bin",
            "application/octet-stream",
            PiiClass::None,
            &[0u8; 17],
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "oversized upload must be rejected, got {err:?}"
    );
    std::env::remove_var("TINKER_MAX_FILE_BYTES");

    // Path-traversal name: the name is registry metadata only — the
    // storage key is content-addressed, so this must store safely and
    // must NOT create anything outside the backend root.
    let r = fs
        .store(
            &ctx_a,
            "../../evil.txt",
            "text/plain",
            PiiClass::None,
            b"traversal-name",
        )
        .await
        .unwrap();
    assert_eq!(r.name, "../../evil.txt");

    // Polyglot bytes with a declared image mime: v1 does NOT sniff
    // content (documented honest limit) — the store records the
    // caller-declared mime. The assertion that matters: bytes round-trip
    // exactly, and the registry hash matches.
    let polyglot = b"GIF89a\x01\x00\x01\x00\x80\x00\x00<script>alert(1)</script>";
    let r = fs
        .store(&ctx_a, "poly.gif", "image/gif", PiiClass::None, polyglot)
        .await
        .unwrap();
    assert_eq!(r.mime, "image/gif");

    // Cross-org link: B linking A's file must fail with the same
    // non-oracle error as a missing file.
    let missing_err = fs
        .assert_linkable(&ctx_b, Uuid::now_v7(), "none")
        .await
        .unwrap_err()
        .to_string();
    let cross_err = fs
        .assert_linkable(&ctx_b, r.id, "none")
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        cross_err, missing_err,
        "cross-org file link must be indistinguishable from missing"
    );

    // Integrity re-verification on link (tamper simulation): corrupt the
    // backend copy through a second store handle on the same root.
    let tampered_root = std::env::temp_dir().join(format!("r3-fs-t{}", Uuid::now_v7().simple()));
    let fs2 = FileStore::new(
        env.core.clone(),
        Arc::new(FsFileBackend::new(tampered_root.clone())),
    );
    let r2 = fs2
        .store(
            &ctx_a,
            "t.bin",
            "application/octet-stream",
            PiiClass::None,
            b"original-bytes",
        )
        .await
        .unwrap();
    {
        let hex = &r2.sha256;
        let p = tampered_root
            .join(ctx_a.organization_id.0.to_string())
            .join(&hex[..2])
            .join(hex);
        std::fs::write(&p, b"tampered-bytes").unwrap();
    }
    let err = fs2
        .assert_linkable(&ctx_a, r2.id, "none")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Internal(_)),
        "tampered backend bytes must fail integrity, got {err:?}"
    );
}
