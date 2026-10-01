//! Item 44: the version-matched agent skill, tested end-to-end.
//!
//! The skill's worked examples are its regression tests. This harness
//! executes each example through the real code paths the skill
//! documents — the real `tinker` CLI binary for discovery/install/
//! verify, the real query compiler+executor for the first query, the
//! real governed mutation connector for the first write, and the real
//! lifecycle engine for the publish flow. If the examples rot, this
//! suite fails and the gate with it.
//!
//! Anti-rot content checks (below the example tests) assert the skill
//! text itself stays in lockstep with the code: CLI usage string, the
//! eight lifecycle transition names, the query-intent keys, and the
//! example anchors the harness maps to.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::lifecycle::LifecycleEngine;
use tinker_ontology::mutate::{CreateRequest, MutationConnector, NoHooks};
use tinker_ontology::{
    FieldDef, FieldType, ObjectDef, Ontology, PresetMode, PresetValue, Scope, ValidationRules,
    WritePreset,
};
use tinker_query::{Filter, FilterOp, Order, QueryIntent};
use tinker_web::agent;
use tokio::sync::OnceCell;
use uuid::Uuid;

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
    let host_id = Uuid::from_u128(0x0);
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,'test') ON CONFLICT (id) DO NOTHING")
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

async fn new_org(env: &Env) -> TenantContext {
    let org_id = Uuid::now_v7();
    let s = Uuid::now_v7().simple().to_string();
    let slug = format!("skorg{}", &s[24..32]);
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(&slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "agent-skill-test".to_string(),
    )
}

fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{prefix}{}", &s[24..32])
}

async fn member(env: &Env, org_id: Uuid, role: &str) -> TenantContext {
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
    TenantContext::new(OrganizationId(org_id), actor_id, format!("skill-{role}"))
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

fn field_def(
    api_name: &str,
    field_type: FieldType,
    required: bool,
    validation: ValidationRules,
    preset: Option<WritePreset>,
) -> FieldDef {
    field_def_with_options(
        api_name,
        field_type,
        required,
        validation,
        preset,
        serde_json::json!({}),
    )
}

fn field_def_with_options(
    api_name: &str,
    field_type: FieldType,
    required: bool,
    validation: ValidationRules,
    preset: Option<WritePreset>,
    options: serde_json::Value,
) -> FieldDef {
    FieldDef {
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type,
        options,
        required,
        validation,
        preset,
        max_pii_class: "restricted".into(),
        sensitive: false,
    }
}

/// The real `tinker` binary under test (CARGO_BIN_EXE_<name> is set for
/// integration tests of the package that owns the binary target).
fn tinker_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tinker"))
}

/// Env for `tinker` CLI subprocesses. The CLI's TINKER_CORE_URL is the
/// OWNER pool and TINKER_APP_URL the tenant app pool; the test env names
/// the app-role URL TINKER_CORE_URL, so map explicitly.
fn cli_env() -> Vec<(String, String)> {
    vec![
        ("TINKER_CORE_URL".to_string(), env("TINKER_CORE_OWNER_URL")),
        ("TINKER_APP_URL".to_string(), env("TINKER_CORE_URL")),
    ]
}

// ---------------------------------------------------------------------------
// Example 0 (skill mechanics): install + verify through the real CLI
// ---------------------------------------------------------------------------

#[tokio::test]
async fn skill_install_and_verify_via_real_cli() {
    let root = std::env::temp_dir().join(format!("tinker-skill-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let bin = tinker_bin();

    // Install: the skill the agent would actually receive.
    let out = Command::new(&bin)
        .args(["agent", "install", "--dir"])
        .arg(&root)
        .envs(cli_env())
        .output()
        .expect("tinker agent install");
    assert!(
        out.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let skill_path = root.join("tinker").join("SKILL.md");
    assert!(skill_path.is_file(), "SKILL.md not installed");
    let text = std::fs::read_to_string(&skill_path).unwrap();
    assert!(!text.contains("__TINKER_VERSION__"), "placeholder leaked");
    assert!(!text.contains("__ONTOLOGY_VERSION__"), "placeholder leaked");

    // Verify: green on a fresh install.
    let out = Command::new(&bin)
        .args(["agent", "verify", "--dir"])
        .arg(&root)
        .envs(cli_env())
        .output()
        .expect("tinker agent verify");
    assert!(
        out.status.success(),
        "verify failed on fresh install: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("skill OK"));

    // Drift: a stale pin fails LOUDLY (non-zero + names both sides).
    let current = agent::current_versions();
    let tampered = text.replacen(
        &format!("tinker_version: {}", current.tinker_version),
        "tinker_version: 0.0.0-stale",
        1,
    );
    std::fs::write(&skill_path, tampered).unwrap();
    let out = Command::new(&bin)
        .args(["agent", "verify", "--dir"])
        .arg(&root)
        .envs(cli_env())
        .output()
        .expect("tinker agent verify (drift)");
    assert!(!out.status.success(), "verify passed on a stale skill");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("drift"), "no drift message: {stderr}");
    assert!(stderr.contains("0.0.0-stale"));
    assert!(stderr.contains(&current.tinker_version));

    // Missing skill: verify names the fix.
    let _ = std::fs::remove_dir_all(&root);
    let out = Command::new(&bin)
        .args(["agent", "verify", "--dir"])
        .arg(&root)
        .envs(cli_env())
        .output()
        .expect("tinker agent verify (missing)");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("tinker agent install"));
}

// ---------------------------------------------------------------------------
// Example 1 (skill): discovery — `tinker describe` for real
// ---------------------------------------------------------------------------

#[tokio::test]
async fn skill_discovery_example_via_real_cli() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let slug = uniq("widget");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(
        &ctx,
        obj.id,
        &field_def(
            "name",
            FieldType::Text,
            true,
            ValidationRules::default(),
            None,
        ),
    )
    .await
    .unwrap();
    let _member = member(&env, org_id, "member").await;
    let bin = tinker_bin();

    // Catalog: the fixture object is listed (human-readable).
    let out = Command::new(&bin)
        .args(["describe", "--org", &org_id.to_string(), "--role", "member"])
        .envs(cli_env())
        .output()
        .expect("tinker describe");
    assert!(
        out.status.success(),
        "describe failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains(&slug), "catalog missing {slug}:\n{stdout}");
    assert!(stdout.contains("tinker "), "catalog missing version header");

    // Object describe as canonical JSON: the contract the skill teaches.
    let out = Command::new(&bin)
        .args([
            "describe",
            &slug,
            "--org",
            &org_id.to_string(),
            "--role",
            "member",
            "--json",
        ])
        .envs(cli_env())
        .output()
        .expect("tinker describe --json");
    assert!(out.status.success());
    let payload: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("describe --json is JSON");
    assert_eq!(payload["api_slug"], slug);
    assert_eq!(
        payload["tinker_version"],
        agent::current_versions().tinker_version
    );
    assert!(payload["ontology_version"].is_string());
    let fields = payload["fields"].as_array().unwrap();
    assert!(fields
        .iter()
        .any(|f| f["api_name"] == "name" && f["required"] == true));
    // Byte-stability: the same describe twice is byte-identical.
    let out2 = Command::new(&bin)
        .args([
            "describe",
            &slug,
            "--org",
            &org_id.to_string(),
            "--role",
            "member",
            "--json",
        ])
        .envs(cli_env())
        .output()
        .unwrap();
    assert_eq!(
        out.stdout, out2.stdout,
        "describe --json is not byte-stable"
    );

    // Misuse fails closed with usage (exit 2), exactly as the skill says.
    let out = Command::new(&bin)
        .args(["describe", "--role", "member"])
        .envs(cli_env())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--org"));
}

// ---------------------------------------------------------------------------
// Example 2 (skill): first query + first valid write (governed path)
// ---------------------------------------------------------------------------

/// `gadget`: name (required text), status (select with a WhenMissing
/// preset to "new"), price (number, min 0). The write example's preset
/// and validation behavior ride on these fields.
async fn gadget_world(env: &Env) -> (TenantContext, Uuid) {
    let ctx = new_org(env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let slug = uniq("gadget");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(
        &ctx,
        obj.id,
        &field_def(
            "name",
            FieldType::Text,
            true,
            ValidationRules::default(),
            None,
        ),
    )
    .await
    .unwrap();
    ont.add_field(
        &ctx,
        obj.id,
        &field_def_with_options(
            "status",
            FieldType::Select,
            false,
            ValidationRules {
                options: Some(vec!["new".into(), "active".into()]),
                ..Default::default()
            },
            Some(WritePreset {
                mode: PresetMode::WhenMissing,
                value: PresetValue::Static {
                    value: serde_json::json!("new"),
                },
            }),
            serde_json::json!({"options": ["new", "active"]}),
        ),
    )
    .await
    .unwrap();
    ont.add_field(
        &ctx,
        obj.id,
        &field_def(
            "price",
            FieldType::Number,
            false,
            ValidationRules {
                min: Some(0.0),
                ..Default::default()
            },
            None,
        ),
    )
    .await
    .unwrap();
    (ctx, obj.id)
}

fn values(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

#[tokio::test]
async fn skill_first_write_example_governed_path() {
    let env = setup().await;
    let (ctx, object_id) = gadget_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let mutator = MutationConnector::new(env.core.clone(), ont);

    // The skill's write example: send only what you mean; the preset
    // fills `status`, validation enforces the rest.
    let outcome = mutator
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[
                    ("name", serde_json::json!("sprocket")),
                    ("price", serde_json::json!(12.5)),
                ]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .expect("valid governed write");
    assert!(outcome.version >= 1);

    // Preset applied: status is "new" even though the write omitted it.
    // Read back through the governed path: the query compiler is the
    // honest read-back (physical table slugs are internal).
    let state = tinker_web::build_state(
        env.core.0.clone(),
        env.core_owner.clone(),
        tinker_auth::AuthBroker::new(vec![]),
        "test".to_string(),
        false,
    );
    let role = "member".to_string();
    let member_ctx = member(&env, ctx.organization_id.0, "member").await;
    let intent = QueryIntent {
        from: object_id,
        select: vec!["name".into(), "status".into(), "price".into()],
        filters: vec![Filter {
            field: "name".into(),
            op: FilterOp::Eq,
            value: serde_json::json!("sprocket"),
        }],
        order: vec![Order {
            field: "name".into(),
            descending: false,
        }],
        limit: Some(100),
        schema_version: Some("active".into()),
    };
    let projection = state
        .grants
        .load_projection_for_query(&member_ctx, &state.ontology, &role, intent.from)
        .await
        .unwrap();
    let policy = state
        .row_filters
        .load_policy(&member_ctx, intent.from, &role)
        .await
        .unwrap();
    let plan = state
        .compiler
        .compile_with_policy(&member_ctx, &intent, &projection, &policy)
        .await
        .unwrap();
    let rows = state.executor.execute(&member_ctx, &plan).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the write example's record must be queryable"
    );
    let got = &rows[0];
    assert_eq!(
        got["status"],
        serde_json::json!("new"),
        "preset did not fill status"
    );

    // 400-class failures, exactly as the skill's error taxonomy says:
    // unknown option value…
    let err = mutator
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[
                    ("name", serde_json::json!("bad")),
                    ("status", serde_json::json!("retired")),
                ]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "expected Validation, got {err:?}"
    );
    // …negative price against min: 0…
    let err = mutator
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[
                    ("name", serde_json::json!("bad")),
                    ("price", serde_json::json!(-1.0)),
                ]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
    // …explicit null on a required field…
    let err = mutator
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", serde_json::Value::Null)]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
    // …and an unknown field is rejected, never ignored.
    let err = mutator
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[
                    ("name", serde_json::json!("bad")),
                    ("no_such_field", serde_json::json!(1)),
                ]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));
}

// ---------------------------------------------------------------------------
// Example 3 (skill): the publish flow (lifecycle path)
// ---------------------------------------------------------------------------

struct ArticleWorld {
    slug: String,
    object_id: Uuid,
    attachment: Uuid,
    ctx_author: TenantContext,
    ctx_reviewer: TenantContext,
}

async fn article_world(env: &Env) -> ArticleWorld {
    let ctx = new_org(env).await;
    let org_id = ctx.organization_id.0;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let slug = uniq("article");
    let obj = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(
        &ctx,
        obj.id,
        &field_def(
            "title",
            FieldType::Text,
            true,
            ValidationRules::default(),
            None,
        ),
    )
    .await
    .unwrap();
    ont.add_field(
        &ctx,
        obj.id,
        &field_def(
            "body",
            FieldType::Text,
            false,
            ValidationRules::default(),
            None,
        ),
    )
    .await
    .unwrap();
    ont.set_lifecycle_enabled(&ctx, obj.id, true).await.unwrap();

    let ctx_author = member(env, org_id, "member").await;
    let ctx_reviewer = member(env, org_id, "reviewer").await;

    // Scratch agent attachment backing the M7 approval rows (the
    // attachment_id FK needs a real row; the engine binds on
    // action_name + payload, not the attachment).
    let mut att_tx = env.core.tenant_tx(&ctx_author).await.unwrap();
    let attachment: Uuid = sqlx::query_scalar(
        "INSERT INTO agent_attachments \
         (organization_id, actor_id, name, kind, scope, action_grants, \
          approval_policy, budgets, status) \
         VALUES ($1, $2, 'skill-test', 'test', '{}', '[]', '{}', '{}', 'active') \
         RETURNING id",
    )
    .bind(org_id)
    .bind(ctx_author.actor_id)
    .fetch_one(&mut *att_tx)
    .await
    .unwrap();
    att_tx.commit().await.unwrap();

    ArticleWorld {
        slug,
        object_id: obj.id,
        attachment,
        ctx_author,
        ctx_reviewer,
    }
}

/// Mint an already-approved M7 approval bound to (action, draft_id),
/// decided by `decided_by`. The engine only reads status/action/payload/
/// decided_by — this is the fixture, not a second approval path.
async fn approved_approval(
    env: &Env,
    w: &ArticleWorld,
    action: &str,
    draft_id: Uuid,
    decided_by: Uuid,
) -> Uuid {
    let id = Uuid::now_v7();
    // RLS is forced on approval_requests: write through a tenant tx,
    // the approval engine's own path.
    let mut tx = env.core.tenant_tx(&w.ctx_author).await.unwrap();
    sqlx::query(
        "INSERT INTO approval_requests \
         (id, organization_id, attachment_id, action_name, payload, \
          idempotency_key, status, decided_by, decided_at) \
         VALUES ($1,$2,$3,$4,$5,$6,'approved',$7,now())",
    )
    .bind(id)
    .bind(w.ctx_author.organization_id.0)
    .bind(w.attachment)
    .bind(action)
    .bind(serde_json::json!({"draft_id": draft_id.to_string()}))
    .bind(format!("skill-{action}-{id}"))
    .bind(decided_by)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

#[tokio::test]
async fn skill_publish_flow_example_lifecycle_path() {
    let env = setup().await;
    let w = article_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let engine = LifecycleEngine::new(env.core.clone(), ont);

    // The skill's publish example, step by step:
    // 1. create_draft with the record content (validated like a write).
    let draft = engine
        .create_draft(
            &w.ctx_author,
            w.object_id,
            None,
            &values(&[
                ("title", serde_json::json!("hello")),
                ("body", serde_json::json!("world")),
            ]),
        )
        .await
        .expect("create_draft");
    assert_eq!(draft.state.as_str(), "draft");

    // A draft with invalid content never gets created (validation at
    // the door, same rules as the governed write path).
    let err = engine
        .create_draft(
            &w.ctx_author,
            w.object_id,
            None,
            &values(&[("body", serde_json::json!("no title"))]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));

    // 2. submit_for_review consumes a bound, approved M7 approval.
    let submit_appr = approved_approval(
        &env,
        &w,
        "submit_for_review",
        draft.draft_id,
        w.ctx_reviewer.actor_id,
    )
    .await;
    let draft = engine
        .submit_for_review(&w.ctx_author, draft.draft_id, submit_appr)
        .await
        .expect("submit_for_review");
    assert_eq!(draft.state.as_str(), "in_review");

    // 3. publish: approval decided by the REVIEWER (not the author).
    let publish_appr =
        approved_approval(&env, &w, "publish", draft.draft_id, w.ctx_reviewer.actor_id).await;
    let outcome = engine
        .publish(&w.ctx_author, draft.draft_id, publish_appr)
        .await
        .expect("publish");
    assert!(outcome.version >= 1);

    // Published: the data row carries the content, immutably.
    let title_col = physical_column(&env, &w.ctx_author, w.object_id, "title").await;
    let (state, title): (String, Option<String>) = sqlx::query_as(&format!(
        "SELECT lifecycle_state, \"{title_col}\" FROM data.{} WHERE organization_id = $1 AND id = $2",
        w.slug
    ))
    .bind(w.ctx_author.organization_id.0)
    .bind(outcome.record_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(state, "published");
    assert_eq!(title.as_deref(), Some("hello"));
}

// ---------------------------------------------------------------------------
// Anti-rot: the skill text stays in lockstep with the code
// ---------------------------------------------------------------------------

/// The physical column for a field is generated (`f_<hex>`); resolve it
/// from the ontology instead of guessing. Shared by the publish-flow
/// read-back.
async fn physical_column(
    env: &Env,
    ctx: &TenantContext,
    object_id: Uuid,
    api_name: &str,
) -> String {
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let desc = ont.describe_object(ctx, object_id).await.unwrap();
    desc.fields
        .iter()
        .find(|f| f.api_name == api_name)
        .unwrap()
        .physical_column
        .clone()
}

#[tokio::test]
async fn skill_publish_flow_readback_and_negatives() {
    let env = setup().await;
    let w = article_world(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let engine = LifecycleEngine::new(env.core.clone(), ont);
    let title_col = physical_column(&env, &w.ctx_author, w.object_id, "title").await;

    let draft = engine
        .create_draft(
            &w.ctx_author,
            w.object_id,
            None,
            &values(&[("title", serde_json::json!("immutable me"))]),
        )
        .await
        .unwrap();
    let submit_appr = approved_approval(
        &env,
        &w,
        "submit_for_review",
        draft.draft_id,
        w.ctx_reviewer.actor_id,
    )
    .await;
    let draft = engine
        .submit_for_review(&w.ctx_author, draft.draft_id, submit_appr)
        .await
        .unwrap();
    let publish_appr =
        approved_approval(&env, &w, "publish", draft.draft_id, w.ctx_reviewer.actor_id).await;
    let outcome = engine
        .publish(&w.ctx_author, draft.draft_id, publish_appr)
        .await
        .unwrap();

    // Published content is on the data row.
    let (state, title): (String, Option<String>) = sqlx::query_as(&format!(
        "SELECT lifecycle_state, \"{title_col}\" FROM data.{} WHERE organization_id = $1 AND id = $2",
        w.slug
    ))
    .bind(w.ctx_author.organization_id.0)
    .bind(outcome.record_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(state, "published");
    assert_eq!(title.as_deref(), Some("immutable me"));

    // Published versions are immutable: the draft row is gone after
    // publish (the immutable snapshot lives in record_versions), so a
    // second publish finds nothing to move — there is no in-place edit
    // of a published version.
    let err = engine
        .publish(&w.ctx_author, draft.draft_id, Uuid::now_v7())
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_)),
        "expected NotFound on re-publish (draft consumed), got {err:?}"
    );

    // No self-approval, ever: an approval decided by the AUTHOR is
    // refused even when it is otherwise valid.
    let draft2 = engine
        .create_draft(
            &w.ctx_author,
            w.object_id,
            None,
            &values(&[("title", serde_json::json!("self approved"))]),
        )
        .await
        .unwrap();
    let submit2 = approved_approval(
        &env,
        &w,
        "submit_for_review",
        draft2.draft_id,
        w.ctx_reviewer.actor_id,
    )
    .await;
    let draft2 = engine
        .submit_for_review(&w.ctx_author, draft2.draft_id, submit2)
        .await
        .unwrap();
    let self_appr = approved_approval(
        &env,
        &w,
        "publish",
        draft2.draft_id,
        w.ctx_author.actor_id, // the author decides: forbidden
    )
    .await;
    let err = engine
        .publish(&w.ctx_author, draft2.draft_id, self_appr)
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "expected Forbidden on self-approval, got {err:?}"
    );

    // Direct writes are refused for lifecycle-managed objects — the
    // skill says 403, and the connector agrees.
    let mutator = MutationConnector::new(
        env.core.clone(),
        Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone())),
    );
    let err = mutator
        .create(
            &w.ctx_author,
            &CreateRequest {
                object_id: w.object_id,
                values: values(&[("title", serde_json::json!("sneaky"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Forbidden(_)),
        "expected Forbidden on direct write to lifecycle object, got {err:?}"
    );
}

#[test]
fn skill_text_matches_code() {
    let skill = agent::SKILL_SOURCE;

    // Example anchors the harness maps to.
    for anchor in [
        "<!-- example: first-query -->",
        "<!-- example: first-write -->",
        "<!-- example: publish-flow -->",
    ] {
        assert!(skill.contains(anchor), "skill missing anchor {anchor}");
    }

    // The exact CLI usage the discovery test executes.
    assert!(
        skill.contains("tinker describe [object] [--json] --org <uuid> --role <role>"),
        "skill CLI usage drifted from main.rs describe_usage"
    );
    assert!(
        skill.contains("tinker agent install [--global]")
            || skill.contains("tinker agent <install|verify>"),
        "skill must document the agent subcommand"
    );

    // All eight lifecycle transitions, exactly as describe documents.
    for t in [
        "create_draft",
        "update_draft",
        "submit_for_review",
        "publish",
        "reject",
        "revise",
        "archive",
        "unarchive",
    ] {
        assert!(skill.contains(t), "skill missing transition {t}");
    }
    assert!(skill.contains("no self-approval"));

    // The query-intent keys the first-query example builds.
    for key in [
        "\"from\"",
        "\"select\"",
        "\"filters\"",
        "\"order\"",
        "\"limit\"",
        "\"schema_version\"",
    ] {
        assert!(skill.contains(key), "skill intent shape missing {key}");
    }

    // Error taxonomy classes from describe's mutation contract.
    for class in ["`invalid`", "`forbidden`", "`not_found`", "`conflict`"] {
        assert!(skill.contains(class), "skill missing error class {class}");
    }

    // Auth facts: key format, env var, Bearer presentation, scope grammar.
    for fact in [
        "tk_",
        "TINKER_API_KEY",
        "Authorization: Bearer",
        "mcp:tools",
        "tinker-cli mcp key issue",
    ] {
        assert!(skill.contains(fact), "skill missing auth fact {fact}");
    }

    // The source carries placeholders; the installed file must not
    // (asserted on the installed bytes in the e2e install test).
    assert!(skill.contains("__TINKER_VERSION__"));
    assert!(skill.contains("__ONTOLOGY_VERSION__"));
}
