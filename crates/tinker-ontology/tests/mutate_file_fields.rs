//! Item 42 (C7): file-field validation on the record write path.
//!
//! Every `file` field value must name an active `stored_files` row in
//! the writing org (missing, deleted, and cross-org references all
//! fail with the same non-oracle error), the file's `pii_class` must
//! not exceed the field's `max_pii_class`, backend bytes are
//! re-hashed against the registry at link time, and a
//! caller-provided expected sha256 (`{id, sha256}`) must match.
//!
//! Covered on both the direct write path (`MutationConnector`
//! create/update) and the lifecycle publication path
//! (`LifecycleEngine::publish`), which has its own parallel
//! write/coercion logic.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tinker_agents::approval::ApprovalEngine;
use tinker_agents::files::{FileRef, FileStore, FsFileBackend, PiiClass};
use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::lifecycle::LifecycleEngine;
use tinker_ontology::mutate::{CreateRequest, MutationConnector, NoHooks, UpdateRequest};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use uuid::Uuid;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Env {
    core: CoreDb,
    core_owner: sqlx::PgPool,
    host_id: Uuid,
}

fn must_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

async fn setup() -> Env {
    let core_owner = sqlx::PgPool::connect(&must_env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("core owner connect");
    tinker_db::MIGRATOR_CORE
        .run(&core_owner)
        .await
        .expect("core migrations");

    // Item-42 migration must be applied: fail loudly if the PII ceiling
    // column the write path depends on is missing.
    let has_col: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='ontology_fields' \
           AND column_name='max_pii_class')",
    )
    .fetch_one(&core_owner)
    .await
    .expect("schema probe");
    assert!(has_col, "migration 0043 (max_pii_class) is not applied");

    let core = CoreDb::connect(&must_env("TINKER_CORE_URL"))
        .await
        .expect("core app-role connect");
    let host_id = Uuid::from_u128(0xC742);
    sqlx::query(
        "INSERT INTO hosts (id, name) VALUES ($1,'c7-file-test') ON CONFLICT (id) DO NOTHING",
    )
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

/// Fresh tenant: org + actor rows (actor via tenant tx for RLS).
async fn new_ctx(env: &Env, slug: &str) -> TenantContext {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    let ctx = TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "c7-file-test".to_string(),
    );
    let mut tx = env.core.tenant_tx(&ctx).await.expect("tenant tx");
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$4)",
    )
    .bind(ctx.actor_id)
    .bind(org_id)
    .bind("file test actor")
    .bind(format!("file-actor-{}", org_id.simple()))
    .execute(&mut *tx)
    .await
    .expect("actor insert");
    tx.commit().await.expect("commit");
    ctx
}

fn ontology(env: &Env) -> Ontology {
    Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
}

/// A FileStore on a private fs dir. Holds ENV_LOCK for the process-wide
/// `TINKER_FILE_ROOT` while building the backend.
fn file_store(env: &Env) -> (Arc<FileStore>, std::path::PathBuf) {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = std::env::temp_dir().join(format!("tinker-c7-{}", Uuid::now_v7().simple()));
    std::env::set_var("TINKER_FILE_ROOT", &dir);
    let backend = FsFileBackend::from_env();
    drop(_guard);
    (
        Arc::new(FileStore::new(env.core.clone(), Arc::new(backend))),
        dir,
    )
}

fn governed_connector(env: &Env, store: &Arc<FileStore>) -> MutationConnector {
    MutationConnector::new(env.core.clone(), ontology(env)).with_file_validator(store.clone())
}

fn governed_lifecycle(env: &Env, store: &Arc<FileStore>) -> LifecycleEngine {
    LifecycleEngine::new(env.core.clone(), ontology(env)).with_file_validator(store.clone())
}

/// Object with a single `file` field whose PII ceiling is `max_pii`.
async fn file_object(env: &Env, ctx: &TenantContext, max_pii: &str) -> Uuid {
    let ont = ontology(env);
    let slug = format!("fileobj_{}", &Uuid::now_v7().simple().to_string()[24..32]);
    let meta = ont
        .define_object(
            ctx,
            &ObjectDef {
                name: "File Target".into(),
                api_slug: slug,
                label: "File Target".into(),
                scope: Scope::Organization,
                pack_id: None,
                pack_version: None,
            },
        )
        .await
        .unwrap();
    ont.add_field(
        ctx,
        meta.id,
        &FieldDef {
            max_pii_class: max_pii.to_string(),
            sensitive: false,
            validation: Default::default(),
            preset: None,
            name: "contract".into(),
            api_name: "contract".into(),
            label: "contract".into(),
            field_type: FieldType::File,
            options: serde_json::Value::Null,
            required: false,
        },
    )
    .await
    .unwrap();
    meta.id
}

async fn store_file(
    store: &FileStore,
    ctx: &TenantContext,
    bytes: &[u8],
    pii: PiiClass,
) -> FileRef {
    store
        .store(ctx, "doc.bin", "application/octet-stream", pii, bytes)
        .await
        .unwrap()
}

fn create_req(object_id: Uuid, file_value: serde_json::Value) -> CreateRequest {
    let mut values = HashMap::new();
    values.insert("contract".to_string(), file_value);
    CreateRequest {
        object_id,
        values,
        require_approval: false,
        approval_request_id: None,
    }
}

fn is_validation(err: &TinkerError) -> bool {
    matches!(err, TinkerError::Validation(_))
}

// ---------------------------------------------------------------------------
// Direct write path: create / update
// ---------------------------------------------------------------------------

#[tokio::test]
async fn file_field_happy_path_create_and_update() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let ctx = new_ctx(&env, &format!("c7f-{}", Uuid::now_v7().simple())).await;
    let obj = file_object(&env, &ctx, "restricted").await;
    let conn = governed_connector(&env, &store);

    let f = store_file(&store, &ctx, b"contract bytes", PiiClass::Pii).await;
    let created = conn
        .create(
            &ctx,
            &create_req(obj, serde_json::Value::String(f.id.to_string())),
            &NoHooks,
        )
        .await
        .expect("create with valid file ref");

    // The stored column holds the plain id string (no structured wrapper).
    // Physical column names are generated `f_<hex>`; resolve via describe.
    let desc = ontology(&env).describe_object(&ctx, obj).await.unwrap();
    let col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "contract")
        .map(|f| f.physical_column.clone())
        .unwrap();
    let mut rtx = env.core.tenant_tx(&ctx).await.expect("read tx");
    let (stored,): (String,) = sqlx::query_as(&format!(
        "SELECT {col} FROM data.{} WHERE organization_id = $1 AND id = $2",
        desc.api_slug
    ))
    .bind(ctx.organization_id.0)
    .bind(created.record_id)
    .fetch_one(&mut *rtx)
    .await
    .expect("read back");
    rtx.rollback().await.expect("rollback");
    assert_eq!(stored, f.id.to_string());

    // Update to a different file also validates.
    let f2 = store_file(&store, &ctx, b"contract v2", PiiClass::None).await;
    let mut values = HashMap::new();
    values.insert(
        "contract".to_string(),
        serde_json::Value::String(f2.id.to_string()),
    );
    conn.update(
        &ctx,
        &UpdateRequest {
            object_id: obj,
            record_id: created.record_id,
            values,
            expected_version: None,
            require_approval: false,
            approval_request_id: None,
        },
        &NoHooks,
    )
    .await
    .expect("update with valid file ref");
}

#[tokio::test]
async fn file_field_missing_reference_rejected() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let ctx = new_ctx(&env, &format!("c7f-{}", Uuid::now_v7().simple())).await;
    let obj = file_object(&env, &ctx, "restricted").await;
    let conn = governed_connector(&env, &store);

    let err = conn
        .create(
            &ctx,
            &create_req(obj, serde_json::Value::String(Uuid::now_v7().to_string())),
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "unexpected: {err:?}");
    assert!(format!("{err}").contains("not an active stored file"));
}

#[tokio::test]
async fn file_field_deleted_reference_rejected() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let ctx = new_ctx(&env, &format!("c7f-{}", Uuid::now_v7().simple())).await;
    let obj = file_object(&env, &ctx, "restricted").await;
    let conn = governed_connector(&env, &store);

    let f = store_file(&store, &ctx, b"doomed", PiiClass::None).await;
    store.delete(&ctx, f.id).await.unwrap();
    let err = conn
        .create(
            &ctx,
            &create_req(obj, serde_json::Value::String(f.id.to_string())),
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "unexpected: {err:?}");
}

#[tokio::test]
async fn file_field_cross_org_reveals_nothing() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let ctx_a = new_ctx(&env, &format!("c7fa-{}", Uuid::now_v7().simple())).await;
    let ctx_b = new_ctx(&env, &format!("c7fb-{}", Uuid::now_v7().simple())).await;
    let obj_b = file_object(&env, &ctx_b, "restricted").await;
    let conn = governed_connector(&env, &store);

    // File belongs to org A; org B tries to link it.
    let f = store_file(&store, &ctx_a, b"org a secret", PiiClass::None).await;
    let err = conn
        .create(
            &ctx_b,
            &create_req(obj_b, serde_json::Value::String(f.id.to_string())),
            &NoHooks,
        )
        .await
        .unwrap_err();
    // Identical error to the missing-reference case: no oracle.
    assert!(is_validation(&err), "unexpected: {err:?}");
    assert_eq!(
        format!("{err}"),
        "validation failed: file reference is not an active stored file"
    );
}

#[tokio::test]
async fn file_field_pii_mismatch_rejected() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let ctx = new_ctx(&env, &format!("c7f-{}", Uuid::now_v7().simple())).await;
    // Field ceiling is "pii"; file is "restricted".
    let obj = file_object(&env, &ctx, "pii").await;
    let conn = governed_connector(&env, &store);

    let f = store_file(&store, &ctx, b"too sensitive", PiiClass::Restricted).await;
    let err = conn
        .create(
            &ctx,
            &create_req(obj, serde_json::Value::String(f.id.to_string())),
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "unexpected: {err:?}");
    assert!(format!("{err}").contains("exceeds field maximum"));

    // And the reverse — a "none" file through a "pii" ceiling — is fine.
    let ok_file = store_file(&store, &ctx, b"fine", PiiClass::None).await;
    conn.create(
        &ctx,
        &create_req(obj, serde_json::Value::String(ok_file.id.to_string())),
        &NoHooks,
    )
    .await
    .expect("none file under pii ceiling");
}

#[tokio::test]
async fn file_field_integrity_mismatch_rejected() {
    let env = setup().await;
    let (store, dir) = file_store(&env);
    let ctx = new_ctx(&env, &format!("c7f-{}", Uuid::now_v7().simple())).await;
    let obj = file_object(&env, &ctx, "restricted").await;
    let conn = governed_connector(&env, &store);

    let f = store_file(&store, &ctx, b"pristine bytes", PiiClass::None).await;
    // Tamper the backend bytes directly (bypass the registry).
    let tampered = dir
        .join(ctx.organization_id.0.to_string())
        .join(&f.sha256[..2])
        .join(&f.sha256);
    std::fs::write(&tampered, b"tampered bytes!!").unwrap();

    let err = conn
        .create(
            &ctx,
            &create_req(obj, serde_json::Value::String(f.id.to_string())),
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(
        format!("{err:?}").contains("integrity check failed"),
        "unexpected: {err:?}"
    );
}

#[tokio::test]
async fn file_field_expected_sha_mismatch_rejected() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let ctx = new_ctx(&env, &format!("c7f-{}", Uuid::now_v7().simple())).await;
    let obj = file_object(&env, &ctx, "restricted").await;
    let conn = governed_connector(&env, &store);

    let f = store_file(&store, &ctx, b"pinned bytes", PiiClass::None).await;
    // Wrong expected hash.
    let err = conn
        .create(
            &ctx,
            &create_req(
                obj,
                serde_json::json!({"id": f.id.to_string(), "sha256": "0".repeat(64)}),
            ),
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "unexpected: {err:?}");
    assert!(format!("{err}").contains("expected sha256"));

    // Right expected hash: accepted, and the column still stores the
    // plain id string.
    let created = conn
        .create(
            &ctx,
            &create_req(
                obj,
                serde_json::json!({"id": f.id.to_string(), "sha256": f.sha256}),
            ),
            &NoHooks,
        )
        .await
        .expect("matching expected sha256");
    assert_ne!(created.record_id, Uuid::nil());
}

#[tokio::test]
async fn file_field_malformed_values_rejected() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let ctx = new_ctx(&env, &format!("c7f-{}", Uuid::now_v7().simple())).await;
    let obj = file_object(&env, &ctx, "restricted").await;
    let conn = governed_connector(&env, &store);

    for bad in [
        serde_json::Value::String("not-a-uuid".into()),
        serde_json::json!(42),
        serde_json::json!({"sha256": "abc"}),
        serde_json::json!({"id": "not-a-uuid"}),
    ] {
        let err = conn
            .create(&ctx, &create_req(obj, bad), &NoHooks)
            .await
            .unwrap_err();
        assert!(is_validation(&err), "unexpected: {err:?}");
    }
}

// ---------------------------------------------------------------------------
// Lifecycle publication path
// ---------------------------------------------------------------------------

/// Seed actors (author + reviewer) and one attachment; returns the
/// attachment id. ApprovalEngine drives the real request/decide flow.
async fn lifecycle_world(
    env: &Env,
    author: &TenantContext,
    reviewer_actor: Uuid,
) -> (ApprovalEngine, Uuid) {
    let mut tx = env.core.tenant_tx(author).await.expect("tenant tx");
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$4)",
    )
    .bind(reviewer_actor)
    .bind(author.organization_id.0)
    .bind("reviewer")
    .bind(format!("reviewer-{}", author.organization_id.0.simple()))
    .execute(&mut *tx)
    .await
    .expect("reviewer insert");
    let (attachment,): (Uuid,) = sqlx::query_as(
        "INSERT INTO agent_attachments (organization_id, actor_id, name, kind) \
         VALUES ($1,$2,'lc file test','test') RETURNING id",
    )
    .bind(author.organization_id.0)
    .bind(author.actor_id)
    .fetch_one(&mut *tx)
    .await
    .expect("attachment insert");
    tx.commit().await.expect("commit");
    (
        ApprovalEngine::new(env.core.clone(), OwnerDb(env.core_owner.clone())),
        attachment,
    )
}

async fn approve_action(
    ap: &ApprovalEngine,
    req_ctx: &TenantContext,
    decide_ctx: &TenantContext,
    attachment: Uuid,
    action: &str,
    draft_id: Uuid,
) -> Uuid {
    let req = ap
        .request(
            req_ctx,
            attachment,
            action,
            serde_json::json!({ "draft_id": draft_id.to_string() }),
            &format!("lc-c7-{action}-{draft_id}"),
        )
        .await
        .expect("approval request");
    ap.decide(decide_ctx, req.id, true).await.expect("decide");
    req.id
}

#[tokio::test]
async fn lifecycle_publish_validates_file_fields() {
    let env = setup().await;
    let (store, _dir) = file_store(&env);
    let author = new_ctx(&env, &format!("c7fl-{}", Uuid::now_v7().simple())).await;
    let reviewer = TenantContext::new(
        author.organization_id,
        Uuid::now_v7(),
        "reviewer".to_string(),
    );
    let (ap, attachment) = lifecycle_world(&env, &author, reviewer.actor_id).await;

    let obj = file_object(&env, &author, "restricted").await;
    ontology(&env)
        .set_lifecycle_enabled(&author, obj, true)
        .await
        .unwrap();
    let lc = governed_lifecycle(&env, &store);

    // Draft with a bogus file reference: submit + publish must fail at
    // publish with the file error (the draft itself only re-validates
    // shapes, not references).
    let bad_draft = lc
        .create_draft(
            &author,
            obj,
            None,
            &HashMap::from([(
                "contract".to_string(),
                serde_json::Value::String(Uuid::now_v7().to_string()),
            )]),
        )
        .await
        .expect("draft create");
    let sub = approve_action(
        &ap,
        &author,
        &reviewer,
        attachment,
        "submit_for_review",
        bad_draft.draft_id,
    )
    .await;
    lc.submit_for_review(&author, bad_draft.draft_id, sub)
        .await
        .expect("submit");
    let publ = approve_action(
        &ap,
        &author,
        &reviewer,
        attachment,
        "publish",
        bad_draft.draft_id,
    )
    .await;
    let err = lc
        .publish(&author, bad_draft.draft_id, publ)
        .await
        .unwrap_err();
    assert!(is_validation(&err), "unexpected: {err:?}");
    assert!(format!("{err}").contains("not an active stored file"));

    // Same flow with a real file: publish succeeds.
    let f = store_file(&store, &author, b"published contract", PiiClass::Pii).await;
    let good_draft = lc
        .create_draft(
            &author,
            obj,
            None,
            &HashMap::from([(
                "contract".to_string(),
                serde_json::Value::String(f.id.to_string()),
            )]),
        )
        .await
        .expect("draft create");
    let sub = approve_action(
        &ap,
        &author,
        &reviewer,
        attachment,
        "submit_for_review",
        good_draft.draft_id,
    )
    .await;
    lc.submit_for_review(&author, good_draft.draft_id, sub)
        .await
        .expect("submit");
    let publ = approve_action(
        &ap,
        &author,
        &reviewer,
        attachment,
        "publish",
        good_draft.draft_id,
    )
    .await;
    let out = lc
        .publish(&author, good_draft.draft_id, publ)
        .await
        .expect("publish with valid file ref");
    assert_ne!(out.record_id, Uuid::nil());
}
