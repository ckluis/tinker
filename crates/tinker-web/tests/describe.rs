//! Item 43 exits: the self-describing ontology (`tinker describe`).
//!
//! The contract under test:
//! - `GET /api/describe`-equivalent projection (via [`Describer`]):
//!   catalog lists exactly the caller's visible objects (platform + own
//!   org), carries `tinker_version` + `ontology_version`, sorted by slug.
//! - Object describe is a read projection over the real sources: fields
//!   (validation rules, presets, `max_pii_class`), relations with live
//!   target slugs, row-policy SUMMARIES (never verbatim), lifecycle
//!   transitions, mutation/read contracts.
//! - Permission-aware: field projections omit hidden fields entirely;
//!   unknown and foreign slugs are both `NotFound` (no oracle); row
//!   policy summaries never name fields, operators, or values.
//! - Canonical JSON: byte-identical across runs, keys sorted.
//! - Version pinning: declared-but-wrong client versions are detected.
//! - Read-only: repeated describes are byte-identical.

use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_live::FieldGrants;
use tinker_ontology::{
    FieldDef, FieldType, ObjectDef, Ontology, PresetMode, PresetValue, Scope, ValidationRules,
    WritePreset,
};
use tinker_query::{RowFilterDef, RowFilters};
use tinker_web::describe::{
    canonical_json, check_client_versions, ontology_version, tinker_version, Describer, VersionPin,
};
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
    let slug = format!("dorg{}", &s[24..32]);
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
        "describe-test".to_string(),
    )
}

fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{prefix}{}", &s[24..32])
}

fn describer(env: &Env) -> (Describer, Ontology) {
    let owner = OwnerDb(env.core_owner.clone());
    let ontology = Ontology::new(env.core.clone(), owner.clone());
    let d = Describer::new(
        env.core.clone(),
        ontology.clone(),
        FieldGrants::new(env.core.clone()),
        RowFilters::new(env.core.clone()),
    );
    (d, ontology)
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

fn field(api_name: &str, field_type: FieldType) -> FieldDef {
    FieldDef {
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type,
        options: serde_json::json!({}),
        required: false,
        validation: ValidationRules::default(),
        preset: None,
        max_pii_class: "restricted".into(),
        sensitive: false,
    }
}

fn is_not_found(e: &TinkerError) -> bool {
    matches!(e, TinkerError::NotFound(_))
}

#[tokio::test]
async fn catalog_lists_objects_with_versions() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (d, ont) = describer(&env);
    let slug_a = uniq("dcat_a");
    let slug_b = uniq("dcat_b");
    ont.define_object(&ctx, &object_def(&slug_a)).await.unwrap();
    ont.define_object(&ctx, &object_def(&slug_b)).await.unwrap();

    let catalog = d.catalog(&ctx, "admin").await.unwrap();
    assert!(!catalog.tinker_version.is_empty());
    assert_eq!(catalog.tinker_version, tinker_version());
    assert_eq!(catalog.ontology_version, ontology_version());
    // ontology_version tracks the embedded core migrations.
    let expected_max = tinker_db::MIGRATOR_CORE
        .migrations
        .iter()
        .map(|m| m.version)
        .max()
        .unwrap();
    assert_eq!(catalog.ontology_version, format!("{expected_max:04}"));

    let slugs: Vec<&str> = catalog
        .objects
        .iter()
        .map(|o| o.api_slug.as_str())
        .collect();
    assert!(slugs.contains(&slug_a.as_str()));
    assert!(slugs.contains(&slug_b.as_str()));
    // Sorted by slug.
    let mut sorted = slugs.clone();
    sorted.sort_unstable();
    assert_eq!(slugs, sorted);
    for o in &catalog.objects {
        assert_eq!(o.describe_href, format!("/api/describe/{}", o.api_slug));
    }
    // Read-only: a second read is identical.
    let again = d.catalog(&ctx, "admin").await.unwrap();
    let b1 = canonical_json(&serde_json::to_value(&catalog).unwrap());
    let b2 = canonical_json(&serde_json::to_value(&again).unwrap());
    assert_eq!(b1, b2);
}

#[tokio::test]
async fn catalog_hides_foreign_org_objects() {
    let env = setup().await;
    let ctx_a = new_org(&env).await;
    let ctx_b = new_org(&env).await;
    let (d, ont) = describer(&env);
    let slug = uniq("dforeign");
    ont.define_object(&ctx_b, &object_def(&slug)).await.unwrap();

    let catalog_a = d.catalog(&ctx_a, "admin").await.unwrap();
    assert!(!catalog_a.objects.iter().any(|o| o.api_slug == slug));
    // And the object endpoint agrees: foreign slug is NotFound, exactly
    // like a slug that never existed — no oracle.
    let foreign = d.object(&ctx_a, "admin", &slug).await;
    let missing = d.object(&ctx_a, "admin", "definitely_not_an_object").await;
    assert!(foreign.as_ref().is_err_and(is_not_found));
    assert!(missing.as_ref().is_err_and(is_not_found));
    assert_eq!(
        std::mem::discriminant(&foreign.unwrap_err()),
        std::mem::discriminant(&missing.unwrap_err())
    );
}

#[tokio::test]
async fn object_describe_round_trip() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (d, ont) = describer(&env);
    let slug = uniq("dobj");
    let company_slug = uniq("dcompany");
    let company = ont
        .define_object(&ctx, &object_def(&company_slug))
        .await
        .unwrap();
    let deal = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();

    // Text field with validation rules + preset.
    let mut f = field("name", FieldType::Text);
    f.required = true;
    f.validation = ValidationRules {
        min: Some(2.0),
        max: Some(80.0),
        pattern: Some("^[A-Za-z ]+$".into()),
        options: None,
    };
    f.preset = Some(WritePreset {
        mode: PresetMode::WhenMissing,
        value: PresetValue::Static {
            value: serde_json::json!("unnamed"),
        },
    });
    ont.add_field(&ctx, deal.id, &f).await.unwrap();
    // Select field with options.
    let mut s = field("stage", FieldType::Select);
    s.options = serde_json::json!({"options": ["lead", "won"]});
    ont.add_field(&ctx, deal.id, &s).await.unwrap();
    // File field with a PII ceiling.
    let mut file = field("contract", FieldType::File);
    file.max_pii_class = "pii".into();
    ont.add_field(&ctx, deal.id, &file).await.unwrap();
    // Relation field.
    let rel = FieldDef {
        field_type: FieldType::Relation {
            target_object_id: company.id,
        },
        ..field("company", FieldType::Text)
    };
    ont.add_field(&ctx, deal.id, &rel).await.unwrap();

    let o = d.object(&ctx, "admin", &slug).await.unwrap();
    assert_eq!(o.tinker_version, tinker_version());
    assert_eq!(o.ontology_version, ontology_version());
    assert_eq!(o.api_slug, slug);
    assert_eq!(o.scope, "organization");
    assert!(!o.lifecycle_enabled);
    assert!(o.lifecycle.is_none());

    let by_name: std::collections::HashMap<_, _> =
        o.fields.iter().map(|f| (f.api_name.as_str(), f)).collect();
    let name = by_name["name"];
    assert_eq!(name.field_type, "text");
    assert_eq!(name.postgres_type, "TEXT");
    assert!(name.required);
    assert!(name.nullable);
    assert_eq!(name.validation.min, Some(2.0));
    assert_eq!(name.validation.max, Some(80.0));
    assert_eq!(name.validation.pattern.as_deref(), Some("^[A-Za-z ]+$"));
    assert!(name.preset.is_some());
    assert_eq!(name.max_pii_class, "restricted");

    let stage = by_name["stage"];
    assert_eq!(
        stage.options.as_deref(),
        Some(vec!["lead".to_string(), "won".to_string()]).as_deref()
    );

    let contract = by_name["contract"];
    assert_eq!(contract.field_type, "file");
    assert_eq!(contract.max_pii_class, "pii");

    let company_f = by_name["company"];
    assert_eq!(company_f.field_type, "relation");
    assert_eq!(company_f.postgres_type, "UUID");
    assert_eq!(
        company_f.relation_target.as_deref(),
        Some(company_slug.as_str())
    );

    assert_eq!(o.relations.len(), 1);
    assert_eq!(o.relations[0].field, "company");
    assert_eq!(o.relations[0].target_object, company_slug);
    assert_eq!(o.relations[0].cardinality, "many-to-one");

    // No row policy for this role: default-open, honestly reported.
    assert!(!o.row_policy.applies);
    assert_eq!(o.row_policy.filter_count, 0);

    // Mutation + read contracts present.
    assert_eq!(o.mutation.write_path, "governed");
    assert_eq!(o.reads.query_endpoint, "POST /api/query");
    assert!(!o.mutation.error_taxonomy.is_empty());
}

#[tokio::test]
async fn field_projection_redacts_without_oracle() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (d, ont) = describer(&env);
    let slug = uniq("dproj");
    let deal = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    for api in ["name", "region", "amount"] {
        ont.add_field(&ctx, deal.id, &field(api, FieldType::Text))
            .await
            .unwrap();
    }
    let grants = FieldGrants::new(env.core.clone());
    grants
        .set_projection(&ctx, deal.id, "viewer", &["name"])
        .await
        .unwrap();

    let admin = d.object(&ctx, "admin", &slug).await.unwrap();
    assert_eq!(admin.fields.len(), 3);
    let viewer = d.object(&ctx, "viewer", &slug).await.unwrap();
    assert_eq!(viewer.fields.len(), 1);
    assert_eq!(viewer.fields[0].api_name, "name");

    // The hidden fields are not named anywhere in the viewer's output —
    // not in fields, relations, or the serialized bytes.
    let bytes = canonical_json(&serde_json::to_value(&viewer).unwrap());
    let text = String::from_utf8(bytes).unwrap();
    assert!(!text.contains("region"));
    assert!(!text.contains("amount"));
}

#[tokio::test]
async fn row_policy_summary_never_verbatim() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (d, ont) = describer(&env);
    let slug = uniq("dpol");
    let deal = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, deal.id, &field("region", FieldType::Text))
        .await
        .unwrap();
    let desc = ont.describe_object(&ctx, deal.id).await.unwrap();
    let rf = RowFilters::new(env.core.clone());
    rf.set_filters(
        &ctx,
        &desc,
        "rep",
        &[RowFilterDef {
            field: "region".into(),
            op: "eq".into(),
            value: Some(serde_json::json!("emea")),
        }],
    )
    .await
    .unwrap();

    let rep = d.object(&ctx, "rep", &slug).await.unwrap();
    assert!(rep.row_policy.applies);
    assert_eq!(rep.row_policy.filter_count, 1);
    // Coarse only: no field name, operator, or value leaks.
    assert!(!rep.row_policy.summary.contains("region"));
    assert!(!rep.row_policy.summary.contains("emea"));
    assert!(!rep.row_policy.summary.contains("eq"));

    let manager = d.object(&ctx, "manager", &slug).await.unwrap();
    assert!(!manager.row_policy.applies);
}

#[tokio::test]
async fn canonical_json_is_stable() {
    // Key order is normalized recursively, independent of insertion.
    let v = serde_json::json!({"b": 1, "a": {"d": 4, "c": 3}, "arr": [{"y": 1, "x": 2}]});
    assert_eq!(
        canonical_json(&v),
        br#"{"a":{"c":3,"d":4},"arr":[{"x":2,"y":1}],"b":1}"#.to_vec()
    );

    // A full describe payload is byte-identical across runs.
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (d, ont) = describer(&env);
    let slug = uniq("dstable");
    let deal = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx, deal.id, &field("name", FieldType::Text))
        .await
        .unwrap();
    let a = d.object(&ctx, "admin", &slug).await.unwrap();
    let b = d.object(&ctx, "admin", &slug).await.unwrap();
    let ba = canonical_json(&serde_json::to_value(&a).unwrap());
    let bb = canonical_json(&serde_json::to_value(&b).unwrap());
    assert_eq!(ba, bb);
}

#[tokio::test]
async fn lifecycle_section_appears_when_enabled() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (d, ont) = describer(&env);
    let slug = uniq("dlife");
    let deal = ont.define_object(&ctx, &object_def(&slug)).await.unwrap();
    ont.set_lifecycle_enabled(&ctx, deal.id, true)
        .await
        .unwrap();

    let o = d.object(&ctx, "admin", &slug).await.unwrap();
    assert!(o.lifecycle_enabled);
    assert_eq!(o.mutation.write_path, "lifecycle");
    let lc = o.lifecycle.expect("lifecycle section");
    assert_eq!(
        lc.states,
        vec!["draft", "in_review", "rejected", "published", "archived"]
    );
    let names: Vec<&str> = lc.transitions.iter().map(|t| t.name.as_str()).collect();
    for expected in [
        "create_draft",
        "update_draft",
        "submit_for_review",
        "publish",
        "reject",
        "revise",
        "archive",
        "unarchive",
    ] {
        assert!(names.contains(&expected), "missing transition {expected}");
    }
    let publish = lc.transitions.iter().find(|t| t.name == "publish").unwrap();
    assert_eq!(publish.from, vec!["in_review"]);
    assert_eq!(publish.to, "published");
    assert!(publish.requires_approval.is_some());
    // No self-approval: the rule is documented, not implied.
    assert!(publish.who.contains("other than the draft author"));
    let create = lc
        .transitions
        .iter()
        .find(|t| t.name == "create_draft")
        .unwrap();
    assert!(create.from.is_empty());
    assert!(create.requires_approval.is_none());

    // Compile-time coupling: the transition table in describe.rs documents
    // the lifecycle engine's public methods one-for-one. Referencing each
    // method here means a rename or removal in tinker_ontology::lifecycle
    // breaks this test at COMPILE time instead of silently drifting the
    // documented table.
    let _ = tinker_ontology::lifecycle::LifecycleEngine::create_draft;
    let _ = tinker_ontology::lifecycle::LifecycleEngine::update_draft;
    let _ = tinker_ontology::lifecycle::LifecycleEngine::submit_for_review;
    let _ = tinker_ontology::lifecycle::LifecycleEngine::publish;
    let _ = tinker_ontology::lifecycle::LifecycleEngine::reject;
    let _ = tinker_ontology::lifecycle::LifecycleEngine::revise;
    let _ = tinker_ontology::lifecycle::LifecycleEngine::archive;
    let _ = tinker_ontology::lifecycle::LifecycleEngine::unarchive;
}

#[tokio::test]
async fn version_pin_mismatch_is_detected() {
    // Unpinned: lenient.
    let none = VersionPin {
        client_tinker_version: None,
        client_ontology_version: None,
    };
    assert!(check_client_versions(&none).is_none());
    // Correct pins: pass.
    let ok = VersionPin {
        client_tinker_version: Some(tinker_version().into()),
        client_ontology_version: Some(ontology_version()),
    };
    assert!(check_client_versions(&ok).is_none());
    // Wrong pin: detected, both sides named.
    let bad = VersionPin {
        client_tinker_version: Some("0.0.0-fake".into()),
        client_ontology_version: None,
    };
    let m = check_client_versions(&bad).expect("mismatch");
    assert_eq!(m.expected_tinker, tinker_version());
    assert_eq!(m.got_tinker.as_deref(), Some("0.0.0-fake"));
}

// ---------------------------------------------------------------------------
// HTTP handler tests: the real axum handlers over a real SharedState.
// ---------------------------------------------------------------------------

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use tinker_web::describe::{get_catalog, get_object};
use tinker_web::{RequestContext, SharedState};

async fn http_state() -> SharedState {
    let tenant_pool = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("tenant pool");
    let system_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("system pool");
    let broker = tinker_auth::AuthBroker::new(vec![]);
    tinker_web::build_state(tenant_pool, system_pool, broker, "test.local".into(), false)
}

fn test_session(org_id: Uuid, actor_id: Uuid) -> RequestContext {
    RequestContext(tinker_identity::Session {
        id: Uuid::now_v7(),
        organization_id: org_id,
        workspace_id: Uuid::now_v7(),
        actor_id,
        method: "test".into(),
        assurance: tinker_auth::AssuranceLevel::Token,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    })
}

async fn member_with_role(env: &Env, org_id: Uuid, role: &str) -> Uuid {
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
    sqlx::query("INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,$3)")
        .bind(actor_id)
        .bind(org_id)
        .bind(role)
        .execute(&env.core_owner)
        .await
        .unwrap();
    actor_id
}

fn no_pin() -> Query<VersionPin> {
    Query(VersionPin {
        client_tinker_version: None,
        client_ontology_version: None,
    })
}

async fn body_json(
    resp: axum::response::Response,
) -> (axum::http::StatusCode, serde_json::Value, Option<String>) {
    let status = resp.status();
    let ctype = resp
        .headers()
        .get("content-type")
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, value, ctype)
}

#[tokio::test]
async fn http_catalog_returns_canonical_json() {
    let env = setup().await;
    let state = http_state().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;
    let actor_id = member_with_role(&env, org_id, "admin").await;
    let slug = uniq("dhttp");
    let (_, ont) = describer(&env);
    ont.define_object(&ctx, &object_def(&slug)).await.unwrap();

    let resp = get_catalog(State(state), test_session(org_id, actor_id), no_pin())
        .await
        .unwrap_or_else(|e| e.into_response());
    let (status, value, ctype) = body_json(resp).await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some("application/json"));
    assert_eq!(value["tinker_version"], serde_json::json!(tinker_version()));
    assert_eq!(
        value["ontology_version"],
        serde_json::json!(ontology_version())
    );
    let slugs: Vec<&str> = value["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["api_slug"].as_str().unwrap())
        .collect();
    assert!(slugs.contains(&slug.as_str()));

    // The body on the wire is already canonical: re-canonicalizing the
    // parsed value reproduces the exact bytes.
    let resp2 = get_catalog(
        State(http_state().await),
        test_session(org_id, actor_id),
        no_pin(),
    )
    .await
    .unwrap_or_else(|e| e.into_response());
    let bytes = axum::body::to_bytes(resp2.into_body(), usize::MAX)
        .await
        .unwrap();
    let reparsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(canonical_json(&reparsed), bytes.to_vec());
}

#[tokio::test]
async fn http_catalog_rejects_without_membership() {
    let env = setup().await;
    let state = http_state().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;
    // Actor exists in no membership row: fail closed, 403.
    let actor_id = Uuid::now_v7();
    let resp = get_catalog(State(state), test_session(org_id, actor_id), no_pin())
        .await
        .unwrap_or_else(|e| e.into_response());
    assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn http_object_unknown_slug_is_404() {
    let env = setup().await;
    let state = http_state().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;
    let actor_id = member_with_role(&env, org_id, "viewer").await;

    let resp = get_object(
        State(state),
        test_session(org_id, actor_id),
        Path("no_such_object".to_string()),
        no_pin(),
    )
    .await
    .unwrap_or_else(|e| e.into_response());
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn http_version_pin_mismatch_is_409() {
    let env = setup().await;
    let state = http_state().await;
    let ctx = new_org(&env).await;
    let org_id = ctx.organization_id.0;
    let actor_id = member_with_role(&env, org_id, "admin").await;

    let pin = Query(VersionPin {
        client_tinker_version: Some("0.0.0-fake".into()),
        client_ontology_version: None,
    });
    // A version mismatch short-circuits before auth: 409 with both
    // sides named, even for a member.
    let resp = get_catalog(State(state), test_session(org_id, actor_id), pin)
        .await
        .unwrap_or_else(|e| e.into_response());
    let (status, value, _) = body_json(resp).await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT);
    assert_eq!(value["error"], serde_json::json!("version_mismatch"));
    assert_eq!(
        value["expected"]["tinker_version"],
        serde_json::json!(tinker_version())
    );
    assert_eq!(
        value["got"]["tinker_version"],
        serde_json::json!("0.0.0-fake")
    );
}
