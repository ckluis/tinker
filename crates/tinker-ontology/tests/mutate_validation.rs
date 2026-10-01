//! Item 37 (C3): field validation + write presets.
//!
//! The governed mutation connector and its shared enforcement functions
//! (`apply_presets`, `validate_fields` — the single enforcement point used
//! by both the connector and any direct writer).
//!
//! Adversarial coverage: every rule kind, invalid rule definitions,
//! preset-before-required ordering, forced-preset overwrite of malicious
//! input, unknown-field bypass, sibling-org bypass with no existence
//! oracle, create/update paths, approval consume/replay/expiry/foreign,
//! audit atomicity, M4 evolution carriage, corrupt-metadata fail-closed,
//! and non-leaking error shapes.

use std::collections::HashMap;

use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::{
    mutate::{
        apply_presets, validate_fields, CreateRequest, MutationConnector, NoHooks, RecordingHooks,
        UpdateRequest,
    },
    FieldDef, FieldDescription, FieldType, ObjectDef, Ontology, PresetMode, PresetValue, Scope,
    ValidationRules, WritePreset,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Harness (mirrors the m0 common setup; self-contained, dev-only)
// ---------------------------------------------------------------------------

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

    // Item-37 migration must be applied: fail loudly if the metadata
    // columns the connector depends on are missing.
    let has_col: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_schema='public' AND table_name='ontology_fields' \
           AND column_name='validation_json')",
    )
    .fetch_one(&core_owner)
    .await
    .expect("schema probe");
    assert!(
        has_col,
        "migration 0038 (validation_json/preset_json) is not applied"
    );
    let has_audit: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema='public' AND table_name='mutation_audit')",
    )
    .fetch_one(&core_owner)
    .await
    .expect("schema probe");
    assert!(has_audit, "migration 0038 (mutation_audit) is not applied");

    let core = CoreDb::connect(&must_env("TINKER_CORE_URL"))
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

async fn new_org(env: &Env, slug: &str) -> TenantContext {
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "c3-test".to_string(),
    )
}

/// Last 8 hex chars of the v7 UUID — the first 8 are the timestamp and
/// identical for tests started in the same millisecond.
fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{}_{}", prefix, &s[24..32])
}

fn ontology(env: &Env) -> Ontology {
    Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()))
}

fn connector(env: &Env) -> MutationConnector {
    MutationConnector::new(env.core.clone(), ontology(env))
}

fn field(
    api_name: &str,
    ft: FieldType,
    required: bool,
    validation: ValidationRules,
    preset: Option<WritePreset>,
) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        validation,
        preset,
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type: ft,
        options: serde_json::json!({}),
        required,
    }
}

fn rules(
    min: Option<f64>,
    max: Option<f64>,
    pattern: Option<&str>,
    options: Option<Vec<&str>>,
) -> ValidationRules {
    ValidationRules {
        min,
        max,
        pattern: pattern.map(|s| s.to_string()),
        options: options.map(|o| o.into_iter().map(|s| s.to_string()).collect()),
    }
}

fn preset_static(mode: PresetMode, value: serde_json::Value) -> WritePreset {
    WritePreset {
        mode,
        value: PresetValue::Static { value },
    }
}

/// The governed test object. `region` is required AND has a WhenMissing
/// preset (preset-before-required ordering); `owner_ref` is Always forced
/// to the actor id (malicious overwrite test).
async fn governed_object(env: &Env, ctx: &TenantContext) -> Uuid {
    let ont = ontology(env);
    let slug = uniq("valobj");
    let meta = ont
        .define_object(
            ctx,
            &ObjectDef {
                name: "Validation Target".into(),
                api_slug: slug,
                label: "Validation Target".into(),
                scope: Scope::Organization,
                pack_id: None,
                pack_version: None,
            },
        )
        .await
        .unwrap();
    let fields = vec![
        field(
            "name",
            FieldType::Text,
            true,
            rules(None, None, None, None),
            None,
        ),
        field(
            "age",
            FieldType::Number,
            false,
            rules(Some(0.0), Some(130.0), None, None),
            None,
        ),
        field(
            "code",
            FieldType::Text,
            false,
            rules(None, None, Some("^[A-Z]{3}-[0-9]{4}$"), None),
            None,
        ),
        field(
            "stage",
            FieldType::Text,
            false,
            rules(None, None, None, Some(vec!["seed", "series_a"])),
            None,
        ),
        field(
            "nickname",
            FieldType::Text,
            false,
            rules(Some(2.0), Some(8.0), None, None),
            None,
        ),
        field(
            "region",
            FieldType::Text,
            true,
            rules(None, None, None, None),
            Some(preset_static(
                PresetMode::WhenMissing,
                serde_json::json!("emea"),
            )),
        ),
        field(
            "owner_ref",
            FieldType::Text,
            false,
            rules(None, None, None, None),
            Some(WritePreset {
                mode: PresetMode::Always,
                value: PresetValue::ActorId,
            }),
        ),
    ];
    for f in &fields {
        ont.add_field(ctx, meta.id, f).await.unwrap();
    }
    meta.id
}

fn values(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn j(s: &str) -> serde_json::Value {
    serde_json::json!(s)
}

fn desc(
    api: &str,
    ft: &str,
    required: bool,
    validation: ValidationRules,
    preset: Option<WritePreset>,
) -> FieldDescription {
    FieldDescription {
        id: Uuid::nil(),
        physical_column: format!("f_{api}"),
        api_name: api.into(),
        label: api.into(),
        field_type: ft.into(),
        options_json: serde_json::json!({}),
        relation_target_id: None,
        extension_table: None,
        validation,
        preset,
        required,
        max_pii_class: "restricted".to_string(),
    }
}

fn is_validation(err: &TinkerError) -> bool {
    matches!(err, TinkerError::Validation(_))
}

fn err_text(err: &TinkerError) -> String {
    format!("{err:?}")
}

// ---------------------------------------------------------------------------
// Pure-function tests: the shared enforcement point (no DB)
// ---------------------------------------------------------------------------

#[test]
fn preset_when_missing_fills_only_where_it_should() {
    let fields = vec![desc(
        "region",
        "text",
        true,
        ValidationRules::default(),
        Some(preset_static(
            PresetMode::WhenMissing,
            serde_json::json!("emea"),
        )),
    )];
    let actor = Uuid::now_v7();

    // Create: absent key gets the preset.
    let out = apply_presets(&fields, &HashMap::new(), actor, true);
    assert_eq!(out.get("region"), Some(&serde_json::json!("emea")));

    // Create: explicit null gets the preset too.
    let out = apply_presets(
        &fields,
        &values(&[("region", serde_json::Value::Null)]),
        actor,
        true,
    );
    assert_eq!(out.get("region"), Some(&serde_json::json!("emea")));

    // Create: writer value wins.
    let out = apply_presets(&fields, &values(&[("region", j("apac"))]), actor, true);
    assert_eq!(out.get("region"), Some(&j("apac")));

    // Update: absent means "don't touch" — no preset injection.
    let out = apply_presets(&fields, &HashMap::new(), actor, false);
    assert!(!out.contains_key("region"));

    // Update: explicit null IS backfilled (writer asked to clear it).
    let out = apply_presets(
        &fields,
        &values(&[("region", serde_json::Value::Null)]),
        actor,
        false,
    );
    assert_eq!(out.get("region"), Some(&serde_json::json!("emea")));
}

#[test]
fn preset_always_overwrites_writer_input() {
    let fields = vec![desc(
        "owner_ref",
        "text",
        false,
        ValidationRules::default(),
        Some(WritePreset {
            mode: PresetMode::Always,
            value: PresetValue::ActorId,
        }),
    )];
    let actor = Uuid::now_v7();
    let attacker = Uuid::now_v7();

    // Even a deliberately hostile value is replaced.
    let out = apply_presets(
        &fields,
        &values(&[("owner_ref", j(&attacker.to_string()))]),
        actor,
        true,
    );
    assert_eq!(out.get("owner_ref"), Some(&j(&actor.to_string())));

    // Same on update.
    let out = apply_presets(
        &fields,
        &values(&[("owner_ref", j(&attacker.to_string()))]),
        actor,
        false,
    );
    assert_eq!(out.get("owner_ref"), Some(&j(&actor.to_string())));
}

#[test]
fn validation_collects_all_violations_in_field_order() {
    let fields = vec![
        desc("name", "text", true, ValidationRules::default(), None),
        desc(
            "age",
            "number",
            false,
            rules(Some(0.0), Some(130.0), None, None),
            None,
        ),
        desc(
            "code",
            "text",
            false,
            rules(None, None, Some("^[A-Z]{3}-[0-9]{4}$"), None),
            None,
        ),
    ];
    let err = validate_fields(
        &fields,
        &values(&[
            ("age", serde_json::json!(-5)),
            ("code", j("nope")),
            // name missing entirely
        ]),
        true,
    )
    .unwrap_err();
    assert!(is_validation(&err));
    let text = err_text(&err);
    // All three violations, in field-definition order, one round trip.
    let name_pos = text.find("'name'").unwrap();
    let age_pos = text.find("'age'").unwrap();
    let code_pos = text.find("'code'").unwrap();
    assert!(name_pos < age_pos && age_pos < code_pos, "{text}");
}

#[test]
fn validation_rejects_unknown_fields() {
    let fields = vec![desc(
        "name",
        "text",
        false,
        ValidationRules::default(),
        None,
    )];
    let err = validate_fields(
        &fields,
        &values(&[("name", j("x")), ("__proto__", j("1"))]),
        true,
    )
    .unwrap_err();
    assert!(is_validation(&err));
    assert!(err_text(&err).contains("unknown field '__proto__'"));
}

#[test]
fn validation_pattern_requires_full_match() {
    let fields = vec![desc(
        "code",
        "text",
        false,
        rules(None, None, Some("[0-9]+"), None),
        None,
    )];
    // A partial match is NOT a match: the pattern must describe the whole value.
    assert!(is_validation(
        &validate_fields(&fields, &values(&[("code", j("abc123"))]), true).unwrap_err()
    ));
    assert!(validate_fields(&fields, &values(&[("code", j("123"))]), true).is_ok());
}

#[test]
fn validation_length_rules_use_characters() {
    let fields = vec![desc(
        "nickname",
        "text",
        false,
        rules(Some(2.0), Some(8.0), None, None),
        None,
    )];
    assert!(is_validation(
        &validate_fields(&fields, &values(&[("nickname", j("x"))]), true).unwrap_err()
    ));
    assert!(is_validation(
        &validate_fields(&fields, &values(&[("nickname", j("waytoolongname"))]), true).unwrap_err()
    ));
    assert!(validate_fields(&fields, &values(&[("nickname", j("ren"))]), true).is_ok());
}

#[test]
fn validation_required_rejects_empty_string_and_update_null() {
    let fields = vec![desc("name", "text", true, ValidationRules::default(), None)];
    assert!(is_validation(
        &validate_fields(&fields, &values(&[("name", j(""))]), true).unwrap_err()
    ));
    // On update, absent is fine ("don't touch") but explicit null fails.
    assert!(validate_fields(&fields, &HashMap::new(), false).is_ok());
    assert!(is_validation(
        &validate_fields(
            &fields,
            &values(&[("name", serde_json::Value::Null)]),
            false
        )
        .unwrap_err()
    ));
}

#[test]
fn validation_type_mismatch_fails_with_field_name() {
    let fields = vec![desc(
        "age",
        "number",
        false,
        ValidationRules::default(),
        None,
    )];
    let err = validate_fields(&fields, &values(&[("age", j("old"))]), true).unwrap_err();
    assert!(is_validation(&err));
    assert!(err_text(&err).contains("'age'"));
}

// ---------------------------------------------------------------------------
// Definition-time: incoherent rules are rejected when the field is defined
// ---------------------------------------------------------------------------

#[tokio::test]
async fn definition_rejects_incoherent_rules() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let ont = ontology(&env);
    let slug = uniq("defchk");
    let meta = ont
        .define_object(
            &ctx,
            &ObjectDef {
                name: "Def Check".into(),
                api_slug: slug,
                label: "Def Check".into(),
                scope: Scope::Organization,
                pack_id: None,
                pack_version: None,
            },
        )
        .await
        .unwrap();

    // min > max
    let err = ont
        .add_field(
            &ctx,
            meta.id,
            &field(
                "bad_range",
                FieldType::Number,
                false,
                rules(Some(10.0), Some(5.0), None, None),
                None,
            ),
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");

    // regex on a non-textual field
    let err = ont
        .add_field(
            &ctx,
            meta.id,
            &field(
                "bad_kind",
                FieldType::Number,
                false,
                rules(None, None, Some("^[0-9]+$"), None),
                None,
            ),
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");

    // syntactically invalid regex
    let err = ont
        .add_field(
            &ctx,
            meta.id,
            &field(
                "bad_regex",
                FieldType::Text,
                false,
                rules(None, None, Some("([unclosed"), None),
                None,
            ),
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");

    // min/max on a boolean
    let err = ont
        .add_field(
            &ctx,
            meta.id,
            &field(
                "bad_bool",
                FieldType::Boolean,
                false,
                rules(Some(0.0), None, None, None),
                None,
            ),
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");

    // explicitly empty options
    let err = ont
        .add_field(
            &ctx,
            meta.id,
            &field(
                "bad_opts",
                FieldType::Text,
                false,
                rules(None, None, None, Some(vec![])),
                None,
            ),
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");
}

// ---------------------------------------------------------------------------
// Create path
// ---------------------------------------------------------------------------

async fn read_record_raw(env: &Env, slug: &str, record_id: Uuid) -> serde_json::Value {
    // Owner pool: the test reads what the tenant wrote. Keys are physical
    // column names here.
    let row: (serde_json::Value,) = sqlx::query_as(&format!(
        "SELECT to_jsonb(t) FROM data.{slug} t WHERE id = $1"
    ))
    .bind(record_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    row.0
}

/// The same row keyed by api_name, via the field description.
async fn read_record(
    env: &Env,
    ctx: &TenantContext,
    object_id: Uuid,
    slug: &str,
    record_id: Uuid,
) -> HashMap<String, serde_json::Value> {
    let ont = ontology(env);
    let desc = ont.describe_object(ctx, object_id).await.unwrap();
    let raw = read_record_raw(env, slug, record_id).await;
    let obj = raw.as_object().unwrap();
    desc.fields
        .iter()
        .map(|f| {
            (
                f.api_name.clone(),
                obj.get(&f.physical_column)
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

#[tokio::test]
async fn create_applies_preset_before_required_validation() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    // `region` is required but has a WhenMissing preset: the preset fills
    // it, so validation passes. Without the preset this would fail.
    let out = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap();
    assert_eq!(out.version, 1);

    let row = read_record(
        &env,
        &ctx,
        object_id,
        &object_slug(&env, &ctx, object_id).await,
        out.record_id,
    )
    .await;
    assert_eq!(row["region"], serde_json::json!("emea"));
    assert_eq!(row["name"], serde_json::json!("Acme"));
    // The Always/ActorId preset resolved to the calling actor.
    assert_eq!(
        row["owner_ref"],
        serde_json::json!(ctx.actor_id.to_string())
    );
}

async fn object_slug(env: &Env, _ctx: &TenantContext, object_id: Uuid) -> String {
    let slug: (String,) = sqlx::query_as("SELECT api_slug FROM ontology_objects WHERE id = $1")
        .bind(object_id)
        .fetch_one(&env.core_owner)
        .await
        .unwrap();
    slug.0
}

#[tokio::test]
async fn create_rejects_each_rule_kind() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    // (values, field expected in the error)
    let cases: Vec<(Vec<(&str, serde_json::Value)>, &str)> = vec![
        (vec![("age", serde_json::json!(-1))], "'age'"), // below min
        (vec![("age", serde_json::json!(200))], "'age'"), // above max
        (vec![("code", j("abc-1234"))], "'code'"),       // pattern
        (vec![("stage", j("bogus"))], "'stage'"),        // options
        (vec![("nickname", j("x"))], "'nickname'"),      // too short
        (vec![], "'name'"), // required missing (region preset covers region)
    ];
    for (vals, field) in cases {
        let mut v = values(&vals);
        // name is required: supply it unless this case is about name itself.
        if !v.contains_key("name") && field != "'name'" {
            v.insert("name".into(), j("Acme"));
        }
        let err = conn
            .create(
                &ctx,
                &CreateRequest {
                    object_id,
                    values: v,
                    require_approval: false,
                    approval_request_id: None,
                },
                &hooks,
            )
            .await
            .unwrap_err();
        assert!(is_validation(&err), "case {field}: {err:?}");
        assert!(
            err_text(&err).contains(field),
            "case {field}: error names the field: {err:?}"
        );
    }
}

#[tokio::test]
async fn create_forced_preset_overwrites_malicious_owner() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    // The writer tries to claim someone else's identity as owner_ref.
    let attacker = Uuid::now_v7();
    let out = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme")), ("owner_ref", j(&attacker.to_string()))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap();
    let row = read_record(
        &env,
        &ctx,
        object_id,
        &object_slug(&env, &ctx, object_id).await,
        out.record_id,
    )
    .await;
    assert_eq!(
        row["owner_ref"],
        serde_json::json!(ctx.actor_id.to_string()),
        "forced preset must overwrite the writer's hostile value"
    );
}

#[tokio::test]
async fn create_rejects_unknown_field_and_type_mismatch() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    let err = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme")), ("is_admin", serde_json::json!(true))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err));
    assert!(err_text(&err).contains("unknown field 'is_admin'"));

    // A type mismatch fails as validation with the field named — never as
    // a raw Postgres error.
    let err = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme")), ("age", j("old"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");
    assert!(err_text(&err).contains("'age'"));
}

#[tokio::test]
async fn create_writes_audit_with_post_preset_values() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    let out = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme")), ("age", serde_json::json!(42))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap();

    let row: (
        String,
        Uuid,
        Option<serde_json::Value>,
        serde_json::Value,
        Option<Uuid>,
    ) = sqlx::query_as(
        "SELECT operation, actor_id, before_json, after_json, approval_request_id \
             FROM mutation_audit WHERE organization_id = $1 AND object_id = $2 AND record_id = $3",
    )
    .bind(ctx.organization_id.0)
    .bind(object_id)
    .bind(out.record_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(row.0, "create");
    assert_eq!(row.1, ctx.actor_id);
    assert!(row.2.is_none());
    // The audit trail records the merged values — post-preset.
    assert_eq!(row.3["region"], serde_json::json!("emea"));
    assert_eq!(row.3["name"], serde_json::json!("Acme"));
    assert_eq!(
        row.3["owner_ref"],
        serde_json::json!(ctx.actor_id.to_string())
    );
    assert!(row.4.is_none());
}

#[tokio::test]
async fn failed_create_writes_no_audit_row() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    let before: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM mutation_audit WHERE organization_id = $1")
            .bind(ctx.organization_id.0)
            .fetch_one(&env.core_owner)
            .await
            .unwrap();
    let err = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme")), ("age", serde_json::json!(-3))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err));
    let after: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM mutation_audit WHERE organization_id = $1")
            .bind(ctx.organization_id.0)
            .fetch_one(&env.core_owner)
            .await
            .unwrap();
    assert_eq!(
        before.0, after.0,
        "a rejected mutation must leave no audit row"
    );
}

// ---------------------------------------------------------------------------
// Update path
// ---------------------------------------------------------------------------

async fn seed_record(env: &Env, ctx: &TenantContext, object_id: Uuid) -> Uuid {
    let conn = connector(env);
    let out = conn
        .create(
            ctx,
            &CreateRequest {
                object_id,
                values: values(&[
                    ("name", j("Acme")),
                    ("age", serde_json::json!(42)),
                    ("region", j("apac")),
                ]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();
    out.record_id
}

#[tokio::test]
async fn update_partial_keeps_untouched_fields_and_bumps_version() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let record_id = seed_record(&env, &ctx, object_id).await;
    let conn = connector(&env);
    let slug = object_slug(&env, &ctx, object_id).await;

    let out = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id,
                record_id,
                values: values(&[("age", serde_json::json!(43))]),
                expected_version: Some(1),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();
    assert_eq!(out.record_id, record_id);
    assert_eq!(out.version, 2);

    let row = read_record(&env, &ctx, object_id, &slug, record_id).await;
    assert_eq!(row["age"], serde_json::json!(43));
    // Absent on update means "don't touch" — even for required fields.
    assert_eq!(row["name"], serde_json::json!("Acme"));
    assert_eq!(row["region"], serde_json::json!("apac"));

    // The audit row carries the before-image from the locked row.
    let audit: (String, Option<serde_json::Value>, serde_json::Value) = sqlx::query_as(
        "SELECT operation, before_json, after_json FROM mutation_audit \
         WHERE organization_id = $1 AND record_id = $2 AND operation = 'update'",
    )
    .bind(ctx.organization_id.0)
    .bind(record_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(audit.0, "update");
    assert_eq!(audit.1.unwrap()["age"], serde_json::json!(42));
    assert_eq!(audit.2["age"], serde_json::json!(43));
}

#[tokio::test]
async fn update_explicit_null_on_required_fails() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let record_id = seed_record(&env, &ctx, object_id).await;
    let conn = connector(&env);

    let err = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id,
                record_id,
                values: values(&[("name", serde_json::Value::Null)]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");
    assert!(err_text(&err).contains("'name'"));
}

#[tokio::test]
async fn update_validates_values_like_create() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let record_id = seed_record(&env, &ctx, object_id).await;
    let conn = connector(&env);

    // Same rule engine, same errors, on the update path.
    let err = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id,
                record_id,
                values: values(&[("code", j("nope")), ("stage", j("bogus"))]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err));
    let text = err_text(&err);
    assert!(
        text.contains("'code'") && text.contains("'stage'"),
        "{text}"
    );
}

#[tokio::test]
async fn update_explicit_null_clears_optional_field() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let record_id = seed_record(&env, &ctx, object_id).await;
    let conn = connector(&env);
    let slug = object_slug(&env, &ctx, object_id).await;

    // Optional nickname -> set, then explicitly clear to NULL.
    conn.update(
        &ctx,
        &UpdateRequest {
            object_id,
            record_id,
            values: values(&[("nickname", j("Amy"))]),
            expected_version: None,
            require_approval: false,
            approval_request_id: None,
        },
        &NoHooks,
    )
    .await
    .unwrap();
    let out = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id,
                record_id,
                values: values(&[("nickname", serde_json::Value::Null)]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();
    assert_eq!(out.version, 3);
    let row = read_record(&env, &ctx, object_id, &slug, record_id).await;
    assert_eq!(row["nickname"], serde_json::Value::Null);
    // Untouched fields keep their values.
    assert_eq!(row["age"], serde_json::json!(42));

    // WhenMissing preset re-fills an explicit null instead of clearing.
    let err = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id,
                record_id,
                values: values(&[("region", serde_json::Value::Null)]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();
    let _ = err;
    let row = read_record(&env, &ctx, object_id, &slug, record_id).await;
    assert_eq!(row["region"], serde_json::json!("emea"));
}

#[tokio::test]
async fn numeric_values_keep_decimal_precision() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let slug = object_slug(&env, &ctx, object_id).await;

    // 29.99 must not come back as 29.98999999999999488... (f64 artifact):
    // the connector parses the JSON number's decimal text directly.
    let mut vals = values(&[("name", j("Precision"))]);
    vals.insert("age".into(), serde_json::json!(29.99));
    let out = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: vals,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();
    let age_text: (String,) = {
        let ont = ontology(&env);
        let desc = ont.describe_object(&ctx, object_id).await.unwrap();
        let phys = desc
            .fields
            .iter()
            .find(|f| f.api_name == "age")
            .unwrap()
            .physical_column
            .clone();
        sqlx::query_as(&format!(
            "SELECT {phys}::text FROM data.{slug} WHERE id = $1"
        ))
        .bind(out.record_id)
        .fetch_one(&env.core_owner)
        .await
        .unwrap()
    };
    assert_eq!(age_text.0, "29.99");
}

#[tokio::test]
async fn update_empty_write_is_rejected() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let ont = ontology(&env);
    // A preset-free object: with no Always presets firing, an empty update
    // has nothing to write and is rejected rather than no-op bumping.
    let slug = uniq("bareobj");
    let meta = ont
        .define_object(
            &ctx,
            &ObjectDef {
                name: "Bare".into(),
                api_slug: slug,
                label: "Bare".into(),
                scope: Scope::Organization,
                pack_id: None,
                pack_version: None,
            },
        )
        .await
        .unwrap();
    ont.add_field(
        &ctx,
        meta.id,
        &field(
            "name",
            FieldType::Text,
            true,
            rules(None, None, None, None),
            None,
        ),
    )
    .await
    .unwrap();
    let conn = connector(&env);
    let out = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id: meta.id,
                values: values(&[("name", j("Acme"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();

    let err = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id: meta.id,
                record_id: out.record_id,
                values: HashMap::new(),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(is_validation(&err), "{err:?}");
    assert!(err_text(&err).contains("no values to write"));
}

#[tokio::test]
async fn update_stale_version_conflicts() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let record_id = seed_record(&env, &ctx, object_id).await;
    let conn = connector(&env);

    let err = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id,
                record_id,
                values: values(&[("age", serde_json::json!(44))]),
                expected_version: Some(99),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    match &err {
        TinkerError::Conflict {
            expected, current, ..
        } => {
            assert_eq!(*expected, 99);
            assert_eq!(*current, 1);
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
    // The failed optimistic write left no audit row and bumped nothing.
    let slug = object_slug(&env, &ctx, object_id).await;
    let row = read_record_raw(&env, &slug, record_id).await;
    assert_eq!(row["version"], serde_json::json!(1));
}

#[tokio::test]
async fn update_unknown_record_is_not_found_without_leak() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);

    let ghost = Uuid::now_v7();
    let err = conn
        .update(
            &ctx,
            &UpdateRequest {
                object_id,
                record_id: ghost,
                values: values(&[("age", serde_json::json!(44))]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "{err:?}");
    // The error names only what the caller already supplied.
    assert!(
        !err_text(&err).contains(&ctx.organization_id.0.to_string()),
        "org id must not leak: {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Tenant isolation: no cross-org reads, writes, or existence oracles
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sibling_org_object_id_is_not_found_not_forbidden() {
    let env = setup().await;
    let ctx_a = new_org(&env, &uniq("org")).await;
    let ctx_b = new_org(&env, &uniq("org")).await;
    let object_b = governed_object(&env, &ctx_b).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    // Org A probing org B's object id: NotFound, exactly like a random id.
    let err_b = conn
        .create(
            &ctx_a,
            &CreateRequest {
                object_id: object_b,
                values: values(&[("name", j("Acme"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap_err();
    let err_random = conn
        .create(
            &ctx_a,
            &CreateRequest {
                object_id: Uuid::now_v7(),
                values: values(&[("name", j("Acme"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err_b, TinkerError::NotFound(_)), "{err_b:?}");
    assert!(
        matches!(err_random, TinkerError::NotFound(_)),
        "{err_random:?}"
    );
    // Same error SHAPE: no oracle distinguishing "exists elsewhere".
    assert_eq!(
        std::mem::discriminant(&err_b),
        std::mem::discriminant(&err_random)
    );
}

#[tokio::test]
async fn sibling_org_record_id_is_not_found_on_update() {
    let env = setup().await;
    let ctx_a = new_org(&env, &uniq("org")).await;
    let ctx_b = new_org(&env, &uniq("org")).await;
    // Same slug family, different orgs: distinct objects, distinct rows.
    let object_a = governed_object(&env, &ctx_a).await;
    let object_b = governed_object(&env, &ctx_b).await;
    let record_b = seed_record(&env, &ctx_b, object_b).await;
    let conn = connector(&env);

    // Org A cannot update org B's record through its own object...
    let err = conn
        .update(
            &ctx_a,
            &UpdateRequest {
                object_id: object_a,
                record_id: record_b,
                values: values(&[("age", serde_json::json!(1))]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "{err:?}");

    // ...nor through org B's object id (which is itself invisible to A).
    let err = conn
        .update(
            &ctx_a,
            &UpdateRequest {
                object_id: object_b,
                record_id: record_b,
                values: values(&[("age", serde_json::json!(1))]),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// Post-commit hooks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn hooks_fire_once_per_committed_mutation_only() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = RecordingHooks::default();

    let out = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap();
    conn.update(
        &ctx,
        &UpdateRequest {
            object_id,
            record_id: out.record_id,
            values: values(&[("age", serde_json::json!(7))]),
            expected_version: None,
            require_approval: false,
            approval_request_id: None,
        },
        &hooks,
    )
    .await
    .unwrap();
    // A rejected mutation must not fan out.
    let _ = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme")), ("age", serde_json::json!(-1))]),
                require_approval: false,
                approval_request_id: None,
            },
            &hooks,
        )
        .await
        .unwrap_err();

    let calls = hooks.calls.lock().unwrap();
    assert_eq!(calls.len(), 2, "exactly one fan-out per committed mutation");
    assert_eq!(calls[0].0, ctx.organization_id.0);
    assert_eq!(calls[0].1, object_id);
    assert_eq!(calls[0].2, vec![out.record_id]);
    assert_eq!(calls[1].2, vec![out.record_id]);
}

// ---------------------------------------------------------------------------
// Approvals: atomic consumption, no replay, no cross-tenant use
// ---------------------------------------------------------------------------

async fn mk_approval(
    env: &Env,
    ctx: &TenantContext,
    status: &str,
    expires_in_hours: Option<i64>,
) -> Uuid {
    // RLS is FORCEd on these tables, so even the owner pool cannot insert:
    // create actor + attachment + request inside a tenant-scoped tx (the
    // same pattern the tinker-agents approval tests use).
    let mut tx = env.core.tenant_tx(ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) \
         VALUES ($1,$2,'c3 actor',$3) ON CONFLICT (id) DO NOTHING",
    )
    .bind(ctx.actor_id)
    .bind(ctx.organization_id.0)
    .bind(format!("c3-{}", ctx.actor_id.simple()))
    .execute(&mut *tx)
    .await
    .unwrap();
    let att: (Uuid,) = sqlx::query_as(
        "INSERT INTO agent_attachments (organization_id, actor_id, name, kind) \
         VALUES ($1,$2,'c3-fixture','test') RETURNING id",
    )
    .bind(ctx.organization_id.0)
    .bind(ctx.actor_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let id = Uuid::now_v7();
    let expires_at: Option<chrono::DateTime<chrono::Utc>> =
        expires_in_hours.map(|h| chrono::Utc::now() + chrono::Duration::hours(h));
    sqlx::query(
        "INSERT INTO approval_requests \
         (id, organization_id, attachment_id, action_name, payload, idempotency_key, status, expires_at) \
         VALUES ($1,$2,$3,'record.write','{}',$4,$5,$6)",
    )
    .bind(id)
    .bind(ctx.organization_id.0)
    .bind(att.0)
    .bind(format!("c3-{id}"))
    .bind(status)
    .bind(expires_at)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

async fn approval_status(env: &Env, ctx: &TenantContext, id: Uuid) -> String {
    // RLS is forced on approval_requests: read through the tenant tx.
    let mut tx = env.core.tenant_tx(ctx).await.unwrap();
    let s: (String,) = sqlx::query_as("SELECT status FROM approval_requests WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    s.0
}

#[tokio::test]
async fn approval_is_consumed_atomically_and_not_replayable() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    let approval = mk_approval(&env, &ctx, "approved", None).await;
    let out = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme"))]),
                require_approval: true,
                approval_request_id: Some(approval),
            },
            &hooks,
        )
        .await
        .unwrap();

    // Consumed in the same transaction as the write.
    assert_eq!(approval_status(&env, &ctx, approval).await, "executed");
    let audit_approval: (Option<Uuid>,) = sqlx::query_as(
        "SELECT approval_request_id FROM mutation_audit \
         WHERE organization_id = $1 AND record_id = $2",
    )
    .bind(ctx.organization_id.0)
    .bind(out.record_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(audit_approval.0, Some(approval));

    // Replay: the same approval can never authorize a second mutation.
    let err = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme2"))]),
                require_approval: true,
                approval_request_id: Some(approval),
            },
            &hooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "{err:?}");
    // And the replay left no audit row behind.
    let n: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM mutation_audit WHERE organization_id = $1 AND after_json->>'name' = 'Acme2'",
    )
    .bind(ctx.organization_id.0)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(n.0, 0);
}

#[tokio::test]
async fn approval_pending_denied_and_expired_are_rejected() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);
    let hooks = NoHooks;

    for (status, expiry) in [
        ("pending", None),
        ("denied", None),
        ("approved", Some(-1)), // approved but past its deadline
    ] {
        let approval = mk_approval(&env, &ctx, status, expiry).await;
        let err = conn
            .create(
                &ctx,
                &CreateRequest {
                    object_id,
                    values: values(&[("name", j("Acme"))]),
                    require_approval: true,
                    approval_request_id: Some(approval),
                },
                &hooks,
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, TinkerError::Forbidden(_)),
            "status={status} expiry={expiry:?}: {err:?}"
        );
        // Rejected approvals are not consumed.
        let after = approval_status(&env, &ctx, approval).await;
        assert!(
            after == status || (status == "approved" && after == "expired"),
            "status={status}: left as {after}"
        );
    }
}

#[tokio::test]
async fn approval_required_without_id_is_rejected() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let conn = connector(&env);

    let err = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme"))]),
                require_approval: true,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "{err:?}");
}

#[tokio::test]
async fn approval_from_sibling_org_cannot_be_consumed() {
    let env = setup().await;
    let ctx_a = new_org(&env, &uniq("org")).await;
    let ctx_b = new_org(&env, &uniq("org")).await;
    let object_a = governed_object(&env, &ctx_a).await;
    let conn = connector(&env);

    // Org B's approved request, presented by org A.
    let approval_b = mk_approval(&env, &ctx_b, "approved", None).await;
    let err = conn
        .create(
            &ctx_a,
            &CreateRequest {
                object_id: object_a,
                values: values(&[("name", j("Acme"))]),
                require_approval: true,
                approval_request_id: Some(approval_b),
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "{err:?}");
    // Org B's approval is untouched — the probe consumed nothing.
    assert_eq!(approval_status(&env, &ctx_b, approval_b).await, "approved");
}

// ---------------------------------------------------------------------------
// Corrupt metadata fails closed at read time
// ---------------------------------------------------------------------------

#[tokio::test]
async fn corrupt_validation_metadata_fails_closed_on_read() {
    let env = setup().await;
    let ctx = new_org(&env, &uniq("org")).await;
    let object_id = governed_object(&env, &ctx).await;
    let ont = ontology(&env);

    // Sanity: reads fine before corruption.
    assert!(ont.describe_object(&ctx, object_id).await.is_ok());

    // Simulate tampering below the API: a rule that cannot deserialize.
    sqlx::query(
        "UPDATE ontology_fields SET validation_json = '{\"min\": \"not-a-number\"}' \
         WHERE object_id = $1 AND api_name = 'age'",
    )
    .bind(object_id)
    .execute(&env.core_owner)
    .await
    .unwrap();

    let err = ont.describe_object(&ctx, object_id).await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Internal(_)),
        "corrupt rules must fail closed, not silently drop enforcement: {err:?}"
    );

    // And the connector refuses to write through the corrupt description.
    let conn = connector(&env);
    let err = conn
        .create(
            &ctx,
            &CreateRequest {
                object_id,
                values: values(&[("name", j("Acme"))]),
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Internal(_)), "{err:?}");
}
