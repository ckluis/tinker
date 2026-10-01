//! Automations over sealed fields, end to end (docs/automations.md).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tinker_automate::{
    Action, AutomationDef, AutomationEngine, CondOp, Condition, Trigger, WebhookPolicy,
};
use tinker_comms::FakeEmailProvider;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::mutate::{CreateRequest, MutationConnector, NoHooks, UpdateRequest};
use tinker_ontology::sensitive::sealer_from_env;
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope, ValidationRules};
use tokio::sync::OnceCell;
use uuid::Uuid;

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

static MIGRATED: OnceCell<()> = OnceCell::const_new();

struct World {
    core: CoreDb,
    owner: OwnerDb,
    org: Uuid,
    admin: TenantContext,
    member: TenantContext,
    object_id: Uuid,
    slug: String,
}

async fn world() -> World {
    let owner_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    MIGRATED
        .get_or_init(|| async {
            tinker_db::MIGRATOR_CORE.run(&owner_pool).await.unwrap();
            let pii = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
                .await
                .unwrap();
            tinker_db::MIGRATOR_PII.run(&pii).await.unwrap();
        })
        .await;
    let core = CoreDb::connect(&env("TINKER_CORE_URL")).await.unwrap();
    let owner = OwnerDb(owner_pool.clone());
    let host = Uuid::from_u128(0);
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,'test') ON CONFLICT (id) DO NOTHING")
        .bind(host)
        .execute(&owner_pool)
        .await
        .unwrap();
    let org = Uuid::now_v7();
    let tag = &Uuid::now_v7().simple().to_string()[20..32];
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org)
        .bind(host)
        .bind(format!("auto{tag}"))
        .execute(&owner_pool)
        .await
        .unwrap();
    let actor = |role: &'static str| {
        let pool = owner_pool.clone();
        async move {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1,$2,$3,$4)",
            )
                .bind(id)
                .bind(org)
                .bind(role)
                .bind(format!("{role}-{}", &id.simple().to_string()[20..]))
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,$3)",
            )
            .bind(id)
            .bind(org)
            .bind(role)
            .execute(&pool)
            .await
            .unwrap();
            TenantContext::new(OrganizationId(org), id, "automation-test")
        }
    };
    let admin = actor("admin").await;
    let member = actor("member").await;
    let ont = Ontology::new(core.clone(), owner.clone());
    let slug = format!("lead{tag}");
    let meta = ont
        .define_object(
            &admin,
            &ObjectDef {
                name: slug.clone(),
                api_slug: slug.clone(),
                label: slug.clone(),
                scope: Scope::Organization,
                pack_id: None,
                pack_version: None,
            },
        )
        .await
        .unwrap();
    for (api, ty) in [
        ("name", FieldType::Text),
        ("tier", FieldType::Text),
        ("email", FieldType::Email),
        ("score", FieldType::Number),
    ] {
        ont.add_field(
            &admin,
            meta.id,
            &FieldDef {
                name: api.into(),
                api_name: api.into(),
                label: api.into(),
                field_type: ty,
                options: json!({}),
                required: false,
                validation: ValidationRules::default(),
                preset: None,
                max_pii_class: "none".into(),
                sensitive: false,
            },
        )
        .await
        .unwrap();
    }
    World {
        core,
        owner,
        org,
        admin,
        member,
        object_id: meta.id,
        slug,
    }
}

async fn engine(w: &World) -> AutomationEngine {
    let sealer = sealer_from_env()
        .await
        .unwrap()
        .expect("PII vault env must be set");
    AutomationEngine::new(w.core.clone(), w.owner.clone(), Some(sealer))
}

async fn mutator(w: &World) -> MutationConnector {
    let sealer = sealer_from_env().await.unwrap().unwrap();
    MutationConnector::new(
        w.core.clone(),
        Ontology::new(w.core.clone(), w.owner.clone()),
    )
    .with_pii(sealer)
}

async fn create(w: &World, values: Value) -> Uuid {
    let values: HashMap<String, Value> = serde_json::from_value(values).unwrap();
    mutator(w)
        .await
        .create(
            &w.admin,
            &CreateRequest {
                object_id: w.object_id,
                values,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap()
        .record_id
}

async fn field_value(w: &World, record: Uuid, api: &str) -> Value {
    let phys: String = sqlx::query_scalar(
        "SELECT physical_column FROM ontology_fields WHERE object_id = $1 AND api_name = $2",
    )
    .bind(w.object_id)
    .bind(api)
    .fetch_one(&w.owner.0)
    .await
    .unwrap();
    sqlx::query_scalar::<_, Option<Value>>(&format!(
        "SELECT to_jsonb(\"{phys}\") FROM data.{} WHERE id = $1",
        w.slug
    ))
    .bind(record)
    .fetch_one(&w.owner.0)
    .await
    .unwrap()
    .unwrap_or(Value::Null)
}

/// A local webhook receiver that records every JSON body it gets.
async fn receiver() -> (String, Arc<Mutex<Vec<Value>>>) {
    let got: Arc<Mutex<Vec<Value>>> = Default::default();
    let sink = got.clone();
    let app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |axum::Json(v): axum::Json<Value>| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(v);
                "ok"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("127.0.0.1:{}", addr.port()), got)
}

fn vip_def(w: &World, hook_url: &str) -> AutomationDef {
    AutomationDef {
        object_id: w.object_id,
        name: "VIP welcome".into(),
        trigger: Trigger::RecordCreated,
        conditions: vec![Condition {
            field: "email".into(),
            op: CondOp::Eq,
            value: Some(json!("ceo@acme.example")),
            keyed: false,
        }],
        actions: vec![
            Action::UpdateRecord {
                values: serde_json::from_value(json!({"tier": "vip"})).unwrap(),
            },
            Action::SendEmail {
                to_field: "email".into(),
                subject: "Welcome {{ name }}".into(),
                body: "Hi {{ name }} ({{ email }}), you are VIP.".into(),
            },
            Action::Webhook {
                url: hook_url.into(),
                fields: vec!["name".into(), "email".into()],
            },
        ],
    }
}

#[tokio::test]
async fn sealed_conditions_route_and_actions_resolve_only_at_send() {
    let w = world().await;
    let (host, hooks) = receiver().await;
    let provider = Arc::new(FakeEmailProvider::new());
    let eng = engine(&w)
        .await
        .with_email_provider(provider.clone())
        .with_webhook_policy(WebhookPolicy {
            allow_hosts: vec![host.clone()],
        });
    let saved = eng
        .save(&w.admin, vip_def(&w, &format!("http://{host}/hook")))
        .await
        .unwrap();
    // The definition holds a key, never the literal.
    let stored: Value = {
        let mut tx = w.core.tenant_tx(&w.admin).await.unwrap();
        let v = sqlx::query_scalar("SELECT conditions FROM automations WHERE id = $1")
            .bind(saved.id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        v
    };
    assert!(
        stored[0]["value"].as_str().unwrap().starts_with("pk_"),
        "{stored}"
    );
    assert!(!stored.to_string().contains("acme"), "{stored}");

    let vip = create(&w, json!({"name": "Dana", "email": " CEO@Acme.example"})).await;
    let other = create(&w, json!({"name": "Eli", "email": "eli@other.example"})).await;
    let stats = eng.run_pending_org(w.org, 100).await.unwrap();
    assert_eq!((stats.succeeded, stats.skipped), (1, 1), "{stats:?}");

    // Action 1: the record was updated as the author.
    assert_eq!(field_value(&w, vip, "tier").await, json!("vip"));
    assert_eq!(field_value(&w, other, "tier").await, Value::Null);

    // Action 2: the provider got the REAL address, resolved at send;
    // the body shows the sealed field masked; core never saw either.
    let runs = eng.runs(&w.admin, saved.id, 10).await.unwrap();
    let run = runs.iter().find(|r| r.record_id == vip).unwrap();
    assert_eq!(run.outcome, "succeeded");
    let key = run.detail["actions"][1]["idempotency_key"]
        .as_str()
        .unwrap();
    assert_eq!(
        provider.to_address_for(key).as_deref(),
        Some(" CEO@Acme.example")
    );
    let body = provider.body_for(key).unwrap();
    assert!(
        body.contains("Hi Dana (••••••)") && !body.contains("Acme"),
        "{body}"
    );
    let outbox: Vec<String> = {
        let mut tx = w.core.tenant_tx(&w.admin).await.unwrap();
        let v = sqlx::query_scalar(
            "SELECT payload_ref::text FROM delivery_outbox WHERE organization_id = $1",
        )
        .bind(w.org)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        v
    };
    assert!(
        outbox
            .iter()
            .all(|p| !p.contains("Acme") && !p.contains("acme")),
        "{outbox:?}"
    );

    // Action 3: the webhook got ids, non-sensitive values and the KEY.
    let posted = hooks.lock().unwrap().clone();
    assert_eq!(posted.len(), 1);
    assert_eq!(posted[0]["fields"]["name"], "Dana");
    let k = posted[0]["keys"]["email"].as_str().unwrap();
    assert!(k.starts_with("pk_"));
    assert_eq!(
        k,
        stored[0]["value"].as_str().unwrap(),
        "same key as the condition"
    );
    assert!(
        !posted[0].to_string().to_lowercase().contains("acme"),
        "{}",
        posted[0]
    );
    for r in &runs {
        assert!(
            !r.detail.to_string().to_lowercase().contains("acme"),
            "{:?}",
            r.detail
        );
    }

    // Idempotent: the update_record action's own write is one more event
    // (kind "updated", matching no created-trigger) — no run repeats.
    let again = eng.run_pending_org(w.org, 100).await.unwrap();
    assert_eq!(
        again.succeeded + again.skipped + again.failed,
        0,
        "{again:?}"
    );
    assert_eq!(eng.runs(&w.admin, saved.id, 10).await.unwrap().len(), 2);
}

#[tokio::test]
async fn saves_refuse_plaintext_paths_and_non_managers() {
    let w = world().await;
    let eng = engine(&w).await;
    let base = |conditions: Vec<Condition>, actions: Vec<Action>| AutomationDef {
        object_id: w.object_id,
        name: "x".into(),
        trigger: Trigger::RecordCreated,
        conditions,
        actions,
    };
    let tag = || Action::UpdateRecord {
        values: serde_json::from_value(json!({"tier": "t"})).unwrap(),
    };
    let cond = |op, value: Option<Value>| Condition {
        field: "email".into(),
        op,
        value,
        keyed: false,
    };
    for (label, def) in [
        (
            "contains on sealed",
            base(
                vec![cond(CondOp::Contains, Some(json!("acme")))],
                vec![tag()],
            ),
        ),
        (
            "range on sealed",
            base(vec![cond(CondOp::Gt, Some(json!("a")))], vec![tag()]),
        ),
        (
            "pre-keyed condition",
            base(
                vec![Condition {
                    keyed: true,
                    ..cond(CondOp::Eq, Some(json!("pk_x")))
                }],
                vec![tag()],
            ),
        ),
        (
            "write a sealed field",
            base(
                vec![],
                vec![Action::UpdateRecord {
                    values: serde_json::from_value(json!({"email": "a@b.c"})).unwrap(),
                }],
            ),
        ),
        (
            "plain-http webhook",
            base(
                vec![],
                vec![Action::Webhook {
                    url: "http://example.com/x".into(),
                    fields: vec![],
                }],
            ),
        ),
        (
            "email to a non-email field",
            base(
                vec![],
                vec![Action::SendEmail {
                    to_field: "name".into(),
                    subject: "s".into(),
                    body: "b".into(),
                }],
            ),
        ),
    ] {
        assert!(
            eng.save(&w.admin, def).await.is_err(),
            "{label} must be refused"
        );
    }
    let err = eng
        .save(&w.member, base(vec![], vec![tag()]))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("owners and admins"), "{err}");
    // Presence and change checks on sealed fields are fine.
    eng.save(&w.admin, base(vec![cond(CondOp::IsSet, None)], vec![tag()]))
        .await
        .unwrap();
}

#[tokio::test]
async fn equality_guessing_is_rate_limited() {
    let w = world().await;
    let eng = engine(&w).await;
    let def = |n: usize| AutomationDef {
        object_id: w.object_id,
        name: format!("guess {n}"),
        trigger: Trigger::RecordCreated,
        conditions: vec![Condition {
            field: "email".into(),
            op: CondOp::In,
            value: Some(Value::Array(
                (0..n).map(|i| json!(format!("g{i}@x.example"))).collect(),
            )),
            keyed: false,
        }],
        actions: vec![Action::UpdateRecord {
            values: serde_json::from_value(json!({"tier": "t"})).unwrap(),
        }],
    };
    eng.save(&w.admin, def(15)).await.unwrap();
    let err = eng.save(&w.admin, def(10)).await.unwrap_err();
    assert!(err.to_string().contains("rate-limited"), "{err}");
    let audits: Vec<Value> = {
        let mut tx = w.core.tenant_tx(&w.admin).await.unwrap();
        let v = sqlx::query_scalar(
            "SELECT metadata FROM audit_events WHERE action = 'automation.saved' AND actor_id = $1",
        )
        .bind(w.admin.actor_id)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        v
    };
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0]["sensitive_literals"], 15);
    assert!(!audits[0].to_string().contains("x.example"));
}

#[tokio::test]
async fn self_triggering_automations_stop_at_the_depth_limit() {
    let w = world().await;
    let eng = engine(&w).await;
    // On ANY update, set score: each run's write is the next event (a
    // `fields: ["score"]` trigger would stop by itself once the value no
    // longer changes — no-op writes do not re-trigger).
    let a = eng
        .save(
            &w.admin,
            AutomationDef {
                object_id: w.object_id,
                name: "ping-pong".into(),
                trigger: Trigger::RecordUpdated { fields: vec![] },
                conditions: vec![],
                actions: vec![Action::UpdateRecord {
                    values: serde_json::from_value(json!({"score": 7})).unwrap(),
                }],
            },
        )
        .await
        .unwrap();
    let r = create(&w, json!({"name": "Loop"})).await;
    mutator(&w)
        .await
        .update(
            &w.admin,
            &UpdateRequest {
                object_id: w.object_id,
                record_id: r,
                values: serde_json::from_value(json!({"score": 1})).unwrap(),
                expected_version: None,
                require_approval: false,
                approval_request_id: None,
            },
            &NoHooks,
        )
        .await
        .unwrap();
    for _ in 0..10 {
        if eng.run_pending_org(w.org, 100).await.unwrap().events == 0 {
            break;
        }
    }
    let runs = eng.runs(&w.admin, a.id, 50).await.unwrap();
    let outcomes: Vec<&str> = runs.iter().rev().map(|r| r.outcome.as_str()).collect();
    assert_eq!(
        outcomes,
        vec!["succeeded", "succeeded", "succeeded", "loop_blocked"],
        "{runs:?}"
    );
}

#[tokio::test]
async fn runs_fail_closed_when_the_author_loses_the_role_and_stop_when_disabled() {
    let w = world().await;
    let eng = engine(&w).await;
    let a = eng
        .save(
            &w.admin,
            AutomationDef {
                object_id: w.object_id,
                name: "tagger".into(),
                trigger: Trigger::RecordCreated,
                conditions: vec![],
                actions: vec![Action::UpdateRecord {
                    values: serde_json::from_value(json!({"tier": "seen"})).unwrap(),
                }],
            },
        )
        .await
        .unwrap();
    sqlx::query("UPDATE memberships SET role = 'member' WHERE actor_id = $1")
        .bind(w.admin.actor_id)
        .execute(&w.owner.0)
        .await
        .unwrap();
    let r1 = create(&w, json!({"name": "One"})).await;
    eng.run_pending_org(w.org, 100).await.unwrap();
    let runs = eng.runs(&w.member, a.id, 10).await.unwrap();
    assert_eq!(runs[0].outcome, "failed");
    assert!(
        runs[0].detail.to_string().contains("no longer holds"),
        "{:?}",
        runs[0].detail
    );
    assert_eq!(field_value(&w, r1, "tier").await, Value::Null);

    sqlx::query("UPDATE memberships SET role = 'admin' WHERE actor_id = $1")
        .bind(w.admin.actor_id)
        .execute(&w.owner.0)
        .await
        .unwrap();
    eng.set_enabled(&w.admin, a.id, false).await.unwrap();
    create(&w, json!({"name": "Two"})).await;
    let stats = eng.run_pending_org(w.org, 100).await.unwrap();
    assert_eq!(
        (stats.events, stats.succeeded + stats.failed + stats.skipped),
        (1, 0)
    );
}
