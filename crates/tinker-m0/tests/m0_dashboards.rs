//! Item 41 (C5) exits: dashboard composer.
//!
//! The contract under test:
//! - Dashboards are governed objects: CRUD is org-scoped, RLS-isolated.
//!   A foreign org's dashboard id returns NotFound — never an existence
//!   oracle. Layout (panels + geometry) round-trips byte-faithfully.
//! - Panel queries are validated at SAVE time under the author's own
//!   permissions: unknown objects/fields, hidden fields, empty selects,
//!   and bad geometry all fail the save, never render.
//! - Render executes every panel under the VIEWER's role: row filters
//!   (item 38), field projection (M3), and lifecycle visibility
//!   (item 40) all apply. A dashboard shared from a privileged author
//!   to a restricted viewer shows the viewer only what they may see —
//!   no privilege escalation via shared dashboards.
//! - Panel failures are per-panel: one bad panel renders as an error
//!   card while the others render fine.
//! - Every panel execution is audit-logged under the viewing actor.

mod common;

use std::collections::HashMap;

use tinker_core::{OrganizationId, TenantContext, TinkerError};
use tinker_db::OwnerDb;
use tinker_ontology::lifecycle::LifecycleEngine;
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope};
use tinker_query::dashboard::{
    DashboardInput, DashboardService, PanelDef, PanelOutcome, VisualizationKind,
};
use tinker_query::{QueryIntent, RowFilterDef, RowFilters};
use uuid::Uuid;

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
        max_pii_class: "restricted".to_string(),
        sensitive: false,
        validation: Default::default(),
        preset: None,
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type,
        options: serde_json::json!({}),
        required: false,
    }
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
    sqlx::query("INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1,$2,$3)")
        .bind(actor_id)
        .bind(org_id)
        .bind(role)
        .execute(&env.core_owner)
        .await
        .unwrap();
    TenantContext::new(
        OrganizationId(org_id),
        actor_id,
        format!("m0-dashboards-{role}"),
    )
}

fn panel(id: &str, object: Uuid, select: &[&str], x: u16, y: u16, w: u16, h: u16) -> PanelDef {
    PanelDef {
        id: id.into(),
        query: QueryIntent {
            from: object,
            select: select.iter().map(|s| s.to_string()).collect(),
            filters: vec![],
            order: vec![],
            limit: Some(100),
            schema_version: None,
        },
        visualization: VisualizationKind::Table,
        x,
        y,
        w,
        h,
    }
}

fn input(name: &str, panels: Vec<PanelDef>) -> DashboardInput {
    DashboardInput {
        name: name.into(),
        description: Some("test dashboard".into()),
        panels,
    }
}

fn def(field: &str, op: &str, value: serde_json::Value) -> RowFilterDef {
    RowFilterDef {
        field: field.into(),
        op: op.into(),
        value: Some(value),
    }
}

struct World {
    deal: Uuid,
    secret: Uuid,
    ctx_manager: TenantContext,
    ctx_rep: TenantContext,
    ctx_outsider: TenantContext,
    ctx_nomember: TenantContext,
}

/// One org with a `deal` object (name/region/amount), a manager (open
/// policy) and a rep (row filter: region = 'emea'), plus a second org
/// and a membership-less context for isolation tests.
async fn setup_world(env: &common::Env) -> World {
    let ctx_a = common::new_org(env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(env, &common::uniq("orgb")).await;
    let org_a = ctx_a.organization_id.0;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));

    let deal_slug = common::uniq("deal");
    let deal = ont
        .define_object(&ctx_a, &object_def(&deal_slug))
        .await
        .unwrap();
    for (api, ft) in [
        ("name", FieldType::Text),
        ("region", FieldType::Text),
        ("amount", FieldType::Number),
    ] {
        ont.add_field(&ctx_a, deal.id, &field(api, ft))
            .await
            .unwrap();
    }
    let desc = ont.describe_object(&ctx_a, deal.id).await.unwrap();
    let col = |api: &str| {
        desc.fields
            .iter()
            .find(|f| f.api_name == api)
            .unwrap()
            .physical_column
            .clone()
    };
    let (c_name, c_region, c_amount) = (col("name"), col("region"), col("amount"));

    let ctx_manager = member(env, org_a, "manager").await;
    let ctx_rep = member(env, org_a, "rep").await;
    let ctx_outsider = member(env, ctx_b.organization_id.0, "manager").await;
    // Membership-less: a bare org context whose actor has no membership row.
    let ctx_nomember = common::new_org(env, &common::uniq("orgc")).await;

    // A second object for the per-panel isolation test: the rep is
    // denied all fields on it.
    let secret_slug = common::uniq("secret");
    let secret = ont
        .define_object(&ctx_a, &object_def(&secret_slug))
        .await
        .unwrap();
    ont.add_field(&ctx_a, secret.id, &field("name", FieldType::Text))
        .await
        .unwrap();
    let secret_desc = ont.describe_object(&ctx_a, secret.id).await.unwrap();
    let s_name = secret_desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let mut tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO data.\"{secret_slug}\" (organization_id, id, version, \"{s_name}\") VALUES ($1,$2,1,'TopSecret')"
    ))
    .bind(org_a)
    .bind(Uuid::now_v7())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Seed: Alpha/emea, Beta/amer, Gamma/emea.
    let mut tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    for (id, name, region, amount) in [
        (Uuid::now_v7(), "Alpha", "emea", 100i64),
        (Uuid::now_v7(), "Beta", "amer", 200i64),
        (Uuid::now_v7(), "Gamma", "emea", 300i64),
    ] {
        sqlx::query(&format!(
            "INSERT INTO data.\"{deal_slug}\" (organization_id, id, version, \"{c_name}\", \"{c_region}\", \"{c_amount}\") VALUES ($1,$2,1,$3,$4,$5)"
        ))
        .bind(org_a)
        .bind(id)
        .bind(name)
        .bind(region)
        .bind(amount)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    // The rep sees only emea rows.
    let rf = RowFilters::new(env.core.clone());
    rf.set_filters(
        &ctx_a,
        &desc,
        "rep",
        &[def("region", "eq", serde_json::json!("emea"))],
    )
    .await
    .unwrap();

    World {
        deal: deal.id,
        secret: secret.id,
        ctx_manager,
        ctx_rep,
        ctx_outsider,
        ctx_nomember,
    }
}

fn service(env: &common::Env) -> DashboardService {
    DashboardService::new(
        env.core.clone(),
        Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone())),
    )
}

fn names_of(rows: &[serde_json::Value]) -> Vec<String> {
    let mut names: Vec<String> = rows
        .iter()
        .filter_map(|r| r.get("name").and_then(|v| v.as_str()).map(String::from))
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn dashboard_crud_scoped_to_org() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let svc = service(&env);

    let dash = svc
        .create(
            &w.ctx_manager,
            input("Sales", vec![panel("p1", w.deal, &["name"], 0, 0, 12, 6)]),
        )
        .await
        .unwrap();
    assert_eq!(dash.name, "Sales");
    assert_eq!(dash.panels.len(), 1);
    assert_eq!(dash.organization_id, w.ctx_manager.organization_id.0);

    // Same org can read; list shows it.
    let got = svc.get(&w.ctx_manager, dash.id).await.unwrap();
    assert_eq!(got.id, dash.id);
    let list = svc.list(&w.ctx_manager).await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].panel_count, 1);

    // Foreign org: NotFound on get, empty list, NotFound on render —
    // never an existence oracle.
    let err = svc.get(&w.ctx_outsider, dash.id).await.unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "got {err:?}");
    assert!(svc.list(&w.ctx_outsider).await.unwrap().is_empty());
    let err = svc
        .render(&w.ctx_outsider, "manager", dash.id)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "got {err:?}");

    // Update round-trips name and panels.
    let upd = svc
        .update(
            &w.ctx_manager,
            dash.id,
            input(
                "Sales v2",
                vec![
                    panel("p1", w.deal, &["name", "amount"], 0, 0, 12, 6),
                    panel("p2", w.deal, &["region"], 12, 0, 12, 6),
                ],
            ),
        )
        .await
        .unwrap();
    assert_eq!(upd.name, "Sales v2");
    assert_eq!(upd.panels.len(), 2);

    // Delete; then NotFound.
    svc.delete(&w.ctx_manager, dash.id).await.unwrap();
    let err = svc.get(&w.ctx_manager, dash.id).await.unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "got {err:?}");
    let err = svc.delete(&w.ctx_manager, dash.id).await.unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn layout_round_trip() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let svc = service(&env);

    let mut p = panel("chart1", w.deal, &["name", "amount"], 3, 7, 21, 9);
    p.visualization = VisualizationKind::Chart;
    let dash = svc
        .create(
            &w.ctx_manager,
            input(
                "Layout",
                vec![p, panel("t1", w.deal, &["region"], 0, 0, 3, 7)],
            ),
        )
        .await
        .unwrap();
    let got = svc.get(&w.ctx_manager, dash.id).await.unwrap();
    assert_eq!(got.panels.len(), 2);
    let c = &got.panels[0];
    assert_eq!(c.id, "chart1");
    assert_eq!(c.visualization, VisualizationKind::Chart);
    assert_eq!((c.x, c.y, c.w, c.h), (3, 7, 21, 9));
    assert_eq!(c.query.select, vec!["name", "amount"]);
    let t = &got.panels[1];
    assert_eq!((t.x, t.y, t.w, t.h), (0, 0, 3, 7));
}

#[tokio::test]
async fn panel_validation_rejects_bad_query_at_save() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let svc = service(&env);

    // Unknown field.
    let err = svc
        .create(
            &w.ctx_manager,
            input("Bad", vec![panel("p1", w.deal, &["nope"], 0, 0, 12, 6)]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");
    assert!(err.to_string().contains("p1"), "panel id named: {err}");

    // Empty select.
    let err = svc
        .create(
            &w.ctx_manager,
            input("Bad", vec![panel("p1", w.deal, &[], 0, 0, 12, 6)]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");

    // Unknown object.
    let err = svc
        .create(
            &w.ctx_manager,
            input(
                "Bad",
                vec![panel("p1", Uuid::now_v7(), &["name"], 0, 0, 12, 6)],
            ),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");

    // Bad geometry: zero width, over-wide, duplicate ids.
    for panels in [
        vec![panel("p1", w.deal, &["name"], 0, 0, 0, 6)],
        vec![panel("p1", w.deal, &["name"], 20, 0, 8, 6)],
        vec![
            panel("p1", w.deal, &["name"], 0, 0, 12, 6),
            panel("p1", w.deal, &["name"], 12, 0, 12, 6),
        ],
    ] {
        let err = svc
            .create(&w.ctx_manager, input("Bad", panels))
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");
    }

    // Nothing was persisted by the failed saves.
    assert!(svc.list(&w.ctx_manager).await.unwrap().is_empty());
}

#[tokio::test]
async fn create_requires_membership() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let svc = service(&env);
    let err = svc
        .create(
            &w.ctx_nomember,
            input("Nope", vec![panel("p1", w.deal, &["name"], 0, 0, 12, 6)]),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)), "got {err:?}");
}

#[tokio::test]
async fn render_executes_as_viewer_no_escalation() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let svc = service(&env);

    // Privileged author shares a dashboard with a restricted viewer.
    let dash = svc
        .create(
            &w.ctx_manager,
            input(
                "Shared",
                vec![panel("p1", w.deal, &["name", "amount"], 0, 0, 24, 8)],
            ),
        )
        .await
        .unwrap();

    // The manager (open policy) sees all three rows.
    let r = svc
        .render(&w.ctx_manager, "manager", dash.id)
        .await
        .unwrap();
    assert_eq!(r.panels.len(), 1);
    match &r.panels[0].outcome {
        PanelOutcome::Ok { rows } => assert_eq!(names_of(rows), vec!["Alpha", "Beta", "Gamma"]),
        PanelOutcome::Error { error } => panic!("manager panel failed: {error}"),
    }

    // The rep (region = 'emea' row filter) sees only emea rows — the
    // shared dashboard does not escalate.
    let r = svc.render(&w.ctx_rep, "rep", dash.id).await.unwrap();
    match &r.panels[0].outcome {
        PanelOutcome::Ok { rows } => {
            assert_eq!(names_of(rows), vec!["Alpha", "Gamma"]);
            for row in rows {
                assert_eq!(
                    row.get("region").and_then(|v| v.as_str()),
                    None,
                    "region was not selected and must not leak: {row}"
                );
            }
        }
        PanelOutcome::Error { error } => panic!("rep panel failed: {error}"),
    }

    // Every panel execution is audit-logged under the VIEWING actor.
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM query_audit WHERE organization_id=$1 AND actor_id=$2",
    )
    .bind(w.ctx_rep.organization_id.0)
    .bind(w.ctx_rep.actor_id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert!(n >= 1, "rep's panel execution must be audited, got {n}");
}

#[tokio::test]
async fn per_panel_failure_isolation() {
    let env = common::setup().await;
    let w = setup_world(&env).await;
    let svc = service(&env);

    // The rep may see `name` but not `amount` on deals (M3 field
    // projection), and nothing at all on the secret object.
    let mut tx = env.core.tenant_tx(&w.ctx_manager).await.unwrap();
    for (object, role, api) in [(w.deal, "rep", "name"), (w.secret, "rep", "__deny_all")] {
        sqlx::query(
            "INSERT INTO field_grants (organization_id, object_id, role, field_api_name)
             VALUES ($1,$2,$3,$4)",
        )
        .bind(w.ctx_manager.organization_id.0)
        .bind(object)
        .bind(role)
        .bind(api)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    // Save-time validation is under the AUTHOR's permissions: the manager
    // (unrestricted) can save both panels.
    let dash = svc
        .create(
            &w.ctx_manager,
            input(
                "Mixed",
                vec![
                    panel("deals", w.deal, &["name", "amount"], 0, 0, 12, 6),
                    panel("secrets", w.secret, &["name"], 12, 0, 12, 6),
                ],
            ),
        )
        .await
        .unwrap();

    // The manager renders both panels fine.
    let r = svc
        .render(&w.ctx_manager, "manager", dash.id)
        .await
        .unwrap();
    for p in &r.panels {
        assert!(
            matches!(p.outcome, PanelOutcome::Ok { .. }),
            "manager panel {} must render: {:?}",
            p.panel_id,
            p.outcome
        );
    }

    // The rep renders a degraded dashboard: the deals panel works with
    // `amount` projected OUT (hidden selected fields are dropped, never
    // leaked), while the secrets panel becomes an error card — one bad
    // panel never breaks the dashboard.
    let r = svc.render(&w.ctx_rep, "rep", dash.id).await.unwrap();
    assert_eq!(r.panels.len(), 2);
    match &r.panels[0].outcome {
        PanelOutcome::Ok { rows } => {
            assert_eq!(names_of(rows), vec!["Alpha", "Gamma"]);
            for row in rows {
                assert!(row.get("name").is_some(), "name visible: {row}");
                assert_eq!(row.get("amount"), None, "amount must not leak: {row}");
            }
        }
        PanelOutcome::Error { error } => panic!("deals panel must render for rep: {error}"),
    }
    match &r.panels[1].outcome {
        PanelOutcome::Ok { rows } => panic!("secrets panel must not render for rep: {rows:?}"),
        PanelOutcome::Error { error } => {
            assert!(error.contains("no visible fields"), "sanitized: {error}");
            assert!(
                !error.contains("SELECT") && !error.contains("FROM"),
                "no SQL leak: {error}"
            );
        }
    }

    // And the rep cannot SAVE a panel filtering on a hidden field —
    // save-time validation fails closed on the author's projection.
    let mut p = panel("p1", w.deal, &["name"], 0, 0, 12, 6);
    p.query.filters = vec![tinker_query::Filter {
        field: "amount".into(),
        op: tinker_query::FilterOp::Gt,
        value: serde_json::json!(0),
    }];
    let err = svc
        .create(&w.ctx_rep, input("Sneaky", vec![p]))
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)), "got {err:?}");
}

#[tokio::test]
async fn render_respects_lifecycle_visibility() {
    let env = common::setup().await;
    let ctx_a = common::new_org(&env, &common::uniq("orga")).await;
    let org_a = ctx_a.organization_id.0;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let svc = service(&env);

    let slug = common::uniq("article");
    let article = ont.define_object(&ctx_a, &object_def(&slug)).await.unwrap();
    ont.add_field(&ctx_a, article.id, &field("title", FieldType::Text))
        .await
        .unwrap();
    ont.set_lifecycle_enabled(&ctx_a, article.id, true)
        .await
        .unwrap();
    let desc = ont.describe_object(&ctx_a, article.id).await.unwrap();
    let c_title = desc
        .fields
        .iter()
        .find(|f| f.api_name == "title")
        .unwrap()
        .physical_column
        .clone();

    let ctx_viewer = member(&env, org_a, "viewer").await;
    let ctx_author = member(&env, org_a, "manager").await;

    // One published row (direct insert = published content by definition).
    let mut tx = env.core.tenant_tx(&ctx_a).await.unwrap();
    sqlx::query(&format!(
        "INSERT INTO data.\"{slug}\" (organization_id, id, version, \"{c_title}\") VALUES ($1,$2,1,'Published')"
    ))
    .bind(org_a)
    .bind(Uuid::now_v7())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // One in-flight draft: lives in record_drafts, never in the data table.
    let lc = LifecycleEngine::new(env.core.clone(), ont.clone());
    let mut values = HashMap::new();
    values.insert("title".to_string(), serde_json::json!("Draft"));
    lc.create_draft(&ctx_viewer, article.id, None, &values)
        .await
        .unwrap();

    let dash = svc
        .create(
            &ctx_author,
            input(
                "News",
                vec![panel("p1", article.id, &["title"], 0, 0, 24, 8)],
            ),
        )
        .await
        .unwrap();
    let r = svc.render(&ctx_viewer, "viewer", dash.id).await.unwrap();
    match &r.panels[0].outcome {
        PanelOutcome::Ok { rows } => {
            let titles: Vec<String> = rows
                .iter()
                .filter_map(|row| row.get("title").and_then(|v| v.as_str()).map(String::from))
                .collect();
            assert_eq!(
                titles,
                vec!["Published"],
                "drafts must stay invisible: {titles:?}"
            );
        }
        PanelOutcome::Error { error } => panic!("panel failed: {error}"),
    }
}
