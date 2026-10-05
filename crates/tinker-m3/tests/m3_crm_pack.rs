//! M3 exit tests: the CRM pack installs and runs without SQL.
//!
//! - The TOML pack creates real platform ontology objects with typed
//!   tables/columns (verified from information_schema — the install
//!   path is the pack installer, not the test's own DDL).
//! - Relations are real composite tenant FKs.
//! - The dashboard app installs into an org workspace, publishes, and
//!   renders rt-grid components whose queries carry the installed ids.
//! - Cross-org app access is denied; sibling org sees only its data.

mod common;

use axum::http::StatusCode;
use common::{post_query, setup};

/// Pack objects become real typed tables; fields become typed columns.
#[tokio::test]
async fn pack_objects_create_real_tables() {
    let env = setup().await;

    // The installer resolved slugs to object ids.
    let slugs = ["crm_company", "crm_contact", "crm_deal"];
    for slug in slugs {
        assert!(env.installed.objects.contains_key(slug), "installed {slug}");
    }
    // from_slug -> id was rewritten for the app too.
    for id in env.installed_app.object_ids.values() {
        assert!(env.installed.objects.values().any(|v| v == id));
    }
    assert_eq!(
        env.installed_app.object_ids.len(),
        2,
        "contacts-grid + deals-grid rewritten"
    );

    // Verify through the DB catalog, not the ontology cache.
    for (slug, object_id) in &env.installed.objects {
        let cols: Vec<(String, String)> = sqlx::query_as(
            "SELECT column_name, data_type FROM information_schema.columns
             WHERE table_schema='data' AND table_name=$1 AND column_name LIKE 'f_%'",
        )
        .bind(slug)
        .fetch_all(&env.system_pool)
        .await
        .unwrap();
        assert!(!cols.is_empty(), "{slug} has f_* columns");
        // organization_id + __id-equivalents exist.
        let all: Vec<(String,)> = sqlx::query_as(
            "SELECT column_name FROM information_schema.columns
             WHERE table_schema='data' AND table_name=$1",
        )
        .bind(slug)
        .fetch_all(&env.system_pool)
        .await
        .unwrap();
        let names: Vec<&str> = all.iter().map(|(n,)| n.as_str()).collect();
        assert!(names.contains(&"organization_id"), "{slug} tenant column");
        assert!(names.contains(&"id"), "{slug} id column");

        // The ontology metadata agrees with the catalog.
        let (count,): (i64,) =
            sqlx::query_as("SELECT count(*) FROM ontology_fields WHERE object_id=$1")
                .bind(object_id)
                .fetch_one(&env.system_pool)
                .await
                .unwrap();
        assert!(count >= 3, "{slug} has >=3 fields");
        let (scope,): (String,) =
            sqlx::query_as("SELECT scope_kind FROM ontology_objects WHERE id=$1")
                .bind(object_id)
                .fetch_one(&env.system_pool)
                .await
                .unwrap();
        assert_eq!(scope, "platform", "{slug} is a platform object");
        let _ = cols;
    }

    // Typed columns: email is a vault ref (PII by type), amount is numeric.
    let (email_type,): (String,) = sqlx::query_as(
        "SELECT data_type FROM information_schema.columns
         WHERE table_schema='data' AND table_name='crm_contact' AND column_name LIKE 'f_%'
         AND column_name IN (SELECT physical_column FROM ontology_fields WHERE api_name='email' AND object_id=$1)",
    )
    .bind(env.installed.objects["crm_contact"])
    .fetch_one(&env.system_pool)
    .await
    .unwrap();
    // Email is PII by type: its column holds the vault ref, never text.
    assert_eq!(
        email_type, "uuid",
        "email is a vault-ref column, got {email_type}"
    );
    let (amount_type,): (String,) = sqlx::query_as(
        "SELECT data_type FROM information_schema.columns
         WHERE table_schema='data' AND table_name='crm_deal'
         AND column_name IN (SELECT physical_column FROM ontology_fields WHERE api_name='amount' AND object_id=$1)",
    )
    .bind(env.installed.objects["crm_deal"])
    .fetch_one(&env.system_pool)
    .await
    .unwrap();
    assert_eq!(
        amount_type, "numeric",
        "amount is numeric, got {amount_type}"
    );
}

/// Relations are real composite tenant foreign keys, not conventions.
#[tokio::test]
async fn pack_relations_are_real_fks() {
    let env = setup().await;
    let fks: Vec<(String, String)> = sqlx::query_as(
        "SELECT tc.table_name, tc.constraint_name
         FROM information_schema.table_constraints tc
         WHERE tc.constraint_type='FOREIGN KEY'
           AND tc.table_name IN ('crm_contact', 'crm_deal')
           AND tc.table_schema='data'",
    )
    .fetch_all(&env.system_pool)
    .await
    .unwrap();
    assert!(
        fks.len() >= 3,
        "contact->company, deal->contact, deal->company FKs"
    );
    // The FK columns include organization_id (composite tenant key).
    for (table, name) in &fks {
        let cols: Vec<(String,)> = sqlx::query_as(
            "SELECT kcu.column_name FROM information_schema.key_column_usage kcu
             WHERE kcu.constraint_name=$1 AND kcu.table_schema='data'
             ORDER BY kcu.ordinal_position",
        )
        .bind(name)
        .fetch_all(&env.system_pool)
        .await
        .unwrap();
        let names: Vec<&str> = cols.iter().map(|(n,)| n.as_str()).collect();
        assert!(
            names.contains(&"organization_id"),
            "{table}.{name} FK carries organization_id: {names:?}"
        );
    }
}

/// The dashboard app installs into org A's workspace, is published, and
/// renders with its rt-grid queries pointing at the installed objects.
#[tokio::test]
async fn dashboard_app_renders_installed_queries() {
    let env = setup().await;
    let app = &env.installed_app;
    assert_eq!(app.slug, "crm-dashboard");
    assert_eq!(app.object_ids.len(), 2, "two grids rewrote from_slug");

    // Render through the real HTTP route as org A's sales actor.
    let res = {
        use axum::http::{header, Request};
        use tower::ServiceExt;
        let req = Request::builder()
            .method("GET")
            .uri("/apps/crm-dashboard")
            .header(header::COOKIE, &env.org_a.sales.cookie)
            .body(axum::body::Body::empty())
            .unwrap();
        env.router.clone().oneshot(req).await.unwrap()
    };
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let html = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(html.contains("rt-grid"), "dashboard renders rt-grid");
    // The rendered page references the installed object ids in queries.
    for id in app.object_ids.values() {
        assert!(
            html.contains(&id.to_string()),
            "rendered app carries installed object id {id}"
        );
    }
}

/// Org B cannot open org A's app; its own workspace has no dashboard.
#[tokio::test]
async fn app_is_per_org() {
    let env = setup().await;
    let res = {
        use axum::http::{header, Request};
        use tower::ServiceExt;
        let req = Request::builder()
            .method("GET")
            .uri("/apps/crm-dashboard")
            .header(header::COOKIE, &env.org_b.sales.cookie)
            .body(axum::body::Body::empty())
            .unwrap();
        env.router.clone().oneshot(req).await.unwrap()
    };
    assert_eq!(
        res.status(),
        StatusCode::NOT_FOUND,
        "sibling org cannot render org A's app"
    );
}

/// The dashboard's grid queries run through the pack-installed objects:
/// contact grid shows the org's contacts, deal grid shows deals.
#[tokio::test]
async fn dashboard_queries_run() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let deal_id = env.installed.objects["crm_deal"];

    let intent = serde_json::json!({
        "from": contact_id,
        "select": ["name", "company.name"],
        "filters": [],
        "order": [],
        "limit": 10,
    });
    let (status, body) = post_query(&env.router, &env.org_a.sales, &intent).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["company.name"], "Acme");

    let intent = serde_json::json!({
        "from": deal_id,
        "select": ["name", "amount", "stage", "contact.name"],
        "filters": [],
        "order": [],
        "limit": 10,
    });
    let (status, body) = post_query(&env.router, &env.org_a.sales, &intent).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["contact.name"], "Alice");
    assert_eq!(rows[0]["stage"], "proposal");
}
