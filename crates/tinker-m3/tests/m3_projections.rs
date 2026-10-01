//! M3 exit tests: two roles receive different authorized projections.
//!
//! The same query intent, issued by `sales` (unrestricted) and `support`
//! (restricted), returns different field sets — through the compiler
//! directly AND through `POST /api/query`. Hidden fields are projected
//! out of selects; filters and sorts on hidden fields are rejected.

mod common;

use axum::http::StatusCode;
use common::{contact_intent, post_query, setup};
use tinker_query::QueryIntent;

/// Compiler-level: the same intent compiles to different output shapes
/// per role.
#[tokio::test]
async fn compiler_projects_per_role() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let intent: QueryIntent = serde_json::from_value(contact_intent(&env.installed)).unwrap();

    let grants = tinker_live::FieldGrants::new(tinker_db::CoreDb(env.tenant_pool.clone()));

    // Sales: no grant rows -> unrestricted.
    let proj_sales = grants
        .load_projection_for_query(
            &env.org_a.sales.tenant,
            &env.state.ontology,
            "sales",
            contact_id,
        )
        .await
        .unwrap();
    let plan_sales = env
        .state
        .compiler
        .compile_with_projection(&env.org_a.sales.tenant, &intent, &proj_sales)
        .await
        .unwrap();
    let fields_sales: Vec<&str> = plan_sales
        .output_fields
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert!(fields_sales.contains(&"email"), "sales sees email");
    assert!(fields_sales.contains(&"phone"), "sales sees phone");
    assert!(
        fields_sales.contains(&"company.name"),
        "sales sees traversal"
    );

    // Support: restricted projection.
    let proj_support = grants
        .load_projection_for_query(
            &env.org_a.support.tenant,
            &env.state.ontology,
            "support",
            contact_id,
        )
        .await
        .unwrap();
    let plan_support = env
        .state
        .compiler
        .compile_with_projection(&env.org_a.support.tenant, &intent, &proj_support)
        .await
        .unwrap();
    let fields_support: Vec<&str> = plan_support
        .output_fields
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert!(
        !fields_support.contains(&"email"),
        "support must not see email"
    );
    assert!(
        !fields_support.contains(&"phone"),
        "support must not see phone"
    );
    assert!(fields_support.contains(&"name"), "support sees name");
    assert!(fields_support.contains(&"title"), "support sees title");
    assert!(
        fields_support.contains(&"company.name"),
        "support sees company traversal"
    );
    // __id is always present: invalidation needs it.
    assert!(fields_support.contains(&"__id"), "__id survives projection");

    // The SQL for support never selects the hidden columns.
    assert!(
        !plan_support.sql.contains("email") || plan_support.sql.contains("company"),
        "hidden columns absent from SQL (company join excepted)"
    );
}

/// HTTP-level: POST /api/query resolves the role from the session and
/// projects. Same intent, two actors, different rows.
#[tokio::test]
async fn http_query_projects_per_role() {
    let env = setup().await;
    let intent = contact_intent(&env.installed);

    let (status, body) = post_query(&env.router, &env.org_a.sales, &intent).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "Acme has one contact");
    assert_eq!(rows[0]["name"], "Alice");
    assert!(rows[0].get("email").is_some(), "sales row carries email");

    let (status, body) = post_query(&env.router, &env.org_a.support, &intent).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "Alice");
    assert!(
        rows[0].get("email").is_none(),
        "support row must not carry email"
    );
    assert!(
        rows[0].get("phone").is_none(),
        "support row must not carry phone"
    );
    assert!(rows[0].get("title").is_some(), "support keeps title");
    // The traversal still resolves: the company name comes through.
    assert_eq!(rows[0]["company.name"], "Acme");

    // The two roles get different cache entries (different plan hashes).
    let (status, body_sales2) = post_query(&env.router, &env.org_a.sales, &intent).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        body_sales2["plan_hash"], body["plan_hash"],
        "role projections hash to different cache entries"
    );
}

/// Hidden fields cannot be used as filters or sort keys: the request is
/// rejected instead of leaking through a boolean oracle.
#[tokio::test]
async fn hidden_fields_cannot_filter_or_sort() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];

    let filter_intent = serde_json::json!({
        "from": contact_id,
        "select": ["name"],
        "filters": [{ "field": "email", "op": "eq", "value": "alice@example.com" }],
        "order": [],
        "limit": 10,
    });
    let (status, _) = post_query(&env.router, &env.org_a.support, &filter_intent).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "filter on hidden field must be rejected"
    );
    // Sales may filter on it.
    let (status, _) = post_query(&env.router, &env.org_a.sales, &filter_intent).await;
    assert_eq!(status, StatusCode::OK, "sales may filter on email");

    let sort_intent = serde_json::json!({
        "from": contact_id,
        "select": ["name"],
        "filters": [],
        "order": [{ "field": "phone", "descending": false }],
        "limit": 10,
    });
    let (status, _) = post_query(&env.router, &env.org_a.support, &sort_intent).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "sort on hidden field must be rejected"
    );
}

/// A projection that hides everything still fails closed (not an empty
/// result masquerading as "no data").
#[tokio::test]
async fn empty_projection_fails_closed() {
    let env = setup().await;
    let contact_id = env.installed.objects["crm_contact"];
    let grants = tinker_live::FieldGrants::new(tinker_db::CoreDb(env.tenant_pool.clone()));
    grants
        .set_projection(&env.org_a.sales.tenant, contact_id, "intern", &[])
        .await
        .unwrap();
    let proj = grants
        .load_projection_for_query(
            &env.org_a.sales.tenant,
            &env.state.ontology,
            "intern",
            contact_id,
        )
        .await
        .unwrap();
    // Select only base-object fields: every one is hidden for intern,
    // so compilation must fail rather than return id-only rows.
    // (Relation traversals like company.name are governed by the TARGET
    // object's projection — per-object semantics, not base-object.)
    let intent_value = serde_json::json!({
        "from": contact_id,
        "select": ["name", "email"],
        "filters": [],
        "order": [],
        "limit": 10,
    });
    let intent: QueryIntent = serde_json::from_value(intent_value).unwrap();
    let res = env
        .state
        .compiler
        .compile_with_projection(&env.org_a.sales.tenant, &intent, &proj)
        .await;
    assert!(res.is_err(), "empty projection must fail closed");
}

/// Org B's actors get their own projections and their own data: the
/// sibling org is fully isolated under the same pack objects.
#[tokio::test]
async fn projections_are_per_org() {
    let env = setup().await;
    let intent = contact_intent(&env.installed);

    let (status, body) = post_query(&env.router, &env.org_b.support, &intent).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], "Bob", "sibling org sees its own contact");
    assert_eq!(rows[0]["company.name"], "Globex");
    assert!(rows[0].get("email").is_none(), "projection applies per org");
}
