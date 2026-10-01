//! Post-M8 item 30 (scale-out spike): approvals are Postgres-backed —
//! two [`ApprovalEngine`]s on separately-connected pools (two
//! "instances", no shared process state) must observe the same
//! approval lifecycle: request on A, decide on B, visible on A.

use tinker_agents::approval::ApprovalEngine;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

#[tokio::test]
async fn approvals_shared_across_instances() {
    // Two independent pool pairs = two instances.
    let owner_a = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let app_a = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let owner_b = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let app_b = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();
    let core_a = CoreDb(app_a);
    let engine_b = ApprovalEngine::new(CoreDb(app_b), OwnerDb(owner_b));

    let org_id = Uuid::now_v7();
    let host_id = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, $2)")
        .bind(host_id)
        .bind("approvals-scale-out-host")
        .execute(&owner_a)
        .await
        .unwrap();
    sqlx::query("INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, $3, $4)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("aso-{}", org_id.simple()))
        .bind("approvals scale-out org")
        .execute(&owner_a)
        .await
        .unwrap();
    let ctx = TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "scale-out-test".to_string(),
    );

    // approval_requests.attachment_id is a real FK (as is
    // agent_attachments.actor_id): create actor + attachment inside a
    // tenant-scoped tx (RLS is forced on these tables, so the owner
    // pool cannot insert directly).
    let actor_id = Uuid::now_v7();
    let mut tx = core_a.tenant_tx(&ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, $3, $4)",
    )
    .bind(actor_id)
    .bind(org_id)
    .bind("scale-out actor")
    .bind("scale-out-actor")
    .execute(&mut *tx)
    .await
    .unwrap();
    let (attachment_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO agent_attachments (organization_id, actor_id, name, kind)
         VALUES ($1, $2, 'scale-out attachment', 'test') RETURNING id",
    )
    .bind(org_id)
    .bind(actor_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let ctx = TenantContext::new(
        OrganizationId(org_id),
        actor_id,
        "scale-out-test".to_string(),
    );
    let engine_a = ApprovalEngine::new(core_a, OwnerDb(owner_a.clone()));

    // Requested on A...
    let req = engine_a
        .request(
            &ctx,
            attachment_id,
            "deploy",
            serde_json::json!({"target": "prod"}),
            &format!("so-key-{}", Uuid::now_v7().simple()),
        )
        .await
        .unwrap();
    assert_eq!(req.status, "pending");

    // ...visible on B, decided on B...
    let seen = engine_b.get(&ctx, req.id).await.unwrap();
    assert_eq!(seen.id, req.id);
    assert_eq!(seen.status, "pending");
    let decided = engine_b.decide(&ctx, req.id, true).await.unwrap();
    assert_eq!(decided.status, "approved");

    // ...and the decision is visible back on A: no per-instance state.
    let back = engine_a.get(&ctx, req.id).await.unwrap();
    assert_eq!(back.status, "approved");
}
