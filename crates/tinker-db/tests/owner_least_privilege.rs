//! Least-privilege owner roles (post-M8 backlog: one-shot privileged
//! bootstrap, then least-privilege owners).
//!
//! Provisioning (`bin/pg-ensure.sh`) is the one-shot privileged
//! bootstrap: it creates roles/databases and installs extensions as the
//! postgres superuser, then converges every role to its declared
//! privilege shape on every run. This test pins that shape:
//!
//! - `tinker_core` / `tinker_pii`: LOGIN + CREATEROLE only — NOT
//!   superuser, NOT createdb. CREATEROLE is the documented minimum for
//!   the supported app-role password rotation
//!   (`tinker_db::rotate_app_role_passwords` issues ALTER ROLE over
//!   owner handles) and the frozen 0001 role-creation backstop.
//! - `tinker_app` / `tinker_pii_app`: plain LOGIN. No DDL, no role admin.
//! - Extensions (`pgcrypto` core+pii, `pg_trgm` core) are installed by
//!   the bootstrap, so the owners never need SUPERUSER for migrations.

use sqlx::Row;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

#[derive(Debug)]
struct RoleFlags {
    can_login: bool,
    is_superuser: bool,
    can_create_db: bool,
    can_create_role: bool,
}

async fn role_flags(pool: &sqlx::PgPool, role: &str) -> RoleFlags {
    let row = sqlx::query(
        "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole
         FROM pg_roles WHERE rolname=$1",
    )
    .bind(role)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|_| panic!("role {role} must exist after provisioning"));
    RoleFlags {
        can_login: row.get("rolcanlogin"),
        is_superuser: row.get("rolsuper"),
        can_create_db: row.get("rolcreatedb"),
        can_create_role: row.get("rolcreaterole"),
    }
}

#[tokio::test]
async fn owner_roles_are_least_privilege() {
    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    for role in ["tinker_core", "tinker_pii"] {
        let f = role_flags(&owner, role).await;
        assert!(f.can_login, "{role} must be able to log in");
        assert!(
            !f.is_superuser,
            "{role} must NOT be superuser (extensions are bootstrap-installed)"
        );
        assert!(!f.can_create_db, "{role} must NOT have CREATEDB");
        assert!(
            f.can_create_role,
            "{role} keeps CREATEROLE: the minimum for app-role password rotation"
        );
    }
}

#[tokio::test]
async fn app_roles_are_plain_login() {
    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    for role in ["tinker_app", "tinker_pii_app"] {
        let f = role_flags(&owner, role).await;
        assert!(f.can_login, "{role} must be able to log in");
        assert!(!f.is_superuser, "{role} must NOT be superuser");
        assert!(!f.can_create_db, "{role} must NOT have CREATEDB");
        assert!(!f.can_create_role, "{role} must NOT have CREATEROLE");
    }
}

#[tokio::test]
async fn owner_holds_admin_option_on_app_roles() {
    // PostgreSQL requires CREATEROLE *and* ADMIN OPTION on the target
    // role to ALTER another role's password. The bootstrap grants
    // exactly that — membership is not used for privilege inheritance
    // (the owners already own their databases).
    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    for (owner_role, app_role) in [
        ("tinker_core", "tinker_app"),
        ("tinker_pii", "tinker_pii_app"),
    ] {
        let row: (bool,) = sqlx::query_as(
            "SELECT m.admin_option FROM pg_auth_members m
             JOIN pg_roles r ON r.oid = m.roleid
             JOIN pg_roles u ON u.oid = m.member
             WHERE r.rolname=$1 AND u.rolname=$2",
        )
        .bind(app_role)
        .bind(owner_role)
        .fetch_one(&owner)
        .await
        .unwrap_or_else(|_| panic!("{owner_role} must be granted {app_role}"));
        assert!(row.0, "{owner_role} needs ADMIN OPTION on {app_role}");
    }
}

#[tokio::test]
async fn system_scope_tables_are_owner_visible_without_tenant_context() {
    // Regression test for the post-M8 item-11 fallout: several code paths
    // read through the owner / system pool BEFORE a tenant context can
    // exist (OIDC pre-tenant binding lookup on auth_credentials +
    // memberships, Authorizer workspace/app scope resolution, operator
    // identity resolution on actors). Migration 0027 removes FORCE RLS
    // on exactly these tables so the non-superuser owner still sees them;
    // RLS stays enabled so the app role remains policy-bound.
    //
    // This test runs as the least-privilege owner (no SUPERUSER) and
    // would fail if FORCE were reintroduced: the owner SELECTs below
    // set no app.organization_id GUC at all.
    let owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let app = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
        .await
        .unwrap();

    let org_id = uuid::Uuid::now_v7();
    let actor_id = uuid::Uuid::now_v7();
    let host_id = uuid::Uuid::now_v7();
    // Unique per run: the test binary may be re-run and a previous
    // failed run can leave rows behind if cleanup never executed.
    let issuer = format!("https://issuer.sys.test/{org_id}");
    let subject = format!("sys-sub-{org_id}");
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, 'sys-scope-test')")
        .bind(host_id)
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organizations (id, host_id, name, slug) VALUES ($1, $2, 'sys-scope', $3)",
    )
    .bind(org_id)
    .bind(host_id)
    .bind(format!("sys-scope-{org_id}"))
    .execute(&owner)
    .await
    .unwrap();
    // actors/workspaces/apps/memberships are seeded inside a tenant-scoped
    // transaction exactly like production code does.
    let mut tx = owner.begin().await.unwrap();
    sqlx::query(&format!("SET LOCAL app.organization_id = '{org_id}'"))
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO actors (id, organization_id, display_name, handle) VALUES ($1, $2, 'sys-scope', 'sys-scope')",
    )
    .bind(actor_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO memberships (actor_id, organization_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(actor_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // The app role with no tenant context must still see NOTHING:
    // RLS is enabled, fail-closed, on every table. This assertion runs
    // BEFORE the app pool is ever given a tenant context: PostgreSQL
    // leaves a recycled pooled connection at app.organization_id = ''
    // (see 0017), which would trip the unhardened identity-table policy
    // with a uuid parse error instead of clean "no rows".
    {
        let fresh_app = sqlx::PgPool::connect(&env("TINKER_CORE_URL"))
            .await
            .unwrap();
        let app_sees: i64 =
            sqlx::query_scalar("SELECT count(*) FROM auth_credentials WHERE subject=$1")
                .bind(&subject)
                .fetch_one(&fresh_app)
                .await
                .unwrap();
        assert_eq!(app_sees, 0, "app role without tenant context stays blind");
        fresh_app.close().await;
    }

    // Bind an OIDC credential the way SessionManager::bind_oidc does:
    // through the APP pool with a transaction-local tenant context.
    let mut atx = app.begin().await.unwrap();
    sqlx::query(&format!("SET LOCAL app.organization_id = '{org_id}'"))
        .execute(&mut *atx)
        .await
        .unwrap();
    sqlx::query(&format!("SET LOCAL app.actor_id = '{actor_id}'"))
        .execute(&mut *atx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO auth_credentials
         (organization_id, actor_id, method, credential_id, issuer, subject)
         VALUES ($1, $2, 'oidc', $3, $4, $5)",
    )
    .bind(org_id)
    .bind(actor_id)
    .bind(format!("sys-scope-cred-{org_id}"))
    .bind(&issuer)
    .bind(&subject)
    .execute(&mut *atx)
    .await
    .unwrap();
    atx.commit().await.unwrap();

    // Owner / system pool with NO tenant GUCs: the pre-tenant lookups.
    let binding: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT actor_id FROM auth_credentials
         WHERE method='oidc' AND issuer=$1 AND subject=$2 AND revoked_at IS NULL",
    )
    .bind(&issuer)
    .bind(&subject)
    .fetch_optional(&owner)
    .await
    .unwrap();
    assert_eq!(binding, Some(actor_id), "owner must see the OIDC binding");

    let orgs: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT organization_id FROM memberships WHERE actor_id = $1")
            .bind(actor_id)
            .fetch_all(&owner)
            .await
            .unwrap();
    assert_eq!(orgs, vec![org_id], "owner must see memberships");

    let seen_actor: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_optional(&owner)
        .await
        .unwrap();
    assert_eq!(seen_actor, Some(actor_id), "owner must see actors");

    // Cleanup (owner bypasses RLS; app role cannot delete cross-context).
    sqlx::query("DELETE FROM auth_credentials WHERE subject=$1")
        .bind(&subject)
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query("DELETE FROM organizations WHERE id=$1")
        .bind(org_id)
        .execute(&owner)
        .await
        .unwrap();
    sqlx::query("DELETE FROM hosts WHERE id=$1")
        .bind(host_id)
        .execute(&owner)
        .await
        .unwrap();
}

#[tokio::test]
async fn extensions_are_bootstrap_installed() {
    // The bootstrap installs extensions as the postgres superuser, so
    // the least-privilege owners hit IF NOT EXISTS no-ops in 0001/0005.
    let core = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let pii = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
        .await
        .unwrap();
    for ext in ["pgcrypto", "pg_trgm"] {
        let n: (i64,) = sqlx::query_as("SELECT count(*) FROM pg_extension WHERE extname=$1")
            .bind(ext)
            .fetch_one(&core)
            .await
            .unwrap();
        assert_eq!(n.0, 1, "core must have {ext} (bootstrap-installed)");
    }
    let n: (i64,) = sqlx::query_as("SELECT count(*) FROM pg_extension WHERE extname='pgcrypto'")
        .fetch_one(&pii)
        .await
        .unwrap();
    assert_eq!(n.0, 1, "pii must have pgcrypto (bootstrap-installed)");
}

// NOTE: the retained CREATEROLE's purpose — ALTER ROLE on the app
// roles — is proven end-to-end by
// `app_role_passwords::rotation_evicts_published_default_passwords`,
// which rotates via owner handles and would fail without it. No
// password is flipped here: this binary's tests share the cluster
// with nothing, but the app password is load-bearing for every other
// suite.
