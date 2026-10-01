//! M0 PII exits: PII values never mix with operational rows. The core
//! holds opaque random tokens; the vault holds ciphertext; core SQL cannot
//! reach the vault — not even by join.

mod common;

use tinker_core::{TenantContext, TinkerError};
use tinker_vault::{PiiProjector, Vault};
use uuid::Uuid;

fn vault(env: &common::Env) -> Vault {
    let kek_hex = std::env::var("TINKER_KEK").expect("TINKER_KEK must be set");
    let bytes: Vec<u8> = (0..kek_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&kek_hex[i..i + 2], 16).unwrap())
        .collect();
    Vault::new(env.pii.clone(), &bytes).unwrap()
}

/// Full two-phase write: seal in the vault, commit the opaque token in core.
async fn seal_contact(
    env: &common::Env,
    ctx: &TenantContext,
    v: &Vault,
    name: &str,
    email: &str,
) -> (Uuid, Uuid) {
    let subject = Uuid::now_v7();
    let name_ref = v.seal(ctx, subject, "pii.name", name).await.unwrap();
    let email_ref = v.seal(ctx, subject, "pii.email", email).await.unwrap();
    let mut tx = env.core.tenant_tx(ctx).await.unwrap();
    for r in [name_ref, email_ref] {
        sqlx::query(
            "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state) \
             VALUES ($1,$2,$3,'pii.name','active')",
        )
        .bind(r)
        .bind(ctx.organization_id.0)
        .bind(subject)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    (subject, name_ref)
}

#[tokio::test]
async fn two_phase_projection_round_trips() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let v = vault(&env);
    let projector = PiiProjector::new(env.core.clone(), vault(&env));

    let (_subject, name_ref) = seal_contact(&env, &ctx, &v, "Maya Chen", "maya@example.com").await;

    let name = projector
        .resolve(&ctx, name_ref, "support ticket #42")
        .await
        .unwrap();
    assert_eq!(name, "Maya Chen");

    // The disclosure was audited with metadata only — never the value.
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let (action, meta): (String, serde_json::Value) =
        sqlx::query_as("SELECT action, metadata FROM audit_events WHERE resource_id=$1")
            .bind(name_ref.to_string())
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(action, "pii.resolve");
    assert!(!meta.to_string().contains("Maya Chen"));
    assert_eq!(meta["purpose"], serde_json::json!("support ticket #42"));
}

#[tokio::test]
async fn core_sql_cannot_reach_pii() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let v = vault(&env);
    let (_subject, name_ref) = seal_contact(&env, &ctx, &v, "Maya Chen", "maya@example.com").await;

    // The core database has NO pii_values table at all.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM information_schema.tables \
         WHERE table_schema='public' AND table_name='pii_values'",
    )
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(n, 0);

    // No foreign-data machinery that could bridge the two stores.
    let n: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_extension WHERE extname IN ('postgres_fdw','dblink')",
    )
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    assert_eq!(n, 0);

    // The core reference row is an opaque token: no name, no email, no
    // ciphertext — just the random id, the subject id, and the class label.
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let row: (Uuid, Uuid, String, String) =
        sqlx::query_as("SELECT id, subject_id, storage_class, state FROM pii_refs WHERE id=$1")
            .bind(name_ref)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(row.0, name_ref);
    assert_eq!(row.2, "pii.name");
    assert_eq!(row.3, "active");

    // The vault row is ciphertext: it does not contain the plaintext.
    let raw: Vec<u8> = sqlx::query_scalar("SELECT ciphertext FROM pii_values WHERE id=$1")
        .bind(name_ref)
        .fetch_one(&env.pii_owner)
        .await
        .unwrap();
    assert!(!raw.windows(b"Maya Chen".len()).any(|w| w == b"Maya Chen"));
}

#[tokio::test]
async fn cross_org_pii_refs_do_not_resolve() {
    let env = common::setup().await;
    let ctx_a = common::new_org(&env, &common::uniq("orga")).await;
    let ctx_b = common::new_org(&env, &common::uniq("orgb")).await;
    let v = vault(&env);
    let projector = PiiProjector::new(env.core.clone(), vault(&env));

    let (_subject, name_ref) =
        seal_contact(&env, &ctx_a, &v, "Maya Chen", "maya@example.com").await;

    // Org B cannot even see the reference row (core RLS), so resolve fails
    // closed before touching the vault.
    let err = projector
        .resolve(&ctx_b, name_ref, "snooping")
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));

    // And the vault's own RLS blocks org B's app-role reads of org A's rows.
    let mut ptx = env.pii.tenant_tx(&ctx_b).await.unwrap();
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM pii_values WHERE id=$1")
        .bind(name_ref)
        .fetch_one(&mut *ptx)
        .await
        .unwrap();
    ptx.commit().await.unwrap();
    assert_eq!(n, 0, "vault rows are organization-scoped");
}

#[tokio::test]
async fn destroy_erases_the_value() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let v = vault(&env);
    let projector = PiiProjector::new(env.core.clone(), vault(&env));

    let (_subject, name_ref) = seal_contact(&env, &ctx, &v, "Maya Chen", "maya@example.com").await;

    // Tombstone the core reference, destroy the ciphertext.
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    sqlx::query("UPDATE pii_refs SET state='tombstoned' WHERE id=$1")
        .bind(name_ref)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    v.destroy(&ctx, name_ref).await.unwrap();

    // Tombstoned references no longer resolve.
    let err = projector
        .resolve(&ctx, name_ref, "after erasure")
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)));

    // The ciphertext row is gone from the vault.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM pii_values WHERE id=$1")
        .bind(name_ref)
        .fetch_one(&env.pii_owner)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn pending_refs_do_not_resolve() {
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let v = vault(&env);
    let projector = PiiProjector::new(env.core.clone(), vault(&env));

    // Seal in the vault but leave the core reference pending (phase 1 of
    // the two-phase write, before core commit).
    let subject = Uuid::now_v7();
    let r = v
        .seal(&ctx, subject, "pii.name", "Maya Chen")
        .await
        .unwrap();
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state) \
         VALUES ($1,$2,$3,'pii.name','pending')",
    )
    .bind(r)
    .bind(ctx.organization_id.0)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let err = projector.resolve(&ctx, r, "too early").await.unwrap_err();
    assert!(matches!(err, TinkerError::Forbidden(_)));
}

#[tokio::test]
async fn concurrent_first_seals_share_one_dek() {
    // Adversarial: N concurrent first-time seals on a fresh org race the
    // DEK creation path. Without serialization the losers would seal under
    // keys that were never persisted (unrecoverable ciphertext).
    let env = common::setup().await;
    let ctx = common::new_org(&env, &common::uniq("org")).await;
    let v = vault(&env);

    let mut handles = Vec::new();
    for i in 0..8u32 {
        let vv = v.clone();
        let cc = ctx.clone();
        handles.push(tokio::spawn(async move {
            let subject = Uuid::now_v7();
            let r = vv
                .seal(&cc, subject, "pii.name", &format!("Person {i}"))
                .await
                .unwrap();
            (subject, r, format!("Person {i}"))
        }));
    }
    let mut sealed = Vec::new();
    for h in handles {
        sealed.push(h.await.unwrap());
    }

    // Exactly one DEK was created for the org.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM wrapped_deks WHERE organization_id=$1")
        .bind(ctx.organization_id.0)
        .fetch_one(&env.pii_owner)
        .await
        .unwrap();
    assert_eq!(n, 1, "concurrent creators must converge on one DEK");

    // Every sealed value resolves: no ciphertext was sealed under a lost key.
    let projector = PiiProjector::new(env.core.clone(), vault(&env));
    for (subject, r, expected) in sealed {
        let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
        sqlx::query(
            "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state) \
             VALUES ($1,$2,$3,'pii.name','active')",
        )
        .bind(r)
        .bind(ctx.organization_id.0)
        .bind(subject)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let got = projector.resolve(&ctx, r, "race test").await.unwrap();
        assert_eq!(got, expected);
    }
}
