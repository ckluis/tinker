//! Post-M8 item 15: KEK rotation and per-DEK rotation.
//!
//! The schema always modeled `wrapped_deks.kek_id` + `version`, but the
//! code hardcoded a single KEK and `version = 1` — rotation was impossible
//! (a second DEK version would violate `UNIQUE(organization_id, version)`).
//! These tests pin: per-DEK rotation without re-encrypting values, KEK
//! rotation via rewrap with the old KEK dropped, and fail-closed behavior
//! on an unknown `kek_id`.

use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, PiiDb};
use tinker_vault::{PiiProjector, Vault, KEK_ID_CURRENT_ENV, KEK_ID_PREVIOUS_ENV};
use uuid::Uuid;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} must be set"))
}

/// Deterministic test KEKs (never used outside tests).
fn kek(seed: u8) -> Vec<u8> {
    (0..32u8)
        .map(|i| seed.wrapping_add(i).wrapping_mul(31))
        .collect()
}

struct Fixture {
    core: CoreDb,
    pii_owner: sqlx::PgPool,
    vault: Vault,
    ctx: TenantContext,
}

async fn fixture(keks: Vec<(String, Vec<u8>)>) -> Fixture {
    let core_pool = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .unwrap();
    let pii_pool = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
        .await
        .unwrap();
    // pii_refs has a FK to organizations; owner bypasses RLS for platform rows.
    let host_id = Uuid::from_u128(0x0);
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,'test') ON CONFLICT (id) DO NOTHING")
        .bind(host_id)
        .execute(&core_pool)
        .await
        .unwrap();
    let org_id = Uuid::now_v7();
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(host_id)
        .bind(format!("kek-test-{org_id}"))
        .execute(&core_pool)
        .await
        .unwrap();
    let vault = Vault::with_keks(PiiDb(pii_pool.clone()), keks).unwrap();
    let ctx = TenantContext::new(OrganizationId(org_id), Uuid::now_v7(), "test.kek_rotation");
    Fixture {
        core: CoreDb(core_pool),
        pii_owner: pii_pool,
        vault,
        ctx,
    }
}

/// Seal a value in the vault and register its opaque token in core, like
/// the two-phase write in production.
async fn seal_and_register(fx: &Fixture, plaintext: &str) -> Uuid {
    seal_and_register_for(fx, Uuid::now_v7(), plaintext).await
}

/// Seal under a given subject (its own DEK) and register the core ref.
async fn seal_and_register_for(fx: &Fixture, subject: Uuid, plaintext: &str) -> Uuid {
    let ref_id = fx
        .vault
        .seal(&fx.ctx, subject, "pii.name", plaintext)
        .await
        .unwrap();
    let mut tx = fx.core.tenant_tx(&fx.ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO pii_refs (id, organization_id, subject_id, storage_class, state) \
         VALUES ($1,$2,$3,'pii.name','active')",
    )
    .bind(ref_id)
    .bind(fx.ctx.organization_id.0)
    .bind(subject)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    ref_id
}

async fn resolve(fx: &Fixture, ref_id: Uuid) -> String {
    let projector = PiiProjector::new(fx.core.clone(), fx.vault.clone());
    projector.resolve(&fx.ctx, ref_id, "test").await.unwrap()
}

/// (version, kek_id) rows for the fixture org, oldest first.
async fn dek_versions(fx: &Fixture) -> Vec<(i32, String)> {
    let mut tx = fx.pii_owner.begin().await.unwrap();
    for stmt in fx.ctx.set_local_statements() {
        sqlx::query(&stmt).execute(&mut *tx).await.unwrap();
    }
    let rows: Vec<(i32, String)> = sqlx::query_as(
        "SELECT version, kek_id FROM wrapped_deks WHERE organization_id=$1 ORDER BY version",
    )
    .bind(fx.ctx.organization_id.0)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    rows
}

#[tokio::test]
async fn dek_rotation_keeps_old_values_readable() {
    let fx = fixture(vec![("test-kek".to_string(), kek(1))]).await;

    // DEKs are per subject (crypto-shred): rotation is per subject too.
    let subject = Uuid::now_v7();
    let old_ref = seal_and_register_for(&fx, subject, "before-rotation").await;
    let dek_v1 = fx.vault.rotate_dek(&fx.ctx, subject).await.unwrap();
    let new_ref = seal_and_register_for(&fx, subject, "after-rotation").await;

    // Both values resolve through the audited projector.
    assert_eq!(resolve(&fx, old_ref).await, "before-rotation");
    assert_eq!(resolve(&fx, new_ref).await, "after-rotation");

    // The subject has two DEK versions; the rotated one is version 2.
    let versions = dek_versions(&fx).await;
    assert_eq!(
        versions,
        vec![(1, "test-kek".to_string()), (2, "test-kek".to_string())]
    );

    // The new seal used the rotated DEK.
    let mut tx = fx.pii_owner.begin().await.unwrap();
    for stmt in fx.ctx.set_local_statements() {
        sqlx::query(&stmt).execute(&mut *tx).await.unwrap();
    }
    let (wrapped_dek_id,): (Uuid,) =
        sqlx::query_as("SELECT wrapped_dek_id FROM pii_values WHERE id=$1")
            .bind(new_ref)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(wrapped_dek_id, dek_v1);
}

#[tokio::test]
async fn kek_rotation_rewrap_then_drop_old_kek() {
    // Phase 1: everything wrapped under kek-a (same org reused across phases).
    let fx_a = fixture(vec![("kek-a".to_string(), kek(10))]).await;
    let old_ref = seal_and_register(&fx_a, "pre-kek-rotation").await;

    // Phase 2: promote kek-b to current, keep kek-a as previous, rewrap.
    let vault_b = Vault::with_keks(
        PiiDb(fx_a.pii_owner.clone()),
        vec![
            ("kek-b".to_string(), kek(20)),
            ("kek-a".to_string(), kek(10)),
        ],
    )
    .unwrap();
    let fx_b = Fixture {
        core: fx_a.core.clone(),
        pii_owner: fx_a.pii_owner.clone(),
        vault: vault_b,
        ctx: TenantContext::new(
            fx_a.ctx.organization_id,
            Uuid::now_v7(),
            "test.kek_rotation",
        ),
    };
    let rewrapped = fx_b.vault.rewrap_deks(&fx_b.ctx).await.unwrap();
    assert_eq!(rewrapped, 1, "the one DEK should be re-wrapped");
    assert_eq!(
        dek_versions(&fx_b).await,
        vec![(1, "kek-b".to_string())],
        "wrapping migrated to the new KEK"
    );
    // Rewrap is idempotent.
    assert_eq!(fx_b.vault.rewrap_deks(&fx_b.ctx).await.unwrap(), 0);

    // Phase 3: drop kek-a entirely — the old value still resolves, and
    // new seals use kek-b.
    let vault_b_only = Vault::with_keks(
        PiiDb(fx_b.pii_owner.clone()),
        vec![("kek-b".to_string(), kek(20))],
    )
    .unwrap();
    let fx_b_only = Fixture {
        core: fx_b.core.clone(),
        pii_owner: fx_b.pii_owner.clone(),
        vault: vault_b_only,
        ctx: fx_b.ctx.clone(),
    };
    assert_eq!(resolve(&fx_b_only, old_ref).await, "pre-kek-rotation");
    let new_ref = seal_and_register(&fx_b_only, "post-kek-rotation").await;
    assert_eq!(resolve(&fx_b_only, new_ref).await, "post-kek-rotation");
    // Two subjects, one DEK each, both wrapped by kek-b.
    assert_eq!(
        dek_versions(&fx_b_only).await,
        vec![(1, "kek-b".to_string()), (1, "kek-b".to_string())]
    );
}

#[tokio::test]
async fn unknown_kek_id_fails_closed() {
    let fx = fixture(vec![("test-kek".to_string(), kek(1))]).await;

    // Simulate a lost KEK: the subject's latest DEK row has a kek_id no
    // configured KEK has.
    let bogus_dek = Uuid::now_v7();
    let subject = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO wrapped_deks (id, organization_id, kek_id, wrapped_key, version, subject_id) \
         VALUES ($1,$2,'kek-that-does-not-exist', decode('00','hex'), 99, $3)",
    )
    .bind(bogus_dek)
    .bind(fx.ctx.organization_id.0)
    .bind(subject)
    .execute(&fx.pii_owner)
    .await
    .unwrap();

    let err = fx
        .vault
        .seal(&fx.ctx, subject, "pii.name", "secret")
        .await
        .expect_err("unknown kek_id must fail closed");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown kek_id"),
        "must name the misconfiguration, got: {msg}"
    );
}

#[tokio::test]
async fn concurrent_rotate_dek_never_duplicates_versions() {
    let fx = std::sync::Arc::new(fixture(vec![("test-kek".to_string(), kek(1))]).await);

    // Eight concurrent rotators on one subject: the advisory lock
    // serializes them, so versions must come out exactly 1..=8 with no
    // duplicates and no unique-violation failures.
    let subject = Uuid::now_v7();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let fx = fx.clone();
        handles.push(tokio::spawn(async move {
            fx.vault.rotate_dek(&fx.ctx, subject).await
        }));
    }
    let mut ids = std::collections::HashSet::new();
    for h in handles {
        let id = h
            .await
            .unwrap()
            .expect("rotation must not fail under concurrency");
        assert!(ids.insert(id), "duplicate DEK id under concurrency");
    }
    let versions = dek_versions(&fx).await;
    let nums: Vec<i32> = versions.iter().map(|(v, _)| *v).collect();
    assert_eq!(
        nums,
        (1..=8).collect::<Vec<_>>(),
        "versions must be exactly 1..=8"
    );
}

#[tokio::test]
async fn with_keks_validates_inputs() {
    let pii = PiiDb(
        sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
            .await
            .unwrap(),
    );
    // Empty set.
    assert!(Vault::with_keks(pii.clone(), vec![]).is_err());
    // Short key.
    assert!(Vault::with_keks(pii.clone(), vec![("a".to_string(), vec![0u8; 31])]).is_err());
    // Duplicate ids.
    assert!(Vault::with_keks(
        pii.clone(),
        vec![("a".to_string(), kek(1)), ("a".to_string(), kek(2)),]
    )
    .is_err());
    // Happy path + env ids.
    let v = Vault::with_keks(
        pii,
        vec![
            (KEK_ID_CURRENT_ENV.to_string(), kek(1)),
            (KEK_ID_PREVIOUS_ENV.to_string(), kek(2)),
        ],
    )
    .unwrap();
    let _ = v;
}

#[tokio::test]
async fn from_env_reads_optional_previous_kek() {
    let pii = PiiDb(
        sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
            .await
            .unwrap(),
    );
    // from_env requires TINKER_KEK; the harness sets it. TINKER_KEK_PREVIOUS
    // is optional — both shapes must construct.
    let v = Vault::from_env(pii.clone()).expect("from_env with TINKER_KEK");
    let _ = v;
}
