//! Item 23: governed file/blob subsystem (Directus C7).
//!
//! - store/fetch round-trip with sha256 integrity, dedup, tenant
//!   isolation, size caps, mime validation, PII classes.
//! - Tampered backend bytes fail closed on fetch.
//! - Delete removes bytes + marks the row; retention deletes expired
//!   bytes honoring legal_hold.
//! - Every access leaves an audit_events row; bytes never touch PG.

mod common;

use common::*;
use std::sync::Arc;
use tinker_agents::files::{FileBackend, FileStore, FsFileBackend, PiiClass};
use tinker_core::{TenantContext, TinkerError};
use uuid::Uuid;

fn tmp_root(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "tinker-files-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn store_for(env: &AgentEnv, tag: &str) -> (FileStore, std::path::PathBuf) {
    let root = tmp_root(tag);
    let backend = Arc::new(FsFileBackend::new(root.clone()));
    (FileStore::new(env.core.clone(), backend), root)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn store_fetch_round_trip() {
    let env = setup().await;
    let (store, _root) = store_for(&env, "roundtrip");
    let bytes = b"hello governed world";

    let r = store
        .store(
            &env.exec_ctx,
            "greeting.txt",
            "text/plain",
            PiiClass::None,
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(r.name, "greeting.txt");
    assert_eq!(r.mime, "text/plain");
    assert_eq!(r.byte_size, bytes.len() as i64);
    assert_eq!(r.sha256, sha256_hex(bytes));
    assert_eq!(r.pii_class, PiiClass::None);

    let (got, out) = store.fetch(&env.exec_ctx, r.id).await.unwrap();
    assert_eq!(got.id, r.id);
    assert_eq!(out, bytes);

    // Audit trail: store + fetch.
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE organization_id = $1 AND resource_type = 'stored_file'
           AND resource_id = $2 AND action IN ('file.store', 'file.fetch')",
    )
    .bind(env.org_id)
    .bind(r.id.to_string())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(n >= 2, "expected store+fetch audit rows, got {n}");
}

#[tokio::test]
async fn duplicate_bytes_dedup_to_one_row() {
    let env = setup().await;
    let (store, _root) = store_for(&env, "dedup");
    let bytes = b"same bytes";

    let a = store
        .store(
            &env.exec_ctx,
            "a.bin",
            "application/octet-stream",
            PiiClass::None,
            bytes,
        )
        .await
        .unwrap();
    let b = store
        .store(
            &env.exec_ctx,
            "b.bin",
            "application/octet-stream",
            PiiClass::None,
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(a.id, b.id, "same org + bytes dedups");

    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM stored_files WHERE organization_id = $1 AND sha256 = $2",
    )
    .bind(env.org_id)
    .bind(a.sha256.clone())
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn tenant_isolation() {
    let env = setup().await;
    let (store, _root) = store_for(&env, "isolation");
    let bytes = b"org secret";

    let r = store
        .store(
            &env.exec_ctx,
            "s.txt",
            "text/plain",
            PiiClass::Restricted,
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(r.pii_class, PiiClass::Restricted);

    // Another tenant's context cannot see or fetch the file.
    let other_ctx = TenantContext::new(
        tinker_core::OrganizationId(Uuid::new_v4()),
        Uuid::new_v4(),
        "tinker-test",
    );
    let err = store.fetch(&other_ctx, r.id).await.unwrap_err();
    assert!(
        matches!(err, TinkerError::NotFound(_)),
        "cross-tenant fetch must 404, got {err:?}"
    );
    let err = store.assert_reference(&other_ctx, r.id).await.unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));

    // Same bytes in another org are a separate row (per-org dedup).
    let other_org_id = Uuid::new_v4();
    // (no org row needed: stored_files.organization_id has an FK to
    // organizations — use the employee/contractor org? All three ctx
    // share one org. Create a second org properly.)
    let mut otx = env.owner.0.begin().await.unwrap();
    let host2 = Uuid::now_v7();
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1, 'iso2-host')")
        .bind(host2)
        .execute(&mut *otx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO organizations (id, host_id, slug, name) VALUES ($1, $2, 'iso2', 'Iso2')",
    )
    .bind(other_org_id)
    .bind(host2)
    .execute(&mut *otx)
    .await
    .unwrap();
    otx.commit().await.unwrap();
    let other_ctx2 = TenantContext::new(
        tinker_core::OrganizationId(other_org_id),
        Uuid::new_v4(),
        "tinker-test",
    );
    let r2 = store
        .store(&other_ctx2, "s.txt", "text/plain", PiiClass::None, bytes)
        .await
        .unwrap();
    assert_ne!(r.id, r2.id, "dedup is per-org");
}

#[tokio::test]
async fn validation_rejects_bad_inputs() {
    let env = setup().await;
    let (store, _root) = store_for(&env, "validation");

    let err = store
        .store(&env.exec_ctx, "x", "not-a-mime", PiiClass::None, b"hi")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "bad mime: {err:?}"
    );

    let err = store
        .store(&env.exec_ctx, "", "text/plain", PiiClass::None, b"hi")
        .await
        .unwrap_err();
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "empty name: {err:?}"
    );

    // Size cap via env (all other payloads in this file are < 16 bytes,
    // so the temporary cap cannot break parallel tests).
    std::env::set_var("TINKER_MAX_FILE_BYTES", "16");
    let err = store
        .store(
            &env.exec_ctx,
            "big.bin",
            "application/octet-stream",
            PiiClass::None,
            b"0123456789abcdefg",
        )
        .await
        .unwrap_err();
    std::env::remove_var("TINKER_MAX_FILE_BYTES");
    assert!(
        matches!(err, TinkerError::Validation(_)),
        "oversize must fail: {err:?}"
    );
}

#[tokio::test]
async fn tampered_backend_bytes_fail_closed() {
    let env = setup().await;
    let (store, root) = store_for(&env, "tamper");
    let bytes = b"pristine";

    let r = store
        .store(&env.exec_ctx, "p.txt", "text/plain", PiiClass::None, bytes)
        .await
        .unwrap();
    // Attacker swaps the bytes on the backend.
    let key = format!("{}/{}", &r.sha256[..2], r.sha256);
    let path = root.join(env.org_id.to_string()).join(&key);
    std::fs::write(&path, b"tampered!!").unwrap();

    let err = store.fetch(&env.exec_ctx, r.id).await.unwrap_err();
    assert!(
        matches!(err, TinkerError::Internal(_)),
        "integrity failure must fail closed: {err:?}"
    );
    assert!(err.to_string().contains("integrity"));

    // The integrity failure is audited.
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events
         WHERE organization_id = $1 AND action = 'file.fetch' AND status = 'integrity_failure'",
    )
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn delete_removes_bytes_and_row() {
    let env = setup().await;
    let (store, root) = store_for(&env, "delete");
    let bytes = b"bye";

    let r = store
        .store(&env.exec_ctx, "d.txt", "text/plain", PiiClass::None, bytes)
        .await
        .unwrap();
    let key = format!("{}/{}", &r.sha256[..2], r.sha256);
    let path = root.join(env.org_id.to_string()).join(&key);
    assert!(path.exists());

    store.delete(&env.exec_ctx, r.id).await.unwrap();
    assert!(!path.exists(), "backend bytes removed");

    let err = store.fetch(&env.exec_ctx, r.id).await.unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));
    let err = store
        .assert_reference(&env.exec_ctx, r.id)
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::Validation(_)));

    // Idempotent: second delete is a no-op.
    store.delete(&env.exec_ctx, r.id).await.unwrap();
}

#[tokio::test]
async fn retention_deletes_expired_bytes_and_honors_hold() {
    let env = setup().await;
    let (store, root) = store_for(&env, "retention");
    let bytes = b"old";

    let r = store
        .store(&env.exec_ctx, "o.txt", "text/plain", PiiClass::None, bytes)
        .await
        .unwrap();

    // Policy: 0 days; backdate the file so it is expired.
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    sqlx::query(
        "INSERT INTO retention_policies (organization_id, object_key, retention_days)
         VALUES ($1, 'stored_files', 0)
         ON CONFLICT (organization_id, object_key) DO UPDATE SET retention_days = 0",
    )
    .bind(env.org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE stored_files SET created_at = now() - interval '2 days'
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(env.org_id)
    .bind(r.id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    // Legal hold suspends deletion.
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    sqlx::query(
        "UPDATE retention_policies SET legal_hold = true
         WHERE organization_id = $1 AND object_key = 'stored_files'",
    )
    .bind(env.org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let outcome = store
        .apply_retention(&env.exec_ctx, "stored_files")
        .await
        .unwrap();
    assert!(outcome.skipped_legal_hold);
    assert_eq!(outcome.deleted, 0);
    store
        .fetch(&env.exec_ctx, r.id)
        .await
        .expect("held file survives");

    // Release the hold: bytes AND row go.
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    sqlx::query(
        "UPDATE retention_policies SET legal_hold = false
         WHERE organization_id = $1 AND object_key = 'stored_files'",
    )
    .bind(env.org_id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let outcome = store
        .apply_retention(&env.exec_ctx, "stored_files")
        .await
        .unwrap();
    assert!(!outcome.skipped_legal_hold);
    assert_eq!(outcome.deleted, 1);
    let key = format!("{}/{}", &r.sha256[..2], r.sha256);
    assert!(
        !root.join(env.org_id.to_string()).join(&key).exists(),
        "retention must delete backend bytes, not just rows"
    );
    assert!(matches!(
        store.fetch(&env.exec_ctx, r.id).await.unwrap_err(),
        TinkerError::NotFound(_)
    ));

    // last_run bookkeeping recorded.
    let mut tx = env.core.tenant_tx(&env.exec_ctx).await.unwrap();
    let last: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT last_run_result FROM retention_policies
         WHERE organization_id = $1 AND object_key = 'stored_files'",
    )
    .bind(env.org_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(last.unwrap()["deleted"], 1);
}

#[tokio::test]
async fn retention_without_policy_fails_closed() {
    let env = setup().await;
    let (store, _root) = store_for(&env, "retention-nopolicy");
    let err = store
        .apply_retention(&env.exec_ctx, "no_such_policy")
        .await
        .unwrap_err();
    assert!(matches!(err, TinkerError::NotFound(_)));
}

#[tokio::test]
async fn backend_rejects_escaping_keys() {
    let b = FsFileBackend::new(tmp_root("keys"));
    let org = Uuid::new_v4();
    for bad in ["../escape", "/absolute", "a/../../b"] {
        let err = b.store(org, bad, b"x").await.unwrap_err();
        assert!(
            matches!(err, TinkerError::Validation(_)),
            "key {bad:?} must be rejected: {err:?}"
        );
    }
}

#[tokio::test]
async fn reupload_after_delete_reactivates_with_fresh_metadata() {
    let env = setup().await;
    let (store, _root) = store_for(&env, "reupload");
    let bytes = b"v1 bytes";

    let v1 = store
        .store(
            &env.exec_ctx,
            "old-name.txt",
            "text/plain",
            PiiClass::None,
            bytes,
        )
        .await
        .unwrap();
    store.delete(&env.exec_ctx, v1.id).await.unwrap();

    // Same bytes, new upload: same row reactivated, metadata refreshed.
    let v2 = store
        .store(
            &env.exec_ctx,
            "new-name.txt",
            "text/plain",
            PiiClass::Pii,
            bytes,
        )
        .await
        .unwrap();
    assert_eq!(v1.id, v2.id);
    assert_eq!(v2.name, "new-name.txt");
    assert_eq!(v2.pii_class, PiiClass::Pii);

    let (got, out) = store.fetch(&env.exec_ctx, v2.id).await.unwrap();
    assert_eq!(got.name, "new-name.txt");
    assert_eq!(out, bytes);
}
