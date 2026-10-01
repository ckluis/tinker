//! PII vault projector (PRD §41).
//!
//! The core database holds opaque random tokens ([`pii_refs`]); this crate
//! owns the only normal path that resolves them to values. Envelope
//! encryption: per-organization DEKs wrapped by a host KEK. Plaintext exists
//! only inside [`PiiProjector::resolve`] and is never logged.
//!
//! KEK rotation: the [`Vault`] holds a versioned KEK set keyed by `kek_id`.
//! New DEKs are wrapped with the current KEK; [`Vault::rotate_dek`]
//! versions the DEK without re-encrypting values; [`Vault::rewrap_deks`]
//! migrates wrappings to the current KEK so a retired KEK can be dropped.
//!
//! There is deliberately NO join between the core store and the PII store:
//! references are correlated in application code, never in SQL.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, PiiDb};
use uuid::Uuid;

const NONCE_LEN: usize = 12;

fn aes(key: &[u8]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|e| TinkerError::Internal(format!("bad key length: {e}")))
}

fn seal_bytes(key: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = aes(key)?
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| TinkerError::Internal(format!("encrypt failed: {e}")))?;
    Ok((nonce.to_vec(), ct))
}

fn open_bytes(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    aes(key)?
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| TinkerError::Forbidden("decryption failed".into()))
}

/// The vault: PII-store handle plus the host KEK set.
///
/// The KEK is versioned by `kek_id`: the first entry is the *current* KEK
/// (new DEKs are wrapped with it); the rest are retired KEKs retained so
/// DEKs wrapped before a rotation still decrypt. In production the KEKs
/// come from KMS/HSM; M0 takes them from the environment (`TINKER_KEK`,
/// plus optional `TINKER_KEK_PREVIOUS`).
#[derive(Clone)]
pub struct Vault {
    pii: PiiDb,
    keks: Vec<(String, [u8; 32])>,
}

/// `kek_id` for the KEK taken from `TINKER_KEK`.
pub const KEK_ID_CURRENT_ENV: &str = "env:tinker_kek";
/// `kek_id` for the retired KEK taken from `TINKER_KEK_PREVIOUS`.
pub const KEK_ID_PREVIOUS_ENV: &str = "env:tinker_kek_previous";

impl Vault {
    pub fn new(pii: PiiDb, kek: &[u8]) -> Result<Self> {
        Self::with_keks(pii, vec![(KEK_ID_CURRENT_ENV.to_string(), kek.to_vec())])
    }

    /// Multiple KEKs: the first entry is current (wraps new DEKs); the
    /// rest are retired but still decrypt DEKs carrying their `kek_id`.
    /// Ids must be unique and every key 32 bytes.
    pub fn with_keks(pii: PiiDb, keks: Vec<(String, Vec<u8>)>) -> Result<Self> {
        if keks.is_empty() {
            return Err(TinkerError::Validation(
                "at least one KEK is required".into(),
            ));
        }
        let mut ids = std::collections::HashSet::new();
        let mut out = Vec::with_capacity(keks.len());
        for (id, raw) in keks {
            if raw.len() != 32 {
                return Err(TinkerError::Validation(format!(
                    "KEK '{id}' must be 32 bytes"
                )));
            }
            if !ids.insert(id.clone()) {
                return Err(TinkerError::Validation(format!("duplicate kek_id '{id}'")));
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&raw);
            out.push((id, k));
        }
        Ok(Self { pii, keks: out })
    }

    pub fn from_env(pii: PiiDb) -> Result<Self> {
        let current = hex_kek(
            &std::env::var("TINKER_KEK")
                .map_err(|_| TinkerError::Validation("TINKER_KEK not set".into()))?,
        )?;
        let mut keks = vec![(KEK_ID_CURRENT_ENV.to_string(), current.to_vec())];
        if let Ok(prev_hex) = std::env::var("TINKER_KEK_PREVIOUS") {
            keks.push((
                KEK_ID_PREVIOUS_ENV.to_string(),
                hex_kek(&prev_hex)?.to_vec(),
            ));
        }
        Self::with_keks(pii, keks)
    }

    fn current_kek_id(&self) -> &str {
        &self.keks[0].0
    }

    fn current_kek(&self) -> &[u8; 32] {
        &self.keks[0].1
    }

    /// Look up the KEK that wrapped a DEK. Fails closed with a distinct
    /// error when the `kek_id` is unknown — a lost KEK is operator
    /// misconfiguration, and silently trying the wrong key would also be
    /// a decryption oracle.
    fn kek_for(&self, kek_id: &str) -> Result<&[u8; 32]> {
        self.keks
            .iter()
            .find(|(id, _)| id == kek_id)
            .map(|(_, k)| k)
            .ok_or_else(|| {
                TinkerError::Internal(format!(
                    "unknown kek_id '{kek_id}' — KEK rotation incomplete or KEK lost"
                ))
            })
    }

    /// Serialize DEK management per organization. Without this, two
    /// concurrent creators both miss the fast path, generate different
    /// DEKs, and the loser's key would never be persisted — any
    /// ciphertext sealed under it would be unrecoverable. The advisory
    /// lock is transaction-scoped: it releases on commit/rollback.
    async fn lock_deks(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, org: Uuid) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("tinker:dek:{org}"))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Wrap a fresh random DEK with the current KEK and persist it as
    /// `version` for the org. Callers hold the advisory lock; the
    /// UNIQUE(organization_id, version) constraint is the backstop.
    async fn create_dek_version(
        &self,
        ctx: &TenantContext,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        version: i32,
    ) -> Result<([u8; 32], Uuid)> {
        let mut dek = [0u8; 32];
        OsRng.fill_bytes(&mut dek);
        let (nonce, ct) = seal_bytes(self.current_kek(), &dek)?;
        let mut wrapped = nonce;
        wrapped.extend_from_slice(&ct);
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO wrapped_deks (id, organization_id, kek_id, wrapped_key, version) \
             VALUES ($1,$2,$3,$4,$5)",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(self.current_kek_id())
        .bind(&wrapped)
        .bind(version)
        .execute(&mut **tx)
        .await?;
        Ok((dek, id))
    }

    /// Highest DEK version for the org, or 0 when the org has no DEK yet.
    async fn max_dek_version(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        org: Uuid,
    ) -> Result<i32> {
        let v: Option<i32> =
            sqlx::query_scalar("SELECT MAX(version) FROM wrapped_deks WHERE organization_id=$1")
                .bind(org)
                .fetch_one(&mut **tx)
                .await?;
        Ok(v.unwrap_or(0))
    }

    /// Get-or-create the organization's current DEK, unwrapped in memory only.
    /// Every access is tenant-pinned: RLS on the PII store is the backstop.
    async fn dek(&self, ctx: &TenantContext) -> Result<([u8; 32], Uuid)> {
        let mut tx = self.pii.tenant_tx(ctx).await?;
        Self::lock_deks(&mut tx, ctx.organization_id.0).await?;
        // Fast path: latest DEK version (re-checked under the lock, so a
        // concurrent creator's commit is visible here).
        let row: Option<(Uuid, String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, kek_id, wrapped_key FROM wrapped_deks \
             WHERE organization_id=$1 ORDER BY version DESC LIMIT 1",
        )
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((id, kek_id, wrapped)) = row {
            tx.commit().await?;
            let kek = self.kek_for(&kek_id)?;
            let (nonce, ct) = wrapped.split_at(NONCE_LEN);
            let raw = open_bytes(kek, nonce, ct)?;
            let mut k = [0u8; 32];
            k.copy_from_slice(&raw);
            return Ok((k, id));
        }
        // Create: version 1, wrapped by the current KEK. The wrapped bytes
        // stored are nonce || ciphertext.
        let (dek, id) = self.create_dek_version(ctx, &mut tx, 1).await?;
        tx.commit().await?;
        Ok((dek, id))
    }

    /// Rotate the organization's DEK: persist a fresh random DEK as the
    /// next version, wrapped by the current KEK. New seals use it
    /// immediately; existing values keep resolving through their stored
    /// `wrapped_dek_id` — no value is re-encrypted.
    pub async fn rotate_dek(&self, ctx: &TenantContext) -> Result<Uuid> {
        let mut tx = self.pii.tenant_tx(ctx).await?;
        Self::lock_deks(&mut tx, ctx.organization_id.0).await?;
        let version = Self::max_dek_version(&mut tx, ctx.organization_id.0).await? + 1;
        let (_, id) = self.create_dek_version(ctx, &mut tx, version).await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Re-wrap every DEK of the organization under the *current* KEK.
    /// This is the second half of KEK rotation: after promoting a new KEK
    /// to current (keeping the old one as previous so existing wrappings
    /// still open), rewrap migrates every wrapping to the new KEK, after
    /// which the retired KEK can be dropped from configuration. Values
    /// are untouched — only the 32-byte DEK wrappings change. Returns
    /// the number of DEKs re-wrapped.
    pub async fn rewrap_deks(&self, ctx: &TenantContext) -> Result<usize> {
        let mut tx = self.pii.tenant_tx(ctx).await?;
        Self::lock_deks(&mut tx, ctx.organization_id.0).await?;
        let rows: Vec<(Uuid, String, Vec<u8>)> = sqlx::query_as(
            "SELECT id, kek_id, wrapped_key FROM wrapped_deks WHERE organization_id=$1",
        )
        .bind(ctx.organization_id.0)
        .fetch_all(&mut *tx)
        .await?;
        let mut rewrapped = 0usize;
        for (id, kek_id, wrapped) in rows {
            if kek_id == self.current_kek_id() {
                continue;
            }
            // Unwrap with the retired KEK — fails closed on unknown kek_id.
            let old_kek = self.kek_for(&kek_id)?;
            let (nonce, ct) = wrapped.split_at(NONCE_LEN);
            let dek_raw = open_bytes(old_kek, nonce, ct)?;
            let (new_nonce, new_ct) = seal_bytes(self.current_kek(), &dek_raw)?;
            let mut new_wrapped = new_nonce;
            new_wrapped.extend_from_slice(&new_ct);
            sqlx::query("UPDATE wrapped_deks SET wrapped_key=$1, kek_id=$2 WHERE id=$3")
                .bind(&new_wrapped)
                .bind(self.current_kek_id())
                .bind(id)
                .execute(&mut *tx)
                .await?;
            rewrapped += 1;
        }
        tx.commit().await?;
        Ok(rewrapped)
    }

    /// Phase 1 of the two-phase write: store the ciphertext, return the
    /// opaque reference id. The caller commits the core `pii_refs` row.
    pub async fn seal(
        &self,
        ctx: &TenantContext,
        subject: Uuid,
        storage_class: &str,
        plaintext: &str,
    ) -> Result<Uuid> {
        let (dek, dek_id) = self.dek(ctx).await?;
        let (nonce, ct) = seal_bytes(&dek, plaintext.as_bytes())?;
        let id = Uuid::now_v7();
        let mut tx = self.pii.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO pii_values \
             (id, organization_id, subject_id, storage_class, ciphertext, nonce, wrapped_dek_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7)",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(subject)
        .bind(storage_class)
        .bind(&ct)
        .bind(&nonce)
        .bind(dek_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Phase 1 of the two-phase write for many values at once: one DEK
    /// lookup, in-process encryption, one bulk insert. Items are
    /// `(subject, storage_class, plaintext)`; returns the ref ids in order.
    /// The caller commits the core `pii_refs` rows (bulk) afterwards.
    pub async fn seal_batch(
        &self,
        ctx: &TenantContext,
        items: &[(Uuid, String, String)],
    ) -> Result<Vec<Uuid>> {
        if items.is_empty() {
            return Ok(vec![]);
        }
        let (dek, dek_id) = self.dek(ctx).await?;
        let mut ids = Vec::with_capacity(items.len());
        let mut subjects = Vec::with_capacity(items.len());
        let mut classes = Vec::with_capacity(items.len());
        let mut cts = Vec::with_capacity(items.len());
        let mut nonces = Vec::with_capacity(items.len());
        for (subject, class, plaintext) in items {
            let (nonce, ct) = seal_bytes(&dek, plaintext.as_bytes())?;
            ids.push(Uuid::now_v7());
            subjects.push(*subject);
            classes.push(class.clone());
            cts.push(ct);
            nonces.push(nonce);
        }
        let mut tx = self.pii.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO pii_values \
             (id, organization_id, subject_id, storage_class, ciphertext, nonce, wrapped_dek_id) \
             SELECT i, $2, s, c, ct, n, $7 \
             FROM unnest($1::uuid[], $3::uuid[], $4::text[], $5::bytea[], $6::bytea[]) \
                  AS v(i, s, c, ct, n)",
        )
        .bind(&ids)
        .bind(ctx.organization_id.0)
        .bind(&subjects)
        .bind(&classes)
        .bind(&cts)
        .bind(&nonces)
        .bind(dek_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(ids)
    }

    /// Destroy many values of one organization (best-effort cleanup of a
    /// failed two-phase write, or bulk erasure). Returns rows destroyed.
    pub async fn destroy_many(&self, ctx: &TenantContext, ref_ids: &[Uuid]) -> Result<u64> {
        let mut tx = self.pii.tenant_tx(ctx).await?;
        let n = sqlx::query("DELETE FROM pii_values WHERE organization_id = $1 AND id = ANY($2)")
            .bind(ctx.organization_id.0)
            .bind(ref_ids)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        Ok(n)
    }

    /// Revoke disclosure, then destroy the ciphertext (erasure = key/data
    /// destruction; the core token is tombstoned by the caller).
    pub async fn destroy(&self, ctx: &TenantContext, ref_id: Uuid) -> Result<()> {
        let mut tx = self.pii.tenant_tx(ctx).await?;
        let n = sqlx::query("DELETE FROM pii_values WHERE id=$1 AND organization_id=$2")
            .bind(ref_id)
            .bind(ctx.organization_id.0)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::NotFound(format!("pii value {ref_id}")));
        }
        Ok(())
    }
}

/// The only normal service allowed to resolve a `pii_ref`.
#[derive(Clone)]
pub struct PiiProjector {
    core: CoreDb,
    vault: Vault,
}

impl PiiProjector {
    pub fn new(core: CoreDb, vault: Vault) -> Self {
        Self { core, vault }
    }

    /// Two-phase projection: authorize the disclosure against the core
    /// reference (tenant-scoped, state-checked), batch-resolve through the
    /// vault, audit the disclosure metadata (never the value).
    pub async fn resolve(
        &self,
        ctx: &TenantContext,
        ref_id: Uuid,
        purpose: &str,
    ) -> Result<String> {
        // Phase 1: core reference, tenant-pinned. RLS guarantees the row
        // belongs to the caller's organization; state must be active.
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT storage_class, state FROM pii_refs WHERE id=$1")
                .bind(ref_id)
                .fetch_optional(&mut *tx)
                .await?;
        let (storage_class, state) =
            row.ok_or_else(|| TinkerError::NotFound(format!("pii_ref {ref_id}")))?;
        if state != "active" {
            return Err(TinkerError::Forbidden(format!(
                "pii_ref {ref_id} is {state}"
            )));
        }

        // Phase 2: vault lookup, tenant-pinned and correlated in app code
        // (never SQL-joined against the core store).
        let mut ptx = self.vault.pii.tenant_tx(ctx).await?;
        let vrow: Option<(Vec<u8>, Vec<u8>, Uuid)> = sqlx::query_as(
            "SELECT ciphertext, nonce, wrapped_dek_id FROM pii_values \
             WHERE id=$1 AND organization_id=$2",
        )
        .bind(ref_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *ptx)
        .await?;
        let (ct, nonce, dek_id) =
            vrow.ok_or_else(|| TinkerError::Forbidden("pii value unavailable".into()))?;

        // Unwrap the DEK and decrypt. Plaintext lives only in this scope.
        // The DEK's own kek_id selects the KEK — a DEK wrapped before a
        // KEK rotation still opens with the retired KEK; an unknown
        // kek_id fails closed rather than trying the wrong key.
        let wrow: (String, Vec<u8>) =
            sqlx::query_as("SELECT kek_id, wrapped_key FROM wrapped_deks WHERE id=$1")
                .bind(dek_id)
                .fetch_one(&mut *ptx)
                .await?;
        ptx.commit().await?;
        let dek_kek = self.vault.kek_for(&wrow.0)?;
        let (wnonce, wct) = wrow.1.split_at(NONCE_LEN);
        let dek_raw = open_bytes(dek_kek, wnonce, wct)?;
        let plaintext = String::from_utf8(open_bytes(&dek_raw, &nonce, &ct)?)
            .map_err(|_| TinkerError::Internal("pii value is not valid UTF-8".into()))?;

        // Phase 3: audit the disclosure — metadata only, never the value.
        sqlx::query(
            "INSERT INTO audit_events \
             (organization_id, actor_id, action, resource_type, resource_id, status, metadata) \
             VALUES ($1,$2,'pii.resolve','pii_ref',$3,'ok',$4)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(ref_id.to_string())
        .bind(serde_json::json!({
            "purpose": purpose,
            "storage_class": storage_class,
        }))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(plaintext)
    }
}

fn hex_kek(s: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(s)?;
    if bytes.len() != 32 {
        return Err(TinkerError::Validation(
            "KEK must be 32 bytes (64 hex chars)".into(),
        ));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    Ok(k)
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(TinkerError::Validation("bad hex".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| TinkerError::Validation("bad hex".into()))
        })
        .collect()
}
