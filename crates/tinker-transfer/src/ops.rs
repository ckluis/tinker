//! Operational hardening (PRD v0.6 §41, §38).
//!
//! - [`RetentionEngine`]: per-object retention with legal hold, per
//!   store (core and PII). A hold suspends deletion; without it, expired
//!   rows are deleted per policy.
//! - [`RestoreRehearsal`]: two-store restore rehearsal. Signed manifests
//!   per store; a paired restore is compatible only when the windows
//!   overlap and the PII window covers the core reference watermark.
//!   Orphaned references fail closed as unavailable — never stale
//!   plaintext, never a bypass.
//! - [`PromotionSoak`]: the self-promotion loop. Every releasable
//!   definition is immutable after release; promotion flips one
//!   active-version pointer; a health-gate failure rolls the pointer
//!   back automatically. History is never rewritten.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, PiiDb};
use uuid::Uuid;

use crate::model::RefStatus;

// ---------------------------------------------------------------------------
// Retention.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionOutcome {
    pub object_key: String,
    pub deleted: i64,
    pub skipped_legal_hold: bool,
}

pub struct RetentionEngine {
    core: CoreDb,
    pii: PiiDb,
}

impl RetentionEngine {
    pub fn new(core: CoreDb, pii: PiiDb) -> Self {
        Self { core, pii }
    }

    pub async fn set_policy(
        &self,
        ctx: &TenantContext,
        object_key: &str,
        retention_days: i32,
    ) -> Result<()> {
        if object_key.trim().is_empty() || object_key.len() > 256 {
            return Err(TinkerError::Validation(
                "object_key must be 1..=256 chars".into(),
            ));
        }
        if retention_days < 0 {
            return Err(TinkerError::Validation(
                "retention_days must be >= 0".into(),
            ));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO retention_policies (organization_id, object_key, retention_days)
             VALUES ($1, $2, $3)
             ON CONFLICT (organization_id, object_key)
             DO UPDATE SET retention_days = EXCLUDED.retention_days",
        )
        .bind(ctx.organization_id.0)
        .bind(object_key)
        .bind(retention_days)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_legal_hold(
        &self,
        ctx: &TenantContext,
        object_key: &str,
        hold: bool,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE retention_policies SET legal_hold = $3
             WHERE organization_id = $1 AND object_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(object_key)
        .bind(hold)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::NotFound("retention policy".into()));
        }
        Ok(())
    }

    /// Apply retention to a core table. `table` must be `schema.name`
    /// with safe identifier characters; it is quoted, never
    /// interpolated raw. Rows older than the policy's retention window
    /// (by `ts_column`) and belonging to this org are deleted — unless a
    /// legal hold suspends deletion.
    pub async fn apply_core(
        &self,
        ctx: &TenantContext,
        object_key: &str,
        table: &str,
        ts_column: &str,
        org_column: &str,
    ) -> Result<RetentionOutcome> {
        for ident in [table] {
            if !is_safe_ident(ident) {
                return Err(TinkerError::Validation(format!(
                    "unsafe identifier: {ident}"
                )));
            }
        }
        for ident in [ts_column, org_column] {
            if !is_safe_column(ident) {
                return Err(TinkerError::Validation(format!(
                    "unsafe identifier: {ident}"
                )));
            }
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let pol: Option<(i32, bool)> = sqlx::query_as(
            "SELECT retention_days, legal_hold FROM retention_policies
             WHERE organization_id = $1 AND object_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(object_key)
        .fetch_optional(&mut *tx)
        .await?;
        let (days, hold) = pol.ok_or_else(|| TinkerError::NotFound("retention policy".into()))?;
        let outcome = if hold {
            RetentionOutcome {
                object_key: object_key.into(),
                deleted: 0,
                skipped_legal_hold: true,
            }
        } else {
            let (schema, name) = split_table(table);
            let sql = format!(
                "DELETE FROM \"{schema}\".\"{name}\" \
                 WHERE \"{org_column}\" = $1 \
                   AND \"{ts_column}\" < now() - make_interval(days => $2)"
            );
            let deleted = sqlx::query(&sql)
                .bind(ctx.organization_id.0)
                .bind(days)
                .execute(&mut *tx)
                .await?
                .rows_affected() as i64;
            RetentionOutcome {
                object_key: object_key.into(),
                deleted,
                skipped_legal_hold: false,
            }
        };
        let result = serde_json::to_value(&outcome)?;
        sqlx::query(
            "UPDATE retention_policies
             SET last_run_at = now(), last_run_result = $3
             WHERE organization_id = $1 AND object_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(object_key)
        .bind(result)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    /// Apply retention to the PII store: delete expired, non-held values
    /// for this org. Legal hold suspends deletion per row.
    pub async fn apply_pii(&self, ctx: &TenantContext) -> Result<RetentionOutcome> {
        let mut tx = self.pii.tenant_tx(ctx).await?;
        let held: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM pii_values
             WHERE organization_id = $1 AND expires_at < now() AND legal_hold",
        )
        .bind(ctx.organization_id.0)
        .fetch_one(&mut *tx)
        .await?;
        let deleted = sqlx::query(
            "DELETE FROM pii_values
             WHERE organization_id = $1 AND expires_at < now() AND NOT legal_hold",
        )
        .bind(ctx.organization_id.0)
        .execute(&mut *tx)
        .await?
        .rows_affected() as i64;
        tx.commit().await?;
        Ok(RetentionOutcome {
            object_key: "pii_values".into(),
            deleted,
            skipped_legal_hold: held.0 > 0,
        })
    }
}

/// `schema.name` with boring identifier characters only.
fn is_safe_ident(s: &str) -> bool {
    let mut parts = s.split('.');
    let (a, b) = (parts.next(), parts.next());
    if parts.next().is_some() {
        return false;
    }
    let (schema, name) = match (a, b) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    is_safe_part(schema) && is_safe_part(name)
}

/// A bare column identifier: no schema part (columns are quoted directly
/// in the generated SQL, so `public.created_at` would be wrong).
fn is_safe_column(s: &str) -> bool {
    !s.contains('.') && is_safe_part(s)
}

fn is_safe_part(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 64
        && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !p.chars().next().unwrap().is_ascii_digit()
}

/// Postgres `timestamptz` resolves to microseconds; truncate so values
/// that survive a storage round-trip hash identically.
fn canon_ts(ts: &DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp_micros(ts.timestamp_micros()).expect("timestamp in range")
}

fn split_table(table: &str) -> (&str, &str) {
    let mut parts = table.split('.');
    (parts.next().unwrap(), parts.next().unwrap())
}

// ---------------------------------------------------------------------------
// Two-store restore rehearsal.
// ---------------------------------------------------------------------------

type HmacSha256 = Hmac<Sha256>;

/// Raw row shape for a signed restore manifest.
type ManifestRow = (DateTime<Utc>, DateTime<Utc>, DateTime<Utc>, String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RehearsalReport {
    pub compatible: bool,
    pub orphans: Vec<Uuid>,
    pub available: Vec<Uuid>,
    pub detail: String,
}

pub struct RestoreRehearsal {
    core: CoreDb,
    pii: PiiDb,
}

impl RestoreRehearsal {
    pub fn new(core: CoreDb, pii: PiiDb) -> Self {
        Self { core, pii }
    }

    /// Operator signature over (store, window, watermark). The key is
    /// held by the operator, never stored beside the manifest.
    ///
    /// Timestamps are canonicalized to whole microseconds first:
    /// Postgres `timestamptz` resolves to microseconds, so a signature
    /// computed from nanosecond `Utc::now()` values must still verify
    /// against the values read back from storage.
    pub fn sign_manifest(
        operator_key: &[u8],
        store: &str,
        window_start: &DateTime<Utc>,
        window_end: &DateTime<Utc>,
        watermark: &DateTime<Utc>,
    ) -> String {
        let mut mac = HmacSha256::new_from_slice(operator_key).expect("hmac key");
        mac.update(store.as_bytes());
        mac.update(canon_ts(window_start).to_rfc3339().as_bytes());
        mac.update(canon_ts(window_end).to_rfc3339().as_bytes());
        mac.update(canon_ts(watermark).to_rfc3339().as_bytes());
        Self::hex_encode(&mac.finalize().into_bytes())
    }

    fn hex_encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn verify_manifest(
        operator_key: &[u8],
        store: &str,
        window_start: &DateTime<Utc>,
        window_end: &DateTime<Utc>,
        watermark: &DateTime<Utc>,
        signature: &str,
    ) -> bool {
        let expected =
            Self::sign_manifest(operator_key, store, window_start, window_end, watermark);
        expected == signature
    }

    pub async fn record_core_manifest(
        &self,
        ctx: &TenantContext,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        watermark: DateTime<Utc>,
        signature: &str,
    ) -> Result<Uuid> {
        if window_end <= window_start {
            return Err(TinkerError::Validation(
                "window_end must be after window_start".into(),
            ));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO restore_manifests
                 (organization_id, store, window_start, window_end,
                  reference_watermark, signature)
             VALUES ($1, 'core', $2, $3, $4, $5) RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(window_start)
        .bind(window_end)
        .bind(watermark)
        .bind(signature)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    pub async fn record_pii_manifest(
        &self,
        ctx: &TenantContext,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
        watermark: DateTime<Utc>,
        signature: &str,
    ) -> Result<Uuid> {
        if window_end <= window_start {
            return Err(TinkerError::Validation(
                "window_end must be after window_start".into(),
            ));
        }
        let mut tx = self.pii.tenant_tx(ctx).await?;
        let (real_id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO pii_restore_manifests
                 (organization_id, store, window_start, window_end,
                  reference_watermark, signature)
             VALUES ($1, 'pii', $2, $3, $4, $5) RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(window_start)
        .bind(window_end)
        .bind(watermark)
        .bind(signature)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(real_id)
    }

    /// Resolve one PII reference against the (restored) PII store.
    /// Missing rows fail closed as unavailable.
    pub async fn resolve_ref(&self, ctx: &TenantContext, ref_id: Uuid) -> Result<RefStatus> {
        let mut tx = self.pii.tenant_tx(ctx).await?;
        let row: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM pii_values WHERE organization_id = $1 AND id = $2")
                .bind(ctx.organization_id.0)
                .bind(ref_id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(if row.is_some() {
            RefStatus::Available
        } else {
            RefStatus::Unavailable
        })
    }

    /// Rehearse a paired restore:
    /// 1. Both manifests verify against the operator key.
    /// 2. Windows overlap, and the PII window covers the core reference
    ///    watermark (never trust references newer than the PII window).
    /// 3. Every supplied core reference is resolved: present rows are
    ///    available; missing rows are orphans and MUST resolve as
    ///    unavailable (fail-closed).
    pub async fn rehearse(
        &self,
        ctx: &TenantContext,
        operator_key: &[u8],
        core_manifest_id: Uuid,
        pii_manifest_id: Uuid,
        refs: &[Uuid],
    ) -> Result<RehearsalReport> {
        let mut ctx_tx = self.core.tenant_tx(ctx).await?;
        let core: Option<ManifestRow> = sqlx::query_as(
            "SELECT window_start, window_end, reference_watermark, signature
             FROM restore_manifests
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(core_manifest_id)
        .fetch_optional(&mut *ctx_tx)
        .await?;
        ctx_tx.commit().await?;
        let (c_start, c_end, c_mark, c_sig) =
            core.ok_or_else(|| TinkerError::NotFound("core restore manifest".into()))?;
        if !Self::verify_manifest(operator_key, "core", &c_start, &c_end, &c_mark, &c_sig) {
            return Err(TinkerError::Validation(
                "core manifest signature does not verify".into(),
            ));
        }

        let mut pii_tx = self.pii.tenant_tx(ctx).await?;
        let pii: Option<ManifestRow> = sqlx::query_as(
            "SELECT window_start, window_end, reference_watermark, signature
             FROM pii_restore_manifests
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(pii_manifest_id)
        .fetch_optional(&mut *pii_tx)
        .await?;
        pii_tx.commit().await?;
        let (p_start, p_end, _p_mark, p_sig) =
            pii.ok_or_else(|| TinkerError::NotFound("pii restore manifest".into()))?;
        if !Self::verify_manifest(operator_key, "pii", &p_start, &p_end, &_p_mark, &p_sig) {
            return Err(TinkerError::Validation(
                "pii manifest signature does not verify".into(),
            ));
        }

        // Compatibility: windows must overlap, and the PII window must
        // cover the core reference watermark.
        let overlap = c_start < p_end && p_start < c_end;
        let watermark_covered = p_end >= c_mark;
        let compatible = overlap && watermark_covered;
        let detail =
            format!("windows overlap={overlap}, pii covers core watermark={watermark_covered}");
        if !compatible {
            return Ok(RehearsalReport {
                compatible: false,
                orphans: vec![],
                available: vec![],
                detail,
            });
        }

        // Resolve every reference; orphans must fail closed.
        let mut orphans = vec![];
        let mut available = vec![];
        for r in refs {
            match self.resolve_ref(ctx, *r).await? {
                RefStatus::Available => available.push(*r),
                RefStatus::Unavailable => orphans.push(*r),
            }
        }
        Ok(RehearsalReport {
            compatible: true,
            orphans,
            available,
            detail,
        })
    }
}

// ---------------------------------------------------------------------------
// Self-promotion soak.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionResult {
    Promoted,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionOutcome {
    pub version: i64,
    pub result: PromotionResult,
    pub active_pointer: i64,
}

pub struct PromotionSoak {
    core: CoreDb,
}

impl PromotionSoak {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Draft a new candidate version. Versions are append-only; the
    /// pointer is untouched until a promotion.
    pub async fn draft_version(
        &self,
        ctx: &TenantContext,
        kind: &str,
        key: &str,
        definition: &serde_json::Value,
    ) -> Result<i64> {
        Self::check_kind_key(kind, key)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (max_v,): (Option<i64>,) = sqlx::query_as(
            "SELECT MAX(version) FROM release_versions
             WHERE organization_id = $1 AND definition_kind = $2 AND definition_key = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .fetch_one(&mut *tx)
        .await?;
        let v = max_v.unwrap_or(0) + 1;
        sqlx::query(
            "INSERT INTO release_versions
                 (organization_id, definition_kind, definition_key,
                  version, definition)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .bind(v)
        .bind(definition)
        .execute(&mut *tx)
        .await?;
        // The pointer row must exist; create it at version 0 (nothing
        // released yet) so promotion has a defined rollback target.
        sqlx::query(
            "INSERT INTO release_pointers
                 (organization_id, definition_kind, definition_key, active_version)
             VALUES ($1, $2, $3, 0)
             ON CONFLICT (organization_id, definition_kind, definition_key)
             DO NOTHING",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(v)
    }

    /// Run one promotion round for a draft candidate:
    /// record the checks, flip the pointer, then run the health gate.
    /// `health_ok = false` forces the gate to fail: the pointer rolls
    /// back automatically and the candidate is marked rolled_back.
    /// The version's definition is never rewritten.
    pub async fn promote(
        &self,
        ctx: &TenantContext,
        kind: &str,
        key: &str,
        version: i64,
        checks: &serde_json::Value,
        health_ok: bool,
    ) -> Result<PromotionOutcome> {
        Self::check_kind_key(kind, key)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let ver: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM release_versions
             WHERE organization_id = $1 AND definition_kind = $2
               AND definition_key = $3 AND version = $4 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .bind(version)
        .fetch_optional(&mut *tx)
        .await?;
        match ver {
            Some((s,)) if s == "draft" => {}
            Some((s,)) => {
                return Err(TinkerError::Validation(format!(
                    "only draft candidates can promote; version {version} is {s}"
                )))
            }
            None => return Err(TinkerError::NotFound("release version".into())),
        }
        let ptr: (i64,) = sqlx::query_as(
            "SELECT active_version FROM release_pointers
             WHERE organization_id = $1 AND definition_kind = $2
               AND definition_key = $3 FOR UPDATE",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .fetch_one(&mut *tx)
        .await?;
        let previous = ptr.0;

        // Flip the pointer to the candidate; record checks on the version.
        sqlx::query(
            "UPDATE release_versions SET status = 'released', checks = $5
             WHERE organization_id = $1 AND definition_kind = $2
               AND definition_key = $3 AND version = $4",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .bind(version)
        .bind(checks)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE release_pointers SET active_version = $4, updated_at = now()
             WHERE organization_id = $1 AND definition_kind = $2 AND definition_key = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .bind(version)
        .execute(&mut *tx)
        .await?;

        // Health gate. On failure the pointer rolls back automatically and
        // the candidate is marked rolled_back — history is appended, never
        // rewritten.
        let (result, active_pointer) = if health_ok {
            (PromotionResult::Promoted, version)
        } else {
            sqlx::query(
                "UPDATE release_versions SET status = 'rolled_back'
                 WHERE organization_id = $1 AND definition_kind = $2
                   AND definition_key = $3 AND version = $4",
            )
            .bind(ctx.organization_id.0)
            .bind(kind)
            .bind(key)
            .bind(version)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE release_pointers SET active_version = $4, updated_at = now()
                 WHERE organization_id = $1 AND definition_kind = $2 AND definition_key = $3",
            )
            .bind(ctx.organization_id.0)
            .bind(kind)
            .bind(key)
            .bind(previous)
            .execute(&mut *tx)
            .await?;
            (PromotionResult::RolledBack, previous)
        };
        let result_s = match result {
            PromotionResult::Promoted => "promoted",
            PromotionResult::RolledBack => "rolled_back",
        };
        sqlx::query(
            "INSERT INTO promotion_soak_runs
                 (organization_id, definition_kind, definition_key,
                  candidate_version, checks, result, active_pointer_after)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .bind(version)
        .bind(checks)
        .bind(result_s)
        .bind(active_pointer)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(PromotionOutcome {
            version,
            result,
            active_pointer,
        })
    }

    /// Current active pointer (0 = nothing released yet).
    pub async fn active_pointer(&self, ctx: &TenantContext, kind: &str, key: &str) -> Result<i64> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(i64,)> = sqlx::query_as(
            "SELECT active_version FROM release_pointers
             WHERE organization_id = $1 AND definition_kind = $2 AND definition_key = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(kind)
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row.map(|(v,)| v).unwrap_or(0))
    }

    fn check_kind_key(kind: &str, key: &str) -> Result<()> {
        if kind.trim().is_empty() || kind.len() > 64 {
            return Err(TinkerError::Validation(
                "definition_kind must be 1..=64 chars".into(),
            ));
        }
        if key.trim().is_empty() || key.len() > 256 {
            return Err(TinkerError::Validation(
                "definition_key must be 1..=256 chars".into(),
            ));
        }
        Ok(())
    }
}
