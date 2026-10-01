//! C4 portable schema snapshots (item 39).
//!
//! A snapshot is a signed, versioned, canonical-JSON document describing an
//! organization's ontology: objects, fields (with item-37 validation rules
//! and write presets), relations (by target slug, never by UUID — UUIDs are
//! per-org), and item-38 row policies per role. Snapshots are the portable
//! unit for dev → staging → prod promotion and pack distribution.
//!
//! Wire format (all JSON):
//! ```text
//! canonical_bytes = compact JSON of the doc with object keys sorted
//!                   recursively (no whitespace ambiguity)
//! digest          = sha256(canonical_bytes)
//! signature       = ed25519_sign(signing_key, digest)
//! envelope        = { payload, payload_sha256, signature, public_key }
//! ```
//! The signing key comes from the environment only
//! (`TINKER_SNAPSHOT_SIGNING_KEY`, 32 raw bytes as hex or base64) — never
//! from the database, never from the artifact. The applier pins the
//! expected vendor public key: the envelope's `public_key` must equal the
//! pin, so an attacker cannot re-sign a tampered payload with their own
//! key and slip it into the envelope (key-swap defense).
//!
//! Guards, all fail-closed:
//! - signature / digest mismatch → reject (tamper-evident: ANY byte change
//!   breaks the digest, and the signature covers the digest).
//! - `vendor_id` mismatch → reject (cross-vendor apply refused).
//! - `format_version` newer than this build understands → reject.
//! - `format_version` older than [`LIFECYCLE_INTRODUCED_FORMAT_VERSION`]
//!   (v2, item 40 / migration 0041) → reject: the snapshot predates the
//!   `lifecycle_enabled` flag and must be re-exported from the source org,
//!   never silently defaulted (fail-closed against security downgrade).
//! - per-object `row_policies` missing on an accepted format version →
//!   reject (malformed payload): the field has no serde default, so a
//!   stripped payload can never apply with zero row policies (fail-open
//!   hole closed; the floor above already covers older versions).
//! - `snapshot_version` lower than the last applied version for (org,
//!   vendor) in `schema_snapshot_log` → reject (downgrade refused).
//! - same version but a different payload hash → reject (replay of a
//!   substituted artifact refused).
//! - same (vendor, version, payload hash) as the log row → safe no-op
//!   (reapplying the exact artifact is idempotent; nothing is written).
//! - target object with a NEWER active evolution version than the
//!   snapshot's `evolution_version` pointer → reject (independent drift).
//! - an existing field whose kind/metadata differs from the snapshot →
//!   reject (type drift; per the item-17 rule we never rewrite a column).
//!
//! Apply goes through the M4 [`SchemaEvolver`] — create_draft → add_field /
//! add_relation → mark_preview → promote — never around it. Atomicity is
//! honest about its phases: (1) signature/format/version/drift/evolution
//! guards all run read-only; (2) object define/adopt metadata rows are
//! written so relation targets resolve; (3) every object gets its draft
//! fully built before ANY object is promoted, so a draft failure leaves
//! the live (active) schema untouched and abandoned drafts are inert;
//! (4) promotion runs one object per transaction — NOT a single global
//! transaction — so a crash between promotions can leave a partial apply,
//! and re-running the same snapshot converges (additive-only,
//! idempotent-safe). The version log upsert only moves forward, so a
//! racing older apply fails closed instead of clobbering a newer row.
//!
//! Portfolio semantics: the slug namespace is shared, so a slug the
//! target lacks is ADOPTED onto the existing table when another org
//! defined it (the adopter then sees the shared base fields live), and
//! only DEFINED as a new table when the slug is genuinely new. Adopted
//! descriptions retarget inherited relation fields at the adopter's own
//! object rows (same slug = same physical table), because the root's
//! rows are invisible to the adopter through RLS and relation hops must
//! keep working. Field convergence always runs against the live
//! effective schema, so a stale snapshot taken before the source moved
//! fails closed on drift — take a fresh snapshot. Drift can only bite
//! on the target's OWN extension fields: adopted base fields resolve
//! live from the root by construction. A snapshot older than the live
//! shared root simply converges to a no-op on the base fields (the root
//! is the source of truth), and the version guard still advances.
//!
//! Canonical form: object keys sorted recursively; arrays keep their
//! order (field order is semantic — `build_snapshot` always emits
//! `api_name` order, so two exports of the same org agree byte for
//! byte). Reordering fields changes the digest by design.
//!
//! Apply never removes fields and never alters an existing field: the M4
//! model is additive, and silently dropping a column would destroy data.
//! Target-only fields and target-only policy roles are left alone — the
//! diff reports them, apply does not touch them.

use std::collections::{BTreeMap, HashMap, HashSet};

use base64::Engine as _;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_evolve::{SchemaEvolver, VersionSel};
use tinker_ontology::{
    FieldDef, FieldDescription, FieldType, ObjectDef, ObjectDescription, Ontology, Scope,
    ValidationRules, WritePreset,
};
use uuid::Uuid;

use crate::{RowFilterDef, RowFilters};

/// Envelope format marker (not security-relevant; the signature is).
pub const SNAPSHOT_FORMAT: &str = "tinker-schema-snapshot";
/// Newest snapshot format version this build can read and apply.
/// v2 adds the per-object `lifecycle_enabled` flag (item 40, migration
/// 0041); see [`LIFECYCLE_INTRODUCED_FORMAT_VERSION`].
pub const SNAPSHOT_FORMAT_VERSION: u32 = 2;
/// First format version that carries the per-object `lifecycle_enabled`
/// flag. Snapshots older than this predate lifecycle support and are
/// rejected outright (fail-closed): silently defaulting the flag to
/// `false` would turn lifecycle enforcement off without anyone asking.
/// Re-export the snapshot from the source org instead.
pub const LIFECYCLE_INTRODUCED_FORMAT_VERSION: u32 = 2;
/// Env var holding the 32-byte Ed25519 seed (hex or base64). Env only.
pub const SIGNING_KEY_ENV: &str = "TINKER_SNAPSHOT_SIGNING_KEY";

// ---------------------------------------------------------------------------
// Document types (the signed payload)
// ---------------------------------------------------------------------------

/// One field in a snapshot. `kind` is the [`FieldType::kind_name`] string
/// ("text", "number", "relation", ...). Relations name their target by
/// api_slug — portable across orgs, unlike UUIDs. Physical columns and
/// internal ids are deliberately absent: they are per-org accidents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldSnapshot {
    pub api_name: String,
    pub label: String,
    pub kind: String,
    pub required: bool,
    #[serde(default)]
    pub options: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relation_target: Option<String>,
    #[serde(default)]
    pub validation: ValidationRules,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<WritePreset>,
    /// Item 42 (C7): ceiling for PII classes of files linked through a
    /// `file` field. Follows the validation/preset convention: absent in
    /// older snapshots means the permissive default (export always
    /// writes it, so round-trips preserve the operator's setting).
    #[serde(default = "default_max_pii_class")]
    pub max_pii_class: String,
    /// Vault-backed field: values are sealed into the PII vault and
    /// read back masked (docs/pii-sensitive-fields.md). Absent = false,
    /// and false is never serialized, so existing payloads are unchanged.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sensitive: bool,
}

/// Item 42 (C7): pre-item-42 snapshots carry no PII ceiling; the
/// permissive default keeps their apply behavior unchanged.
fn default_max_pii_class() -> String {
    "restricted".to_string()
}

/// One row-filter rule in a snapshot: data shapes only, never SQL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FilterSnapshot {
    pub field: String,
    pub op: String,
    pub value: serde_json::Value,
}

/// A role's row policy in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RolePolicySnapshot {
    pub role: String,
    pub filters: Vec<FilterSnapshot>,
}

/// One object in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObjectSnapshot {
    pub api_slug: String,
    pub name: String,
    pub label: String,
    pub fields: Vec<FieldSnapshot>,
    /// Item 38 (C2) row policies, item-39 snapshot coverage: REQUIRED on
    /// the wire for every accepted format version — there is deliberately
    /// no `#[serde(default)]`. Row policies predate the snapshot format
    /// itself (present since v1), so a payload that lacks them is
    /// malformed, not old: silently defaulting to an empty list would
    /// apply the snapshot with ZERO row policies (fail-open). Versions
    /// that predate the row-policy-carrying shape are rejected by the
    /// version floor in [`verify_snapshot`], never defaulted.
    pub row_policies: Vec<RolePolicySnapshot>,
    /// Active M4 evolution version_number at snapshot time, if the object
    /// has ever been evolved. The applier refuses targets that evolved
    /// past this pointer independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evolution_version: Option<i32>,
    /// Item 40 (C1): whether the object is lifecycle-managed
    /// (draft → review → publish). This field is REQUIRED on the wire
    /// for format_version >= [`LIFECYCLE_INTRODUCED_FORMAT_VERSION`]:
    /// there is deliberately no `#[serde(default)]` — a missing flag
    /// must fail deserialization rather than silently disable
    /// lifecycle enforcement. Older snapshots are rejected by the
    /// version floor in [`verify_snapshot`], never defaulted.
    pub lifecycle_enabled: bool,
}

/// The signed document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SnapshotDoc {
    pub format: String,
    pub format_version: u32,
    pub vendor_id: String,
    /// Monotonic per vendor. The applier requires strictly increasing.
    pub snapshot_version: u64,
    pub created_at: String,
    pub objects: Vec<ObjectSnapshot>,
}

/// The distributed artifact: payload plus tamper-evident seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSnapshot {
    pub payload: serde_json::Value,
    pub payload_sha256: String,
    pub signature: String,
    pub public_key: String,
}

// ---------------------------------------------------------------------------
// Canonical JSON, hashing, signing
// ---------------------------------------------------------------------------

fn canonical_value(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => {
            let sorted: BTreeMap<&String, serde_json::Value> =
                m.iter().map(|(k, v)| (k, canonical_value(v))).collect();
            serde_json::Value::Object(sorted.into_iter().map(|(k, v)| (k.clone(), v)).collect())
        }
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.iter().map(canonical_value).collect())
        }
        _ => v.clone(),
    }
}

/// Canonical bytes: compact JSON with object keys sorted recursively.
/// Two docs that differ only in whitespace or key order canonicalize
/// identically; ANY semantic byte change alters the digest.
pub fn canonical_bytes(doc: &SnapshotDoc) -> Result<Vec<u8>> {
    let v = serde_json::to_value(doc)
        .map_err(|e| TinkerError::Internal(format!("snapshot serialize: {e}")))?;
    serde_json::to_vec(&canonical_value(&v))
        .map_err(|e| TinkerError::Internal(format!("snapshot canonicalize: {e}")))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let (chunks, _) = b.as_chunks::<2>();
    let mut out = Vec::with_capacity(chunks.len());
    for pair in chunks {
        out.push(hex_val(pair[0])? << 4 | hex_val(pair[1])?);
    }
    Some(out)
}

fn b64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// sha256 of the canonical bytes, hex. This is the content hash: the
/// version/vendor hash guard compares these, not the envelope bytes.
pub fn payload_digest_hex(canonical: &[u8]) -> String {
    hex_encode(&Sha256::digest(canonical))
}

/// Sign a snapshot doc. Returns the distributable envelope.
pub fn sign_snapshot(doc: &SnapshotDoc, signing_key: &SigningKey) -> Result<SignedSnapshot> {
    let canonical = canonical_bytes(doc)?;
    let digest = Sha256::digest(&canonical);
    let signature = signing_key.sign(&digest);
    let payload = serde_json::to_value(doc)
        .map_err(|e| TinkerError::Internal(format!("snapshot serialize: {e}")))?;
    Ok(SignedSnapshot {
        payload,
        payload_sha256: hex_encode(&digest),
        signature: b64_encode(&signature.to_bytes()),
        public_key: hex_encode(signing_key.verifying_key().as_bytes()),
    })
}

/// Load the Ed25519 seed from the environment. Fails closed when the var
/// is missing or malformed — signing must never silently use a zero key.
pub fn signing_key_from_env() -> Result<SigningKey> {
    let raw = std::env::var(SIGNING_KEY_ENV)
        .map_err(|_| TinkerError::Internal(format!("{SIGNING_KEY_ENV} is not set")))?;
    let bytes = hex_decode(raw.trim())
        .or_else(|| b64_decode(raw.trim()))
        .ok_or_else(|| {
            TinkerError::Internal(format!("{SIGNING_KEY_ENV} is not 32 bytes (hex or base64)"))
        })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        TinkerError::Internal(format!("{SIGNING_KEY_ENV} must be exactly 32 bytes"))
    })?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Parse a pinned vendor public key (hex, 32 bytes).
pub fn verifying_key_from_hex(s: &str) -> Result<[u8; 32]> {
    let bytes = hex_decode(s.trim())
        .ok_or_else(|| TinkerError::Validation("bad vendor public key (expected hex)".into()))?;
    bytes
        .try_into()
        .map_err(|_| TinkerError::Validation("vendor public key must be 32 bytes".into()))
}

/// Verify an envelope and return the authenticated document. Order:
/// shape → digest recompute → signature (pinned key, key-swap defense) →
/// vendor → format. Every failure is a hard reject.
pub fn verify_snapshot(
    envelope: &SignedSnapshot,
    expected_vendor_id: &str,
    expected_public_key: &[u8; 32],
) -> Result<SnapshotDoc> {
    // The envelope's claimed key must equal the pin: otherwise an attacker
    // re-signs a tampered payload with their own key and the signature
    // would "verify".
    let claimed: [u8; 32] = verifying_key_from_hex(&envelope.public_key).map_err(|_| {
        TinkerError::Validation("snapshot rejected: bad envelope public key".into())
    })?;
    if claimed != *expected_public_key {
        return Err(TinkerError::Validation(
            "snapshot rejected: envelope public key does not match the pinned vendor key".into(),
        ));
    }
    // Version floor for lifecycle (item 40, migration 0041): the
    // `lifecycle_enabled` flag is required on the wire from
    // LIFECYCLE_INTRODUCED_FORMAT_VERSION on, so a snapshot that predates
    // it would otherwise fail deserialization with a bare "missing field"
    // error — or worse, be silently defaulted. Probe the raw payload
    // first so the rejection names the real problem and the fix.
    match envelope
        .payload
        .get("format_version")
        .and_then(|v| v.as_u64())
    {
        Some(v) if v < u64::from(LIFECYCLE_INTRODUCED_FORMAT_VERSION) => {
            return Err(TinkerError::Validation(format!(
                "snapshot rejected: format_version {v} predates lifecycle support \
                 (migration 0041); re-export the snapshot from the source org"
            )))
        }
        _ => {}
    }
    let doc: SnapshotDoc = serde_json::from_value(envelope.payload.clone())
        .map_err(|e| TinkerError::Validation(format!("snapshot rejected: bad payload: {e}")))?;
    if doc.format != SNAPSHOT_FORMAT {
        return Err(TinkerError::Validation(format!(
            "snapshot rejected: unknown format '{}'",
            doc.format
        )));
    }
    if doc.format_version > SNAPSHOT_FORMAT_VERSION {
        return Err(TinkerError::Validation(format!(
            "snapshot rejected: format_version {} newer than supported {SNAPSHOT_FORMAT_VERSION}",
            doc.format_version
        )));
    }
    if doc.vendor_id.is_empty() || doc.vendor_id.len() > 128 {
        return Err(TinkerError::Validation(
            "snapshot rejected: bad vendor_id".into(),
        ));
    }
    if doc.snapshot_version == 0 {
        return Err(TinkerError::Validation(
            "snapshot rejected: snapshot_version must be > 0".into(),
        ));
    }
    // Recompute the digest from the payload (canonicalized, so cosmetic
    // JSON differences don't break verification) and compare before
    // touching the signature.
    let canonical = canonical_bytes(&doc)?;
    let digest = Sha256::digest(&canonical);
    if hex_encode(&digest) != envelope.payload_sha256.to_lowercase() {
        return Err(TinkerError::Validation(
            "snapshot rejected: payload digest mismatch (tampered payload)".into(),
        ));
    }
    let sig_bytes = b64_decode(&envelope.signature).ok_or_else(|| {
        TinkerError::Validation("snapshot rejected: bad signature encoding".into())
    })?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| TinkerError::Validation("snapshot rejected: bad signature length".into()))?;
    let verifying = VerifyingKey::from_bytes(expected_public_key)
        .map_err(|_| TinkerError::Internal("bad pinned vendor key".into()))?;
    verifying
        .verify(&digest, &Signature::from_bytes(&sig_arr))
        .map_err(|_| {
            TinkerError::Validation("snapshot rejected: signature verification failed".into())
        })?;
    if doc.vendor_id != expected_vendor_id {
        return Err(TinkerError::Validation(format!(
            "snapshot rejected: vendor '{}' does not match expected '{expected_vendor_id}'",
            doc.vendor_id
        )));
    }
    Ok(doc)
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// How one field differs between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FieldChangeDetail {
    pub api_name: String,
    pub from_kind: String,
    pub to_kind: String,
    /// Human-readable list of what changed, e.g. "kind text->number",
    /// "required false->true", "validation changed".
    pub changes: Vec<String>,
}

/// Field-level diff for one object (matched by api_slug).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ObjectDiff {
    pub api_slug: String,
    /// Full definitions — the diff is machine-appliable: an applier can
    /// create exactly these fields from this struct alone.
    pub added: Vec<FieldSnapshot>,
    pub removed: Vec<String>,
    pub changed: Vec<FieldChangeDetail>,
    pub policies_added: Vec<String>,
    pub policies_removed: Vec<String>,
    pub policies_changed: Vec<String>,
    /// Item 40 (C1): lifecycle flag flip, if any. `None` = unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_changed: Option<bool>,
}

/// Diff between two snapshots. Serializable: the diff itself is the
/// machine-appliable artifact; [`SnapshotDiff::render_human`] is the
/// human-readable rendering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SnapshotDiff {
    pub objects_added: Vec<String>,
    pub objects_removed: Vec<String>,
    pub objects: Vec<ObjectDiff>,
}

impl SnapshotDiff {
    pub fn is_empty(&self) -> bool {
        self.objects_added.is_empty()
            && self.objects_removed.is_empty()
            && self.objects.iter().all(|o| {
                o.added.is_empty()
                    && o.removed.is_empty()
                    && o.changed.is_empty()
                    && o.policies_added.is_empty()
                    && o.policies_removed.is_empty()
                    && o.policies_changed.is_empty()
                    && o.lifecycle_changed.is_none()
            })
    }

    /// Human-readable rendering, one change per line.
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        for slug in &self.objects_added {
            out.push_str(&format!("+ object {slug}\n"));
        }
        for slug in &self.objects_removed {
            out.push_str(&format!("- object {slug}\n"));
        }
        for o in &self.objects {
            for f in &o.added {
                out.push_str(&format!(
                    "+ field {}.{} (kind {}, required {}){}\n",
                    o.api_slug,
                    f.api_name,
                    f.kind,
                    f.required,
                    f.relation_target
                        .as_ref()
                        .map(|t| format!(" -> {t}"))
                        .unwrap_or_default()
                ));
            }
            for api_name in &o.removed {
                out.push_str(&format!("- field {}.{api_name}\n", o.api_slug));
            }
            for c in &o.changed {
                out.push_str(&format!(
                    "~ field {}.{}: {}\n",
                    o.api_slug,
                    c.api_name,
                    c.changes.join(", ")
                ));
            }
            for role in &o.policies_added {
                out.push_str(&format!("+ row policy {}.{role}\n", o.api_slug));
            }
            for role in &o.policies_removed {
                out.push_str(&format!("- row policy {}.{role}\n", o.api_slug));
            }
            for role in &o.policies_changed {
                out.push_str(&format!("~ row policy {}.{role}\n", o.api_slug));
            }
            if let Some(enabled) = o.lifecycle_changed {
                out.push_str(&format!(
                    "~ lifecycle {}.lifecycle_enabled -> {}\n",
                    o.api_slug, enabled
                ));
            }
        }
        if out.is_empty() {
            out.push_str("(no differences)\n");
        }
        out
    }
}

fn field_change_notes(from: &FieldSnapshot, to: &FieldSnapshot) -> Vec<String> {
    let mut notes = Vec::new();
    if from.kind != to.kind {
        notes.push(format!("kind {}->{}", from.kind, to.kind));
    }
    if from.label != to.label {
        notes.push("label changed".into());
    }
    if from.required != to.required {
        notes.push(format!("required {}->{}", from.required, to.required));
    }
    if from.options != to.options {
        notes.push("options changed".into());
    }
    if from.relation_target != to.relation_target {
        notes.push(format!(
            "relation_target {:?}->{:?}",
            from.relation_target, to.relation_target
        ));
    }
    if from.validation != to.validation {
        notes.push("validation changed".into());
    }
    if from.preset != to.preset {
        notes.push("preset changed".into());
    }
    if from.max_pii_class != to.max_pii_class {
        notes.push(format!(
            "max_pii_class {}->{}",
            from.max_pii_class, to.max_pii_class
        ));
    }
    notes
}

fn diff_object(from: &ObjectSnapshot, to: &ObjectSnapshot) -> ObjectDiff {
    let mut d = ObjectDiff {
        api_slug: to.api_slug.clone(),
        ..Default::default()
    };
    let from_fields: HashMap<&str, &FieldSnapshot> = from
        .fields
        .iter()
        .map(|f| (f.api_name.as_str(), f))
        .collect();
    let to_fields: HashMap<&str, &FieldSnapshot> =
        to.fields.iter().map(|f| (f.api_name.as_str(), f)).collect();
    for (name, f) in &to_fields {
        match from_fields.get(name) {
            None => d.added.push((*f).clone()),
            Some(old) => {
                let notes = field_change_notes(old, f);
                if !notes.is_empty() {
                    d.changed.push(FieldChangeDetail {
                        api_name: name.to_string(),
                        from_kind: old.kind.clone(),
                        to_kind: f.kind.clone(),
                        changes: notes,
                    });
                }
            }
        }
    }
    for name in from_fields.keys() {
        if !to_fields.contains_key(name) {
            d.removed.push(name.to_string());
        }
    }
    d.added.sort_by(|a, b| a.api_name.cmp(&b.api_name));
    d.removed.sort();
    d.changed.sort_by(|a, b| a.api_name.cmp(&b.api_name));

    let from_pol: HashMap<&str, &RolePolicySnapshot> = from
        .row_policies
        .iter()
        .map(|p| (p.role.as_str(), p))
        .collect();
    let to_pol: HashMap<&str, &RolePolicySnapshot> = to
        .row_policies
        .iter()
        .map(|p| (p.role.as_str(), p))
        .collect();
    for (role, p) in &to_pol {
        match from_pol.get(role) {
            None => d.policies_added.push(role.to_string()),
            Some(old) => {
                if *old != *p {
                    d.policies_changed.push(role.to_string());
                }
            }
        }
    }
    for role in from_pol.keys() {
        if !to_pol.contains_key(role) {
            d.policies_removed.push(role.to_string());
        }
    }
    d.policies_added.sort();
    d.policies_removed.sort();
    d.policies_changed.sort();
    // Item 40 (C1): surface lifecycle flag flips in the diff.
    if from.lifecycle_enabled != to.lifecycle_enabled {
        d.lifecycle_changed = Some(to.lifecycle_enabled);
    }
    d
}

/// Compare two snapshots. Objects are matched by api_slug; fields by
/// api_name; policies by role.
pub fn diff_snapshots(from: &SnapshotDoc, to: &SnapshotDoc) -> SnapshotDiff {
    let mut d = SnapshotDiff::default();
    let from_objs: HashMap<&str, &ObjectSnapshot> = from
        .objects
        .iter()
        .map(|o| (o.api_slug.as_str(), o))
        .collect();
    let to_objs: HashMap<&str, &ObjectSnapshot> = to
        .objects
        .iter()
        .map(|o| (o.api_slug.as_str(), o))
        .collect();
    for (slug, o) in &to_objs {
        match from_objs.get(slug) {
            None => d.objects_added.push(slug.to_string()),
            Some(old) => {
                let od = diff_object(old, o);
                if !(od.added.is_empty()
                    && od.removed.is_empty()
                    && od.changed.is_empty()
                    && od.policies_added.is_empty()
                    && od.policies_removed.is_empty()
                    && od.policies_changed.is_empty()
                    && od.lifecycle_changed.is_none())
                {
                    d.objects.push(od);
                }
            }
        }
    }
    for slug in from_objs.keys() {
        if !to_objs.contains_key(slug) {
            d.objects_removed.push(slug.to_string());
        }
    }
    d.objects_added.sort();
    d.objects_removed.sort();
    d.objects.sort_by(|a, b| a.api_slug.cmp(&b.api_slug));
    d
}

// ---------------------------------------------------------------------------
// Build + apply service
// ---------------------------------------------------------------------------

/// Planned application step (dry-run output; also the machine-readable
/// form of "what would apply do").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApplyOp {
    CreateObject {
        api_slug: String,
    },
    /// The slug's table is shared portfolio-wide: the target adopts it
    /// (metadata-only row) instead of defining a new table. The adopter
    /// then sees the shared base fields live.
    AdoptObject {
        api_slug: String,
    },
    AddField {
        api_slug: String,
        api_name: String,
        kind: String,
    },
    SetRowPolicy {
        api_slug: String,
        role: String,
    },
}

/// Dry-run result: the ops [`SnapshotService::apply_snapshot`] would
/// execute, computed without writing anything.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ApplyPlan {
    pub ops: Vec<ApplyOp>,
}

impl ApplyPlan {
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn render_human(&self) -> String {
        if self.ops.is_empty() {
            return "(no changes — target already converges)\n".into();
        }
        let mut out = String::new();
        for op in &self.ops {
            match op {
                ApplyOp::CreateObject { api_slug } => {
                    out.push_str(&format!("create object {api_slug}\n"))
                }
                ApplyOp::AdoptObject { api_slug } => {
                    out.push_str(&format!("adopt object {api_slug} (shared table)\n"))
                }
                ApplyOp::AddField {
                    api_slug,
                    api_name,
                    kind,
                } => out.push_str(&format!("add field {api_slug}.{api_name} ({kind})\n")),
                ApplyOp::SetRowPolicy { api_slug, role } => {
                    out.push_str(&format!("set row policy {api_slug} role {role}\n"))
                }
            }
        }
        out
    }
}

/// What [`SnapshotService::apply_snapshot`] did.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyReport {
    pub vendor_id: String,
    pub snapshot_version: u64,
    pub payload_sha256: String,
    /// Slugs defined as brand-new tables.
    pub objects_created: Vec<String>,
    /// Slugs adopted onto the shared portfolio table.
    pub objects_adopted: Vec<String>,
    pub fields_added: u32,
    pub policies_set: u32,
}

pub struct SnapshotService {
    core: CoreDb,
    ontology: Ontology,
    evolver: SchemaEvolver,
    policies: RowFilters,
}

impl SnapshotService {
    pub fn new(
        core: CoreDb,
        ontology: Ontology,
        evolver: SchemaEvolver,
        policies: RowFilters,
    ) -> Self {
        Self {
            core,
            ontology,
            evolver,
            policies,
        }
    }

    /// Newest snapshot_version applied for (org, vendor), 0 if none.
    pub async fn last_applied_version(&self, ctx: &TenantContext, vendor_id: &str) -> Result<u64> {
        Ok(self
            .last_applied(ctx, vendor_id)
            .await?
            .map(|(v, _)| v)
            .unwrap_or(0))
    }

    /// Last applied (version, payload hash) for (org, vendor), if any.
    pub async fn last_applied(
        &self,
        ctx: &TenantContext,
        vendor_id: &str,
    ) -> Result<Option<(u64, String)>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(i64, String)> = sqlx::query_as(
            "SELECT snapshot_version, payload_sha256 FROM schema_snapshot_log \
             WHERE organization_id=$1 AND vendor_id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(vendor_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(row.map(|(v, h)| (v as u64, h)))
    }

    /// Export objects into a snapshot doc. `object_ids` must be visible to
    /// the caller (platform or own-org); siblings' objects fail closed.
    pub async fn build_snapshot(
        &self,
        ctx: &TenantContext,
        vendor_id: &str,
        snapshot_version: u64,
        object_ids: &[Uuid],
    ) -> Result<SnapshotDoc> {
        if vendor_id.is_empty() || vendor_id.len() > 128 {
            return Err(TinkerError::Validation("bad vendor_id".into()));
        }
        if snapshot_version == 0 {
            return Err(TinkerError::Validation(
                "snapshot_version must be > 0".into(),
            ));
        }
        let slug_by_id = self.slug_map(ctx).await?;
        let mut objects = Vec::with_capacity(object_ids.len());
        for object_id in object_ids {
            objects.push(self.snapshot_object(ctx, *object_id, &slug_by_id).await?);
        }
        objects.sort_by(|a, b| a.api_slug.cmp(&b.api_slug));
        Ok(SnapshotDoc {
            format: SNAPSHOT_FORMAT.into(),
            format_version: SNAPSHOT_FORMAT_VERSION,
            vendor_id: vendor_id.into(),
            snapshot_version,
            created_at: Utc::now().to_rfc3339(),
            objects,
        })
    }

    /// Export the tenant's full organization ontology: every
    /// organization-scope object visible to the caller — defined or
    /// adopted — ordered by slug. Platform-scope objects are excluded:
    /// they are not the organization's to port, and applying them would
    /// try to adopt rows the target has no business owning.
    pub async fn build_full_snapshot(
        &self,
        ctx: &TenantContext,
        vendor_id: &str,
        snapshot_version: u64,
    ) -> Result<SnapshotDoc> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM ontology_objects \
             WHERE scope_kind='organization' AND state='active' \
             ORDER BY api_slug",
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        self.build_snapshot(ctx, vendor_id, snapshot_version, &ids)
            .await
    }

    async fn slug_map(&self, ctx: &TenantContext) -> Result<HashMap<Uuid, String>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, String, Option<Uuid>)> = sqlx::query_as(
            "SELECT id, api_slug, adopted_from FROM ontology_objects \
             WHERE scope_kind='platform' \
                OR (scope_kind='organization' AND organization_id=$1)",
        )
        .bind(ctx.organization_id.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        let mut map = HashMap::with_capacity(rows.len() * 2);
        for (id, slug, adopted_from) in &rows {
            map.insert(*id, slug.clone());
            // Adopted rows see the root's base fields live, and those
            // fields' relation targets point at the ROOT's object ids —
            // which are invisible to this tenant. Mapping adopted_from
            // to the slug keeps relation targets resolvable.
            if let Some(root) = adopted_from {
                map.insert(*root, slug.clone());
            }
        }
        Ok(map)
    }

    async fn snapshot_object(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        slug_by_id: &HashMap<Uuid, String>,
    ) -> Result<ObjectSnapshot> {
        // Base description (fails closed for invisible objects) plus the
        // active evolution's extension fields: the snapshot captures the
        // EFFECTIVE schema, not just the pack base.
        let base = self.ontology.describe_object(ctx, object_id).await?;
        let resolved = self
            .evolver
            .resolve(ctx, object_id, VersionSel::Active)
            .await?;
        let desc = self
            .ontology
            .describe_object_with_ext(ctx, object_id, &resolved.ext_fields)
            .await?;
        // The object label is not part of ObjectDescription; fetch it
        // directly so apply can re-create the object faithfully.
        let label = {
            let mut tx = self.core.tenant_tx(ctx).await?;
            let row: Option<(String,)> =
                sqlx::query_as("SELECT label FROM ontology_objects WHERE id=$1")
                    .bind(object_id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(TinkerError::Db)?;
            tx.commit().await.map_err(TinkerError::Db)?;
            row.map(|(l,)| l).unwrap_or_else(|| base.name.clone())
        };
        let mut fields = Vec::with_capacity(desc.fields.len());
        for f in &desc.fields {
            let relation_target = f
                .relation_target_id
                .and_then(|id| slug_by_id.get(&id).cloned());
            if f.relation_target_id.is_some() && relation_target.is_none() {
                // A relation whose target the caller cannot see must not
                // be silently exported as a dangling reference.
                return Err(TinkerError::Internal(format!(
                    "cannot snapshot field '{}': relation target invisible",
                    f.api_name
                )));
            }
            fields.push(FieldSnapshot {
                api_name: f.api_name.clone(),
                label: f.label.clone(),
                kind: f.field_type.clone(),
                required: f.required,
                options: f.options_json.clone(),
                relation_target,
                validation: f.validation.clone(),
                preset: f.preset.clone(),
                // Item 42 (C7): always exported, so re-apply preserves it.
                max_pii_class: f.max_pii_class.clone(),
                sensitive: f.sensitive,
            });
        }
        fields.sort_by(|a, b| a.api_name.cmp(&b.api_name));

        let row_policies = self.snapshot_policies(ctx, object_id).await?;
        let evolution_version = self
            .evolver
            .list_versions(ctx, object_id)
            .await?
            .into_iter()
            .find(|v| v.status == "active")
            .map(|v| v.version_number);

        Ok(ObjectSnapshot {
            api_slug: base.api_slug,
            name: base.name,
            label,
            fields,
            row_policies,
            evolution_version,
            lifecycle_enabled: base.lifecycle_enabled,
        })
    }

    async fn snapshot_policies(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
    ) -> Result<Vec<RolePolicySnapshot>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let roles: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT role FROM row_filters \
             WHERE organization_id=$1 AND object_id=$2 ORDER BY role",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        let mut out = Vec::with_capacity(roles.len());
        for (role,) in roles {
            let policy = self.policies.load_policy(ctx, object_id, &role).await?;
            let mut filters = Vec::with_capacity(policy.filters.len());
            for f in &policy.filters {
                let value = match &f.value {
                    crate::RowFilterValue::Const(v) => v.clone(),
                    crate::RowFilterValue::ActorId => serde_json::json!({"actor": "id"}),
                };
                filters.push(FilterSnapshot {
                    field: f.field.clone(),
                    op: f.op.as_str().into(),
                    value,
                });
            }
            out.push(RolePolicySnapshot { role, filters });
        }
        Ok(out)
    }

    /// Dry-run: compute the ops apply would execute. Read-only. Fails
    /// closed on drift (existing field differs) and on targets that
    /// evolved past the snapshot's version pointer.
    ///
    /// For an object the target lacks, the plan distinguishes the two
    /// portfolio outcomes: `CreateObject` (the slug is new — apply will
    /// define a fresh table) vs `AdoptObject` (the slug's table is shared —
    /// apply will adopt it and the adopter then sees the shared base
    /// live, so only the delta fields are listed).
    pub async fn plan_apply(&self, ctx: &TenantContext, doc: &SnapshotDoc) -> Result<ApplyPlan> {
        let slug_by_id = self.slug_map(ctx).await?;
        let snapshot_slugs: HashSet<&str> =
            doc.objects.iter().map(|o| o.api_slug.as_str()).collect();
        let mut plan = ApplyPlan::default();
        for obj in &doc.objects {
            match self
                .ontology
                .describe_object_by_slug(ctx, &obj.api_slug)
                .await
            {
                Ok(desc) => {
                    self.evolution_guard(ctx, obj, desc.id).await?;
                    let effective = self.effective_schema(ctx, desc.id).await?;
                    let missing = self
                        .missing_fields(&effective, obj, &slug_by_id, &snapshot_slugs)
                        .await?;
                    for f in &missing {
                        plan.ops.push(ApplyOp::AddField {
                            api_slug: obj.api_slug.clone(),
                            api_name: f.api_name.clone(),
                            kind: f.kind.clone(),
                        });
                    }
                    for p in self.policies_to_set(ctx, Some(desc.id), obj).await? {
                        plan.ops.push(ApplyOp::SetRowPolicy {
                            api_slug: obj.api_slug.clone(),
                            role: p.role.clone(),
                        });
                    }
                }
                Err(TinkerError::NotFound(_)) => {
                    match self
                        .ontology
                        .describe_shared_root(ctx, &obj.api_slug)
                        .await?
                    {
                        Some(root) => {
                            plan.ops.push(ApplyOp::AdoptObject {
                                api_slug: obj.api_slug.clone(),
                            });
                            // The adopter will see the root's base live:
                            // converge the snapshot against it (no evolution
                            // guard — the target has no versions yet).
                            // The root's relation targets are its own
                            // (tenant-invisible) ids: resolve them through
                            // the owner pool so the plan compares against
                            // the root's REAL targets instead of waving
                            // them through on the snapshot-slug fallback.
                            let mut root_slugs = slug_by_id.clone();
                            let unmapped: Vec<Uuid> = root
                                .fields
                                .iter()
                                .filter(|f| f.field_type == "relation")
                                .filter_map(|f| f.relation_target_id)
                                .filter(|id| !root_slugs.contains_key(id))
                                .collect();
                            for (id, slug) in self.ontology.slugs_for_ids(&unmapped).await? {
                                root_slugs.insert(id, slug);
                            }
                            let missing = self
                                .missing_fields(&root, obj, &root_slugs, &snapshot_slugs)
                                .await?;
                            for f in &missing {
                                plan.ops.push(ApplyOp::AddField {
                                    api_slug: obj.api_slug.clone(),
                                    api_name: f.api_name.clone(),
                                    kind: f.kind.clone(),
                                });
                            }
                            for p in &obj.row_policies {
                                plan.ops.push(ApplyOp::SetRowPolicy {
                                    api_slug: obj.api_slug.clone(),
                                    role: p.role.clone(),
                                });
                            }
                        }
                        None => {
                            plan.ops.push(ApplyOp::CreateObject {
                                api_slug: obj.api_slug.clone(),
                            });
                            for f in &obj.fields {
                                plan.ops.push(ApplyOp::AddField {
                                    api_slug: obj.api_slug.clone(),
                                    api_name: f.api_name.clone(),
                                    kind: f.kind.clone(),
                                });
                            }
                            for p in &obj.row_policies {
                                plan.ops.push(ApplyOp::SetRowPolicy {
                                    api_slug: obj.api_slug.clone(),
                                    role: p.role.clone(),
                                });
                            }
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Ok(plan)
    }

    /// Refuse when the target's active evolution version is NEWER than the
    /// snapshot's pointer: the target evolved independently past the
    /// snapshot's lineage, so merging would be blind.
    async fn evolution_guard(
        &self,
        ctx: &TenantContext,
        obj: &ObjectSnapshot,
        object_id: Uuid,
    ) -> Result<()> {
        let Some(snap_v) = obj.evolution_version else {
            return Ok(());
        };
        if let Some(av) = self.active_evolution_version(ctx, object_id).await? {
            if av > snap_v {
                return Err(TinkerError::Validation(format!(
                    "snapshot apply refused for '{}': target evolved to v{av}, snapshot is v{snap_v}",
                    obj.api_slug
                )));
            }
        }
        Ok(())
    }

    async fn active_evolution_version(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
    ) -> Result<Option<i32>> {
        Ok(self
            .evolver
            .list_versions(ctx, object_id)
            .await?
            .into_iter()
            .find(|v| v.status == "active")
            .map(|v| v.version_number))
    }

    /// The target's effective schema: base fields (adopted roots resolve
    /// live) plus the active evolution's extension fields.
    async fn effective_schema(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
    ) -> Result<ObjectDescription> {
        let resolved = self
            .evolver
            .resolve(ctx, object_id, VersionSel::Active)
            .await?;
        self.ontology
            .describe_object_with_ext(ctx, object_id, &resolved.ext_fields)
            .await
    }

    /// Snapshot fields missing from the target's effective schema. Every
    /// present field is drift-checked: anything but identity fails closed
    /// (kind, label, required, options, relation target, validation
    /// rules, write preset). Physical columns and internal ids are
    /// per-org and ignored.
    ///
    /// `snapshot_slugs` covers the ordering case: a relation whose target
    /// is ensured by the same apply (adopted or defined in pass 1) is not
    /// "drift" just because the target row isn't visible yet.
    async fn missing_fields(
        &self,
        effective: &ObjectDescription,
        obj: &ObjectSnapshot,
        slug_by_id: &HashMap<Uuid, String>,
        snapshot_slugs: &HashSet<&str>,
    ) -> Result<Vec<FieldSnapshot>> {
        let current_fields: HashMap<&str, &FieldDescription> = effective
            .fields
            .iter()
            .map(|f| (f.api_name.as_str(), f))
            .collect();
        let mut missing = Vec::new();
        for f in &obj.fields {
            match current_fields.get(f.api_name.as_str()) {
                None => missing.push(f.clone()),
                Some(cur) => {
                    let mut drift = Vec::new();
                    if cur.field_type != f.kind {
                        drift.push(format!("kind {}->{}", cur.field_type, f.kind));
                    }
                    if cur.label != f.label {
                        drift.push("label differs".into());
                    }
                    if cur.required != f.required {
                        drift.push("required differs".into());
                    }
                    if cur.options_json != f.options {
                        drift.push("options differ".into());
                    }
                    if !relation_targets_match(
                        cur.relation_target_id,
                        &f.relation_target,
                        slug_by_id,
                        snapshot_slugs,
                    ) {
                        drift.push(format!(
                            "relation target {:?} -> {:?} differs",
                            cur.relation_target_id.and_then(|id| slug_by_id.get(&id)),
                            f.relation_target
                        ));
                    }
                    if cur.validation != f.validation {
                        drift.push("validation differs".into());
                    }
                    if cur.preset != f.preset {
                        drift.push("preset differs".into());
                    }
                    if !drift.is_empty() {
                        return Err(TinkerError::Validation(format!(
                            "schema convergence refused: field '{}.{}' drifted ({})",
                            obj.api_slug,
                            f.api_name,
                            drift.join(", ")
                        )));
                    }
                }
            }
        }
        Ok(missing)
    }

    /// Row policies needing (re-)set: replace semantics — a role whose
    /// current filters differ from the snapshot is re-set. `None`
    /// object id means the target has no policies yet (fresh adoption).
    async fn policies_to_set(
        &self,
        ctx: &TenantContext,
        object_id: Option<Uuid>,
        obj: &ObjectSnapshot,
    ) -> Result<Vec<RolePolicySnapshot>> {
        let mut out = Vec::new();
        for p in &obj.row_policies {
            let needs = match object_id {
                None => true,
                Some(id) => {
                    let current_pol = self.policies.load_policy(ctx, id, &p.role).await?;
                    let current_snap: Vec<FilterSnapshot> = current_pol
                        .filters
                        .iter()
                        .map(|f| FilterSnapshot {
                            field: f.field.clone(),
                            op: f.op.as_str().into(),
                            value: match &f.value {
                                crate::RowFilterValue::Const(v) => v.clone(),
                                crate::RowFilterValue::ActorId => {
                                    serde_json::json!({"actor": "id"})
                                }
                            },
                        })
                        .collect();
                    current_snap != p.filters
                }
            };
            if needs {
                out.push(p.clone());
            }
        }
        Ok(out)
    }

    /// Verify, guard, and apply a signed snapshot through M4 evolution.
    /// See the module docs for the atomicity story and honest limits.
    pub async fn apply_snapshot(
        &self,
        ctx: &TenantContext,
        envelope: &SignedSnapshot,
        expected_vendor_id: &str,
        expected_public_key: &[u8; 32],
    ) -> Result<ApplyReport> {
        let doc = verify_snapshot(envelope, expected_vendor_id, expected_public_key)?;
        // The log column is bigint: reject absurd versions before they
        // can wrap in the `as i64` cast at record time.
        if doc.snapshot_version > i64::MAX as u64 {
            return Err(TinkerError::Validation(
                "snapshot version out of range".into(),
            ));
        }
        match self.last_applied(ctx, &doc.vendor_id).await? {
            Some((v, h)) if v == doc.snapshot_version && h == envelope.payload_sha256 => {
                // The exact same artifact: a safe no-op. Idempotent
                // reapply converges here without touching the schema.
                return Ok(ApplyReport {
                    vendor_id: doc.vendor_id,
                    snapshot_version: doc.snapshot_version,
                    payload_sha256: envelope.payload_sha256.clone(),
                    objects_created: vec![],
                    objects_adopted: vec![],
                    fields_added: 0,
                    policies_set: 0,
                });
            }
            Some((v, _)) if doc.snapshot_version <= v => {
                return Err(TinkerError::Validation(format!(
                    "snapshot apply refused: version {} is not newer than last applied {v} (downgrade/replay)",
                    doc.snapshot_version
                )));
            }
            _ => {}
        }
        let snapshot_slugs: HashSet<&str> =
            doc.objects.iter().map(|o| o.api_slug.as_str()).collect();

        // Pass 1: every object exists — defined as a new table, or adopted
        // onto the shared portfolio table. Dependency-safe: relations
        // resolve by slug only after all objects are present.
        let mut ids: HashMap<&str, Uuid> = HashMap::new();
        let mut objects_created = Vec::new();
        let mut objects_adopted = Vec::new();
        for obj in &doc.objects {
            let id = match self
                .ontology
                .describe_object_by_slug(ctx, &obj.api_slug)
                .await
            {
                Ok(d) => d.id,
                Err(TinkerError::NotFound(_)) => {
                    let (meta, adopted) = self
                        .ontology
                        .define_or_adopt(
                            ctx,
                            &ObjectDef {
                                name: obj.name.clone(),
                                api_slug: obj.api_slug.clone(),
                                label: obj.label.clone(),
                                scope: Scope::Organization,
                                pack_id: None,
                                pack_version: None,
                            },
                        )
                        .await?;
                    if adopted {
                        objects_adopted.push(obj.api_slug.clone());
                    } else {
                        objects_created.push(obj.api_slug.clone());
                    }
                    meta.id
                }
                Err(e) => return Err(e),
            };
            // Item 40 (C1): converge the lifecycle flag. A restore must
            // not silently drop lifecycle management (which would
            // re-open direct writes on the object).
            self.ontology
                .set_lifecycle_enabled(ctx, id, obj.lifecycle_enabled)
                .await?;
            ids.insert(obj.api_slug.as_str(), id);
        }
        // Rebuild the slug map now: it includes this apply's adoptions
        // (adopted_from rows), so relation targets on adopted base fields
        // resolve to slugs.
        let slug_by_id = self.slug_map(ctx).await?;

        // Pass 2: converge every object against its LIVE effective schema
        // (adopted base resolves live from the root). Drift and evolution
        // guards fail closed here, before any schema write — the dry-run
        // plan computed the same delta read-only.
        let mut drafts: Vec<Uuid> = Vec::new();
        let mut fields_added: u32 = 0;
        let mut policy_work: Vec<(Uuid, Vec<RolePolicySnapshot>)> = Vec::new();
        for obj in &doc.objects {
            let object_id = ids[obj.api_slug.as_str()];
            self.evolution_guard(ctx, obj, object_id).await?;
            let effective = self.effective_schema(ctx, object_id).await?;
            let missing = self
                .missing_fields(&effective, obj, &slug_by_id, &snapshot_slugs)
                .await?;
            if !missing.is_empty() {
                // Build the draft fully before anything is promoted: a
                // failure here leaves the live schema untouched
                // (abandoned drafts are inert).
                let draft = self.evolver.create_draft(ctx, object_id).await?;
                for f in &missing {
                    let def = self.field_def_from_snapshot(ctx, f).await?;
                    if matches!(def.field_type, FieldType::Relation { .. }) {
                        self.evolver.add_relation(ctx, draft.id, &def).await?;
                    } else {
                        self.evolver.add_field(ctx, draft.id, &def).await?;
                    }
                    fields_added += 1;
                }
                self.evolver.mark_preview(ctx, draft.id).await?;
                drafts.push(draft.id);
            }
            let psets = self.policies_to_set(ctx, Some(object_id), obj).await?;
            if !psets.is_empty() {
                policy_work.push((object_id, psets));
            }
        }
        if drafts.is_empty() && policy_work.is_empty() {
            // Converged already, but the version is new: record it so the
            // version guard advances (a no-op apply is still an apply).
            self.record_apply(ctx, &doc, &envelope.payload_sha256)
                .await?;
            return Ok(ApplyReport {
                vendor_id: doc.vendor_id,
                snapshot_version: doc.snapshot_version,
                payload_sha256: envelope.payload_sha256.clone(),
                objects_created,
                objects_adopted,
                fields_added: 0,
                policies_set: 0,
            });
        }

        // Pass 3: promote everything. Per-object transactions; see the
        // module docs for the honest atomicity story.
        for draft_id in &drafts {
            self.evolver.promote(ctx, *draft_id).await?;
        }

        // Pass 4: row policies (replace semantics) against the promoted
        // schema.
        let mut policies_set: u32 = 0;
        for (object_id, psets) in &policy_work {
            let desc = self.effective_schema(ctx, *object_id).await?;
            for p in psets {
                let defs: Vec<RowFilterDef> = p
                    .filters
                    .iter()
                    .map(|f| RowFilterDef {
                        field: f.field.clone(),
                        op: f.op.clone(),
                        value: Some(f.value.clone()),
                    })
                    .collect();
                self.policies
                    .set_filters(ctx, &desc, &p.role, &defs)
                    .await?;
                policies_set += 1;
            }
        }

        // Pass 5: advance the version guard.
        self.record_apply(ctx, &doc, &envelope.payload_sha256)
            .await?;

        Ok(ApplyReport {
            vendor_id: doc.vendor_id,
            snapshot_version: doc.snapshot_version,
            payload_sha256: envelope.payload_sha256.clone(),
            objects_created,
            objects_adopted,
            fields_added,
            policies_set,
        })
    }

    /// Advance the version guard. The upsert only moves the log row
    /// forward: when two applies race, the loser (whose version is no
    /// longer newer) fails closed instead of clobbering the winner's
    /// row. The schema work it already did is additive and idempotent,
    /// so the loser can simply re-read the log and retry with a newer
    /// snapshot.
    async fn record_apply(
        &self,
        ctx: &TenantContext,
        doc: &SnapshotDoc,
        payload_sha256: &str,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let applied = sqlx::query(
            "INSERT INTO schema_snapshot_log \
             (organization_id, vendor_id, snapshot_version, payload_sha256) \
             VALUES ($1,$2,$3,$4) \
             ON CONFLICT (organization_id, vendor_id) DO UPDATE SET \
               snapshot_version = EXCLUDED.snapshot_version, \
               payload_sha256 = EXCLUDED.payload_sha256, \
               applied_at = now() \
             WHERE schema_snapshot_log.snapshot_version < EXCLUDED.snapshot_version",
        )
        .bind(ctx.organization_id.0)
        .bind(&doc.vendor_id)
        .bind(doc.snapshot_version as i64)
        .bind(payload_sha256)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        if applied.rows_affected() == 0 {
            return Err(TinkerError::Validation(
                "snapshot apply lost a concurrent race: a newer version was \
                 recorded by another apply; re-read the log and retry"
                    .into(),
            ));
        }
        Ok(())
    }

    async fn field_def_from_snapshot(
        &self,
        ctx: &TenantContext,
        f: &FieldSnapshot,
    ) -> Result<FieldDef> {
        let field_type = if f.kind == "relation" {
            let target_slug = f.relation_target.as_ref().ok_or_else(|| {
                TinkerError::Validation(format!(
                    "field '{}': relation without a target slug",
                    f.api_name
                ))
            })?;
            // describe fails closed for invisible targets: no
            // cross-tenant FK can be built here.
            let target = self
                .ontology
                .describe_object_by_slug(ctx, target_slug)
                .await?;
            FieldType::Relation {
                target_object_id: target.id,
            }
        } else {
            parse_field_kind(&f.kind)?
        };
        Ok(FieldDef {
            name: f.api_name.clone(),
            api_name: f.api_name.clone(),
            label: f.label.clone(),
            field_type,
            options: f.options.clone(),
            required: f.required,
            validation: f.validation.clone(),
            preset: f.preset.clone(),
            // Item 42 (C7): validated by add_field; a corrupt value fails
            // the apply, never lands permissive.
            max_pii_class: f.max_pii_class.clone(),
            sensitive: f.sensitive,
        })
    }
}

/// Do a live relation target and a snapshot relation target name the same
/// object? The live side is a per-org UUID resolved through the tenant's
/// slug map (adopted roots included); the snapshot side is a portable
/// slug. A target the same apply is ensuring (adopted or defined in
/// pass 1) is not "drift" merely because its row isn't visible yet.
fn relation_targets_match(
    live_target_id: Option<Uuid>,
    snapshot_target: &Option<String>,
    slug_by_id: &HashMap<Uuid, String>,
    snapshot_slugs: &HashSet<&str>,
) -> bool {
    match (
        live_target_id.and_then(|id| slug_by_id.get(&id)),
        snapshot_target,
    ) {
        (Some(a), Some(b)) => a == b,
        (None, Some(b)) => snapshot_slugs.contains(b.as_str()),
        (None, None) => true,
        (Some(_), None) => false,
    }
}

/// Reverse of [`FieldType::kind_name`] for non-relation kinds.
fn parse_field_kind(kind: &str) -> Result<FieldType> {
    match kind {
        "text" => Ok(FieldType::Text),
        "richtext" => Ok(FieldType::RichText),
        "number" => Ok(FieldType::Number),
        "date" => Ok(FieldType::Date),
        "datetime" => Ok(FieldType::DateTime),
        "boolean" => Ok(FieldType::Boolean),
        "select" => Ok(FieldType::Select),
        "multi_select" => Ok(FieldType::MultiSelect),
        "currency" => Ok(FieldType::Currency),
        "email" => Ok(FieldType::Email),
        "phone" => Ok(FieldType::Phone),
        "url" => Ok(FieldType::Url),
        "file" => Ok(FieldType::File),
        "relation" => Err(TinkerError::Internal(
            "relation kinds need a target and are handled separately".into(),
        )),
        other => Err(TinkerError::Validation(format!(
            "unknown field kind: {other}"
        ))),
    }
}
