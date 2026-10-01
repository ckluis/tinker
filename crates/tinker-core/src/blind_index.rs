//! Keyed blind index for sensitive (vault-backed) fields.
//!
//! A sensitive field's value lives only in the PII vault; the data row
//! holds its `pii_refs` id plus this digest, so exact-match lookups
//! ("find the contact with this email") work without plaintext in core.
//! The digest is `HMAC-SHA256(key, org_id ‖ field_id ‖ normalize(value))`:
//! scoped per organization and per field, so equal values in two orgs or
//! two fields never share a digest. The key is separate from the vault
//! KEK (`TINKER_BLIND_INDEX_KEY`), so KEK rotation never invalidates an
//! index. See docs/pii-sensitive-fields.md.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

use crate::{Result, TinkerError};

/// Environment variable holding the 32-byte key as 64 hex chars.
pub const BLIND_INDEX_KEY_ENV: &str = "TINKER_BLIND_INDEX_KEY";

#[derive(Clone)]
pub struct BlindIndexKey([u8; 32]);

impl std::fmt::Debug for BlindIndexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlindIndexKey(..)")
    }
}

impl BlindIndexKey {
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self(key)
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.trim();
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TinkerError::Validation(format!(
                "{BLIND_INDEX_KEY_ENV} must be 32 bytes as 64 hex chars"
            )));
        }
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).map_err(|_| {
                TinkerError::Validation(format!("{BLIND_INDEX_KEY_ENV} is not hex"))
            })?;
        }
        Ok(Self(key))
    }

    /// `Ok(None)` when unset (sensitive writes and lookups then fail
    /// closed at use); an unparseable value is an error, never ignored.
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var(BLIND_INDEX_KEY_ENV) {
            Ok(v) if !v.is_empty() => Self::from_hex(&v).map(Some),
            _ => Ok(None),
        }
    }

    /// Hex digest of `value` for one field of one organization.
    pub fn digest(&self, org: Uuid, field_id: Uuid, field_kind: &str, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(org.as_bytes());
        mac.update(field_id.as_bytes());
        mac.update(normalize(field_kind, value).as_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

/// Exact-match normalization: what counts as "the same value" for a
/// lookup. Trimmed always; emails case-folded; phones reduced to `+` and
/// digits so formatting differences do not split matches.
pub fn normalize(field_kind: &str, value: &str) -> String {
    let v = value.trim();
    match field_kind {
        "email" => v.to_lowercase(),
        "phone" => v
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '+')
            .collect(),
        _ => v.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> BlindIndexKey {
        BlindIndexKey::from_bytes([7u8; 32])
    }

    #[test]
    fn digest_is_stable_scoped_and_normalized() {
        let (org, other_org, field) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let a = key().digest(org, field, "email", "Maya@Example.com ");
        assert_eq!(a, key().digest(org, field, "email", "maya@example.com"));
        assert_eq!(a.len(), 64);
        assert_ne!(
            a,
            key().digest(other_org, field, "email", "maya@example.com")
        );
        assert_ne!(
            a,
            key().digest(org, Uuid::from_u128(4), "email", "maya@example.com")
        );
        assert_eq!(
            key().digest(org, field, "phone", "+1 (555) 010-2000"),
            key().digest(org, field, "phone", "+15550102000")
        );
        // Text is case-sensitive: only trimmed.
        assert_ne!(
            key().digest(org, field, "text", "Maya"),
            key().digest(org, field, "text", "maya")
        );
    }

    #[test]
    fn key_parsing_fails_closed() {
        assert!(BlindIndexKey::from_hex("abc").is_err());
        assert!(BlindIndexKey::from_hex(&"zz".repeat(32)).is_err());
        assert!(BlindIndexKey::from_hex(&"0a".repeat(32)).is_ok());
        assert_eq!(format!("{:?}", key()), "BlindIndexKey(..)");
    }
}
