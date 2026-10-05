//! WebAuthn (W3C Web Authentication Level 2) relying-party verification.
//!
//! The browser ceremony (`navigator.credentials.create/get`) produces
//! `clientDataJSON`, `authenticatorData`, a signature (assertions) or an
//! `attestationObject` (registration). This module verifies them:
//!
//! - client data: `type`, `challenge` (the server's single-use bytes),
//!   and `origin` (one of the relying party's configured origins);
//! - authenticator data: `rpIdHash == SHA-256(rp_id)`, user presence
//!   (UP) set, user verification (UV) reported, signature counter
//!   monotonic when the authenticator keeps one;
//! - the signature over `authenticatorData ‖ SHA-256(clientDataJSON)`
//!   with the credential's COSE public key: ES256 (P-256, the common
//!   platform-authenticator algorithm) or EdDSA (Ed25519).
//!
//! Attestation statements are not verified against vendor roots (the
//! "none" conveyance model): registration proves possession of the new
//! key and binds it to this origin and RP, not the authenticator's make.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ciborium::value::Value as Cbor;
use sha2::{Digest, Sha256};

use tinker_core::{Result, TinkerError};

/// COSE algorithm identifiers (IANA).
pub const COSE_ALG_ES256: i64 = -7;
pub const COSE_ALG_EDDSA: i64 = -8;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

/// The relying party: the RP ID authenticators scope credentials to and
/// the exact origins a ceremony may come from.
#[derive(Debug, Clone)]
pub struct RelyingParty {
    pub id: String,
    pub origins: Vec<String>,
}

impl RelyingParty {
    /// `TINKER_WEBAUTHN_RP_ID` / `TINKER_WEBAUTHN_ORIGINS` (comma list),
    /// defaulting to `host` and `https://host`.
    pub fn from_env(host: &str) -> Self {
        let id = std::env::var("TINKER_WEBAUTHN_RP_ID")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| host.to_string());
        let origins = std::env::var("TINKER_WEBAUTHN_ORIGINS")
            .ok()
            .filter(|v| !v.is_empty())
            .map(|v| v.split(',').map(|o| o.trim().to_string()).collect())
            .unwrap_or_else(|| vec![format!("https://{host}")]);
        Self { id, origins }
    }
}

/// A credential public key, parsed from its COSE_Key encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseKey {
    Ed25519([u8; 32]),
    P256 { x: [u8; 32], y: [u8; 32] },
}

impl CoseKey {
    pub fn alg(&self) -> i64 {
        match self {
            CoseKey::Ed25519(_) => COSE_ALG_EDDSA,
            CoseKey::P256 { .. } => COSE_ALG_ES256,
        }
    }

    /// Parse a CBOR COSE_Key (RFC 9053): OKP/Ed25519 or EC2/P-256.
    pub fn from_cose(bytes: &[u8]) -> Result<Self> {
        let v: Cbor = ciborium::de::from_reader(bytes)
            .map_err(|_| bad("credential public key is not CBOR"))?;
        Self::from_cbor(&v)
    }

    fn from_cbor(v: &Cbor) -> Result<Self> {
        let map = v.as_map().ok_or_else(|| bad("COSE key is not a map"))?;
        let get = |label: i64| {
            map.iter()
                .find(|(k, _)| k.as_integer().and_then(|i| i64::try_from(i).ok()) == Some(label))
                .map(|(_, v)| v)
        };
        let int = |label: i64| {
            get(label)
                .and_then(|v| v.as_integer())
                .and_then(|i| i64::try_from(i).ok())
        };
        let bytes32 = |label: i64| -> Result<[u8; 32]> {
            get(label)
                .and_then(|v| v.as_bytes())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| bad("COSE key coordinate is not 32 bytes"))
        };
        match (int(1), int(3), int(-1)) {
            // kty OKP, alg EdDSA, crv Ed25519
            (Some(1), Some(COSE_ALG_EDDSA), Some(6)) => Ok(CoseKey::Ed25519(bytes32(-2)?)),
            // kty EC2, alg ES256, crv P-256
            (Some(2), Some(COSE_ALG_ES256), Some(1)) => Ok(CoseKey::P256 {
                x: bytes32(-2)?,
                y: bytes32(-3)?,
            }),
            _ => Err(bad(
                "unsupported COSE key (want EdDSA/Ed25519 or ES256/P-256)",
            )),
        }
    }

    /// Canonical COSE_Key bytes for storage.
    pub fn to_cose(&self) -> Vec<u8> {
        let int = |i: i64| Cbor::Integer(i.into());
        let map = match self {
            CoseKey::Ed25519(x) => vec![
                (int(1), int(1)),
                (int(3), int(COSE_ALG_EDDSA)),
                (int(-1), int(6)),
                (int(-2), Cbor::Bytes(x.to_vec())),
            ],
            CoseKey::P256 { x, y } => vec![
                (int(1), int(2)),
                (int(3), int(COSE_ALG_ES256)),
                (int(-1), int(1)),
                (int(-2), Cbor::Bytes(x.to_vec())),
                (int(-3), Cbor::Bytes(y.to_vec())),
            ],
        };
        let mut out = Vec::new();
        ciborium::ser::into_writer(&Cbor::Map(map), &mut out).expect("CBOR encode to Vec");
        out
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            CoseKey::Ed25519(pk) => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                let key = VerifyingKey::from_bytes(pk).map_err(|_| bad("bad Ed25519 key"))?;
                let sig = <[u8; 64]>::try_from(signature).map_err(|_| denied("bad signature"))?;
                key.verify(message, &Signature::from_bytes(&sig))
                    .map_err(|_| denied("bad signature"))
            }
            CoseKey::P256 { x, y } => {
                use p256::ecdsa::signature::Verifier;
                use p256::ecdsa::{Signature, VerifyingKey};
                let mut sec1 = [0u8; 65];
                sec1[0] = 0x04;
                sec1[1..33].copy_from_slice(x);
                sec1[33..].copy_from_slice(y);
                let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| bad("bad P-256 key"))?;
                // WebAuthn ES256 signatures are ASN.1 DER.
                let sig = Signature::from_der(signature).map_err(|_| denied("bad signature"))?;
                key.verify(message, &sig)
                    .map_err(|_| denied("bad signature"))
            }
        }
    }
}

fn bad(msg: &str) -> TinkerError {
    TinkerError::Validation(format!("webauthn: {msg}"))
}

fn denied(msg: &str) -> TinkerError {
    TinkerError::Forbidden(format!("webauthn: {msg}"))
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| bad("bad base64url"))
}

/// Parsed authenticator data (the fixed header plus, at registration, the
/// attested credential).
struct AuthData {
    flags: u8,
    sign_count: u32,
    attested: Option<(Vec<u8>, CoseKey)>,
}

fn parse_auth_data(rp: &RelyingParty, data: &[u8]) -> Result<AuthData> {
    if data.len() < 37 {
        return Err(bad("authenticator data too short"));
    }
    if data[..32] != Sha256::digest(rp.id.as_bytes())[..] {
        return Err(denied("rpIdHash does not match this relying party"));
    }
    let flags = data[32];
    if flags & FLAG_UP == 0 {
        return Err(denied("user presence flag not set"));
    }
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    let attested = if flags & FLAG_AT != 0 {
        // aaguid(16) ‖ credIdLen(2) ‖ credId ‖ COSE key (CBOR, then any
        // extensions — decode exactly one CBOR item).
        let rest = &data[37..];
        if rest.len() < 18 {
            return Err(bad("attested credential data too short"));
        }
        let len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        let cred = rest
            .get(18..18 + len)
            .ok_or_else(|| bad("credential id overruns authenticator data"))?
            .to_vec();
        let mut key_bytes = &rest[18 + len..];
        let v: Cbor = ciborium::de::from_reader(&mut key_bytes)
            .map_err(|_| bad("credential public key is not CBOR"))?;
        Some((cred, CoseKey::from_cbor(&v)?))
    } else {
        None
    };
    Ok(AuthData {
        flags,
        sign_count,
        attested,
    })
}

fn check_client_data(
    rp: &RelyingParty,
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge: &[u8],
) -> Result<()> {
    let cd: serde_json::Value =
        serde_json::from_slice(client_data_json).map_err(|_| bad("clientDataJSON is not JSON"))?;
    if cd.get("type").and_then(|v| v.as_str()) != Some(expected_type) {
        return Err(denied("wrong ceremony type"));
    }
    let challenge = cd
        .get("challenge")
        .and_then(|v| v.as_str())
        .map(b64url_decode)
        .transpose()?
        .ok_or_else(|| bad("clientDataJSON has no challenge"))?;
    // Constant-time is unnecessary: the challenge is public by design;
    // what matters is that it is the single-use one this server minted.
    if challenge != expected_challenge {
        return Err(denied("challenge mismatch"));
    }
    let origin = cd.get("origin").and_then(|v| v.as_str()).unwrap_or("");
    if !rp.origins.iter().any(|o| o == origin) {
        return Err(denied("origin not allowed for this relying party"));
    }
    Ok(())
}

/// A verified assertion.
#[derive(Debug, Clone, Copy)]
pub struct Assertion {
    /// UV flag: the authenticator verified the user (biometric / PIN) —
    /// the only case a passkey login counts as multi-factor.
    pub user_verified: bool,
    pub sign_count: u32,
}

/// Verify a login assertion (`navigator.credentials.get`).
pub fn verify_assertion(
    rp: &RelyingParty,
    key: &CoseKey,
    stored_sign_count: u32,
    expected_challenge: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
) -> Result<Assertion> {
    check_client_data(rp, client_data_json, "webauthn.get", expected_challenge)?;
    let ad = parse_auth_data(rp, authenticator_data)?;
    // A counter that does not advance means a cloned authenticator (when
    // the authenticator keeps counters at all; 0/0 means it does not).
    if (ad.sign_count != 0 || stored_sign_count != 0) && ad.sign_count <= stored_sign_count {
        return Err(denied(
            "signature counter did not advance (possible cloned key)",
        ));
    }
    let mut message = authenticator_data.to_vec();
    message.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&message, signature)?;
    Ok(Assertion {
        user_verified: ad.flags & FLAG_UV != 0,
        sign_count: ad.sign_count,
    })
}

/// A verified registration.
#[derive(Debug, Clone)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub key: CoseKey,
    pub sign_count: u32,
    pub user_verified: bool,
}

/// Verify a registration (`navigator.credentials.create`).
pub fn verify_registration(
    rp: &RelyingParty,
    expected_challenge: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<Registration> {
    check_client_data(rp, client_data_json, "webauthn.create", expected_challenge)?;
    let att: Cbor = ciborium::de::from_reader(attestation_object)
        .map_err(|_| bad("attestationObject is not CBOR"))?;
    let auth_data = att
        .as_map()
        .and_then(|m| {
            m.iter()
                .find(|(k, _)| k.as_text() == Some("authData"))
                .and_then(|(_, v)| v.as_bytes())
        })
        .ok_or_else(|| bad("attestationObject has no authData"))?;
    let ad = parse_auth_data(rp, auth_data)?;
    let (credential_id, key) = ad
        .attested
        .ok_or_else(|| bad("registration carries no attested credential"))?;
    if credential_id.is_empty() || credential_id.len() > 1023 {
        return Err(bad("credential id length out of range"));
    }
    Ok(Registration {
        credential_id,
        key,
        sign_count: ad.sign_count,
        user_verified: ad.flags & FLAG_UV != 0,
    })
}

/// A software authenticator for tests and local tooling: produces real
/// WebAuthn assertion fields (base64url) for an Ed25519 key, exactly as a
/// browser + authenticator would. Never part of a production login path.
pub mod soft_authenticator {
    use super::*;

    /// Flags byte for an assertion with user presence and, optionally,
    /// user verification.
    pub fn flags(user_verified: bool) -> u8 {
        FLAG_UP | if user_verified { FLAG_UV } else { 0 }
    }

    /// `(client_data_json, attestation_object)`, base64url: a "none"
    /// attestation registering `key` under `credential_id`.
    pub fn ed25519_registration(
        key: &ed25519_dalek::SigningKey,
        rp: &RelyingParty,
        challenge: &[u8],
        credential_id: &[u8],
    ) -> (String, String) {
        let cd = serde_json::json!({
            "type": "webauthn.create",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": rp.origins.first().cloned().unwrap_or_default(),
        })
        .to_string();
        let mut ad = Sha256::digest(rp.id.as_bytes()).to_vec();
        ad.push(FLAG_UP | FLAG_UV | FLAG_AT);
        ad.extend_from_slice(&0u32.to_be_bytes());
        ad.extend_from_slice(&[0u8; 16]);
        ad.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        ad.extend_from_slice(credential_id);
        ad.extend_from_slice(&CoseKey::Ed25519(key.verifying_key().to_bytes()).to_cose());
        let att = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
        ]);
        let mut att_bytes = Vec::new();
        ciborium::ser::into_writer(&att, &mut att_bytes).expect("CBOR encode to Vec");
        (
            URL_SAFE_NO_PAD.encode(cd.as_bytes()),
            URL_SAFE_NO_PAD.encode(att_bytes),
        )
    }

    /// `(client_data_json, authenticator_data, signature)`, base64url.
    pub fn ed25519_assertion(
        key: &ed25519_dalek::SigningKey,
        rp: &RelyingParty,
        challenge: &[u8],
        sign_count: u32,
        user_verified: bool,
    ) -> (String, String, String) {
        use ed25519_dalek::Signer;
        let cd = serde_json::json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": rp.origins.first().cloned().unwrap_or_default(),
        })
        .to_string();
        let mut ad = Sha256::digest(rp.id.as_bytes()).to_vec();
        ad.push(flags(user_verified));
        ad.extend_from_slice(&sign_count.to_be_bytes());
        let mut msg = ad.clone();
        msg.extend_from_slice(&Sha256::digest(cd.as_bytes()));
        let sig = key.sign(&msg).to_bytes();
        (
            URL_SAFE_NO_PAD.encode(cd.as_bytes()),
            URL_SAFE_NO_PAD.encode(&ad),
            URL_SAFE_NO_PAD.encode(sig),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp() -> RelyingParty {
        RelyingParty {
            id: "tinker.test".into(),
            origins: vec!["https://tinker.test".into()],
        }
    }

    fn client_data(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::json!({
            "type": ty,
            "challenge": URL_SAFE_NO_PAD.encode(challenge),
            "origin": origin,
        })
        .to_string()
        .into_bytes()
    }

    fn auth_data(rp_id: &str, flags: u8, count: u32) -> Vec<u8> {
        let mut d = Sha256::digest(rp_id.as_bytes()).to_vec();
        d.push(flags);
        d.extend_from_slice(&count.to_be_bytes());
        d
    }

    fn sign_ed(sk: &ed25519_dalek::SigningKey, ad: &[u8], cd: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut m = ad.to_vec();
        m.extend_from_slice(&Sha256::digest(cd));
        sk.sign(&m).to_bytes().to_vec()
    }

    fn p256_key() -> (p256::ecdsa::SigningKey, CoseKey) {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pt = sk.verifying_key().to_encoded_point(false);
        let key = CoseKey::P256 {
            x: pt.x().unwrap().as_slice().try_into().unwrap(),
            y: pt.y().unwrap().as_slice().try_into().unwrap(),
        };
        (sk, key)
    }

    #[test]
    fn es256_and_eddsa_assertions_verify_with_uv_reported() {
        let challenge = [9u8; 32];
        let cd = client_data("webauthn.get", &challenge, "https://tinker.test");

        let (psk, pkey) = p256_key();
        let ad = auth_data("tinker.test", FLAG_UP | FLAG_UV, 5);
        let mut m = ad.clone();
        m.extend_from_slice(&Sha256::digest(&cd));
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = psk.sign(&m);
        let a = verify_assertion(
            &rp(),
            &pkey,
            4,
            &challenge,
            &cd,
            &ad,
            sig.to_der().as_bytes(),
        )
        .unwrap();
        assert!(a.user_verified);
        assert_eq!(a.sign_count, 5);

        let esk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let ekey = CoseKey::Ed25519(esk.verifying_key().to_bytes());
        let ad = auth_data("tinker.test", FLAG_UP, 0);
        let a = verify_assertion(
            &rp(),
            &ekey,
            0,
            &challenge,
            &cd,
            &ad,
            &sign_ed(&esk, &ad, &cd),
        )
        .unwrap();
        assert!(!a.user_verified, "UP without UV is single-factor");
        // COSE round trip.
        assert_eq!(CoseKey::from_cose(&ekey.to_cose()).unwrap(), ekey);
        assert_eq!(CoseKey::from_cose(&pkey.to_cose()).unwrap(), pkey);
    }

    #[test]
    fn every_binding_is_enforced() {
        let challenge = [9u8; 32];
        let esk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let key = CoseKey::Ed25519(esk.verifying_key().to_bytes());
        let good_cd = client_data("webauthn.get", &challenge, "https://tinker.test");
        let good_ad = auth_data("tinker.test", FLAG_UP | FLAG_UV, 10);
        let case = |cd: &[u8], ad: &[u8], stored: u32| {
            verify_assertion(
                &rp(),
                &key,
                stored,
                &challenge,
                cd,
                ad,
                &sign_ed(&esk, ad, cd),
            )
        };
        assert!(case(&good_cd, &good_ad, 9).is_ok());
        let cases: Vec<(&str, Vec<u8>, Vec<u8>, u32)> = vec![
            (
                "phishing origin",
                client_data("webauthn.get", &challenge, "https://evil.test"),
                good_ad.clone(),
                9,
            ),
            (
                "other challenge",
                client_data("webauthn.get", &[1u8; 32], "https://tinker.test"),
                good_ad.clone(),
                9,
            ),
            (
                "registration data",
                client_data("webauthn.create", &challenge, "https://tinker.test"),
                good_ad.clone(),
                9,
            ),
            (
                "other rp",
                good_cd.clone(),
                auth_data("evil.test", FLAG_UP, 10),
                9,
            ),
            (
                "no user presence",
                good_cd.clone(),
                auth_data("tinker.test", FLAG_UV, 10),
                9,
            ),
            ("counter replay", good_cd.clone(), good_ad.clone(), 10),
        ];
        for (label, cd, ad, stored) in cases {
            assert!(case(&cd, &ad, stored).is_err(), "{label} must fail");
        }
        // Signature over different bytes.
        let other = sign_ed(&esk, &auth_data("tinker.test", FLAG_UP, 11), &good_cd);
        assert!(verify_assertion(&rp(), &key, 9, &challenge, &good_cd, &good_ad, &other).is_err());
    }

    #[test]
    fn registration_extracts_the_attested_key() {
        let challenge = [4u8; 32];
        let (_, key) = p256_key();
        let cred_id = vec![0xAB; 16];
        let mut ad = auth_data("tinker.test", FLAG_UP | FLAG_UV | FLAG_AT, 0);
        ad.extend_from_slice(&[0u8; 16]); // aaguid
        ad.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        ad.extend_from_slice(&cred_id);
        ad.extend_from_slice(&key.to_cose());
        let att = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(ad)),
        ]);
        let mut att_bytes = Vec::new();
        ciborium::ser::into_writer(&att, &mut att_bytes).unwrap();
        let cd = client_data("webauthn.create", &challenge, "https://tinker.test");
        let r = verify_registration(&rp(), &challenge, &cd, &att_bytes).unwrap();
        assert_eq!(r.credential_id, cred_id);
        assert_eq!(r.key, key);
        assert!(r.user_verified);
        // A login-type client data cannot register a key.
        let wrong = client_data("webauthn.get", &challenge, "https://tinker.test");
        assert!(verify_registration(&rp(), &challenge, &wrong, &att_bytes).is_err());
    }
}
