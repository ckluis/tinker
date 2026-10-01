//! OIDC adapter.
//!
//! Validates an OIDC ID token (JWT) and maps its subject to a Tinker actor
//! through a stored (issuer, subject) binding. The token's signature,
//! issuer, audience, and expiry are all verified; nothing about the token
//! is trusted on shape alone.
//!
//! Key management: the adapter is constructed with explicit decoding keys.
//! Production deployments resolve keys from the provider's JWKS endpoint;
//! that fetch-and-cache loop is backlog (see BACKLOG.md). The verification
//! path — parse, verify signature, validate claims, bind subject — is the
//! same either way, which is what the M1 exit test exercises.

use async_trait::async_trait;
use chrono::Utc;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use uuid::Uuid;

use tinker_core::{Result, TinkerError};

use super::{AssuranceLevel, AuthAdapter, AuthnContext, Credential, CredentialKind, PrincipalKind};

/// A Tinker actor bound to an external OIDC subject.
#[derive(Debug, Clone)]
pub struct OidcBinding {
    pub actor_id: Uuid,
    pub organization_ids: Vec<Uuid>,
}

/// Storage the adapter needs for subject → actor resolution.
///
/// Actors are per-organization in Tinker, so one human can hold bindings
/// in several orgs under the same (issuer, subject). The optional
/// organization hint scopes the lookup to the org the login request
/// names; without it the store may return any live binding.
#[async_trait]
pub trait OidcBindingStore: Send + Sync {
    async fn find_actor_by_subject(
        &self,
        issuer: &str,
        subject: &str,
        organization_id: Option<Uuid>,
    ) -> Result<Option<OidcBinding>>;
}

/// One accepted signing key for an issuer.
#[derive(Clone)]
pub struct OidcKey {
    pub key_id: Option<String>,
    pub algorithm: Algorithm,
    pub decoding_key: DecodingKey,
}

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub keys: Vec<OidcKey>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: Aud,
    // Required claim: jsonwebtoken rejects the token when exp is missing
    // or past (modulo clock-skew leeway). We don't read the value —
    // validation happens inside `decode`.
    #[allow(dead_code)]
    exp: i64,
    /// Echo of the nonce the login attempt sent to the provider.
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Aud {
    One(String),
    Many(Vec<String>),
}

impl Aud {
    fn contains(&self, aud: &str) -> bool {
        match self {
            Aud::One(a) => a == aud,
            Aud::Many(list) => list.iter().any(|a| a == aud),
        }
    }
}

pub struct OidcAdapter<S: OidcBindingStore> {
    store: S,
    config: OidcConfig,
}

impl<S: OidcBindingStore> OidcAdapter<S> {
    pub fn new(store: S, config: OidcConfig) -> Self {
        Self { store, config }
    }

    fn verify_token(&self, id_token: &str) -> Result<IdTokenClaims> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|_| TinkerError::Validation("oidc: malformed token".into()))?;
        let key = self
            .config
            .keys
            .iter()
            .find(|k| {
                k.algorithm == header.alg
                    && match (&k.key_id, &header.kid) {
                        (Some(want), Some(got)) => want == got,
                        (None, _) => true,
                        (Some(_), None) => false,
                    }
            })
            .ok_or_else(|| TinkerError::Validation("oidc: no key for token alg/kid".into()))?;

        let mut validation = Validation::new(key.algorithm);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        // Audience is checked manually below to support both shapes.
        validation.validate_aud = false;

        let data = decode::<IdTokenClaims>(id_token, &key.decoding_key, &validation)
            .map_err(|e| TinkerError::Validation(format!("oidc: token rejected: {e}")))?;
        if !data.claims.aud.contains(&self.config.audience) {
            return Err(TinkerError::Validation("oidc: audience mismatch".into()));
        }
        Ok(data.claims)
    }
}

#[async_trait]
impl<S: OidcBindingStore> AuthAdapter for OidcAdapter<S> {
    fn method(&self) -> &'static str {
        "oidc"
    }

    fn supports(&self, credential: &Credential) -> bool {
        credential.kind == CredentialKind::OidcCode
    }

    async fn authenticate(&self, credential: &Credential) -> Result<AuthnContext> {
        let id_token = credential
            .payload
            .get("id_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TinkerError::Validation("oidc: missing id_token".into()))?;

        let claims = self.verify_token(id_token)?;
        // Replay binding: the token must carry the nonce of THIS login
        // attempt (minted server-side at /login/oidc/start and consumed
        // once at the callback). A token lifted from another session —
        // or a bare token presented without an attempt — has none that
        // matches, so it never mints a session.
        let expected_nonce = credential
            .payload
            .get("nonce")
            .and_then(|v| v.as_str())
            .filter(|n| !n.is_empty())
            .ok_or_else(|| TinkerError::Validation("oidc: missing login nonce".into()))?;
        if claims.nonce.as_deref() != Some(expected_nonce) {
            return Err(TinkerError::Validation("oidc: nonce mismatch".into()));
        }

        // The login request names its organization; scope the binding
        // lookup so a human with actors in several orgs resolves to the
        // actor of the org they are logging into.
        let organization_id = credential
            .payload
            .get("organization_id")
            .and_then(|v| v.as_str())
            .map(Uuid::parse_str)
            .transpose()
            .map_err(|_| TinkerError::Validation("oidc: bad organization_id".into()))?;

        let binding = self
            .store
            .find_actor_by_subject(&claims.iss, &claims.sub, organization_id)
            .await?
            .ok_or_else(|| TinkerError::NotFound("oidc binding".into()))?;

        Ok(AuthnContext {
            actor_id: binding.actor_id,
            principal_kind: PrincipalKind::Human,
            organization_ids: binding.organization_ids,
            method: self.method().to_string(),
            assurance: AssuranceLevel::SingleFactor,
            authenticated_at: Utc::now(),
            credential_id: format!("{}:{}", claims.iss, claims.sub),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MemStore {
        bindings: Mutex<HashMap<(String, String), OidcBinding>>,
    }

    #[async_trait]
    impl OidcBindingStore for MemStore {
        async fn find_actor_by_subject(
            &self,
            issuer: &str,
            subject: &str,
            _organization_id: Option<Uuid>,
        ) -> Result<Option<OidcBinding>> {
            Ok(self
                .bindings
                .lock()
                .unwrap()
                .get(&(issuer.to_string(), subject.to_string()))
                .cloned())
        }
    }

    // A fixed test RSA key. Generated once for the test suite; never used
    // outside tests. The adapter only ever sees the PUBLIC key — same as
    // production, where verifiers hold public keys and the private key
    // stays with the issuer.
    const RSA_PEM: &str = include_str!("../testdata/oidc_test_rsa.pem");
    const RSA_PUB_PEM: &str = include_str!("../testdata/oidc_test_rsa_pub.pem");

    fn config() -> OidcConfig {
        OidcConfig {
            issuer: "https://issuer.example".into(),
            audience: "tinker".into(),
            keys: vec![OidcKey {
                key_id: None,
                algorithm: Algorithm::RS256,
                decoding_key: DecodingKey::from_rsa_pem(RSA_PUB_PEM.as_bytes()).unwrap(),
            }],
        }
    }

    fn adapter(actor: Uuid, org: Uuid) -> OidcAdapter<MemStore> {
        let store = MemStore {
            bindings: Mutex::new(HashMap::from([(
                ("https://issuer.example".into(), "user-123".into()),
                OidcBinding {
                    actor_id: actor,
                    organization_ids: vec![org],
                },
            )])),
        };
        OidcAdapter::new(store, config())
    }

    fn token(sub: &str, iss: &str, aud: &str, exp_offset_secs: i64) -> String {
        let exp = (Utc::now() + chrono::Duration::seconds(exp_offset_secs)).timestamp();
        let claims = serde_json::json!({
            "iss": iss, "sub": sub, "aud": aud, "exp": exp, "iat": exp - 60, "nonce": NONCE,
        });
        encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(RSA_PEM.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// The nonce of the (simulated) login attempt the tokens answer.
    const NONCE: &str = "attempt-nonce-1";

    fn credential(id_token: &str) -> Credential {
        Credential {
            kind: CredentialKind::OidcCode,
            payload: serde_json::json!({ "id_token": id_token, "nonce": NONCE }),
        }
    }

    #[tokio::test]
    async fn token_without_the_attempt_nonce_is_rejected() {
        let a = adapter(Uuid::now_v7(), Uuid::now_v7());
        let t = token("user-123", "https://issuer.example", "tinker", 300);
        // A bare token (no login attempt) and a token answering another
        // attempt are both refused, even though signature/claims verify.
        for payload in [
            serde_json::json!({ "id_token": t }),
            serde_json::json!({ "id_token": t, "nonce": "some-other-attempt" }),
        ] {
            let err = a
                .authenticate(&Credential {
                    kind: CredentialKind::OidcCode,
                    payload,
                })
                .await
                .unwrap_err();
            assert!(err.to_string().contains("nonce"), "{err}");
        }
    }

    #[tokio::test]
    async fn valid_id_token_authenticates() {
        let actor = Uuid::now_v7();
        let org = Uuid::now_v7();
        let a = adapter(actor, org);
        let ctx = a
            .authenticate(&credential(&token(
                "user-123",
                "https://issuer.example",
                "tinker",
                300,
            )))
            .await
            .unwrap();
        assert_eq!(ctx.actor_id, actor);
        assert_eq!(ctx.method, "oidc");
        assert_eq!(ctx.assurance, AssuranceLevel::SingleFactor);
        assert_eq!(ctx.organization_ids, vec![org]);
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let a = adapter(Uuid::now_v7(), Uuid::now_v7());
        let err = a
            .authenticate(&credential(&token(
                "user-123",
                "https://issuer.example",
                "tinker",
                -300,
            )))
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)));
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let a = adapter(Uuid::now_v7(), Uuid::now_v7());
        let err = a
            .authenticate(&credential(&token(
                "user-123",
                "https://issuer.example",
                "someone-else",
                300,
            )))
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)));
    }

    #[tokio::test]
    async fn unknown_subject_is_not_found() {
        let a = adapter(Uuid::now_v7(), Uuid::now_v7());
        let err = a
            .authenticate(&credential(&token(
                "stranger",
                "https://issuer.example",
                "tinker",
                300,
            )))
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::NotFound(_)));
    }

    #[tokio::test]
    async fn tampered_token_rejected() {
        let a = adapter(Uuid::now_v7(), Uuid::now_v7());
        let mut t = token("user-123", "https://issuer.example", "tinker", 300);
        t.push('x');
        let err = a.authenticate(&credential(&t)).await.unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)));
    }
}
