//! WebAuthn passkey adapter.
//!
//! A passkey is a WebAuthn credential (ES256 or EdDSA COSE key) enrolled
//! against an actor. Login is the WebAuthn assertion ceremony:
//!
//! 1. The server mints a single-use, short-lived random challenge.
//! 2. The browser runs `navigator.credentials.get`; the authenticator
//!    signs `authenticatorData ‖ SHA-256(clientDataJSON)`.
//! 3. This adapter consumes the challenge, then verifies the assertion
//!    (type, challenge, origin, RP ID hash, user presence, counter,
//!    signature — see [`crate::webauthn`]) and records the new counter.
//!
//! Assurance is `MultiFactor` only when the authenticator reports user
//! verification (biometric / PIN); presence alone is `SingleFactor`.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use uuid::Uuid;

use crate::webauthn::{verify_assertion, CoseKey, RelyingParty};

use tinker_core::{Result, TinkerError};

use super::{AssuranceLevel, AuthAdapter, AuthnContext, Credential, CredentialKind, PrincipalKind};

/// An enrolled passkey credential as the adapter needs it.
#[derive(Debug, Clone)]
pub struct StoredPasskey {
    pub actor_id: Uuid,
    /// Organizations the identity may act in (membership).
    pub organization_ids: Vec<Uuid>,
    pub key: CoseKey,
    /// Last signature counter seen (0 when the authenticator keeps none).
    pub sign_count: u32,
    pub revoked: bool,
}

/// A minted challenge awaiting one assertion.
#[derive(Debug, Clone)]
pub struct StoredChallenge {
    pub actor_id: Option<Uuid>,
    pub challenge: Vec<u8>,
    /// True when expired or already consumed.
    pub dead: bool,
}

/// Storage the adapter needs. Implementations live in `tinker-identity`
/// (Postgres) or in tests (memory). Consume must be atomic: exactly one
/// successful assertion per challenge.
#[async_trait]
pub trait PasskeyStore: Send + Sync {
    async fn find_credential(
        &self,
        organization_id: Uuid,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>>;
    async fn find_challenge(
        &self,
        organization_id: Uuid,
        challenge_id: Uuid,
    ) -> Result<Option<StoredChallenge>>;
    /// Atomically consume a live challenge. Returns false when the
    /// challenge is unknown, expired, or already consumed.
    async fn consume_challenge(&self, organization_id: Uuid, challenge_id: Uuid) -> Result<bool>;
    /// Record the counter of a verified assertion.
    async fn update_sign_count(
        &self,
        organization_id: Uuid,
        credential_id: &str,
        sign_count: u32,
    ) -> Result<()>;
}

pub struct PasskeyAdapter<S: PasskeyStore> {
    store: S,
    rp: RelyingParty,
}

impl<S: PasskeyStore> PasskeyAdapter<S> {
    pub fn new(store: S, rp: RelyingParty) -> Self {
        Self { store, rp }
    }
}

fn field(credential: &Credential, name: &str) -> Result<Vec<u8>> {
    credential
        .payload
        .get(name)
        .and_then(|v| v.as_str())
        .map(crate::webauthn::b64url_decode)
        .ok_or_else(|| TinkerError::Validation(format!("passkey: missing {name}")))?
}

#[async_trait]
impl<S: PasskeyStore> AuthAdapter for PasskeyAdapter<S> {
    fn method(&self) -> &'static str {
        "passkey"
    }

    fn supports(&self, credential: &Credential) -> bool {
        credential.kind == CredentialKind::WebAuthn
    }

    async fn authenticate(&self, credential: &Credential) -> Result<AuthnContext> {
        let org_id = credential
            .payload
            .get("organization_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| TinkerError::Validation("passkey: missing organization_id".into()))?;
        let credential_id = credential
            .payload
            .get("credential_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| TinkerError::Validation("passkey: missing credential_id".into()))?;
        let challenge_id = credential
            .payload
            .get("challenge_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or_else(|| TinkerError::Validation("passkey: missing challenge_id".into()))?;
        let client_data_json = field(credential, "client_data_json")?;
        let authenticator_data = field(credential, "authenticator_data")?;
        let signature = field(credential, "signature")?;

        let stored = self
            .store
            .find_credential(org_id, credential_id)
            .await?
            .filter(|c| !c.revoked)
            .ok_or_else(|| TinkerError::NotFound("passkey credential".into()))?;

        let challenge = self
            .store
            .find_challenge(org_id, challenge_id)
            .await?
            .filter(|c| !c.dead)
            .ok_or_else(|| {
                TinkerError::Validation("passkey: challenge expired or unknown".into())
            })?;

        // The challenge may be bound to a specific actor at mint time; when
        // it is, the credential must belong to that actor.
        if let Some(bound) = challenge.actor_id {
            if bound != stored.actor_id {
                return Err(TinkerError::Forbidden(
                    "passkey: challenge bound to a different actor".into(),
                ));
            }
        }

        // Consume BEFORE verifying the signature so a failed verification
        // still burns the challenge — no oracle for signature grinding.
        if !self.store.consume_challenge(org_id, challenge_id).await? {
            return Err(TinkerError::Validation(
                "passkey: challenge already consumed".into(),
            ));
        }

        let assertion = verify_assertion(
            &self.rp,
            &stored.key,
            stored.sign_count,
            &challenge.challenge,
            &client_data_json,
            &authenticator_data,
            &signature,
        )?;
        self.store
            .update_sign_count(org_id, credential_id, assertion.sign_count)
            .await?;

        Ok(AuthnContext {
            actor_id: stored.actor_id,
            principal_kind: PrincipalKind::Human,
            organization_ids: stored.organization_ids,
            method: self.method().to_string(),
            // Possession of the key is one factor; the authenticator's
            // own user verification (biometric / PIN) is the second.
            assurance: if assertion.user_verified {
                AssuranceLevel::MultiFactor
            } else {
                AssuranceLevel::SingleFactor
            },
            authenticated_at: Utc::now(),
            credential_id: credential_id.to_string(),
        })
    }
}

/// Mint a fresh challenge's random bytes. The caller persists it with a TTL.
pub fn fresh_challenge_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MemStore {
        creds: Mutex<HashMap<String, StoredPasskey>>,
        challenges: Mutex<HashMap<Uuid, StoredChallenge>>,
    }

    #[async_trait]
    impl PasskeyStore for MemStore {
        async fn find_credential(&self, _org: Uuid, id: &str) -> Result<Option<StoredPasskey>> {
            Ok(self.creds.lock().unwrap().get(id).cloned())
        }
        async fn find_challenge(&self, _org: Uuid, id: Uuid) -> Result<Option<StoredChallenge>> {
            Ok(self.challenges.lock().unwrap().get(&id).cloned())
        }
        async fn update_sign_count(&self, _org: Uuid, id: &str, n: u32) -> Result<()> {
            if let Some(c) = self.creds.lock().unwrap().get_mut(id) {
                c.sign_count = n;
            }
            Ok(())
        }
        async fn consume_challenge(&self, _org: Uuid, id: Uuid) -> Result<bool> {
            let mut map = self.challenges.lock().unwrap();
            match map.get_mut(&id) {
                Some(c) if !c.dead => {
                    c.dead = true;
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
    }

    fn signing() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn adapter_with(signing: &SigningKey) -> (PasskeyAdapter<MemStore>, Uuid, Uuid, String) {
        let org = Uuid::now_v7();
        let actor = Uuid::now_v7();
        let cred_id = "cred-1".to_string();
        let store = MemStore {
            creds: Mutex::new(HashMap::from([(
                cred_id.clone(),
                StoredPasskey {
                    actor_id: actor,
                    organization_ids: vec![org],
                    key: CoseKey::Ed25519(signing.verifying_key().to_bytes()),
                    sign_count: 0,
                    revoked: false,
                },
            )])),
            challenges: Mutex::new(HashMap::new()),
        };
        (PasskeyAdapter::new(store, rp()), org, actor, cred_id)
    }

    fn mint(store: &MemStore, bound: Option<Uuid>) -> (Uuid, [u8; 32]) {
        let id = Uuid::now_v7();
        let bytes = fresh_challenge_bytes();
        store.challenges.lock().unwrap().insert(
            id,
            StoredChallenge {
                actor_id: bound,
                challenge: bytes.to_vec(),
                dead: false,
            },
        );
        (id, bytes)
    }

    fn rp() -> RelyingParty {
        RelyingParty {
            id: "tinker.test".into(),
            origins: vec!["https://tinker.test".into()],
        }
    }

    /// A user-verified assertion over `challenge` from a soft authenticator.
    fn sign(sk: &SigningKey, challenge: &[u8]) -> (String, String, String) {
        crate::webauthn::soft_authenticator::ed25519_assertion(sk, &rp(), challenge, 0, true)
    }

    fn credential(
        org: Uuid,
        cred_id: &str,
        challenge_id: Uuid,
        a: &(String, String, String),
    ) -> Credential {
        Credential {
            kind: CredentialKind::WebAuthn,
            payload: serde_json::json!({
                "organization_id": org.to_string(),
                "credential_id": cred_id,
                "challenge_id": challenge_id.to_string(),
                "client_data_json": a.0,
                "authenticator_data": a.1,
                "signature": a.2,
            }),
        }
    }

    #[tokio::test]
    async fn presence_without_verification_is_single_factor() {
        let sk = signing();
        let (adapter, org, actor, cred_id) = adapter_with(&sk);
        let (cid, bytes) = mint(&adapter.store, Some(actor));
        let a =
            crate::webauthn::soft_authenticator::ed25519_assertion(&sk, &rp(), &bytes, 0, false);
        let ctx = adapter
            .authenticate(&credential(org, &cred_id, cid, &a))
            .await
            .unwrap();
        assert_eq!(ctx.assurance, AssuranceLevel::SingleFactor);
    }

    #[tokio::test]
    async fn valid_assertion_authenticates() {
        let sk = signing();
        let (adapter, org, actor, cred_id) = adapter_with(&sk);
        let (cid, bytes) = mint(&adapter.store, Some(actor));
        let sig = sign(&sk, &bytes);
        let ctx = adapter
            .authenticate(&credential(org, &cred_id, cid, &sig))
            .await
            .unwrap();
        assert_eq!(ctx.actor_id, actor);
        assert_eq!(ctx.method, "passkey");
        assert_eq!(ctx.assurance, AssuranceLevel::MultiFactor);
        assert_eq!(ctx.organization_ids, vec![org]);
    }

    #[tokio::test]
    async fn replayed_challenge_is_rejected() {
        let sk = signing();
        let (adapter, org, actor, cred_id) = adapter_with(&sk);
        let (cid, bytes) = mint(&adapter.store, Some(actor));
        let sig = sign(&sk, &bytes);
        adapter
            .authenticate(&credential(org, &cred_id, cid, &sig))
            .await
            .unwrap();
        let err = adapter
            .authenticate(&credential(org, &cred_id, cid, &sig))
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)));
    }

    #[tokio::test]
    async fn wrong_key_fails_closed() {
        let sk = signing();
        let (adapter, org, actor, cred_id) = adapter_with(&sk);
        let (cid, bytes) = mint(&adapter.store, Some(actor));
        let wrong = SigningKey::from_bytes(&[9u8; 32]);
        let sig = sign(&wrong, &bytes);
        let err = adapter
            .authenticate(&credential(org, &cred_id, cid, &sig))
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::Forbidden(_)));
    }

    #[tokio::test]
    async fn revoked_credential_is_not_found() {
        let sk = signing();
        let (adapter, org, actor, cred_id) = adapter_with(&sk);
        adapter
            .store
            .creds
            .lock()
            .unwrap()
            .get_mut(&cred_id)
            .unwrap()
            .revoked = true;
        let (cid, bytes) = mint(&adapter.store, Some(actor));
        let sig = sign(&sk, &bytes);
        let err = adapter
            .authenticate(&credential(org, &cred_id, cid, &sig))
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::NotFound(_)));
    }
}
