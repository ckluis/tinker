//! Authentication broker contract (PRD §36).
//!
//! Adapters validate provider assertions and emit one normalized
//! [`AuthnContext`]. Authorization stays Tinker's own scoped grant system.
//! Concrete adapters (local passkey, OIDC) land in M1; the broker contract
//! itself was proven provider-agnostic in M0.

pub mod apikey;
pub mod oidc;
pub mod passkey;

pub use apikey::{
    scope_allows, validate_scope, ApiKeyAdapter, IssuedCredential, MachineCredential,
    MachineCredentialStore, VerifiedCredential, KEY_PREFIX_LEN, KEY_SECRET_PREFIX,
};
pub use oidc::{OidcAdapter, OidcBinding, OidcBindingStore, OidcConfig, OidcKey};
pub use passkey::{
    fresh_challenge_bytes, PasskeyAdapter, PasskeyStore, StoredChallenge, StoredPasskey,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tinker_core::{Result, TinkerError};
use uuid::Uuid;

/// What kind of principal authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Human,
    Directory,
    Machine,
    Workload,
}

/// How strongly we believe the authentication. Actions can require a
/// minimum level or step-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    /// API key / bearer token with no proof of possession beyond the secret.
    Token,
    /// Password, magic link, or single factor.
    SingleFactor,
    /// MFA, WebAuthn/passkey, phishing-resistant factor.
    MultiFactor,
}

/// The single normalized output of every auth adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthnContext {
    pub actor_id: Uuid,
    pub principal_kind: PrincipalKind,
    /// Organizations this identity may act in (membership, not active scope).
    pub organization_ids: Vec<Uuid>,
    pub method: String,
    pub assurance: AssuranceLevel,
    pub authenticated_at: DateTime<Utc>,
    pub credential_id: String,
}

/// Input to an authorization check. Tinker owns this; providers do not.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzInput {
    pub actor_id: Uuid,
    pub active_scope: AuthzScope,
    pub purpose: String,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    pub policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthzScope {
    Host,
    Portfolio { portfolio_id: Uuid },
    Organization { organization_id: Uuid },
    Workspace { workspace_id: Uuid },
    App { app_id: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny,
}

/// Provider adapter contract. Implementations validate whatever the
/// provider issued (assertion, code, token, key) and return a normalized
/// [`AuthnContext`]. Business logic never branches on providers.
#[async_trait::async_trait]
pub trait AuthAdapter: Send + Sync {
    /// Stable identifier for this adapter, e.g. "oidc", "saml", "passkey".
    fn method(&self) -> &'static str;

    /// Validate a provider-issued credential and normalize the identity.
    async fn authenticate(&self, credential: &Credential) -> Result<AuthnContext>;

    /// Whether this adapter can attempt the given credential shape.
    fn supports(&self, credential: &Credential) -> bool;
}

/// Opaque credential material handed to an adapter. Adapters downcast the
/// payload they understand and reject the rest.
#[derive(Debug, Clone)]
pub struct Credential {
    pub kind: CredentialKind,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Password,
    WebAuthn,
    MagicLink,
    OidcCode,
    SamlResponse,
    ApiKey,
    ServiceAccountJwt,
    WorkloadToken,
}

/// The broker: tries adapters in order, returns the first success.
/// Provider outage preserves existing bounded sessions but never bypasses
/// expiry or policy (enforced by the session layer in M1).
pub struct AuthBroker {
    adapters: Vec<Box<dyn AuthAdapter>>,
}

impl AuthBroker {
    pub fn new(adapters: Vec<Box<dyn AuthAdapter>>) -> Self {
        Self { adapters }
    }

    pub async fn authenticate(&self, credential: &Credential) -> Result<AuthnContext> {
        for adapter in &self.adapters {
            if adapter.supports(credential) {
                return adapter.authenticate(credential).await;
            }
        }
        Err(TinkerError::Validation(format!(
            "no adapter supports credential kind {:?}",
            credential.kind
        )))
    }

    pub fn methods(&self) -> Vec<&'static str> {
        self.adapters.iter().map(|a| a.method()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M0 stub adapter: proves the broker contract without any provider.
    struct StubAdapter {
        method: &'static str,
        kind: CredentialKind,
    }

    #[async_trait::async_trait]
    impl AuthAdapter for StubAdapter {
        fn method(&self) -> &'static str {
            self.method
        }
        fn supports(&self, c: &Credential) -> bool {
            c.kind == self.kind
        }
        async fn authenticate(&self, c: &Credential) -> Result<AuthnContext> {
            let actor = c
                .payload
                .get("actor_id")
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| TinkerError::Validation("stub: missing actor_id".into()))?;
            Ok(AuthnContext {
                actor_id: actor,
                principal_kind: PrincipalKind::Human,
                organization_ids: vec![],
                method: self.method.to_string(),
                assurance: AssuranceLevel::SingleFactor,
                authenticated_at: Utc::now(),
                credential_id: "stub".into(),
            })
        }
    }

    #[tokio::test]
    async fn broker_routes_by_credential_kind_and_replaces_cleanly() {
        let broker = AuthBroker::new(vec![
            Box::new(StubAdapter {
                method: "stub-a",
                kind: CredentialKind::Password,
            }),
            Box::new(StubAdapter {
                method: "stub-b",
                kind: CredentialKind::ApiKey,
            }),
        ]);
        let actor = Uuid::now_v7();
        let ctx = broker
            .authenticate(&Credential {
                kind: CredentialKind::ApiKey,
                payload: serde_json::json!({ "actor_id": actor.to_string() }),
            })
            .await
            .unwrap();
        // The API-key adapter won; the password adapter was never consulted.
        assert_eq!(ctx.method, "stub-b");
        assert_eq!(ctx.actor_id, actor);

        // Swapping the adapter set changes behavior with no caller change:
        // this is the M1 exit test ("an authentication method can be replaced
        // without changing authorization code") at the contract level.
        let broker2 = AuthBroker::new(vec![Box::new(StubAdapter {
            method: "stub-c",
            kind: CredentialKind::ApiKey,
        })]);
        let ctx2 = broker2
            .authenticate(&Credential {
                kind: CredentialKind::ApiKey,
                payload: serde_json::json!({ "actor_id": actor.to_string() }),
            })
            .await
            .unwrap();
        assert_eq!(ctx2.method, "stub-c");
        assert_eq!(ctx2.actor_id, actor);
    }

    #[tokio::test]
    async fn broker_rejects_unsupported_credential() {
        let broker = AuthBroker::new(vec![]);
        let err = broker
            .authenticate(&Credential {
                kind: CredentialKind::SamlResponse,
                payload: serde_json::json!({}),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)));
    }
}
