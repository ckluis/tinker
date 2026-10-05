//! Inbound machine credentials: API-key issuance, verification, rotation,
//! revocation (Directus C6, second half — the credential story the MCP
//! HTTP/SSE transport was blocked on).
//!
//! Wire format: `tk_` + 43 base64url chars (256 bits from the OS CSPRNG).
//! Only `SHA-256(secret)` is stored; the plaintext is returned exactly
//! once at issuance/rotation and never logged. Lookup is by `key_prefix`
//! (the first 12 chars) through the owner pool — the key itself identifies
//! the organization, so verification cannot be tenant-RLS-scoped; the
//! constant-time hash comparison is the authorization.
//!
//! Scope grammar (validated at issuance, enforced by the MCP HTTP layer):
//!   `mcp:tools`        — tools/list + tools/call on any tool
//!   `mcp:resources`    — resources/list + resources/read
//!   `mcp:tool:<name>`  — tools/call on one named tool
//!
//! Every verification failure — unknown prefix, malformed secret, hash
//! mismatch, revoked, expired — returns the same `Unauthorized` error: no
//! existence oracle.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tinker_core::{Result, TinkerError};
use tinker_db::OwnerDb;
use uuid::Uuid;

use crate::{AssuranceLevel, AuthAdapter, AuthnContext, Credential, CredentialKind, PrincipalKind};

/// One row from `machine_credentials` as selected by [`MachineCredentialStore::verify`].
type CredentialRow = (
    Uuid,                  // id
    Uuid,                  // organization_id
    Uuid,                  // actor_id
    Vec<u8>,               // key_hash
    Vec<String>,           // scopes
    Option<DateTime<Utc>>, // expires_at
    Option<DateTime<Utc>>, // revoked_at
);

/// Secret prefix: also the human signal that this is a Tinker API key.
pub const KEY_SECRET_PREFIX: &str = "tk_";
/// Chars of the secret used as the DB lookup key (`tk_` + 9).
pub const KEY_PREFIX_LEN: usize = 12;
const SECRET_BYTES: usize = 32;

/// One stored machine credential (hashes never leave the store).
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MachineCredential {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub actor_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Issuance/rotation result. `secret` is shown once — the store never
/// retains it.
#[derive(Debug)]
pub struct IssuedCredential {
    pub credential: MachineCredential,
    pub secret: String,
}

/// A successfully verified credential: everything the transport needs to
/// build a tenant context and enforce scopes.
#[derive(Debug, Clone)]
pub struct VerifiedCredential {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub actor_id: Uuid,
    pub scopes: Vec<String>,
}

/// Validate one scope string against the grammar.
pub fn validate_scope(scope: &str) -> Result<()> {
    if scope == "mcp:tools" || scope == "mcp:resources" {
        return Ok(());
    }
    if let Some(name) = scope.strip_prefix("mcp:tool:") {
        if !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Ok(());
        }
    }
    Err(TinkerError::Validation(format!(
        "invalid machine-credential scope {scope:?}: want mcp:tools, mcp:resources, or mcp:tool:<name>"
    )))
}

/// Tools that `mcp:tools` does not cover: each needs `mcp:tool:<name>`.
pub const EXPLICIT_ONLY_TOOLS: &[&str] = &[
    "reveal",
    "erase",
    "automation",
    "request_reveal",
    "approvals",
];

/// Does this scope set authorize an MCP method? `initialize`, `ping`,
/// and notifications need auth only; everything else needs a scope.
pub fn scope_allows(scopes: &[String], method: &str, tool_name: Option<&str>) -> bool {
    match method {
        "initialize" | "ping" | "notifications/initialized" => true,
        "tools/list" => scopes
            .iter()
            .any(|s| s == "mcp:tools" || s.starts_with("mcp:tool:")),
        "tools/call" => {
            let name = tool_name.unwrap_or_default();
            // Plaintext PII disclosure and irreversible erasure are never
            // implied by the blanket `mcp:tools`: each needs its own grant.
            if EXPLICIT_ONLY_TOOLS.contains(&name) {
                return scopes.iter().any(|s| s == &format!("mcp:tool:{name}"));
            }
            scopes
                .iter()
                .any(|s| s == "mcp:tools" || s == &format!("mcp:tool:{name}"))
        }
        "resources/list" | "resources/read" => scopes.iter().any(|s| s == "mcp:resources"),
        _ => false,
    }
}

/// Constant-time byte equality. Length mismatch fails closed.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn new_secret() -> String {
    let mut bytes = [0u8; SECRET_BYTES];
    OsRng.fill_bytes(&mut bytes);
    format!("{KEY_SECRET_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn hash_secret(secret: &str) -> Vec<u8> {
    Sha256::digest(secret.as_bytes()).to_vec()
}

/// The store. All methods take an explicit `organization_id` and run on
/// the owner pool: the CLI/operator is trusted, and the key itself is the
/// org identifier at verify time. The table's RLS policy remains as
/// defense-in-depth for any future app-role path.
pub struct MachineCredentialStore {
    owner: OwnerDb,
}

impl MachineCredentialStore {
    pub fn new(owner: OwnerDb) -> Self {
        Self { owner }
    }

    /// Issue a credential: creates a `machine`-kind actor plus the
    /// credential row. Returns the secret exactly once.
    pub async fn issue(
        &self,
        organization_id: Uuid,
        name: &str,
        scopes: &[String],
        ttl_days: Option<i64>,
        created_by: Option<Uuid>,
    ) -> Result<IssuedCredential> {
        if name.trim().is_empty() {
            return Err(TinkerError::Validation(
                "credential name is required".into(),
            ));
        }
        for s in scopes {
            validate_scope(s)?;
        }
        if scopes.is_empty() {
            return Err(TinkerError::Validation(
                "at least one scope is required".into(),
            ));
        }
        let expires_at = ttl_days.map(|d| Utc::now() + chrono::Duration::days(d));

        let mut tx = self.owner.0.begin().await.map_err(TinkerError::Db)?;
        // Machine actors get a mention handle derived from the credential
        // name. Collisions (same normalized name, same org) resolve with
        // the deterministic suffix policy (handle-2, handle-3, ...), the
        // same rule the 0036 backfill used. ON CONFLICT DO NOTHING keeps
        // the transaction usable across retries.
        let base_handle = tinker_core::handles::normalize_handle(&format!("machine: {name}"));
        let mut attempt: u32 = 0;
        let actor_id: Uuid = loop {
            attempt += 1;
            let handle = tinker_core::handles::suffixed_handle(&base_handle, attempt);
            let id: Option<Uuid> = sqlx::query_scalar(
                "INSERT INTO actors (organization_id, kind, display_name, handle)
                 VALUES ($1, 'machine', $2, $3)
                 ON CONFLICT (organization_id, handle) DO NOTHING
                 RETURNING id",
            )
            .bind(organization_id)
            .bind(format!("machine: {name}"))
            .bind(&handle)
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            match id {
                Some(id) => break id,
                None if attempt < 10 => continue,
                None => {
                    return Err(TinkerError::Internal(
                        "actor handle collision: exhausted suffix retries".into(),
                    ))
                }
            }
        };

        // Retry on the (astronomically unlikely) prefix collision.
        let mut attempts = 0;
        let (secret, prefix) = loop {
            attempts += 1;
            let secret = new_secret();
            let prefix = secret[..KEY_PREFIX_LEN].to_string();
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM machine_credentials WHERE key_prefix = $1)",
            )
            .bind(&prefix)
            .fetch_one(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            if !exists {
                break (secret, prefix);
            }
            if attempts >= 5 {
                return Err(TinkerError::Internal("key prefix collision".into()));
            }
        };

        let credential: MachineCredential = sqlx::query_as(
            "INSERT INTO machine_credentials
                 (organization_id, actor_id, name, key_prefix, key_hash, scopes, expires_at, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, organization_id, actor_id, name, key_prefix, scopes,
                       expires_at, revoked_at, last_used_at, created_at",
        )
        .bind(organization_id)
        .bind(actor_id)
        .bind(name)
        .bind(&prefix)
        .bind(hash_secret(&secret))
        .bind(scopes)
        .bind(expires_at)
        .bind(created_by)
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(IssuedCredential { credential, secret })
    }

    /// Verify a presented secret. Every failure mode returns the same
    /// `Unauthorized` — no existence oracle.
    pub async fn verify(&self, secret: &str) -> Result<VerifiedCredential> {
        let invalid = || TinkerError::Forbidden("invalid API key".into());
        if !secret.starts_with(KEY_SECRET_PREFIX) || secret.len() < KEY_PREFIX_LEN {
            return Err(invalid());
        }
        // Issued secrets are `tk_` + base64url (ASCII by construction), so
        // any non-UTF-8-boundary or non-ASCII input here is attacker-shaped.
        // `get` fails closed instead of panicking on a mid-char boundary
        // (R3: a multibyte byte-12 used to crash the process).
        let prefix = secret
            .get(..KEY_PREFIX_LEN)
            .filter(|p| p.is_ascii())
            .ok_or_else(invalid)?;
        let row: Option<CredentialRow> = sqlx::query_as(
            "SELECT id, organization_id, actor_id, key_hash, scopes, expires_at, revoked_at
                 FROM machine_credentials WHERE key_prefix = $1",
        )
        .bind(prefix)
        .fetch_optional(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        let (id, organization_id, actor_id, key_hash, scopes, expires_at, revoked_at) =
            row.ok_or_else(invalid)?;
        if revoked_at.is_some() {
            return Err(invalid());
        }
        if let Some(exp) = expires_at {
            if exp <= Utc::now() {
                return Err(invalid());
            }
        }
        if !ct_eq(&hash_secret(secret), &key_hash) {
            return Err(invalid());
        }
        // Best-effort usage telemetry: never fails the request.
        let _ = sqlx::query("UPDATE machine_credentials SET last_used_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.owner.0)
            .await;
        Ok(VerifiedCredential {
            id,
            organization_id,
            actor_id,
            scopes,
        })
    }

    /// Grant (or replace) the machine actor's organization membership
    /// role. Roles are free-form org strings (1..=64 chars, matching
    /// the memberships CHECK constraint widened in migration 0014) —
    /// not a closed set.
    ///
    /// This is what gives an API key its *data* visibility, distinct
    /// from its *scopes* (which gate MCP methods). The `tinker-mcp`
    /// front door resolves the caller's role from this row and fails
    /// closed when it is missing; `tinker-cli mcp key issue --role`
    /// is the operator path that sets it.
    pub async fn grant_machine_role(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        role: &str,
    ) -> Result<()> {
        if role.is_empty() || role.len() > 64 {
            return Err(TinkerError::Validation(
                "machine role must be 1..=64 chars".into(),
            ));
        }
        sqlx::query(
            "INSERT INTO memberships (organization_id, actor_id, role)
             VALUES ($1, $2, $3)
             ON CONFLICT (actor_id, organization_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(organization_id)
        .bind(actor_id)
        .bind(role)
        .execute(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Rotate: replace the key material on the same row (id, actor,
    /// scopes unchanged). The old secret stops working atomically.
    /// Returns the new secret exactly once.
    pub async fn rotate(&self, organization_id: Uuid, id: Uuid) -> Result<IssuedCredential> {
        let mut tx = self.owner.0.begin().await.map_err(TinkerError::Db)?;
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM machine_credentials
             WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL)",
        )
        .bind(id)
        .bind(organization_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        if !exists {
            return Err(TinkerError::NotFound("machine credential".into()));
        }
        let secret = new_secret();
        let prefix = secret[..KEY_PREFIX_LEN].to_string();
        let credential: MachineCredential = sqlx::query_as(
            "UPDATE machine_credentials
             SET key_prefix = $3, key_hash = $4, last_used_at = NULL
             WHERE id = $1 AND organization_id = $2
             RETURNING id, organization_id, actor_id, name, key_prefix, scopes,
                       expires_at, revoked_at, last_used_at, created_at",
        )
        .bind(id)
        .bind(organization_id)
        .bind(&prefix)
        .bind(hash_secret(&secret))
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(IssuedCredential { credential, secret })
    }

    /// Revoke: idempotent. The secret stops working immediately.
    pub async fn revoke(&self, organization_id: Uuid, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE machine_credentials SET revoked_at = now()
             WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL",
        )
        .bind(id)
        .bind(organization_id)
        .execute(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        Ok(())
    }

    /// List an org's credentials. Hashes are never returned.
    pub async fn list(&self, organization_id: Uuid) -> Result<Vec<MachineCredential>> {
        sqlx::query_as(
            "SELECT id, organization_id, actor_id, name, key_prefix, scopes,
                    expires_at, revoked_at, last_used_at, created_at
             FROM machine_credentials WHERE organization_id = $1 ORDER BY created_at",
        )
        .bind(organization_id)
        .fetch_all(&self.owner.0)
        .await
        .map_err(TinkerError::Db)
    }
}

/// The [`AuthAdapter`] for inbound machine credentials: validates an API
/// key and normalizes to a machine [`AuthnContext`] at token assurance.
pub struct ApiKeyAdapter {
    store: MachineCredentialStore,
}

impl ApiKeyAdapter {
    pub fn new(store: MachineCredentialStore) -> Self {
        Self { store }
    }
}

#[async_trait]
impl AuthAdapter for ApiKeyAdapter {
    fn method(&self) -> &'static str {
        "api_key"
    }

    fn supports(&self, credential: &Credential) -> bool {
        credential.kind == CredentialKind::ApiKey
    }

    async fn authenticate(&self, credential: &Credential) -> Result<AuthnContext> {
        let secret = credential
            .payload
            .get("api_key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                TinkerError::Validation("api_key payload needs an api_key string".into())
            })?;
        let v = self.store.verify(secret).await?;
        Ok(AuthnContext {
            actor_id: v.actor_id,
            principal_kind: PrincipalKind::Machine,
            organization_ids: vec![v.organization_id],
            method: "api_key".to_string(),
            assurance: AssuranceLevel::Token,
            authenticated_at: Utc::now(),
            credential_id: v.id.to_string(),
        })
    }
}
