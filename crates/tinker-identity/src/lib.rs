//! Identity plane (M1): server sessions, scoped grants, authorization.
//!
//! Authentication is provider-owned (see `tinker-auth`): adapters validate
//! whatever the provider issued and emit one normalized [`AuthnContext`].
//! Everything in this crate is Tinker-owned:
//!
//! * [`SessionManager`] — opaque server sessions. The cookie carries a
//!   random 256-bit token; only its SHA-256 hash is stored. Sessions bind
//!   the mandatory (host, organization, workspace) context for every
//!   request.
//! * [`Authorizer`] — scoped grants. A grant names (actor, scope, action);
//!   scopes nest organization > workspace > app. Providers never appear in
//!   this code path, which is exactly the M1 exit: swapping the auth
//!   adapter cannot change an authorization decision.
//!
//! Every tenant read/write runs inside a transaction pinned with
//! `SET LOCAL app.organization_id`, the same mechanism M0's `CoreDb`
//! uses. RLS stays fail-closed.
//!
//! [`AuthnContext`]: tinker_auth::AuthnContext

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use tinker_auth::{AssuranceLevel, AuthnContext, AuthzDecision, AuthzInput, AuthzScope};
use tinker_core::{Result, TenantContext, TinkerError};

/// Open a transaction pinned to the tenant. Mirrors `CoreDb::tenant_tx`
/// for call sites that hold a raw pool.
async fn tenant_tx(
    pool: &PgPool,
    organization_id: Uuid,
    actor_id: Uuid,
    purpose: &str,
) -> Result<Transaction<'static, Postgres>> {
    let ctx = TenantContext::new(
        tinker_core::OrganizationId(organization_id),
        actor_id,
        purpose,
    );
    let mut tx = pool.begin().await.map_err(TinkerError::Db)?;
    for stmt in ctx.set_local_statements() {
        sqlx::query(&stmt)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
    }
    Ok(tx)
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

/// A live, validated session: the mandatory request context.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub workspace_id: Uuid,
    pub actor_id: Uuid,
    pub method: String,
    pub assurance: AssuranceLevel,
    pub expires_at: DateTime<Utc>,
}

/// Postgres-backed [`tinker_auth::PasskeyStore`].
pub struct PgPasskeyStore {
    tenant: PgPool,
}

impl PgPasskeyStore {
    pub fn new(tenant: PgPool) -> Self {
        Self { tenant }
    }
}

#[async_trait]
impl tinker_auth::PasskeyStore for PgPasskeyStore {
    async fn find_credential(
        &self,
        organization_id: Uuid,
        credential_id: &str,
    ) -> Result<Option<tinker_auth::StoredPasskey>> {
        let mut tx =
            tenant_tx(&self.tenant, organization_id, Uuid::nil(), "passkey.lookup").await?;
        let row = sqlx::query!(
            r#"SELECT actor_id, public_key, revoked_at IS NOT NULL AS "revoked!"
               FROM auth_credentials
               WHERE method = 'passkey' AND credential_id = $1"#,
            credential_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let public_key: [u8; 32] = row
            .public_key
            .ok_or_else(|| TinkerError::Validation("passkey credential has no public key".into()))?
            .try_into()
            .map_err(|_| TinkerError::Validation("passkey public key wrong length".into()))?;
        let orgs = sqlx::query!(
            "SELECT organization_id FROM memberships WHERE actor_id = $1",
            row.actor_id
        )
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(Some(tinker_auth::StoredPasskey {
            actor_id: row.actor_id,
            organization_ids: orgs.into_iter().map(|r| r.organization_id).collect(),
            public_key,
            revoked: row.revoked,
        }))
    }

    async fn find_challenge(
        &self,
        organization_id: Uuid,
        challenge_id: Uuid,
    ) -> Result<Option<tinker_auth::StoredChallenge>> {
        let mut tx =
            tenant_tx(&self.tenant, organization_id, Uuid::nil(), "passkey.lookup").await?;
        let row = sqlx::query!(
            r#"SELECT actor_id, challenge,
                      (consumed_at IS NOT NULL OR expires_at <= now()) AS "dead!"
               FROM auth_challenges WHERE id = $1"#,
            challenge_id
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(row.map(|r| tinker_auth::StoredChallenge {
            actor_id: r.actor_id,
            challenge: r.challenge,
            dead: r.dead,
        }))
    }

    async fn consume_challenge(&self, organization_id: Uuid, challenge_id: Uuid) -> Result<bool> {
        let mut tx = tenant_tx(
            &self.tenant,
            organization_id,
            Uuid::nil(),
            "passkey.consume",
        )
        .await?;
        // Atomic: exactly one winner per challenge.
        let res = sqlx::query!(
            r#"UPDATE auth_challenges SET consumed_at = now()
               WHERE id = $1 AND consumed_at IS NULL AND expires_at > now()"#,
            challenge_id
        )
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(res.rows_affected() == 1)
    }
}

/// Postgres-backed [`tinker_auth::OidcBindingStore`].
pub struct PgOidcBindingStore {
    system: PgPool,
}

impl PgOidcBindingStore {
    pub fn new(system: PgPool) -> Self {
        Self { system }
    }
}

#[async_trait]
impl tinker_auth::OidcBindingStore for PgOidcBindingStore {
    async fn find_actor_by_subject(
        &self,
        issuer: &str,
        subject: &str,
        organization_id: Option<Uuid>,
    ) -> Result<Option<tinker_auth::OidcBinding>> {
        // Bindings are looked up before a tenant context exists, so this
        // queries the owner-visible mapping explicitly by (issuer, subject,
        // org). The session layer re-checks organization membership
        // afterwards.
        let row = sqlx::query!(
            r#"SELECT c.actor_id
               FROM auth_credentials c
               WHERE c.method = 'oidc' AND c.issuer = $1 AND c.subject = $2
                 AND c.organization_id = COALESCE($3, c.organization_id)
                 AND c.revoked_at IS NULL
               ORDER BY c.created_at DESC
               LIMIT 1"#,
            issuer,
            subject,
            organization_id
        )
        .fetch_optional(&self.system)
        .await
        .map_err(TinkerError::Db)?;
        let Some(row) = row else { return Ok(None) };
        let orgs = sqlx::query!(
            "SELECT organization_id FROM memberships WHERE actor_id = $1",
            row.actor_id
        )
        .fetch_all(&self.system)
        .await
        .map_err(TinkerError::Db)?;
        Ok(Some(tinker_auth::OidcBinding {
            actor_id: row.actor_id,
            organization_ids: orgs.into_iter().map(|r| r.organization_id).collect(),
        }))
    }
}

/// Issues and validates opaque server sessions.
///
/// `tenant` (app role) serves everything inside a pinned tenant
/// transaction. `system` (owner) serves only the two pre-tenant lookups:
/// session-by-token-hash and OIDC subject binding — both keyed by
/// unguessable identifiers, never by tenant.
pub struct SessionManager {
    tenant: PgPool,
    system: PgPool,
    /// Default session TTL.
    pub default_ttl: chrono::Duration,
}

impl SessionManager {
    pub fn new(tenant: PgPool, system: PgPool) -> Self {
        Self {
            tenant,
            system,
            default_ttl: chrono::Duration::hours(12),
        }
    }

    fn hash_token(token: &[u8]) -> Vec<u8> {
        Sha256::digest(token).to_vec()
    }

    /// Mint a session for an authenticated identity inside one
    /// organization + workspace. Returns the raw cookie token (shown once).
    pub async fn create_session(
        &self,
        authn: &AuthnContext,
        organization_id: Uuid,
        workspace_id: Uuid,
    ) -> Result<String> {
        if !authn.organization_ids.contains(&organization_id) {
            return Err(TinkerError::Forbidden(
                "identity is not a member of this organization".into(),
            ));
        }
        let mut token = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token);
        let hash = Self::hash_token(&token);
        let expires_at = Utc::now() + self.default_ttl;

        let mut tx = tenant_tx(
            &self.tenant,
            organization_id,
            authn.actor_id,
            "session.create",
        )
        .await?;
        // The workspace must belong to the organization; fail closed.
        let ws = sqlx::query!("SELECT id FROM workspaces WHERE id = $1", workspace_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)?
            .ok_or_else(|| TinkerError::NotFound("workspace".into()))?;

        let assurance = match authn.assurance {
            AssuranceLevel::Token => "token",
            AssuranceLevel::SingleFactor => "single_factor",
            AssuranceLevel::MultiFactor => "multi_factor",
        };
        sqlx::query!(
            r#"INSERT INTO sessions
               (organization_id, workspace_id, actor_id, token_hash, method,
                assurance, expires_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            organization_id,
            ws.id,
            authn.actor_id,
            hash,
            authn.method,
            assurance,
            expires_at,
        )
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(URL_SAFE_NO_PAD.encode(token))
    }

    /// Resolve a cookie token to a live session. Expired or revoked
    /// sessions resolve to `None` — never to a degraded identity.
    pub async fn load_session(&self, token_b64: &str) -> Result<Option<Session>> {
        let token = URL_SAFE_NO_PAD
            .decode(token_b64)
            .map_err(|_| TinkerError::Validation("bad session token".into()))?;
        if token.len() != 32 {
            return Ok(None);
        }
        let hash = Self::hash_token(&token);
        // Sessions span organizations; resolve on the owner handle and let
        // the row's own organization_id scope everything downstream.
        let row = sqlx::query!(
            r#"SELECT id, organization_id, workspace_id, actor_id, method,
                      assurance, expires_at,
                      (revoked_at IS NOT NULL OR expires_at <= now()) AS "dead!"
               FROM sessions WHERE token_hash = $1"#,
            hash
        )
        .fetch_optional(&self.system)
        .await
        .map_err(TinkerError::Db)?;
        let Some(row) = row else { return Ok(None) };
        if row.dead {
            return Ok(None);
        }
        let assurance = match row.assurance.as_str() {
            "multi_factor" => AssuranceLevel::MultiFactor,
            "single_factor" => AssuranceLevel::SingleFactor,
            _ => AssuranceLevel::Token,
        };
        Ok(Some(Session {
            id: row.id,
            organization_id: row.organization_id,
            workspace_id: row.workspace_id,
            actor_id: row.actor_id,
            method: row.method,
            assurance,
            expires_at: row.expires_at,
        }))
    }

    /// Sliding renewal: extend expiry on activity. Returns false when the
    /// session is dead.
    pub async fn touch(&self, session_id: Uuid) -> Result<bool> {
        let res = sqlx::query!(
            r#"UPDATE sessions
               SET last_seen_at = now(),
                   expires_at = GREATEST(expires_at, now() + make_interval(secs => $1))
               WHERE id = $2 AND revoked_at IS NULL AND expires_at > now()"#,
            self.default_ttl.num_seconds() as f64,
            session_id
        )
        .execute(&self.system)
        .await
        .map_err(TinkerError::Db)?;
        Ok(res.rows_affected() == 1)
    }

    pub async fn revoke(&self, session_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE sessions SET revoked_at = now() WHERE id = $1",
            session_id
        )
        .execute(&self.system)
        .await
        .map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Mint a passkey challenge bound to an actor, TTL 5 minutes.
    /// Returns (challenge_id, base64url challenge bytes for the client).
    pub async fn mint_passkey_challenge(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
    ) -> Result<(Uuid, String)> {
        let bytes = tinker_auth::fresh_challenge_bytes();
        let mut tx = tenant_tx(&self.tenant, organization_id, actor_id, "passkey.mint").await?;
        let row = sqlx::query!(
            r#"INSERT INTO auth_challenges
               (organization_id, actor_id, challenge, expires_at)
               VALUES ($1, $2, $3, now() + INTERVAL '5 minutes')
               RETURNING id"#,
            organization_id,
            actor_id,
            bytes.to_vec(),
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok((row.id, tinker_auth::passkey::b64url(&bytes)))
    }

    /// Enroll a passkey public key for an actor. Returns the credential id.
    pub async fn enroll_passkey(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        credential_id: &str,
        public_key: [u8; 32],
    ) -> Result<()> {
        let mut tx = tenant_tx(&self.tenant, organization_id, actor_id, "passkey.enroll").await?;
        sqlx::query!(
            r#"INSERT INTO auth_credentials
               (organization_id, actor_id, method, credential_id, public_key)
               VALUES ($1, $2, 'passkey', $3, $4)"#,
            organization_id,
            actor_id,
            credential_id,
            public_key.to_vec(),
        )
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Bind an OIDC (issuer, subject) to an actor.
    pub async fn bind_oidc(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        credential_id: &str,
        issuer: &str,
        subject: &str,
    ) -> Result<()> {
        let mut tx = tenant_tx(&self.tenant, organization_id, actor_id, "oidc.bind").await?;
        sqlx::query!(
            r#"INSERT INTO auth_credentials
               (organization_id, actor_id, method, credential_id, issuer, subject)
               VALUES ($1, $2, 'oidc', $3, $4, $5)"#,
            organization_id,
            actor_id,
            credential_id,
            issuer,
            subject,
        )
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Grants + authorization
// ---------------------------------------------------------------------------

/// Minimum assurance per sensitive action. Ordinary reads accept any live
/// session; publishing an app version requires a phishing-resistant factor.
fn min_assurance_for(action: &str) -> AssuranceLevel {
    match action {
        "app:publish" | "grant:write" | "org:admin" | "schema:evolve" => {
            AssuranceLevel::MultiFactor
        }
        _ => AssuranceLevel::Token,
    }
}

/// Tinker-owned authorization. Providers never appear here: the input is a
/// normalized [`AuthzInput`] and the decision comes from scoped grants plus
/// the scope hierarchy.
///
/// Scope coverage: a grant at the organization scope covers every workspace
/// and app inside it; a workspace grant covers its apps. Grants never cross
/// organizations — the lookup is keyed by the input's organization.
pub struct Authorizer {
    tenant: PgPool,
    system: PgPool,
}

impl Authorizer {
    pub fn new(tenant: PgPool, system: PgPool) -> Self {
        Self { tenant, system }
    }

    pub async fn grant(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        scope: &AuthzScope,
        action: &str,
        created_by: Option<Uuid>,
    ) -> Result<()> {
        let (scope_type, scope_id) = match scope {
            AuthzScope::Host => {
                return Err(TinkerError::Forbidden(
                    "host-scope grants are not issued to tenants".into(),
                ))
            }
            AuthzScope::Portfolio { .. } => {
                return Err(TinkerError::Validation(
                    "portfolio scope is not modeled in M1".into(),
                ))
            }
            AuthzScope::Organization { .. } => ("organization", None),
            AuthzScope::Workspace { workspace_id } => ("workspace", Some(*workspace_id)),
            AuthzScope::App { app_id } => ("app", Some(*app_id)),
        };
        let mut tx = tenant_tx(
            &self.tenant,
            organization_id,
            created_by.unwrap_or(actor_id),
            "grant.write",
        )
        .await?;
        // The unique index ux_grants_one_row_per_scope is total (no
        // expiry predicate: predicates must be IMMUTABLE), so clear
        // expired rows for this grant before inserting. Live duplicates
        // stay impossible at the database level.
        sqlx::query!(
            r#"DELETE FROM grants
               WHERE organization_id = $1 AND actor_id = $2 AND scope_type = $3
                 AND scope_id IS NOT DISTINCT FROM $4 AND action = $5
                 AND expires_at IS NOT NULL AND expires_at <= now()"#,
            organization_id,
            actor_id,
            scope_type,
            scope_id,
            action,
        )
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        sqlx::query!(
            r#"INSERT INTO grants
               (organization_id, actor_id, scope_type, scope_id, action, created_by)
               VALUES ($1, $2, $3, $4, $5, $6)
               ON CONFLICT DO NOTHING"#,
            organization_id,
            actor_id,
            scope_type,
            scope_id,
            action,
            created_by,
        )
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }

    pub async fn authorize(
        &self,
        input: &AuthzInput,
        assurance: AssuranceLevel,
    ) -> Result<AuthzDecision> {
        if assurance < min_assurance_for(&input.action) {
            return Ok(AuthzDecision::Deny);
        }
        let (organization_id, scope_checks): (Uuid, Vec<(&str, Option<Uuid>)>) =
            match &input.active_scope {
                AuthzScope::Host | AuthzScope::Portfolio { .. } => return Ok(AuthzDecision::Deny),
                AuthzScope::Organization { organization_id } => {
                    (*organization_id, vec![("organization", None)])
                }
                AuthzScope::Workspace { workspace_id } => {
                    // The workspace id implies its org; resolve it explicitly
                    // so a caller cannot smuggle a foreign workspace id.
                    // Unresolvable ids deny EXACTLY like foreign ones: the
                    // caller learns nothing about whether the id exists.
                    let org = match self.org_of_workspace(*workspace_id).await {
                        Ok(org) => org,
                        Err(TinkerError::NotFound(_)) => return Ok(AuthzDecision::Deny),
                        Err(e) => return Err(e),
                    };
                    (
                        org,
                        vec![("organization", None), ("workspace", Some(*workspace_id))],
                    )
                }
                AuthzScope::App { app_id } => {
                    let (org, ws) = match self.org_and_workspace_of_app(*app_id).await {
                        Ok(pair) => pair,
                        Err(TinkerError::NotFound(_)) => return Ok(AuthzDecision::Deny),
                        Err(e) => return Err(e),
                    };
                    (
                        org,
                        vec![
                            ("organization", None),
                            ("workspace", Some(ws)),
                            ("app", Some(*app_id)),
                        ],
                    )
                }
            };

        let mut tx =
            tenant_tx(&self.tenant, organization_id, input.actor_id, "authz.check").await?;
        for (scope_type, scope_id) in scope_checks {
            let hit = sqlx::query!(
                r#"SELECT 1 AS one FROM grants
                   WHERE actor_id = $1 AND scope_type = $2
                     AND ($3::UUID IS NULL AND scope_id IS NULL
                          OR scope_id = $3)
                     AND action = $4
                     AND (expires_at IS NULL OR expires_at > now())"#,
                input.actor_id,
                scope_type,
                scope_id,
                input.action,
            )
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            if hit.is_some() {
                tx.commit().await.map_err(TinkerError::Db)?;
                return Ok(AuthzDecision::Allow);
            }
        }
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(AuthzDecision::Deny)
    }

    async fn org_of_workspace(&self, workspace_id: Uuid) -> Result<Uuid> {
        let row = sqlx::query!(
            "SELECT organization_id FROM workspaces WHERE id = $1",
            workspace_id
        )
        .fetch_optional(&self.system)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound("workspace".into()))?;
        Ok(row.organization_id)
    }

    async fn org_and_workspace_of_app(&self, app_id: Uuid) -> Result<(Uuid, Uuid)> {
        let row = sqlx::query!(
            "SELECT organization_id, workspace_id FROM apps WHERE id = $1",
            app_id
        )
        .fetch_optional(&self.system)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound("app".into()))?;
        Ok((row.organization_id, row.workspace_id))
    }
}

/// Build the [`AuthzInput`] the web layer passes to [`Authorizer`].
pub fn authz_input(
    session: &Session,
    scope: AuthzScope,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    purpose: &str,
) -> AuthzInput {
    AuthzInput {
        actor_id: session.actor_id,
        active_scope: scope,
        purpose: purpose.into(),
        action: action.into(),
        resource_type: resource_type.into(),
        resource_id: resource_id.into(),
        policy_version: "m1".into(),
    }
}
