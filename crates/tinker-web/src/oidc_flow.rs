//! OIDC authorization-code login: code flow + PKCE (S256) + nonce.
//!
//! `GET /login/oidc/start?organization_id=..&workspace_id=..` records a
//! single-use login attempt (random `state`, `nonce`, PKCE verifier; 5
//! minute TTL) on the system handle and redirects to the provider.
//! `GET /login/oidc/callback?code=..&state=..` consumes the attempt
//! exactly once, exchanges the code (with the verifier) at the token
//! endpoint, and hands the ID token plus the attempt's nonce to the OIDC
//! adapter, which refuses any token that does not echo that nonce. A
//! stolen ID token alone can no longer mint a session.

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tinker_auth::{Credential, CredentialKind};
use tinker_core::{Result, TinkerError};
use uuid::Uuid;

use crate::SharedState;

/// Login attempts live this long between start and callback.
const ATTEMPT_TTL_SECS: i64 = 300;

/// Relying-party configuration for one OIDC provider.
#[derive(Debug, Clone)]
pub struct OidcClient {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub client_id: String,
    /// Confidential clients authenticate at the token endpoint; public
    /// clients rely on PKCE alone.
    pub client_secret: Option<String>,
    pub redirect_uri: String,
}

impl OidcClient {
    /// From `OIDC_AUTHORIZATION_ENDPOINT`, `OIDC_TOKEN_ENDPOINT`,
    /// `OIDC_CLIENT_ID`, `OIDC_REDIRECT_URI` (+ optional
    /// `OIDC_CLIENT_SECRET`). `Ok(None)` when none are set; a partial set
    /// is a startup error, never a silently disabled login path.
    pub fn from_env() -> Result<Option<Self>> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let keys = [
            "OIDC_AUTHORIZATION_ENDPOINT",
            "OIDC_TOKEN_ENDPOINT",
            "OIDC_CLIENT_ID",
            "OIDC_REDIRECT_URI",
        ];
        let vals: Vec<Option<String>> = keys.iter().map(|k| get(k)).collect();
        if vals.iter().all(Option::is_none) {
            return Ok(None);
        }
        if vals.iter().any(Option::is_none) {
            let missing: Vec<&str> = keys
                .iter()
                .zip(&vals)
                .filter(|(_, v)| v.is_none())
                .map(|(k, _)| *k)
                .collect();
            return Err(TinkerError::Validation(format!(
                "OIDC client partially configured: missing {}",
                missing.join(", ")
            )));
        }
        let mut it = vals.into_iter().flatten();
        Ok(Some(Self {
            authorization_endpoint: it.next().unwrap_or_default(),
            token_endpoint: it.next().unwrap_or_default(),
            client_id: it.next().unwrap_or_default(),
            redirect_uri: it.next().unwrap_or_default(),
            client_secret: get("OIDC_CLIENT_SECRET"),
        }))
    }
}

/// Router extension: the configured client, if any.
#[derive(Clone, Default)]
pub struct OidcFlow(pub Option<Arc<OidcClient>>);

fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(tinker_auth::fresh_challenge_bytes())
}

/// RFC 7636 S256: BASE64URL(SHA256(verifier)).
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn enc(s: &str) -> String {
    // RFC 3986 unreserved characters pass through; everything else is
    // percent-encoded (redirect URIs and client ids carry ':' and '/').
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct StartQuery {
    organization_id: Uuid,
    workspace_id: Uuid,
}

pub async fn start(
    State(state): State<SharedState>,
    Extension(flow): Extension<OidcFlow>,
    Query(q): Query<StartQuery>,
) -> Response {
    let Some(client) = flow.0 else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (attempt_state, nonce, verifier) = (random_token(), random_token(), random_token());
    let inserted = sqlx::query(
        "INSERT INTO oidc_login_attempts \
         (state, organization_id, workspace_id, nonce, code_verifier, expires_at) \
         VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))",
    )
    .bind(&attempt_state)
    .bind(q.organization_id)
    .bind(q.workspace_id)
    .bind(&nonce)
    .bind(&verifier)
    .bind(ATTEMPT_TTL_SECS as f64)
    .execute(&state.owner.0)
    .await;
    if inserted.is_err() {
        // Unknown org/workspace (FK) looks like any other refusal.
        return StatusCode::BAD_REQUEST.into_response();
    }
    let location = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}&nonce={}\
         &code_challenge={}&code_challenge_method=S256",
        client.authorization_endpoint,
        enc(&client.client_id),
        enc(&client.redirect_uri),
        attempt_state,
        nonce,
        pkce_challenge(&verifier),
    );
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: String,
}

pub async fn callback(
    State(state): State<SharedState>,
    Extension(flow): Extension<OidcFlow>,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(client) = flow.0 else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Single use, unexpired: consumed atomically before anything else, so
    // a replayed or raced callback finds nothing.
    let attempt: Option<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "UPDATE oidc_login_attempts SET consumed_at = now() \
         WHERE state = $1 AND consumed_at IS NULL AND expires_at > now() \
         RETURNING organization_id, workspace_id, nonce, code_verifier",
    )
    .bind(&q.state)
    .fetch_optional(&state.owner.0)
    .await
    .unwrap_or(None);
    let Some((organization_id, workspace_id, nonce, verifier)) = attempt else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let mut form = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", q.code.clone()),
        ("redirect_uri", client.redirect_uri.clone()),
        ("client_id", client.client_id.clone()),
        ("code_verifier", verifier),
    ];
    if let Some(secret) = &client.client_secret {
        form.push(("client_secret", secret.clone()));
    }
    let id_token = match exchange(&client.token_endpoint, &form).await {
        Ok(t) => t,
        Err(_) => return StatusCode::UNAUTHORIZED.into_response(),
    };
    let credential = Credential {
        kind: CredentialKind::OidcCode,
        payload: serde_json::json!({
            "id_token": id_token,
            "nonce": nonce,
            "organization_id": organization_id.to_string(),
        }),
    };
    crate::finish_login(&state, &credential, organization_id, workspace_id).await
}

async fn exchange(token_endpoint: &str, form: &[(&str, String)]) -> Result<String> {
    let body = form
        .iter()
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    let resp = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| TinkerError::Internal(format!("oidc http client: {e}")))?
        .post(token_endpoint)
        .header(
            header::CONTENT_TYPE.as_str(),
            "application/x-www-form-urlencoded",
        )
        .body(body)
        .send()
        .await
        .map_err(|e| TinkerError::Validation(format!("oidc token endpoint: {e}")))?;
    if !resp.status().is_success() {
        return Err(TinkerError::Validation(format!(
            "oidc token endpoint returned {}",
            resp.status()
        )));
    }
    let tr: TokenResponse = resp
        .json()
        .await
        .map_err(|_| TinkerError::Validation("oidc token response has no id_token".into()))?;
    Ok(tr.id_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc7636_example() {
        // RFC 7636 appendix B.
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn query_encoding_escapes_reserved() {
        assert_eq!(
            enc("https://a.b/c?d=e f"),
            "https%3A%2F%2Fa.b%2Fc%3Fd%3De%20f"
        );
    }
}
