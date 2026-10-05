//! Governed file/blob subsystem (Directus C7).
//!
//! The `file` ontology field kind used to be a bare TEXT column holding
//! an ungoverned string. This module is the governed backend for it:
//!
//! - [`FileStore`]: tenant-scoped registry (`stored_files`) + bytes on a
//!   [`FileBackend`]. Bytes NEVER touch Postgres; per-org isolation is
//!   enforced by RLS on the registry and by per-org roots on the backend.
//! - Content addressing: sha256 identifies bytes; same bytes uploaded
//!   twice in one org dedup to one row. Every fetch re-verifies the hash
//!   — tampered bytes fail closed with an integrity error, never
//!   silently served.
//! - PII-safe handling: `pii_class` is flagged at upload; every access
//!   is audit-logged; the PII store stays physically separate and file
//!   bytes are never copied into PG columns.
//! - Retention interplay: [`FileStore::apply_retention`] mirrors the
//!   transfer crate's retention semantics (policy lookup, legal_hold
//!   suspends deletion) and deletes backend BYTES as well as registry
//!   rows — `apply_core` alone would orphan bytes on the backend.
//!
//! The TEXT column of a `file` ontology field stores the
//! `stored_files.id` UUID. Record writers validate references with
//! [`FileStore::assert_reference`] (active row, same org), or with the
//! full link-time checks via
//! [`tinker_ontology::mutate::FileLinkValidator`], which the store
//! implements.

use std::collections::HashMap;
use std::path::{Component, PathBuf};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_ontology::mutate::FileLinkValidator;
use tinker_ontology::FieldDescription;
use uuid::Uuid;

/// Default cap when `TINKER_MAX_FILE_BYTES` is unset: 100 MiB.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// PII classification flagged at upload. 'restricted' is a marker for
/// operators and audit — access control stays tenant-scoped; callers
/// that need stronger gates check the class before serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiClass {
    None,
    Pii,
    Restricted,
}

impl PiiClass {
    fn as_str(self) -> &'static str {
        match self {
            PiiClass::None => "none",
            PiiClass::Pii => "pii",
            PiiClass::Restricted => "restricted",
        }
    }

    /// Sensitivity ordering: None < Pii < Restricted. A file may be
    /// linked through a field whose `max_pii_class` ranks at or above
    /// the file's own class.
    fn rank(self) -> u8 {
        match self {
            PiiClass::None => 0,
            PiiClass::Pii => 1,
            PiiClass::Restricted => 2,
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "none" => Ok(PiiClass::None),
            "pii" => Ok(PiiClass::Pii),
            "restricted" => Ok(PiiClass::Restricted),
            _ => Err(TinkerError::Validation(format!("bad pii_class: {s}"))),
        }
    }
}

/// Registry row for one stored file (metadata only — no bytes).
#[derive(Debug, Clone)]
pub struct FileRef {
    pub id: Uuid,
    pub name: String,
    pub mime: String,
    pub byte_size: i64,
    pub sha256: String,
    pub pii_class: PiiClass,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Byte storage behind the registry. Implementations resolve `key`
/// under their own per-org root; keys must never escape it.
#[async_trait::async_trait]
pub trait FileBackend: Send + Sync {
    /// Short discriminator persisted in `stored_files.backend`
    /// ('fs', 's3', ...). Drives nothing at read time today — the
    /// backend is a deployment-wide setting — but it records where
    /// each row's bytes live for operators.
    fn name(&self) -> &'static str;
    async fn store(&self, org: Uuid, key: &str, bytes: &[u8]) -> Result<()>;
    async fn fetch(&self, org: Uuid, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, org: Uuid, key: &str) -> Result<()>;
}

/// Select the file backend from configuration. `TINKER_FILE_BACKEND`
/// unset or `"fs"` → local filesystem (the default); `"s3"` → the
/// S3-compatible backend, which fails closed when its environment
/// config is incomplete. Anything else → error.
pub fn backend_from_env() -> Result<Arc<dyn FileBackend>> {
    match std::env::var("TINKER_FILE_BACKEND").as_deref() {
        Ok("s3") => Ok(Arc::new(S3FileBackend::from_env()?)),
        Ok("fs") | Err(_) => Ok(Arc::new(FsFileBackend::from_env())),
        Ok(other) => Err(TinkerError::Internal(format!(
            "unknown TINKER_FILE_BACKEND: {other}"
        ))),
    }
}

/// Local-filesystem backend: `<root>/<org>/<shard>/<sha256>`.
/// Writes are atomic (temp file + rename); reads stream fully into
/// memory (files are size-capped at upload).
pub struct FsFileBackend {
    root: PathBuf,
}

impl FsFileBackend {
    /// Root from `TINKER_FILE_ROOT`, else `./var/files`.
    pub fn from_env() -> Self {
        let root = std::env::var("TINKER_FILE_ROOT").unwrap_or_else(|_| "./var/files".into());
        Self {
            root: PathBuf::from(root),
        }
    }

    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn resolve(&self, org: Uuid, key: &str) -> Result<PathBuf> {
        // Key hygiene: relative, no parent escapes, no absolute paths.
        let rel = PathBuf::from(key);
        if rel.is_absolute()
            || rel.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(TinkerError::Validation(format!(
                "unsafe storage key: {key}"
            )));
        }
        Ok(self.root.join(org.to_string()).join(rel))
    }
}

#[async_trait::async_trait]
impl FileBackend for FsFileBackend {
    fn name(&self) -> &'static str {
        "fs"
    }

    async fn store(&self, org: Uuid, key: &str, bytes: &[u8]) -> Result<()> {
        let path = self.resolve(org, key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| TinkerError::Internal(e.to_string()))?;
        }
        // Atomic write: temp + rename, so a crash never leaves a
        // half-written blob that would pass the name but fail the hash.
        let tmp = path.with_extension("tmp");
        tokio::fs::write(&tmp, bytes)
            .await
            .map_err(|e| TinkerError::Internal(e.to_string()))?;
        tokio::fs::rename(&tmp, &path)
            .await
            .map_err(|e| TinkerError::Internal(e.to_string()))?;
        Ok(())
    }

    async fn fetch(&self, org: Uuid, key: &str) -> Result<Vec<u8>> {
        let path = self.resolve(org, key)?;
        tokio::fs::read(&path)
            .await
            .map_err(|e| TinkerError::Internal(format!("file backend read: {e}")))
    }

    async fn delete(&self, org: Uuid, key: &str) -> Result<()> {
        let path = self.resolve(org, key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(TinkerError::Internal(e.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// S3-compatible backend (item 42, C7)
// ---------------------------------------------------------------------------

/// S3 backend configuration — environment only, never logged.
///
/// - `TINKER_S3_ENDPOINT`: e.g. `https://s3.amazonaws.com` or a
///   MinIO-style `http://127.0.0.1:9000`. Path-style addressing
///   (`{endpoint}/{bucket}/{key}`) is used throughout: it works
///   against AWS and S3-compatibles alike.
/// - `TINKER_S3_BUCKET`, `TINKER_S3_ACCESS_KEY`, `TINKER_S3_SECRET_KEY`:
///   required when `TINKER_FILE_BACKEND=s3`; absent → fail closed.
/// - `TINKER_S3_REGION`: default `us-east-1` (SigV4 scope only).
/// - `TINKER_S3_SSE`: optional server-side-encryption value passed
///   through as the `x-amz-server-side-encryption` header (e.g.
///   `AES256`); never logged.
pub struct S3Config {
    pub endpoint: String,
    pub bucket: String,
    pub access_key: String,
    /// Never logged, never Debug-printed: see the manual `Debug` impl.
    pub secret_key: String,
    pub region: String,
    pub sse: Option<String>,
}

// Manual Debug: the secret key must never appear in logs, panics, or
// error surfaces. Every other field is operational config.
impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("region", &self.region)
            .field("sse", &self.sse)
            .finish()
    }
}

impl S3Config {
    /// Read from the environment. Any missing required variable is a
    /// hard error — the backend refuses to construct rather than
    /// running half-configured. The error names the variable, never
    /// its value.
    pub fn from_env() -> Result<Self> {
        let required = |key: &str| {
            std::env::var(key).map_err(|_| {
                TinkerError::Internal(format!("S3 file backend selected but {key} is not set"))
            })
        };
        Ok(Self {
            endpoint: required("TINKER_S3_ENDPOINT")?
                .trim_end_matches('/')
                .to_string(),
            bucket: required("TINKER_S3_BUCKET")?,
            access_key: required("TINKER_S3_ACCESS_KEY")?,
            secret_key: required("TINKER_S3_SECRET_KEY")?,
            region: std::env::var("TINKER_S3_REGION").unwrap_or_else(|_| "us-east-1".into()),
            sse: std::env::var("TINKER_S3_SSE")
                .ok()
                .filter(|s| !s.trim().is_empty()),
        })
    }
}

/// S3-compatible byte backend: `{endpoint}/{bucket}/{org}/{key}`.
///
/// Requests are SigV4-signed (hand-rolled over `sha2`: canonical
/// request → string-to-sign → HMAC chain). No multipart in v1 — files
/// are size-capped at upload, so single PUT suffices (honest limit).
pub struct S3FileBackend {
    client: reqwest::Client,
    config: S3Config,
}

// Same redaction guarantee one level up: Debug of the backend must not
// leak the secret through the nested config.
impl std::fmt::Debug for S3FileBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3FileBackend")
            .field("config", &self.config)
            .finish()
    }
}

impl S3FileBackend {
    pub fn new(config: S3Config) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| TinkerError::Internal(format!("s3 http client: {e}")))?;
        Ok(Self { client, config })
    }

    /// Fail-closed constructor from the environment.
    pub fn from_env() -> Result<Self> {
        Self::new(S3Config::from_env()?)
    }

    /// Key hygiene, same rules as the fs backend: relative, no parent
    /// escapes, no absolute paths. The org prefix keeps tenants
    /// separated inside one bucket.
    fn object_key(org: Uuid, key: &str) -> Result<String> {
        let rel = PathBuf::from(key);
        if rel.is_absolute()
            || rel.components().any(|c| {
                matches!(
                    c,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(TinkerError::Validation(format!(
                "unsafe storage key: {key}"
            )));
        }
        Ok(format!("{org}/{key}"))
    }

    /// S3 path-segment encoding: unreserved chars pass through, `/`
    /// separates segments, everything else is %XX uppercase hex.
    fn encode_segment(seg: &str) -> String {
        let mut out = String::with_capacity(seg.len());
        for b in seg.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
        // Hand-rolled HMAC-SHA256 over `sha2` (no extra dep): the
        // textbook ipad/opad construction.
        const BLOCK: usize = 64;
        let mut kb = [0u8; BLOCK];
        if key.len() > BLOCK {
            let h = Sha256::digest(key);
            kb[..32].copy_from_slice(&h);
        } else {
            kb[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= kb[i];
            opad[i] ^= kb[i];
        }
        let mut inner = Sha256::new();
        inner.update(ipad);
        inner.update(msg);
        let inner_hash = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(opad);
        outer.update(inner_hash);
        let digest = outer.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// SigV4 Authorization header value for one request. Pure function
    /// of (config, method, path, payload_hash, date) — unit-testable
    /// without any network.
    fn authorization(
        &self,
        method: &str,
        canonical_uri: &str,
        payload_hash: &str,
        amz_date: &str,
        date_stamp: &str,
    ) -> String {
        let host = self.host();
        let mut headers =
            format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");
        let mut signed = "host;x-amz-content-sha256;x-amz-date".to_string();
        if method == "PUT" {
            if let Some(sse) = &self.config.sse {
                headers.push_str(&format!("x-amz-server-side-encryption:{sse}\n"));
                signed.push_str(";x-amz-server-side-encryption");
            }
        }
        let canonical_request =
            format!("{method}\n{canonical_uri}\n\n{headers}\n{signed}\n{payload_hash}");
        let scope = format!("{date_stamp}/{}/s3/aws4_request", self.config.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            Self::hex(&Sha256::digest(canonical_request.as_bytes()))
        );
        let k_date = Self::hmac_sha256(
            format!("AWS4{}", self.config.secret_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = Self::hmac_sha256(&k_date, self.config.region.as_bytes());
        let k_service = Self::hmac_sha256(&k_region, b"s3");
        let k_signing = Self::hmac_sha256(&k_service, b"aws4_request");
        let signature = Self::hex(&Self::hmac_sha256(&k_signing, string_to_sign.as_bytes()));
        format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
            self.config.access_key
        )
    }

    fn host(&self) -> String {
        // Endpoint is validated at construction time by reqwest::Url
        // parsing below; this strips scheme and any path prefix.
        self.config
            .endpoint
            .split("://")
            .last()
            .unwrap_or(&self.config.endpoint)
            .split('/')
            .next()
            .unwrap_or(&self.config.endpoint)
            .to_string()
    }

    fn url(&self, object_key: &str) -> Result<String> {
        let encoded: Vec<String> = std::iter::once(self.config.bucket.as_str())
            .chain(object_key.split('/'))
            .map(Self::encode_segment)
            .collect();
        let url = format!("{}/{}", self.config.endpoint, encoded.join("/"));
        // Validate the URL shape now: a malformed endpoint fails here,
        // not as a confusing request error later.
        reqwest::Url::parse(&url)
            .map_err(|e| TinkerError::Internal(format!("bad S3 endpoint: {e}")))?;
        Ok(url)
    }

    async fn request(
        &self,
        method: &str,
        object_key: &str,
        body: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>> {
        let url = self.url(object_key)?;
        let payload_hash = match body {
            Some(b) => Self::hex(&Sha256::digest(b)),
            None => Self::hex(&Sha256::digest(b"")),
        };
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let canonical_uri = format!(
            "/{}",
            std::iter::once(self.config.bucket.as_str())
                .chain(object_key.split('/'))
                .map(Self::encode_segment)
                .collect::<Vec<_>>()
                .join("/")
        );
        let auth = self.authorization(
            method,
            &canonical_uri,
            &payload_hash,
            &amz_date,
            &date_stamp,
        );

        let mut req = self
            .client
            .request(
                method
                    .parse()
                    .map_err(|_| TinkerError::Internal("bad s3 method".into()))?,
                &url,
            )
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("Authorization", &auth);
        // SSE passes through as a header on PUT; it is config, never a
        // secret, but it is still never logged.
        if method == "PUT" {
            if let Some(sse) = &self.config.sse {
                req = req.header("x-amz-server-side-encryption", sse);
            }
        }
        if let Some(b) = body {
            req = req.body(b.to_vec());
        }
        // The secret never appears in error surfaces: reqwest errors
        // carry status/URL only, and the Authorization header value is
        // never interpolated into our messages.
        let resp = req
            .send()
            .await
            .map_err(|e| TinkerError::Internal(format!("s3 request failed: {e}")))?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(TinkerError::Internal(format!(
                "s3 {method} failed with status {status}"
            )));
        }
        Ok(Some(
            resp.bytes()
                .await
                .map_err(|e| TinkerError::Internal(format!("s3 read body: {e}")))?
                .to_vec(),
        ))
    }
}

#[async_trait::async_trait]
impl FileBackend for S3FileBackend {
    fn name(&self) -> &'static str {
        "s3"
    }

    async fn store(&self, org: Uuid, key: &str, bytes: &[u8]) -> Result<()> {
        let object_key = Self::object_key(org, key)?;
        self.request("PUT", &object_key, Some(bytes)).await?;
        Ok(())
    }

    async fn fetch(&self, org: Uuid, key: &str) -> Result<Vec<u8>> {
        let object_key = Self::object_key(org, key)?;
        match self.request("GET", &object_key, None).await? {
            Some(bytes) => Ok(bytes),
            None => Err(TinkerError::Internal("file backend read: not found".into())),
        }
    }

    async fn delete(&self, org: Uuid, key: &str) -> Result<()> {
        let object_key = Self::object_key(org, key)?;
        // S3 DELETE is idempotent: deleting a missing key is a no-op.
        self.request("DELETE", &object_key, None).await?;
        Ok(())
    }
}

/// Registry row as decoded from `stored_files` (metadata only).
type StoredFileRow = (
    Uuid,
    String,                        // name
    String,                        // mime
    i64,                           // byte_size
    String,                        // sha256
    String,                        // backend
    String,                        // pii_class
    chrono::DateTime<chrono::Utc>, // created_at
);

/// Governed file registry + backend.
pub struct FileStore {
    core: CoreDb,
    backend: Arc<dyn FileBackend>,
}

impl FileStore {
    pub fn new(core: CoreDb, backend: Arc<dyn FileBackend>) -> Self {
        Self { core, backend }
    }

    fn max_bytes() -> u64 {
        std::env::var("TINKER_MAX_FILE_BYTES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_MAX_FILE_BYTES)
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn storage_key(sha256: &str) -> String {
        format!("{}/{}", &sha256[..2], sha256)
    }

    async fn audit(
        &self,
        ctx: &TenantContext,
        action: &str,
        file_id: Uuid,
        status: &str,
        meta: serde_json::Value,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO audit_events
                 (organization_id, actor_id, action, resource_type, resource_id,
                  status, metadata)
             VALUES ($1, $2, $3, 'stored_file', $4, $5, $6)",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(action)
        .bind(file_id.to_string())
        .bind(status)
        .bind(meta)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        Ok(())
    }

    fn row_to_ref(
        id: Uuid,
        name: String,
        mime: String,
        byte_size: i64,
        sha256: String,
        pii_class: String,
        created_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<FileRef> {
        Ok(FileRef {
            id,
            name,
            mime,
            byte_size,
            sha256,
            pii_class: PiiClass::parse(&pii_class)?,
            created_at,
        })
    }

    async fn lookup_in(
        tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
        ctx: &TenantContext,
        file_id: Uuid,
    ) -> Result<Option<FileRef>> {
        let row: Option<StoredFileRow> = sqlx::query_as(
            "SELECT id, name, mime, byte_size, sha256, backend, pii_class, created_at
                 FROM stored_files
                 WHERE organization_id = $1 AND id = $2 AND status = 'active'",
        )
        .bind(ctx.organization_id.0)
        .bind(file_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        row.map(
            |(id, name, mime, byte_size, sha256, _backend, pii_class, created_at)| {
                Self::row_to_ref(id, name, mime, byte_size, sha256, pii_class, created_at)
            },
        )
        .transpose()
    }

    async fn lookup_active(&self, ctx: &TenantContext, file_id: Uuid) -> Result<Option<FileRef>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let r = Self::lookup_in(&mut tx, ctx, file_id).await?;
        tx.commit().await?;
        Ok(r)
    }

    /// Store bytes under governance. Returns the registry ref; duplicate
    /// bytes in the same org dedup to the existing row.
    pub async fn store(
        &self,
        ctx: &TenantContext,
        name: &str,
        mime: &str,
        pii_class: PiiClass,
        bytes: &[u8],
    ) -> Result<FileRef> {
        if name.is_empty() || name.len() > 256 {
            return Err(TinkerError::Validation(
                "file name must be 1..=256 chars".into(),
            ));
        }
        if !mime.contains('/') {
            return Err(TinkerError::Validation(format!("bad mime type: {mime}")));
        }
        if bytes.len() as u64 > Self::max_bytes() {
            return Err(TinkerError::Validation(format!(
                "file too large: {} bytes > {} max",
                bytes.len(),
                Self::max_bytes()
            )));
        }
        let sha256 = Self::sha256_hex(bytes);
        let key = Self::storage_key(&sha256);

        // Dedup: same org + bytes already stored → return the row.
        {
            let mut tx = self.core.tenant_tx(ctx).await?;
            let row: Option<StoredFileRow> = sqlx::query_as(
                "SELECT id, name, mime, byte_size, sha256, backend, pii_class, created_at
                     FROM stored_files
                     WHERE organization_id = $1 AND sha256 = $2 AND byte_size = $3
                       AND status = 'active'",
            )
            .bind(ctx.organization_id.0)
            .bind(&sha256)
            .bind(bytes.len() as i64)
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            if let Some((id, rname, rmime, size, rsha, _b, pii, created)) = row {
                let mut r = Self::row_to_ref(id, rname, rmime, size, rsha, pii, created)?;
                // Same bytes, same content: a stricter declaration on the
                // re-upload must win, never be dropped by the dedup.
                let raised = pii_class.rank() > r.pii_class.rank();
                if raised {
                    sqlx::query(
                        "UPDATE stored_files SET pii_class = $3 \
                         WHERE organization_id = $1 AND id = $2",
                    )
                    .bind(ctx.organization_id.0)
                    .bind(id)
                    .bind(pii_class.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(TinkerError::Db)?;
                    r.pii_class = pii_class;
                }
                tx.commit().await?;
                self.audit(
                    ctx,
                    "file.store",
                    id,
                    "dedup",
                    serde_json::json!({"sha256": sha256, "pii_class_raised": raised}),
                )
                .await?;
                return Ok(r);
            }
            tx.commit().await?;
        }

        // Bytes first, then the registry row — a row without bytes is a
        // dangling reference; bytes without a row are orphaned but
        // content-addressed and invisible (no registry entry).
        self.backend
            .store(ctx.organization_id.0, &key, bytes)
            .await?;

        let mut tx = self.core.tenant_tx(ctx).await?;
        // Race with a concurrent identical upload: the unique
        // (org, sha256, byte_size) constraint collapses it to one row.
        // Re-uploading after a delete reactivates the row AND refreshes
        // the operator-facing metadata to the latest upload.
        let (id,): (Uuid,) = sqlx::query_as(
            "INSERT INTO stored_files
                 (organization_id, uploaded_by, name, mime, byte_size, sha256,
                  backend, storage_key, pii_class)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (organization_id, sha256, byte_size) DO UPDATE
               SET status = 'active', name = EXCLUDED.name,
                   mime = EXCLUDED.mime,
                   -- Never downgrade: identical bytes keep the stricter
                   -- of the stored and the newly declared class.
                   pii_class = CASE
                       WHEN array_position(ARRAY['none','pii','restricted'], EXCLUDED.pii_class)
                          > array_position(ARRAY['none','pii','restricted'], stored_files.pii_class)
                       THEN EXCLUDED.pii_class ELSE stored_files.pii_class END,
                   -- The bytes were just (re)written to the current
                   -- backend, so the row records where they live now.
                   backend = EXCLUDED.backend
             RETURNING id",
        )
        .bind(ctx.organization_id.0)
        .bind(ctx.actor_id)
        .bind(name)
        .bind(mime)
        .bind(bytes.len() as i64)
        .bind(&sha256)
        // Item 42 (C7): the row records which backend holds the bytes.
        .bind(self.backend.name())
        .bind(&key)
        .bind(pii_class.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        // Re-read so the returned ref matches the row exactly.
        let r: FileRef = Self::lookup_in(&mut tx, ctx, id)
            .await?
            .ok_or_else(|| TinkerError::Internal("stored file vanished after upsert".into()))?;
        tx.commit().await?;
        self.audit(
            ctx,
            "file.store",
            id,
            "ok",
            serde_json::json!({"sha256": sha256, "byte_size": r.byte_size, "mime": mime, "pii_class": r.pii_class.as_str()}),
        )
        .await?;
        Ok(r)
    }

    /// Fetch bytes for an active file in this tenant. Re-verifies sha256 —
    /// backend tampering fails closed.
    pub async fn fetch(&self, ctx: &TenantContext, file_id: Uuid) -> Result<(FileRef, Vec<u8>)> {
        let r = self
            .lookup_active(ctx, file_id)
            .await?
            .ok_or_else(|| TinkerError::NotFound("file".into()))?;
        let key = Self::storage_key(&r.sha256);
        let bytes = self.backend.fetch(ctx.organization_id.0, &key).await?;
        if Self::sha256_hex(&bytes) != r.sha256 {
            self.audit(
                ctx,
                "file.fetch",
                file_id,
                "integrity_failure",
                serde_json::json!({"sha256": r.sha256}),
            )
            .await?;
            return Err(TinkerError::Internal(
                "file integrity check failed: backend bytes do not match registry hash".into(),
            ));
        }
        self.audit(
            ctx,
            "file.fetch",
            file_id,
            "ok",
            serde_json::json!({"sha256": r.sha256, "byte_size": r.byte_size}),
        )
        .await?;
        Ok((r, bytes))
    }

    /// Delete a file: backend bytes removed, registry row marked deleted.
    /// Idempotent — deleting twice is a no-op.
    pub async fn delete(&self, ctx: &TenantContext, file_id: Uuid) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String,)> = sqlx::query_as(
            "UPDATE stored_files SET status = 'deleted'
             WHERE organization_id = $1 AND id = $2 AND status = 'active'
             RETURNING sha256",
        )
        .bind(ctx.organization_id.0)
        .bind(file_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        if let Some((sha256,)) = row {
            let key = Self::storage_key(&sha256);
            self.backend.delete(ctx.organization_id.0, &key).await?;
            self.audit(
                ctx,
                "file.delete",
                file_id,
                "ok",
                serde_json::json!({"sha256": sha256}),
            )
            .await?;
        }
        Ok(())
    }

    /// Validate a `file` ontology field value: the TEXT column stores a
    /// `stored_files.id`; it must be an active row in the same org.
    /// Record writers call this before persisting a File field.
    pub async fn assert_reference(&self, ctx: &TenantContext, file_id: Uuid) -> Result<FileRef> {
        self.lookup_active(ctx, file_id).await?.ok_or_else(|| {
            TinkerError::Validation("file reference is not an active stored file".into())
        })
    }

    /// Item 42 (C7): full link validation for the record write path —
    /// existence + org + PII ceiling + integrity, fail closed.
    ///
    /// - The row must be active and in the writing org. Missing,
    ///   deleted, and other-org files all produce the SAME error: no
    ///   existence oracle.
    /// - The file's `pii_class` must rank at or below `max_pii_class`
    ///   (the field's ceiling).
    /// - Backend bytes are fetched and their sha256 re-verified against
    ///   the registry: a tampered backend fails the write closed
    ///   (audited as `file.link` / `integrity_failure`).
    pub async fn assert_linkable(
        &self,
        ctx: &TenantContext,
        file_id: Uuid,
        max_pii_class: &str,
    ) -> Result<FileRef> {
        let max = PiiClass::parse(max_pii_class).map_err(|_| {
            TinkerError::Internal(format!("corrupt max_pii_class on field: {max_pii_class}"))
        })?;
        let r = self.lookup_active(ctx, file_id).await?.ok_or_else(|| {
            TinkerError::Validation("file reference is not an active stored file".into())
        })?;
        if r.pii_class.rank() > max.rank() {
            return Err(TinkerError::Validation(format!(
                "file pii_class '{}' exceeds field maximum '{}'",
                r.pii_class.as_str(),
                max.as_str()
            )));
        }
        let key = Self::storage_key(&r.sha256);
        let bytes = self.backend.fetch(ctx.organization_id.0, &key).await?;
        if Self::sha256_hex(&bytes) != r.sha256 {
            self.audit(
                ctx,
                "file.link",
                file_id,
                "integrity_failure",
                serde_json::json!({"sha256": r.sha256}),
            )
            .await?;
            return Err(TinkerError::Internal(
                "file integrity check failed: backend bytes do not match registry hash".into(),
            ));
        }
        Ok(r)
    }

    /// Retention for files: mirrors `tinker-transfer`'s `apply_core`
    /// semantics (policy lookup by object_key, legal_hold suspends
    /// deletion, `last_run_*` bookkeeping) and additionally deletes
    /// backend BYTES — row-only deletion would orphan bytes on the
    /// backend forever.
    pub async fn apply_retention(
        &self,
        ctx: &TenantContext,
        object_key: &str,
    ) -> Result<RetentionOutcome> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let pol: Option<(i32, bool)> = sqlx::query_as(
            "SELECT retention_days, legal_hold FROM retention_policies
             WHERE organization_id = $1 AND object_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(object_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let (days, hold) = pol.ok_or_else(|| TinkerError::NotFound("retention policy".into()))?;
        if hold {
            let outcome = RetentionOutcome {
                deleted: 0,
                skipped_legal_hold: true,
            };
            self.record_retention_run(ctx, object_key, &outcome).await?;
            tx.commit().await?;
            return Ok(outcome);
        }
        let expired: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, sha256 FROM stored_files
             WHERE organization_id = $1 AND status = 'active'
               AND created_at < now() - make_interval(days => $2)",
        )
        .bind(ctx.organization_id.0)
        .bind(days)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;

        let mut deleted = 0i64;
        for (id, sha256) in expired {
            let key = Self::storage_key(&sha256);
            // Bytes first; a failed backend delete aborts before the row
            // is marked, so retention retries rather than orphaning.
            self.backend.delete(ctx.organization_id.0, &key).await?;
            let mut tx2 = self.core.tenant_tx(ctx).await?;
            sqlx::query(
                "UPDATE stored_files SET status = 'deleted'
                 WHERE organization_id = $1 AND id = $2",
            )
            .bind(ctx.organization_id.0)
            .bind(id)
            .execute(&mut *tx2)
            .await
            .map_err(TinkerError::Db)?;
            tx2.commit().await?;
            deleted += 1;
        }
        let outcome = RetentionOutcome {
            deleted,
            skipped_legal_hold: false,
        };
        self.record_retention_run(ctx, object_key, &outcome).await?;
        Ok(outcome)
    }

    async fn record_retention_run(
        &self,
        ctx: &TenantContext,
        object_key: &str,
        outcome: &RetentionOutcome,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "UPDATE retention_policies
             SET last_run_at = now(), last_run_result = $3
             WHERE organization_id = $1 AND object_key = $2",
        )
        .bind(ctx.organization_id.0)
        .bind(object_key)
        .bind(serde_json::to_value(outcome).map_err(TinkerError::Serde)?)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await?;
        Ok(())
    }
}

/// Outcome of a file-retention run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RetentionOutcome {
    pub deleted: i64,
    pub skipped_legal_hold: bool,
}

// ---------------------------------------------------------------------------
// Record-write-path file validation (item 42, C7)
// ---------------------------------------------------------------------------

/// File reference values accepted on the write path: the plain
/// `stored_files.id` UUID string, or a structured `{"id": ..., "sha256":
/// ...}` form where the caller also supplies the expected sha256 (the
/// "compare expected sha256 if provided" acceptance rule).
enum FileValue {
    Id(Uuid),
    IdWithSha { id: Uuid, expected_sha: String },
}

impl FileValue {
    fn parse(v: &serde_json::Value) -> Result<Option<Self>> {
        match v {
            serde_json::Value::Null => Ok(None),
            serde_json::Value::String(s) => {
                let id = Uuid::parse_str(s)
                    .map_err(|_| TinkerError::Validation("file value is not a valid id".into()))?;
                Ok(Some(Self::Id(id)))
            }
            serde_json::Value::Object(m) => {
                let id = m
                    .get("id")
                    .and_then(|i| i.as_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .ok_or_else(|| {
                        TinkerError::Validation("file value id is not a valid id".into())
                    })?;
                match m.get("sha256") {
                    Some(serde_json::Value::String(expected)) => Ok(Some(Self::IdWithSha {
                        id,
                        expected_sha: expected.clone(),
                    })),
                    Some(_) => Err(TinkerError::Validation(
                        "file value sha256 must be a string".into(),
                    )),
                    None => Ok(Some(Self::Id(id))),
                }
            }
            _ => Err(TinkerError::Validation(
                "file value must be an id or {id, sha256}".into(),
            )),
        }
    }

    fn id(&self) -> Uuid {
        match self {
            Self::Id(id) | Self::IdWithSha { id, .. } => *id,
        }
    }

    fn expected_sha(&self) -> Option<&str> {
        match self {
            Self::Id(_) => None,
            Self::IdWithSha { expected_sha, .. } => Some(expected_sha),
        }
    }
}

#[async_trait::async_trait]
impl FileLinkValidator for FileStore {
    async fn validate_file_fields(
        &self,
        ctx: &TenantContext,
        fields: &[FieldDescription],
        values: &HashMap<String, serde_json::Value>,
    ) -> Result<()> {
        for f in fields {
            if f.field_type != "file" {
                continue;
            }
            let Some(v) = values.get(&f.api_name) else {
                continue;
            };
            let Some(file_value) = FileValue::parse(v)? else {
                continue; // null → nothing linked; `required` is enforced by validate_fields
            };
            let linked = self
                .assert_linkable(ctx, file_value.id(), &f.max_pii_class)
                .await?;
            // Item 42 (C7): caller-provided expected sha256, when present,
            // must match the registry hash — a mismatch fails the write.
            if let Some(expected) = file_value.expected_sha() {
                if expected != linked.sha256 {
                    return Err(TinkerError::Validation(
                        "file expected sha256 does not match stored file".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod s3_unit_tests {
    use super::*;

    /// RFC 4231 test case 1 for HMAC-SHA-256: key = 0x0b * 20,
    /// data = "Hi There". (Vector cross-checked against Python's
    /// `hmac` module, 2026-09-26.)
    #[test]
    fn hmac_sha256_matches_rfc_vector() {
        let got = S3FileBackend::hmac_sha256(&[0x0bu8; 20], b"Hi There");
        assert_eq!(
            S3FileBackend::hex(&got),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn encode_segment_keeps_unreserved_and_escapes_rest() {
        assert_eq!(S3FileBackend::encode_segment("abc-_.~09"), "abc-_.~09");
        assert_eq!(S3FileBackend::encode_segment("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn object_key_rejects_escapes() {
        let org = Uuid::now_v7();
        assert!(S3FileBackend::object_key(org, "a/b/c").is_ok());
        assert!(S3FileBackend::object_key(org, "../evil").is_err());
        assert!(S3FileBackend::object_key(org, "/abs").is_err());
    }

    #[test]
    fn s3_config_from_env_fails_closed_on_missing_vars() {
        // Save/restore so parallel tests in this binary are unaffected
        // (this test serializes on nothing, but it only READS env after
        // removing the vars — other tests set their own vars; a missing
        // var here could in theory collide with a parallel test that
        // sets it. The integration test binary sets S3 vars under a
        // mutex; this unit test runs in the lib target, a different
        // process. Safe.)
        for k in [
            "TINKER_S3_ENDPOINT",
            "TINKER_S3_BUCKET",
            "TINKER_S3_ACCESS_KEY",
            "TINKER_S3_SECRET_KEY",
        ] {
            std::env::remove_var(k);
        }
        let err = S3Config::from_env().unwrap_err();
        assert!(format!("{err:?}").contains("TINKER_S3_ENDPOINT"));
    }

    #[test]
    fn debug_never_leaks_secret() {
        let cfg = S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            bucket: "b".into(),
            access_key: "AKID".into(),
            secret_key: "super-secret-value-xyz".into(),
            region: "us-east-1".into(),
            sse: Some("AES256".into()),
        };
        let backend = S3FileBackend::new(cfg).unwrap();
        let dbg = format!("{backend:?}");
        assert!(!dbg.contains("super-secret-value-xyz"));
        assert!(dbg.contains("<redacted>"));
        // Access key and endpoint are operational config — fine to show.
        assert!(dbg.contains("AKID"));
    }

    #[test]
    fn authorization_header_shape() {
        let cfg = S3Config {
            endpoint: "https://s3.example.com".into(),
            bucket: "b".into(),
            access_key: "AKID".into(),
            secret_key: "secret".into(),
            region: "us-east-1".into(),
            sse: Some("AES256".into()),
        };
        let backend = S3FileBackend::new(cfg).unwrap();
        let auth = backend.authorization(
            "PUT",
            "/b/org/key",
            &S3FileBackend::hex(&Sha256::digest(b"data")),
            "20260926T000000Z",
            "20260926",
        );
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKID/20260926/us-east-1/s3/aws4_request, SignedHeaders="
        ));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption, Signature="));
        let sig = auth.rsplit("Signature=").next().unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        // GET (no SSE): the SSE header must not be signed.
        let auth_get = backend.authorization(
            "GET",
            "/b/org/key",
            &S3FileBackend::hex(&Sha256::digest(b"")),
            "20260926T000000Z",
            "20260926",
        );
        assert!(auth_get.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date,"));
    }
}
