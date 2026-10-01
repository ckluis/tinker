//! Disclosure audit: which policy and transform produced each emitted
//! value — never a second copy of secrets.
//!
//! For model transforms the row also carries input lineage (hash of the
//! source value), model/profile version, output hash, and review state,
//! per the retention policy.

use tinker_core::{Result, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DisclosureRecord {
    pub attachment_id: Option<Uuid>,
    pub virtual_path: String,
    pub policy_version: String,
    pub transform_version: String,
    pub input_hash: String,
    pub output_hash: String,
    pub model_ref: Option<String>,
    pub review_state: String,
}

#[derive(Clone)]
pub struct AuditWriter {
    core: CoreDb,
    #[allow(dead_code)]
    owner: OwnerDb,
}

/// Parameters for one disclosure row. Bundled so the writer API stays
/// narrow (clippy::too_many_arguments) as fields are added.
pub struct Disclosure<'a> {
    pub attachment_id: Option<Uuid>,
    pub virtual_path: &'a str,
    pub policy_version: &'a str,
    pub transform_version: &'a str,
    pub input_hash: &'a str,
    pub output_hash: &'a str,
    pub model_ref: Option<&'a str>,
}

impl AuditWriter {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    pub async fn record(&self, ctx: &TenantContext, d: Disclosure<'_>) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "INSERT INTO disclosure_audit
                 (organization_id, attachment_id, actor_id, virtual_path,
                  policy_version, transform_version, purpose,
                  input_hash, output_hash, model_ref)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(ctx.organization_id.0)
        .bind(d.attachment_id)
        .bind(ctx.actor_id)
        .bind(d.virtual_path)
        .bind(d.policy_version)
        .bind(d.transform_version)
        .bind(&ctx.purpose)
        .bind(d.input_hash)
        .bind(d.output_hash)
        .bind(d.model_ref)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Model-transform disclosure: hashes of input/output (lineage without
    /// secret copies), model ref, and review state.
    pub async fn record_model_disclosure(
        &self,
        ctx: &TenantContext,
        d: ModelDisclosure<'_>,
    ) -> Result<()> {
        let input_hash = hash_json(d.input_value);
        let output_hash = hash_json(d.output_value);
        self.record(
            ctx,
            Disclosure {
                attachment_id: d.attachment_id,
                virtual_path: d.virtual_path,
                policy_version: d.policy_version,
                transform_version: d.transform_version,
                input_hash: &input_hash,
                output_hash: &output_hash,
                model_ref: Some(d.model_ref),
            },
        )
        .await
    }
}

/// Parameters for a model-transform disclosure: values in, hashes stored.
pub struct ModelDisclosure<'a> {
    pub attachment_id: Option<Uuid>,
    pub virtual_path: &'a str,
    pub policy_version: &'a str,
    pub transform_version: &'a str,
    pub input_value: &'a serde_json::Value,
    pub output_value: &'a serde_json::Value,
    pub model_ref: &'a str,
}

pub fn hash_json(v: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(serde_json::to_string(v).unwrap_or_default().as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}
