//! Semantic transforms: the Identify → Authorize → Transform → Emit →
//! Audit pipeline.
//!
//! Field policies are declarative per role (`field_transforms` rows):
//! actual / omit / bucket / range / round / mask / tokenize are
//! deterministic rules; `llm_transform` routes unstructured richtext
//! through the model gateway.
//!
//! Rules-only degradation: when a model transform fails or exceeds its
//! budget, the field is omitted or replaced by an explicit unavailable
//! marker — never revealed raw. Authorization happens BEFORE transform:
//! a forbidden value never reaches a model prompt.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::Ontology;
use tinker_query::{FieldProjection, RowFilters};
use uuid::Uuid;

use crate::audit::{AuditWriter, Disclosure, ModelDisclosure};
use crate::gateway::ModelGateway;

/// Declarative per-role field policy.
#[derive(Debug, Clone)]
pub enum FieldTransform {
    /// Exact value.
    Actual,
    /// Field is dropped from the output.
    Omit,
    /// Numeric bucketing: value < thresholds[i] → labels[i], else last.
    Bucket {
        labels: Vec<String>,
        thresholds: Vec<f64>,
    },
    /// Clamp a numeric into [min, max].
    Range { min: f64, max: f64 },
    /// Round a numeric to `places` decimals.
    Round { places: u32 },
    /// Keep the last `keep_last` chars of a string, mask the rest.
    Mask { keep_last: usize },
    /// Replace with an opaque, value-stable token.
    Tokenize,
    /// Model transform for unstructured richtext. Only used where rules
    /// cannot preserve useful meaning.
    LlmTransform { provider: String, profile: String },
}

impl FieldTransform {
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Actual => "actual",
            Self::Omit => "omit",
            Self::Bucket { .. } => "bucket",
            Self::Range { .. } => "range",
            Self::Round { .. } => "round",
            Self::Mask { .. } => "mask",
            Self::Tokenize => "tokenize",
            Self::LlmTransform { .. } => "llm_transform",
        }
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        let kind = v
            .get("kind")
            .and_then(|k| k.as_str())
            .ok_or_else(|| TinkerError::Validation("field transform needs a kind".into()))?;
        match kind {
            "actual" => Ok(Self::Actual),
            "omit" => Ok(Self::Omit),
            "bucket" => {
                let labels = v
                    .get("labels")
                    .and_then(|l| l.as_array())
                    .ok_or_else(|| TinkerError::Validation("bucket needs labels".into()))?
                    .iter()
                    .map(|x| {
                        x.as_str().map(|s| s.to_string()).ok_or_else(|| {
                            TinkerError::Validation("bucket label not a string".into())
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                let thresholds = v
                    .get("thresholds")
                    .and_then(|l| l.as_array())
                    .ok_or_else(|| TinkerError::Validation("bucket needs thresholds".into()))?
                    .iter()
                    .map(|x| {
                        x.as_f64().ok_or_else(|| {
                            TinkerError::Validation("bucket threshold not numeric".into())
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                if labels.len() != thresholds.len() + 1 {
                    return Err(TinkerError::Validation(
                        "bucket labels must be thresholds+1".into(),
                    ));
                }
                Ok(Self::Bucket { labels, thresholds })
            }
            "range" => {
                let min = v
                    .get("min")
                    .and_then(|x| x.as_f64())
                    .ok_or_else(|| TinkerError::Validation("range needs min".into()))?;
                let max = v
                    .get("max")
                    .and_then(|x| x.as_f64())
                    .ok_or_else(|| TinkerError::Validation("range needs max".into()))?;
                Ok(Self::Range { min, max })
            }
            "round" => {
                let places = v
                    .get("places")
                    .and_then(|x| x.as_u64())
                    .ok_or_else(|| TinkerError::Validation("round needs places".into()))?
                    as u32;
                Ok(Self::Round { places })
            }
            "mask" => {
                let keep_last = v
                    .get("keep_last")
                    .and_then(|x| x.as_u64())
                    .map(|x| x as usize)
                    .unwrap_or(4);
                Ok(Self::Mask { keep_last })
            }
            "tokenize" => Ok(Self::Tokenize),
            "llm_transform" => {
                let provider = v
                    .get("provider")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| TinkerError::Validation("llm_transform needs provider".into()))?
                    .to_string();
                let profile = v
                    .get("profile")
                    .and_then(|x| x.as_str())
                    .unwrap_or("default")
                    .to_string();
                Ok(Self::LlmTransform { provider, profile })
            }
            other => Err(TinkerError::Validation(format!(
                "unknown field transform kind: {other}"
            ))),
        }
    }
}

/// One rendered field: present, omitted, or explicitly unavailable.
#[derive(Debug, Clone)]
pub enum RenderedField {
    Present(serde_json::Value),
    Omitted,
    Unavailable { reason: String },
}

/// The explicit marker for rules-only degradation. Clients must handle
/// this; it is never confused with a real value.
pub fn unavailable_marker(reason: &str) -> serde_json::Value {
    serde_json::json!({"unavailable": true, "reason": reason})
}

/// Deterministic opaque token for a value (stable per value, reveals
/// nothing about it).
fn tokenize(value: &serde_json::Value) -> String {
    let mut h = Sha256::new();
    h.update(value.to_string().as_bytes());
    format!("tok_{:.16}", hex::encode(h.finalize()))
}

fn as_f64(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

impl FieldTransform {
    /// Apply a RULE transform to an already-authorized value. Never calls
    /// a model; `LlmTransform` is handled by the engine.
    pub fn apply_rule(&self, value: &serde_json::Value) -> RenderedField {
        match self {
            Self::Actual => RenderedField::Present(value.clone()),
            Self::Omit => RenderedField::Omitted,
            Self::Bucket { labels, thresholds } => match as_f64(value) {
                Some(n) => {
                    let mut label = labels.last().cloned().unwrap_or_default();
                    for (i, t) in thresholds.iter().enumerate() {
                        if n < *t {
                            label = labels[i].clone();
                            break;
                        }
                    }
                    RenderedField::Present(serde_json::Value::String(label))
                }
                None => RenderedField::Omitted,
            },
            Self::Range { min, max } => match as_f64(value) {
                Some(n) => RenderedField::Present(serde_json::json!(n.clamp(*min, *max))),
                None => RenderedField::Omitted,
            },
            Self::Round { places } => match as_f64(value) {
                Some(n) => {
                    let f = 10f64.powi(*places as i32);
                    RenderedField::Present(serde_json::json!((n * f).round() / f))
                }
                None => RenderedField::Omitted,
            },
            Self::Mask { keep_last } => match value.as_str() {
                Some(s) => {
                    let keep = s.chars().rev().take(*keep_last).collect::<String>();
                    let keep: String = keep.chars().rev().collect();
                    RenderedField::Present(serde_json::Value::String(format!("***{keep}")))
                }
                None => RenderedField::Omitted,
            },
            Self::Tokenize => RenderedField::Present(serde_json::Value::String(tokenize(value))),
            Self::LlmTransform { .. } => {
                // The engine handles model transforms; reaching here is a bug.
                RenderedField::Unavailable {
                    reason: "llm transform misrouted".into(),
                }
            }
        }
    }
}

use crate::costs::CostLedger;

/// The semantic access pipeline.
pub struct TransformEngine {
    core: CoreDb,
    // Held for future owner-DB metadata reads; the pipeline currently
    // resolves everything through core/ontology/gateway.
    #[allow(dead_code)]
    owner: OwnerDb,
    ontology: Ontology,
    gateway: ModelGateway,
    audit: AuditWriter,
    costs: CostLedger,
    row_filters: RowFilters,
    /// Transform schema version, bumped whenever transform semantics
    /// change (part of the no-privileged-cache key).
    pub transform_version: String,
}

impl TransformEngine {
    pub fn new(
        core: CoreDb,
        owner: OwnerDb,
        ontology: Ontology,
        gateway: ModelGateway,
        audit: AuditWriter,
    ) -> Self {
        let costs = CostLedger::new(core.clone(), owner.clone());
        Self {
            core: core.clone(),
            owner,
            ontology,
            gateway,
            audit,
            costs,
            row_filters: RowFilters::new(core),
            transform_version: "m7-v1".to_string(),
        }
    }

    /// The actor's role in this org (Identify step).
    pub async fn role_of(&self, ctx: &TenantContext) -> Result<String> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT role FROM memberships WHERE actor_id = $1 AND organization_id = $2",
        )
        .bind(ctx.actor_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(|(r,)| r)
            .ok_or_else(|| TinkerError::Forbidden("actor has no membership in org".into()))
    }

    /// Build the field projection for (object, role) from field_grants.
    pub async fn projection_for(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        role: &str,
    ) -> Result<FieldProjection> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT field_api_name FROM field_grants
             WHERE organization_id = $1 AND object_id = $2 AND role = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .bind(role)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        if rows.is_empty() {
            return Ok(FieldProjection::unrestricted());
        }
        let mut map = HashMap::new();
        map.insert(object_id, rows.into_iter().map(|(f,)| f).collect());
        Ok(FieldProjection::allowlist(map))
    }

    /// Load the per-role transform policies for (object, role).
    pub async fn transforms_for(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        role: &str,
    ) -> Result<HashMap<String, FieldTransform>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT field_api_name, transform FROM field_transforms
             WHERE organization_id = $1 AND object_id = $2 AND role = $3",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .bind(role)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        rows.into_iter()
            .map(|(f, v)| Ok((f, FieldTransform::from_json(&v)?)))
            .collect()
    }

    /// Render one record through the full pipeline:
    /// Identify → Authorize → Transform → Emit → Audit.
    ///
    /// Returns (fields in api_name order, record version). Fields the
    /// role may not see are absent; model-degraded fields carry the
    /// unavailable marker.
    pub async fn render_record(
        &self,
        ctx: &TenantContext,
        object_slug: &str,
        record_id: Uuid,
        attachment_id: Option<Uuid>,
        virtual_path: &str,
    ) -> Result<(Vec<(String, serde_json::Value)>, i64)> {
        // Identify.
        let role = self.role_of(ctx).await?;
        // Resolve the object (owner handle: metadata, not tenant data).
        let desc = self
            .ontology
            .describe_object_by_slug(ctx, object_slug)
            .await?;
        // Authorize: projection first — forbidden fields are removed before
        // any transform or model call can see them.
        let projection = self.projection_for(ctx, desc.id, &role).await?;
        let transforms = self.transforms_for(ctx, desc.id, &role).await?;

        // Fetch the authorized columns only. Hidden fields are never
        // selected, so a filter oracle cannot leak them either.
        let mut cols = vec!["id".to_string(), "version".to_string()];
        let mut api_for_col: HashMap<String, String> = HashMap::new();
        for f in &desc.fields {
            if projection.allows(desc.id, &f.api_name) {
                cols.push(format!("\"{}\"", f.physical_column));
                api_for_col.insert(f.physical_column.clone(), f.api_name.clone());
            }
        }
        // Identifier quoting: physical columns are validated at DDL time
        // (hostile names rejected), and `id`/`version` are fixed.
        let mut tx = self.core.tenant_tx(ctx).await?;
        let table = format!("data.{object_slug}");
        // C2 (item 38): the caller's row policy applies to this direct
        // record read too. A row the role may not see comes back NotFound
        // — never an existence oracle, and never a privileged-row render.
        let policy = self.row_filters.load_policy(ctx, desc.id, &role).await?;
        let mut sql = format!(
            "SELECT {} FROM {table} WHERE organization_id = $1 AND id = $2",
            cols.join(", ")
        );
        let mut params = vec![
            tinker_core::Param::Uuid(ctx.organization_id.0),
            tinker_core::Param::Uuid(record_id),
        ];
        policy.append_predicates(ctx, &desc, None, &mut sql, &mut params)?;
        // C1 (item 40): default published-only, same clause as the C2
        // policy — one enforcement path. An explicit lifecycle_state
        // filter in the role policy overrides the default.
        tinker_query::append_default_published_predicate(
            &policy,
            desc.lifecycle_enabled,
            &mut sql,
            &mut params,
            None,
            &|n| format!("${n}"),
        );
        let mut q = sqlx::query(&sql);
        for p in &params {
            q = tinker_query::bind_param(q, p);
        }
        let row: Option<sqlx::postgres::PgRow> =
            q.fetch_optional(&mut *tx).await.map_err(TinkerError::Db)?;
        let row = row.ok_or_else(|| TinkerError::NotFound(format!("record {record_id}")))?;
        use sqlx::Row;
        let version: i64 = row.try_get("version").map_err(TinkerError::Db)?;

        // Raw values keyed by api_name (only authorized columns fetched).
        // Decode by declared field type: every ordinary field is a typed
        // column, so the getter matches the DDL.
        let mut raw: HashMap<String, serde_json::Value> = HashMap::new();
        for f in &desc.fields {
            let Some(api) = api_for_col.get(&f.physical_column) else {
                continue;
            };
            let phys = f.physical_column.as_str();
            // PII by type / declared sensitive: the column holds a vault
            // ref, never the value. Agents get the mask whatever the
            // role's transform says — plaintext PII only ever leaves the
            // vault through the audited `reveal`, never into a prompt.
            if f.sensitive {
                let present = row
                    .try_get::<Option<Uuid>, _>(phys)
                    .map_err(TinkerError::Db)?
                    .is_some();
                raw.insert(
                    api.clone(),
                    if present {
                        serde_json::Value::String(tinker_ontology::sensitive::MASK.to_string())
                    } else {
                        serde_json::Value::Null
                    },
                );
                continue;
            }
            let v: serde_json::Value = match f.field_type.as_str() {
                // NUMERIC decodes exactly via BigDecimal — no f64 round-trip
                // (M6 lesson: decimal canonicalization, not float compare).
                "number" | "currency" => {
                    let n: Option<sqlx::types::BigDecimal> =
                        row.try_get(phys).map_err(TinkerError::Db)?;
                    n.map(|d| serde_json::Value::String(d.to_string()))
                        .unwrap_or(serde_json::Value::Null)
                }
                "boolean" => row
                    .try_get::<Option<bool>, _>(phys)
                    .map(|o| o.map(|b| serde_json::json!(b)))
                    .map_err(TinkerError::Db)?
                    .unwrap_or(serde_json::Value::Null),
                "relation" => row
                    .try_get::<Option<Uuid>, _>(phys)
                    .map(|o| o.map(|u| serde_json::json!(u.to_string())))
                    .map_err(TinkerError::Db)?
                    .unwrap_or(serde_json::Value::Null),
                "date" => row
                    .try_get::<Option<chrono::NaiveDate>, _>(phys)
                    .map(|o| o.map(|d| serde_json::json!(d.to_string())))
                    .map_err(TinkerError::Db)?
                    .unwrap_or(serde_json::Value::Null),
                "datetime" => row
                    .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(phys)
                    .map(|o| o.map(|t| serde_json::json!(t.to_rfc3339())))
                    .map_err(TinkerError::Db)?
                    .unwrap_or(serde_json::Value::Null),
                "richtext" => row
                    .try_get::<Option<serde_json::Value>, _>(phys)
                    .map_err(TinkerError::Db)?
                    .unwrap_or(serde_json::Value::Null),
                _ => row
                    .try_get::<Option<String>, _>(phys)
                    .map(|o| o.map(serde_json::Value::String))
                    .map_err(TinkerError::Db)?
                    .unwrap_or(serde_json::Value::Null),
            };
            raw.insert(api.clone(), v);
        }
        tx.commit().await?;

        // Transform: rules first; llm_transform goes through the gateway.
        // A model failure degrades to the unavailable marker — never raw.
        let mut out: Vec<(String, serde_json::Value)> = Vec::new();
        for f in &desc.fields {
            if !projection.allows(desc.id, &f.api_name) {
                continue;
            }
            let value = raw
                .get(&f.api_name)
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            // Sensitive values are already the mask: no transform applies
            // (a token or bucket of the mask would only fake a signal).
            let transform = transforms.get(&f.api_name).filter(|_| !f.sensitive);
            match transform {
                None => out.push((f.api_name.clone(), value)),
                Some(FieldTransform::LlmTransform { provider, profile }) => {
                    // Only unstructured richtext may take the model path.
                    if f.field_type != "richtext" {
                        out.push((
                            f.api_name.clone(),
                            unavailable_marker("llm transform reserved for richtext"),
                        ));
                        continue;
                    }
                    let text = value.as_str().unwrap_or("");
                    match self
                        .gateway
                        .transform_richtext(ctx, provider, profile, text)
                        .await
                    {
                        Ok(c) => {
                            self.audit
                                .record_model_disclosure(
                                    ctx,
                                    ModelDisclosure {
                                        attachment_id,
                                        virtual_path,
                                        policy_version: &format!(
                                            "field_transforms/{object_slug}/role={role}"
                                        ),
                                        transform_version: &self.transform_version,
                                        input_value: &value,
                                        output_value: &serde_json::Value::String(c.text.clone()),
                                        model_ref: &c.model_ref,
                                    },
                                )
                                .await?;
                            // Cost records: real token counts from the live
                            // completion (not estimates). Best-effort: a
                            // cost-recording failure must not fail the
                            // transform — usage telemetry is already
                            // covered by the budget ledger.
                            if let Err(e) = self
                                .costs
                                .record_usage(ctx, &c.model_ref, c.tokens_in, c.tokens_out)
                                .await
                            {
                                tracing::warn!(
                                    model_ref = %c.model_ref,
                                    error = %e,
                                    "cost record write failed"
                                );
                            }
                            out.push((f.api_name.clone(), serde_json::Value::String(c.text)));
                        }
                        Err(e) => {
                            // Rules-only degradation: explicit marker, raw
                            // value never emitted.
                            out.push((
                                f.api_name.clone(),
                                unavailable_marker(&format!("model unavailable: {}", e.code())),
                            ));
                        }
                    }
                }
                Some(t) => match t.apply_rule(&value) {
                    RenderedField::Present(v) => out.push((f.api_name.clone(), v)),
                    RenderedField::Omitted => {}
                    RenderedField::Unavailable { reason } => {
                        out.push((f.api_name.clone(), unavailable_marker(&reason)))
                    }
                },
            }
        }

        // Audit the disclosure: policy + transform versions and hashes,
        // never a second copy of secrets.
        let policy_version = format!("field_grants/{object_slug}/{role}");
        let input_hash = {
            let mut h = Sha256::new();
            h.update(format!("{object_slug}:{record_id}:{version}").as_bytes());
            hex::encode(h.finalize())
        };
        let output_hash = {
            let mut h = Sha256::new();
            h.update(serde_json::to_string(&out).unwrap_or_default().as_bytes());
            hex::encode(h.finalize())
        };
        self.audit
            .record(
                ctx,
                Disclosure {
                    attachment_id,
                    virtual_path,
                    policy_version: &policy_version,
                    transform_version: &self.transform_version,
                    input_hash: &input_hash,
                    output_hash: &output_hash,
                    model_ref: None,
                },
            )
            .await?;

        Ok((out, version))
    }
}

// `hex` is not a workspace dependency; implement the tiny encoder locally
// to avoid a new dependency for two call sites.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}
