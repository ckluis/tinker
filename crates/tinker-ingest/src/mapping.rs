//! Field mappings: source field -> ontology (object, field).
//!
//! Mappings move through a lifecycle: `draft` -> `proposed` -> `approved`
//! -> `activated`. Promotion uses only `activated` mappings. New rows start
//! as drafts (fail closed).
//!
//! Three proposal paths feed the lifecycle:
//! - [`MappingEngine::propose_mappings`]: a deterministic name-similarity
//!   proposer (exact, then partial normalized matches). It never activates.
//! - [`MappingEngine::propose_mappings_ai`]: asks a model provider to map
//!   a stream's observed fields; suggestions land as `proposed` rows.
//! - [`MappingEngine::suggest_mappings`] (item 49): suggestion-only — an
//!   ad-hoc source schema (names + sample values) mapped onto a target
//!   object, returned to the caller and NEVER persisted. It has no code
//!   path that writes schema or records.
//!
//! Applying an activated mapping set is deterministic and replayable — the
//! same landed rows plus the same mappings always produce the same
//! canonical mutations.

use std::cmp::Ordering;

use tinker_agents::costs::CostLedger;
use tinker_agents::ModelGateway;
use tinker_core::{Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

use crate::ident;

#[derive(Debug, Clone)]
pub struct FieldMapping {
    pub id: Uuid,
    pub stream_id: Uuid,
    pub source_field: String,
    pub target_object: String,
    pub target_field: String,
    pub state: String,
}

/// A freshly created proposal (state = `proposed`).
#[derive(Debug, Clone)]
pub struct MappingProposal {
    pub mapping_id: Uuid,
    pub source_field: String,
    pub target_field: String,
    pub confidence: f64,
    pub reason: String,
}

/// Bounds for the suggestion-only proposer (item 49). Samples are prompt
/// bytes, so every bound here is also a privacy bound: the model never
/// sees more than a few truncated values per field, and the whole prompt
/// is capped.
const MAX_SUGGEST_FIELDS: usize = 200;
const MAX_SAMPLES_PER_FIELD: usize = 3;
const MAX_SAMPLE_CHARS: usize = 200;
const MAX_PROMPT_BYTES: usize = 100_000;

/// One source field in an ad-hoc schema: a name plus a few sample values.
///
/// Sample values are PROMPT BYTES — unlike item 25's names-only prompts,
/// item 49 deliberately sends values so the model can disambiguate
/// meaning ("Industry" vs "Sector"). The gateway's item-24 placement
/// checks run before any of these bytes leave the process: a `hosted`
/// provider is rejected for org-controlled content.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MappingSourceField {
    pub name: String,
    #[serde(default)]
    pub field_type: Option<String>,
    #[serde(default)]
    pub samples: Vec<serde_json::Value>,
}

/// Ad-hoc source schema for the suggestion-only proposer.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct MappingSource {
    pub fields: Vec<MappingSourceField>,
}

/// One ranked mapping suggestion. Suggestions only: applying one goes
/// through the governed write paths (`put_mapping` / `approve_mapping` /
/// `activate_mapping`, or `define_object` / `add_field` for ontology
/// work) with the caller's own auth — the proposer never writes them.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FieldSuggestion {
    pub source_field: String,
    pub target_field: String,
    pub confidence: f64,
    pub reason: String,
}

/// The suggestion report: ranked proposals plus the accounted model call
/// that produced them.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MappingSuggestions {
    pub target_object: String,
    pub provider: String,
    pub model_ref: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub proposals: Vec<FieldSuggestion>,
}

pub struct MappingEngine {
    core: CoreDb,
    owner: OwnerDb,
}

impl MappingEngine {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    fn validate_names(source_field: &str, target_object: &str, target_field: &str) -> Result<()> {
        for (label, v) in [
            ("source_field", source_field),
            ("target_object", target_object),
            ("target_field", target_field),
        ] {
            if v.trim().is_empty() || v.len() > 120 {
                return Err(TinkerError::Validation(format!(
                    "{label} must be 1-120 chars"
                )));
            }
            // These values are interpolated into SQL elsewhere (mapping
            // application resolves physical columns, but defense in depth
            // rejects hostile values at the door).
            ident::ident(label, v)?;
        }
        Ok(())
    }

    /// Activate (upsert) one field mapping directly — the operator fast
    /// path. Re-activating the same mapping converges; changing the target
    /// bumps the version. A lifecycle row in any earlier state moves
    /// straight to `activated`.
    pub async fn put_mapping(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_field: &str,
        target_object: &str,
        target_field: &str,
    ) -> Result<FieldMapping> {
        Self::validate_names(source_field, target_object, target_field)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let stream: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM ingest_stream WHERE organization_id=$1 AND id=$2")
                .bind(ctx.organization_id.0)
                .bind(stream_id)
                .fetch_optional(&mut *tx)
                .await?;
        if stream.is_none() {
            return Err(tinker_core::TinkerError::NotFound(format!(
                "stream {stream_id}"
            )));
        }
        let row: (Uuid, Uuid, String, String, String, String) = sqlx::query_as(
            "INSERT INTO ingest_mapping
             (id, organization_id, stream_id, source_field, target_object, target_field,
              state)
             VALUES ($1,$2,$3,$4,$5,$6,'activated')
             ON CONFLICT (organization_id, stream_id, source_field)
             DO UPDATE SET target_object=EXCLUDED.target_object,
                           target_field=EXCLUDED.target_field,
                           state='activated',
                           version=ingest_mapping.version+1
             RETURNING id, stream_id, source_field, target_object, target_field, state",
        )
        .bind(Uuid::now_v7())
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(source_field)
        .bind(target_object)
        .bind(target_field)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(FieldMapping {
            id: row.0,
            stream_id: row.1,
            source_field: row.2,
            target_object: row.3,
            target_field: row.4,
            state: row.5,
        })
    }

    /// All ACTIVATED mappings for a stream. Promotion reads only these.
    pub async fn mappings_for(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
    ) -> Result<Vec<FieldMapping>> {
        self.mappings_in_state(ctx, stream_id, "activated").await
    }

    /// Mappings for a stream in any one lifecycle state.
    pub async fn mappings_in_state(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        state: &str,
    ) -> Result<Vec<FieldMapping>> {
        if !matches!(state, "draft" | "proposed" | "approved" | "activated") {
            return Err(TinkerError::Validation(format!(
                "bad mapping state: {state}"
            )));
        }
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(Uuid, Uuid, String, String, String, String)> = sqlx::query_as(
            "SELECT id, stream_id, source_field, target_object, target_field, state
             FROM ingest_mapping
             WHERE organization_id=$1 AND stream_id=$2 AND state=$3
             ORDER BY source_field",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .bind(state)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|r| FieldMapping {
                id: r.0,
                stream_id: r.1,
                source_field: r.2,
                target_object: r.3,
                target_field: r.4,
                state: r.5,
            })
            .collect())
    }

    /// Deterministic mapping proposer: matches source fields (from the
    /// stream's latest observed schema) against the target platform
    /// object's api fields by normalized name similarity.
    ///
    /// Created rows are `proposed`, never activated. Fields that already
    /// have a mapping row in any state are skipped (operator mappings win).
    /// The match is deterministic: exact normalized match beats partial,
    /// ties break alphabetically.
    pub async fn propose_mappings(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        object_slug: &str,
    ) -> Result<Vec<MappingProposal>> {
        ident::ident("object_slug", object_slug)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let stream: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM ingest_stream WHERE organization_id=$1 AND id=$2")
                .bind(ctx.organization_id.0)
                .bind(stream_id)
                .fetch_optional(&mut *tx)
                .await?;
        if stream.is_none() {
            return Err(tinker_core::TinkerError::NotFound(format!(
                "stream {stream_id}"
            )));
        }
        let schema_row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT observed_schema FROM ingest_schema_version
             WHERE organization_id=$1 AND stream_id=$2
             ORDER BY observed_at DESC LIMIT 1",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let schema = schema_row.map(|r| r.0);
        let source_fields = schema_fields(&schema);

        // Target api fields, owner-backed (metadata plane).
        let target_fields = self.platform_api_fields(object_slug).await?;
        if target_fields.is_empty() {
            return Err(TinkerError::Validation(format!(
                "unknown platform object: {object_slug}"
            )));
        }

        let mut tx = self.core.tenant_tx(ctx).await?;
        let existing: Vec<(String,)> = sqlx::query_as(
            "SELECT source_field FROM ingest_mapping
             WHERE organization_id=$1 AND stream_id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_all(&mut *tx)
        .await?;
        let existing: std::collections::HashSet<String> =
            existing.into_iter().map(|r| r.0).collect();

        let mut proposals = vec![];
        for src in &source_fields {
            if existing.contains(src) {
                continue;
            }
            if let Some((tgt, confidence, reason)) = best_match(src, &target_fields) {
                let proposal = serde_json::json!({
                    "confidence": confidence,
                    "reason": reason,
                    "proposer": "deterministic-name-matcher v1",
                });
                // fetch_optional: a concurrent proposer may have inserted
                // the same source field first (DO NOTHING skips it).
                let row: Option<(Uuid,)> = sqlx::query_as(
                    "INSERT INTO ingest_mapping
                     (id, organization_id, stream_id, source_field,
                      target_object, target_field, state, proposal)
                     VALUES ($1,$2,$3,$4,$5,$6,'proposed',$7)
                     ON CONFLICT (organization_id, stream_id, source_field)
                     DO NOTHING
                     RETURNING id",
                )
                .bind(Uuid::now_v7())
                .bind(ctx.organization_id.0)
                .bind(stream_id)
                .bind(src)
                .bind(object_slug)
                .bind(&tgt)
                .bind(&proposal)
                .fetch_optional(&mut *tx)
                .await?;
                if let Some((id,)) = row {
                    proposals.push(MappingProposal {
                        mapping_id: id,
                        source_field: src.clone(),
                        target_field: tgt,
                        confidence,
                        reason: reason.to_string(),
                    });
                }
            }
        }
        tx.commit().await?;
        Ok(proposals)
    }

    /// AI-assisted mapping proposer: asks the named model provider to map
    /// the stream's observed source fields onto the target platform
    /// object's api fields.
    ///
    /// The governed lifecycle is unchanged: suggestions land as `proposed`
    /// rows — NEVER activated — and only `approve_mapping` +
    /// `activate_mapping` move them forward. Fields that already have a
    /// mapping row in any state are skipped (operator mappings win), and a
    /// concurrent proposer racing the same source field converges through
    /// `ON CONFLICT DO NOTHING`, exactly like the deterministic proposer.
    ///
    /// Privacy: the model sees ONLY field-name lists. Record VALUES never
    /// leave the process — the prompt builder takes names, never records,
    /// so there is no code path that could leak a value into a prompt.
    /// Field names are treated as org-controlled content: the gateway
    /// rejects `hosted` providers for this call, same as record content.
    ///
    /// Model output is untrusted content: it is parsed as JSON and every
    /// suggestion is validated against the observed schema and the target
    /// object before any row is written. Malformed output fails closed
    /// with zero rows; suggestions referencing unknown sources, unknown
    /// targets, or out-of-range confidences are dropped individually.
    pub async fn propose_mappings_ai(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        object_slug: &str,
        gateway: &ModelGateway,
        provider_name: &str,
    ) -> Result<Vec<MappingProposal>> {
        ident::ident("object_slug", object_slug)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let stream: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM ingest_stream WHERE organization_id=$1 AND id=$2")
                .bind(ctx.organization_id.0)
                .bind(stream_id)
                .fetch_optional(&mut *tx)
                .await?;
        if stream.is_none() {
            return Err(tinker_core::TinkerError::NotFound(format!(
                "stream {stream_id}"
            )));
        }
        let schema_row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT observed_schema FROM ingest_schema_version
             WHERE organization_id=$1 AND stream_id=$2
             ORDER BY observed_at DESC LIMIT 1",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let schema = schema_row.map(|r| r.0);
        let source_fields = schema_fields(&schema);

        // Target api fields, owner-backed (metadata plane).
        let target_fields = self.platform_api_fields(object_slug).await?;
        if target_fields.is_empty() {
            return Err(TinkerError::Validation(format!(
                "unknown platform object: {object_slug}"
            )));
        }

        let mut tx = self.core.tenant_tx(ctx).await?;
        let existing: Vec<(String,)> = sqlx::query_as(
            "SELECT source_field FROM ingest_mapping
             WHERE organization_id=$1 AND stream_id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(stream_id)
        .fetch_all(&mut *tx)
        .await?;
        let existing: std::collections::HashSet<String> =
            existing.into_iter().map(|r| r.0).collect();

        let unmapped: Vec<&str> = source_fields
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !existing.contains(*s))
            .collect();
        if unmapped.is_empty() {
            tx.commit().await?;
            return Ok(vec![]);
        }

        // Names only — never record values. The lists are JSON-encoded so a
        // hostile field NAME cannot break the prompt's structure.
        let prompt = format!(
            "[tag:map] Propose source->target field mappings as JSON.\n\
             Rules:\n\
             - Respond with a single JSON object and nothing else: \
             {{\"mappings\":[{{\"source\":\"...\",\"target\":\"...\",\"confidence\":0.0,\"reason\":\"...\"}}]}}\n\
             - \"source\" must be exactly one of the source fields below.\n\
             - \"target\" must be exactly one of the target fields below.\n\
             - \"confidence\" is a number in [0,1]; \"reason\" is a short phrase.\n\
             - Omit source fields with no good match instead of guessing.\n\
             - These are field NAMES only; there are no record values here.\n\
             Source fields: {}\n\
             Target fields: {}",
            serde_json::to_string(&unmapped).unwrap_or_default(),
            serde_json::to_string(&target_fields).unwrap_or_default(),
        );
        // Gateway call happens BEFORE the write transaction proceeds so a
        // provider failure leaves zero rows; the call itself writes
        // nothing.
        let completion = gateway.propose_mapping(ctx, provider_name, &prompt).await?;

        let suggestions = parse_ai_suggestions(&completion.text).map_err(|e| {
            TinkerError::Validation(format!("model returned unusable mapping JSON: {e}"))
        })?;
        let target_set: std::collections::HashSet<&str> =
            target_fields.iter().map(|s| s.as_str()).collect();
        let source_set: std::collections::HashSet<&str> = unmapped.iter().copied().collect();

        let mut proposals = vec![];
        for s in suggestions {
            // Per-suggestion validation: the model is untrusted, so each
            // suggestion must reference a real unmapped source, a real
            // target, and a sane confidence. Bad ones are dropped; they
            // never reach the database.
            if !source_set.contains(s.source.as_str()) {
                continue;
            }
            if !target_set.contains(s.target.as_str()) {
                continue;
            }
            if !(0.0..=1.0).contains(&s.confidence) || !s.confidence.is_finite() {
                continue;
            }
            let reason = s.reason.trim();
            if reason.is_empty() || reason.len() > 500 {
                continue;
            }
            if Self::validate_names(&s.source, object_slug, &s.target).is_err() {
                continue;
            }
            let proposal = serde_json::json!({
                "confidence": s.confidence,
                "reason": reason,
                "proposer": format!("ai:{provider_name}/{}", completion.model_ref),
            });
            let row: Option<(Uuid,)> = sqlx::query_as(
                "INSERT INTO ingest_mapping
                 (id, organization_id, stream_id, source_field,
                  target_object, target_field, state, proposal)
                 VALUES ($1,$2,$3,$4,$5,$6,'proposed',$7)
                 ON CONFLICT (organization_id, stream_id, source_field)
                 DO NOTHING
                 RETURNING id",
            )
            .bind(Uuid::now_v7())
            .bind(ctx.organization_id.0)
            .bind(stream_id)
            .bind(&s.source)
            .bind(object_slug)
            .bind(&s.target)
            .bind(&proposal)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some((id,)) = row {
                proposals.push(MappingProposal {
                    mapping_id: id,
                    source_field: s.source,
                    target_field: s.target,
                    confidence: s.confidence,
                    reason: reason.to_string(),
                });
            }
        }
        tx.commit().await?;
        Ok(proposals)
    }

    /// AI-assisted mapping proposer, suggestion-only (item 49).
    ///
    /// Given an ad-hoc source schema (field names + sample values) and a
    /// target platform object slug, asks the named model provider to rank
    /// source→target field mappings and returns them WITHOUT persisting
    /// anything. Applying a suggestion goes only through the existing
    /// governed write paths with the caller's own auth.
    ///
    /// Guardrails (each pinned by tests in
    /// `crates/tinker-m6/tests/mapping_suggest.rs`):
    /// - **No writes.** This method has no code path that writes schema
    ///   or records: no `ingest_mapping` / `ingest_schema_version` rows,
    ///   no ontology changes, no record writes. The single exception is
    ///   the mandated M7 cost record (next bullet).
    /// - **Placement.** Sample values are prompt bytes. The gateway's
    ///   item-24 placement checks run inside `propose_mapping` BEFORE any
    ///   byte leaves: org-controlled content on a `hosted` provider is
    ///   rejected with a teaching error before the adapter is touched.
    /// - **Cost accounting.** The live completion's tokens_in/tokens_out/
    ///   model_ref are recorded via `CostLedger::record_usage` (never
    ///   estimates). A ledger failure fails the whole call closed — an
    ///   unaccounted model call is never returned.
    /// - **Unmappable input.** Empty source schema, unknown target slug,
    ///   target with no active api fields, malformed model JSON, and zero
    ///   usable suggestions after per-suggestion validation all return
    ///   teaching errors naming the problem — never an empty list
    ///   presented as a confident answer, never hallucinated entries.
    /// - **Untrusted model output.** Parsed as JSON; every suggestion is
    ///   validated against the input schema and the target object (known
    ///   source, known target, confidence finite in [0,1], non-empty
    ///   reason of at most 500 chars). Bad entries are dropped
    ///   individually; they never reach the caller.
    pub async fn suggest_mappings(
        &self,
        ctx: &TenantContext,
        source: &MappingSource,
        object_slug: &str,
        gateway: &ModelGateway,
        provider_name: &str,
    ) -> Result<MappingSuggestions> {
        ident::ident("object_slug", object_slug)?;
        if source.fields.is_empty() {
            return Err(TinkerError::Validation(
                "cannot propose mappings: the source schema has no fields — \
                 suggestions need at least one named source field"
                    .to_string(),
            ));
        }
        if source.fields.len() > MAX_SUGGEST_FIELDS {
            return Err(TinkerError::Validation(format!(
                "cannot propose mappings: {} source fields exceeds the cap of {} — \
                 trim to the fields that matter",
                source.fields.len(),
                MAX_SUGGEST_FIELDS
            )));
        }
        // Dedupe by name (first wins). Names are prompt content only —
        // they never reach SQL — so they get length/blank checks, not
        // SQL-identifier checks (real-world field names like "First Name"
        // are not idents).
        let mut seen = std::collections::HashSet::new();
        let mut fields: Vec<&MappingSourceField> = vec![];
        for f in &source.fields {
            let name = f.name.trim();
            if name.is_empty() || name.len() > 120 {
                return Err(TinkerError::Validation(format!(
                    "cannot propose mappings: source field names must be 1-120 chars, got {name:?}"
                )));
            }
            if seen.insert(name.to_string()) {
                fields.push(f);
            }
        }

        // Target object: distinguish "unknown slug" from "no mappable
        // fields" so the teaching error names the actual problem.
        let object_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ontology_objects \
             WHERE api_slug=$1 AND state='active' AND scope_kind='platform')",
        )
        .bind(object_slug)
        .fetch_one(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        if !object_exists {
            return Err(TinkerError::Validation(format!(
                "cannot propose mappings: unknown target object '{object_slug}' — \
                 no active platform object with that slug"
            )));
        }
        let target_fields = self.platform_api_fields(object_slug).await?;
        if target_fields.is_empty() {
            return Err(TinkerError::Validation(format!(
                "cannot propose mappings: target object '{object_slug}' has no active \
                 api fields to map onto"
            )));
        }

        // Prompt: names + bounded samples, JSON-encoded so a hostile field
        // name or sample value cannot break the prompt's structure.
        let src_json: Vec<serde_json::Value> = fields
            .iter()
            .map(|f| {
                serde_json::json!({
                    "name": f.name.trim(),
                    "type": f.field_type.as_deref().unwrap_or(""),
                    "samples": f.samples.iter().take(MAX_SAMPLES_PER_FIELD).map(truncate_sample).collect::<Vec<_>>(),
                })
            })
            .collect();
        let prompt = format!(
            "[tag:map-suggest] Propose source->target field mappings as JSON.\n\
             Rules:\n\
             - Respond with a single JSON object and nothing else: \
             {{\"mappings\":[{{\"source\":\"...\",\"target\":\"...\",\"confidence\":0.0,\"reason\":\"...\"}}]}}\n\
             - \"source\" must be exactly one of the source field names below.\n\
             - \"target\" must be exactly one of the target field names below.\n\
             - \"confidence\" is a number in [0,1]; \"reason\" is a short phrase.\n\
             - Omit source fields with no good match instead of guessing.\n\
             - Rank by confidence, most confident first.\n\
             - Below are field NAMES plus a few sample VALUES per field; use the \
             values only to disambiguate meaning, never invent fields.\n\
             Source fields: {}\n\
             Target fields: {}",
            serde_json::to_string(&src_json).unwrap_or_default(),
            serde_json::to_string(&target_fields).unwrap_or_default(),
        );
        if prompt.len() > MAX_PROMPT_BYTES {
            return Err(TinkerError::Validation(format!(
                "cannot propose mappings: the prompt would be {} bytes (cap {}) — \
                 send fewer fields or fewer/smaller samples",
                prompt.len(),
                MAX_PROMPT_BYTES
            )));
        }

        // Gateway call: placement is enforced inside `propose_mapping`
        // BEFORE any prompt byte leaves the process. On rejection the
        // adapter is never touched — and nothing is accounted, because no
        // model call happened.
        let completion = gateway.propose_mapping(ctx, provider_name, &prompt).await?;

        // M7 cost accounting: live token counts from the completion, never
        // estimates (item-24's live-usage rule; the HTTP adapter already
        // fails closed on a missing usage block). Fail closed: a ledger
        // failure returns an error, never silent unaccounted proposals.
        CostLedger::new(self.core.clone(), self.owner.clone())
            .record_usage(
                ctx,
                &completion.model_ref,
                completion.tokens_in,
                completion.tokens_out,
            )
            .await?;

        let suggestions = parse_ai_suggestions(&completion.text).map_err(|e| {
            TinkerError::Validation(format!("model returned unusable mapping JSON: {e}"))
        })?;
        let target_set: std::collections::HashSet<&str> =
            target_fields.iter().map(|s| s.as_str()).collect();
        let source_names: Vec<String> = fields.iter().map(|f| f.name.trim().to_string()).collect();
        let source_set: std::collections::HashSet<&str> =
            source_names.iter().map(|s| s.as_str()).collect();

        let mut proposals = vec![];
        for s in &suggestions {
            // Per-suggestion validation: the model is untrusted. Bad
            // entries are dropped individually — they never reach the
            // caller — and a zero-survivor result is a teaching error,
            // not an empty confident answer.
            if !source_set.contains(s.source.as_str()) {
                continue;
            }
            if !target_set.contains(s.target.as_str()) {
                continue;
            }
            if !(0.0..=1.0).contains(&s.confidence) || !s.confidence.is_finite() {
                continue;
            }
            let reason = s.reason.trim();
            if reason.is_empty() || reason.len() > 500 {
                continue;
            }
            proposals.push(FieldSuggestion {
                source_field: s.source.clone(),
                target_field: s.target.clone(),
                confidence: s.confidence,
                reason: reason.to_string(),
            });
        }
        if proposals.is_empty() {
            return Err(TinkerError::Validation(format!(
                "no usable mappings: the model returned {} suggestion(s) for target \
                 object '{object_slug}' but none named a real source field and a real \
                 target field with a confidence in [0,1] — refusing to present an \
                 empty or hallucinated list; source fields were: {}",
                suggestions.len(),
                source_names.join(", ")
            )));
        }
        // Ranked: confidence descending, deterministic tiebreak.
        proposals.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(Ordering::Equal)
                .then_with(|| a.source_field.cmp(&b.source_field))
                .then_with(|| a.target_field.cmp(&b.target_field))
        });
        Ok(MappingSuggestions {
            target_object: object_slug.to_string(),
            provider: provider_name.to_string(),
            model_ref: completion.model_ref,
            tokens_in: completion.tokens_in,
            tokens_out: completion.tokens_out,
            proposals,
        })
    }

    /// Approve a `draft` or `proposed` mapping. Approval is the human (or
    /// deterministic policy) gate; it never activates by itself.
    pub async fn approve_mapping(
        &self,
        ctx: &TenantContext,
        mapping_id: Uuid,
    ) -> Result<FieldMapping> {
        self.transition(ctx, mapping_id, &["draft", "proposed"], "approved")
            .await
    }

    /// Activate an `approved` mapping. Only activated mappings promote.
    pub async fn activate_mapping(
        &self,
        ctx: &TenantContext,
        mapping_id: Uuid,
    ) -> Result<FieldMapping> {
        self.transition(ctx, mapping_id, &["approved"], "activated")
            .await
    }

    async fn transition(
        &self,
        ctx: &TenantContext,
        mapping_id: Uuid,
        from: &[&str],
        to: &str,
    ) -> Result<FieldMapping> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row: Option<(Uuid, Uuid, String, String, String, String)> = sqlx::query_as(
            "UPDATE ingest_mapping SET state=$4, version=version+1
             WHERE organization_id=$1 AND id=$2 AND state = ANY($3)
             RETURNING id, stream_id, source_field, target_object, target_field, state",
        )
        .bind(ctx.organization_id.0)
        .bind(mapping_id)
        .bind(from)
        .bind(to)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        row.map(|r| FieldMapping {
            id: r.0,
            stream_id: r.1,
            source_field: r.2,
            target_object: r.3,
            target_field: r.4,
            state: r.5,
        })
        .ok_or_else(|| {
            TinkerError::Validation(format!(
                "mapping {mapping_id} is not in an approvable state"
            ))
        })
    }

    /// Active platform api fields for an object slug (owner-backed).
    async fn platform_api_fields(&self, object_slug: &str) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT f.api_name FROM ontology_fields f
             JOIN ontology_objects o ON o.id = f.object_id
             WHERE o.api_slug=$1 AND o.state='active' AND o.scope_kind='platform'
               AND f.state='active'
             ORDER BY f.api_name",
        )
        .bind(object_slug)
        .fetch_all(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    /// Apply mappings to one landed row: returns
    /// `(target_object, target_field, value)` triples. Unmapped source
    /// fields are dropped (they stay inspectable in the landing table).
    pub fn apply(
        mappings: &[FieldMapping],
        landed: &std::collections::HashMap<String, serde_json::Value>,
    ) -> Vec<(String, String, serde_json::Value)> {
        mappings
            .iter()
            .filter_map(|m| {
                landed
                    .get(&m.source_field)
                    .filter(|v| !v.is_null())
                    .map(|v| (m.target_object.clone(), m.target_field.clone(), v.clone()))
            })
            .collect()
    }
}

/// One model-suggested mapping, before validation. Every field is
/// checked against the observed schema / target object by the caller —
/// nothing here is trusted.
#[derive(Debug, serde::Deserialize)]
struct AiSuggestion {
    #[serde(default)]
    source: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    confidence: f64,
    #[serde(default)]
    reason: String,
}

#[derive(Debug, serde::Deserialize)]
struct AiSuggestionDoc {
    #[serde(default)]
    mappings: Vec<AiSuggestion>,
}

/// Extract the JSON document from a model completion. Tolerates
/// ```json fences and surrounding prose (models rarely obey "JSON only"),
/// but the result must still parse as the exact mapping shape — anything
/// else fails closed.
/// Bound one sample value before it enters the prompt: long strings are
/// truncated on a char boundary, nested arrays are capped, nested objects
/// collapse to a type tag. Samples are prompt bytes — this is a privacy
/// bound as well as a size bound.
fn truncate_sample(v: &serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(s) => {
            if s.len() > MAX_SAMPLE_CHARS {
                let t: String = s.chars().take(MAX_SAMPLE_CHARS).collect();
                serde_json::Value::String(format!("{t}...[truncated]"))
            } else {
                v.clone()
            }
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .take(MAX_SAMPLES_PER_FIELD)
                .map(truncate_sample)
                .collect(),
        ),
        serde_json::Value::Object(_) => serde_json::Value::String("[object]".to_string()),
        _ => v.clone(),
    }
}

fn parse_ai_suggestions(text: &str) -> std::result::Result<Vec<AiSuggestion>, String> {
    let t = text.trim();
    let t = t
        .strip_prefix("```")
        .map(|s| s.strip_prefix("json").unwrap_or(s).trim())
        .unwrap_or(t);
    let t = t.strip_suffix("```").map(str::trim).unwrap_or(t);
    // If prose surrounds the object, take the outermost {...} span.
    let json = match (t.find('{'), t.rfind('}')) {
        (Some(a), Some(b)) if b > a => &t[a..=b],
        _ => t,
    };
    let doc: AiSuggestionDoc =
        serde_json::from_str(json).map_err(|e| format!("not mapping JSON: {e}"))?;
    if doc.mappings.len() > 10_000 {
        return Err("absurd mapping count".to_string());
    }
    Ok(doc.mappings)
}

fn schema_fields(schema: &Option<serde_json::Value>) -> Vec<String> {
    schema
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| f.get("name")?.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Best target api field for a source field by normalized name.
/// Deterministic: exact beats partial, ties break alphabetically.
fn best_match(source: &str, targets: &[String]) -> Option<(String, f64, &'static str)> {
    let sn = normalize(source);
    if sn.is_empty() {
        return None;
    }
    let mut best: Option<(String, f64, &'static str)> = None;
    for t in targets {
        let tn = normalize(t);
        let (confidence, reason) = if sn == tn {
            (1.0, "exact name match")
        } else if sn.contains(&tn) || tn.contains(&sn) {
            (0.6, "partial name match")
        } else {
            continue;
        };
        let replace = match &best {
            None => true,
            Some((bt, bc, _)) => confidence > *bc || (confidence == *bc && t < bt),
        };
        if replace {
            best = Some((t.clone(), confidence, reason));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::best_match;

    #[test]
    fn matcher_is_deterministic() {
        let targets = vec![
            "name".to_string(),
            "email".to_string(),
            "industry".to_string(),
        ];
        assert_eq!(
            best_match("Email", &targets).unwrap().0,
            "email",
            "exact normalized"
        );
        assert_eq!(best_match("Email", &targets).unwrap().1, 1.0);
        // "FullName" contains "name" -> partial.
        let (t, c, _) = best_match("FullName", &targets).unwrap();
        assert_eq!(t, "name");
        assert_eq!(c, 0.6);
        assert!(best_match("Id", &targets).is_none());
        // Deterministic across calls.
        assert_eq!(
            best_match("FullName", &targets),
            best_match("FullName", &targets)
        );
    }
}
