//! User-defined schema: metadata plane + DDL runner (PRD §09).
//!
//! The headline invariant: **every object is a real table, every field is a
//! real typed column.** No EAV, no JSONB catch-all. richText is a typed jsonb
//! column validated against the document schema; everything else is scalar.
//!
//! Stable IDs make names mutable without losing identity: renames touch only
//! metadata rows, never physical storage.

use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use std::collections::HashMap;
use tinker_core::{OrganizationId, Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

pub mod lifecycle;
/// Item 37 (C3): the governed mutation connector (M3 debt). The single
/// production writer for ontology records: write presets, server-side
/// validation, approval consumption, mutation audit, and post-commit
/// invalidation/signal hooks — atomically coupled so no writer can take
/// one without the others.
pub mod mutate;

/// Item 37 (C3): decode validation rules from field metadata. A corrupt
/// row fails closed: silently dropping enforcement would be worse than
/// refusing the read.
fn field_validation_from_json(v: &serde_json::Value) -> Result<ValidationRules> {
    serde_json::from_value(v.clone()).map_err(|e| {
        TinkerError::Internal(format!("corrupt validation_json on ontology_fields: {e}"))
    })
}

/// Item 37 (C3): decode a write preset from field metadata. NULL (no
/// preset) decodes to None; anything else must parse or the read fails
/// closed.
fn field_preset_from_json(v: &serde_json::Value) -> Result<Option<WritePreset>> {
    if v.is_null() {
        return Ok(None);
    }
    serde_json::from_value(v.clone())
        .map_err(|e| TinkerError::Internal(format!("corrupt preset_json on ontology_fields: {e}")))
}

/// One row of `ontology_fields` for `describe_object`.
type FieldRow = (
    Uuid,
    String,
    String,
    String,
    String,
    serde_json::Value,
    Option<Uuid>,
    serde_json::Value,
    serde_json::Value,
    bool,
    // Item 42 (C7): per-field ceiling for linked file PII classes.
    String,
);

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Platform,
    Organization,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectDef {
    pub name: String,
    pub api_slug: String,
    pub label: String,
    pub scope: Scope,
    pub pack_id: Option<String>,
    pub pack_version: Option<String>,
}

/// Field types in v1 (PRD §09). Each maps to exactly one Postgres type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FieldType {
    Text,
    RichText,
    Number,
    Date,
    DateTime,
    Boolean,
    Select,
    MultiSelect,
    Currency,
    Email,
    Phone,
    Url,
    Relation { target_object_id: Uuid },
    File,
}

impl FieldType {
    /// The physical Postgres type. One field kind = one column type, always.
    pub fn pg_type(&self) -> &'static str {
        match self {
            Self::Text | Self::Email | Self::Phone | Self::Url | Self::Select | Self::File => {
                "TEXT"
            }
            Self::RichText => "JSONB",
            Self::Number | Self::Currency => "NUMERIC",
            Self::Date => "DATE",
            Self::DateTime => "TIMESTAMPTZ",
            Self::Boolean => "BOOLEAN",
            Self::MultiSelect => "TEXT[]",
            Self::Relation { .. } => "UUID",
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::RichText => "richtext",
            Self::Number => "number",
            Self::Date => "date",
            Self::DateTime => "datetime",
            Self::Boolean => "boolean",
            Self::Select => "select",
            Self::MultiSelect => "multi_select",
            Self::Currency => "currency",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Url => "url",
            Self::Relation { .. } => "relation",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDef {
    pub name: String,
    pub api_name: String,
    pub label: String,
    pub field_type: FieldType,
    /// e.g. {"options": ["lead","won"]} for select.
    pub options: serde_json::Value,
    pub required: bool,
    /// Item 37 (C3): server-side validation rules, stored as field
    /// metadata. The rule language is data, never code: range/pattern/
    /// enum constraints the mutation layer enforces. Serialized to
    /// `ontology_fields.validation_json`.
    #[serde(default)]
    pub validation: ValidationRules,
    /// Item 37 (C3): forced default applied at write time by the governed
    /// mutation connector, before validation (so a preset can satisfy
    /// `required`). Serialized to `ontology_fields.preset_json`.
    #[serde(default)]
    pub preset: Option<WritePreset>,
    /// Item 42 (C7): ceiling for PII classes of files linked through a
    /// `file` field. Serialized to `ontology_fields.max_pii_class`.
    /// Defaults to 'restricted' (permissive) so existing definitions
    /// keep working; validated at `add_field` time.
    #[serde(default = "default_max_pii_class")]
    pub max_pii_class: String,
}

/// Item 42 (C7): the permissive default — pre-item-42 field
/// definitions carry no PII ceiling, so nothing previously writable
/// becomes rejected until an operator tightens the field.
fn default_max_pii_class() -> String {
    "restricted".to_string()
}

/// Item 37 (C3): per-field validation rules. All optional; `required`
/// stays a first-class field flag. Semantics:
/// - `min`/`max`: numeric value range for Number/Currency; string length
///   range for text-ish types (text, richtext, email, phone, url).
/// - `pattern`: regex matched against the whole value, text-ish types only.
/// - `options`: explicit enum allow-list (in addition to a Select field's
///   own options, which Postgres enforces with a CHECK constraint).
///   Deliberately v1-small: no cross-field rules, no async validators.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ValidationRules {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
}

/// Item 37 (C3): when a write preset fires.
/// - `WhenMissing`: fill the value only when the writer omitted the field
///   or sent explicit null. On update, absent means "don't touch", so
///   WhenMissing only backfills keys the update explicitly nulled.
/// - `Always`: forced — overwrites whatever the writer sent, on create
///   and on update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresetMode {
    WhenMissing,
    Always,
}

/// Item 37 (C3): where a preset's value comes from. Static values only in
/// v1 — no expressions, no code. `ActorId` resolves to the acting actor's
/// id (useful for forced `owner`-style fields) without letting rule
/// authors smuggle in computation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PresetValue {
    Static { value: serde_json::Value },
    ActorId,
}

/// Item 37 (C3): a forced default on a field, applied by the governed
/// mutation connector before validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WritePreset {
    pub mode: PresetMode,
    pub value: PresetValue,
}

#[derive(Debug, Clone)]
pub struct ObjectMeta {
    pub id: Uuid,
    pub api_slug: String,
    pub table: String, // data.<slug>
}

#[derive(Debug, Clone)]
pub struct FieldMeta {
    pub id: Uuid,
    pub physical_column: String,
    pub field_type: String,
}

/// One active field row on a platform object, for the pack installer's
/// drift reconciliation: reinstall re-adds missing pack fields, restores
/// drifted metadata, and fails closed on type drift (never rewrites a
/// physical column).
#[derive(Debug, Clone)]
pub struct PlatformFieldRow {
    pub api_name: String,
    pub field_type: String,
    pub name: String,
    pub label: String,
    pub required: bool,
    pub options_json: serde_json::Value,
    pub relation_target_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn valid_slug(s: &str) -> bool {
    if s.len() < 2 || s.len() > 63 {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => (),
        _ => return false,
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return false;
    }
    !is_reserved(s)
}

fn is_reserved(s: &str) -> bool {
    matches!(
        s,
        "select"
            | "table"
            | "where"
            | "from"
            | "data"
            | "organization"
            | "user"
            | "order"
            | "group"
            | "index"
    )
}

fn validate_slug(slug: &str) -> Result<()> {
    if !valid_slug(slug) {
        return Err(TinkerError::Validation(format!("invalid api_slug: {slug}")));
    }
    Ok(())
}

fn validate_object_def(def: &ObjectDef) -> Result<()> {
    validate_slug(&def.api_slug)?;
    if def.name.trim().is_empty() || def.label.trim().is_empty() {
        return Err(TinkerError::Validation(
            "object name and label are required".into(),
        ));
    }
    Ok(())
}

/// Item 37 (C3): definition-time sanity for validation rules and write
/// presets. The rule language is data, never code: this only checks that
/// the data is coherent — min <= max, regex syntactically valid, rules
/// only on kinds they make sense for.
pub fn validate_field_def(def: &FieldDef) -> Result<()> {
    if !valid_slug(&def.api_name) {
        return Err(TinkerError::Validation(format!(
            "invalid api_name: {}",
            def.api_name
        )));
    }
    if let FieldType::Select = def.field_type {
        let opts = def
            .options
            .get("options")
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty() && a.iter().all(|v| v.is_string()))
            .ok_or_else(|| {
                TinkerError::Validation(
                    "select fields need options.options as a non-empty string array".into(),
                )
            })?;
        let _ = opts;
    }
    validate_validation_rules(def)?;
    Ok(())
}

/// Item 37 (C3): the validation rules themselves are validated at
/// definition time, so a bad rule fails when the field is defined — not
/// when the first record write trips over it.
fn validate_validation_rules(def: &FieldDef) -> Result<()> {
    let r = &def.validation;
    if let (Some(min), Some(max)) = (r.min, r.max) {
        if min > max {
            return Err(TinkerError::Validation(format!(
                "field '{}': validation min ({min}) > max ({max})",
                def.api_name
            )));
        }
    }
    let is_textual = matches!(
        def.field_type,
        FieldType::Text
            | FieldType::RichText
            | FieldType::Email
            | FieldType::Phone
            | FieldType::Url
    );
    let is_numeric = matches!(def.field_type, FieldType::Number | FieldType::Currency);
    if let Some(pattern) = &r.pattern {
        if !is_textual {
            return Err(TinkerError::Validation(format!(
                "field '{}': pattern rules only apply to text-ish field types",
                def.api_name
            )));
        }
        regex::Regex::new(pattern).map_err(|e| {
            TinkerError::Validation(format!(
                "field '{}': invalid validation pattern: {e}",
                def.api_name
            ))
        })?;
    }
    if (r.min.is_some() || r.max.is_some()) && !(is_textual || is_numeric) {
        return Err(TinkerError::Validation(format!(
            "field '{}': min/max rules only apply to numeric or text-ish field types",
            def.api_name
        )));
    }
    if let Some(options) = &r.options {
        if options.is_empty() {
            return Err(TinkerError::Validation(format!(
                "field '{}': validation options must be a non-empty array",
                def.api_name
            )));
        }
    }
    Ok(())
}

/// Stable physical column name: `f_` + 12 hex chars of randomness. Never
/// derived from the display name, so renames never touch storage.
///
/// The 12 hex chars MUST be random bits, not the leading chars of a v7
/// UUID: a v7's first 12 hex chars are the millisecond timestamp, so two
/// fields created in the same millisecond would share a physical name and
/// their `{physical}_idx` index creations would collide with 42P07
/// (index names live in the schema namespace, not per-table). The trailing
/// 12 hex chars are 48 bits of `rand_b`.
pub fn new_physical_column() -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("f_{}", &s[20..32])
}

// ---------------------------------------------------------------------------
// Ontology service
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Ontology {
    core: CoreDb,
    owner: OwnerDb,
}

/// Session-scoped advisory lock guard for installers. See
/// [`Ontology::install_lock`].
pub struct InstallLock {
    conn: sqlx::pool::PoolConnection<Postgres>,
    name: String,
}

impl InstallLock {
    /// Release the lock, returning the connection to the pool.
    pub async fn release(mut self) -> Result<()> {
        sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
            .bind(&self.name)
            .execute(&mut *self.conn)
            .await
            .map_err(TinkerError::Db)?;
        Ok(())
    }
}

impl Ontology {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    /// Acquire the named installer lock, blocking until it is held.
    ///
    /// Check-then-create installers (comms, packs) are idempotent for
    /// sequential repeats, but two concurrent installs can both observe a
    /// missing global slug and both attempt the define — one then fails
    /// with "object slug already exists". The session-level lock
    /// serializes installs per name so the idempotency checks converge.
    /// It is held on a dedicated pooled connection for the install's
    /// duration and must be released explicitly: dropping the guard would
    /// return the connection to the pool with the session-level lock
    /// still held.
    pub async fn install_lock(&self, name: &str) -> Result<InstallLock> {
        let mut conn = self.owner.0.acquire().await.map_err(TinkerError::Db)?;
        sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
            .bind(name)
            .execute(&mut *conn)
            .await
            .map_err(TinkerError::Db)?;
        Ok(InstallLock {
            conn,
            name: name.to_string(),
        })
    }
    /// Define an object and materialize its table. The metadata row starts as
    /// `draft`; it becomes `active` only after the DDL commits. Postgres DDL
    /// is transactional, so a failed CREATE TABLE rolls back everything.
    pub async fn define_object(&self, ctx: &TenantContext, def: &ObjectDef) -> Result<ObjectMeta> {
        validate_object_def(def)?;
        // M0: tenant callers may only create organization-scoped objects.
        // Platform scope writes rows visible to every tenant; it requires a
        // platform-authorized actor (the pack installer, M3). Accepting it
        // here would let any tenant pollute the shared base.
        if matches!(def.scope, Scope::Platform) {
            return Err(TinkerError::Forbidden(
                "platform scope requires a platform-authorized actor".into(),
            ));
        }
        self.define_object_inner(
            "organization",
            Some(ctx.organization_id.0),
            Some(ctx.actor_id),
            def,
        )
        .await
    }

    /// Item 39 (C4): ensure an organization object for `def`, adopting the
    /// shared table when another org already defined the slug. Returns the
    /// metadata and whether the row was adopted (`false` = newly defined).
    ///
    /// The check-then-act is racy by nature; both writers are race-safe
    /// (define fails closed with "table is shared" on 42P07, adopt
    /// converges concurrent racers on 23505), so the fallback covers the
    /// interleaving.
    pub async fn define_or_adopt(
        &self,
        ctx: &TenantContext,
        def: &ObjectDef,
    ) -> Result<(ObjectMeta, bool)> {
        if self
            .describe_shared_root(ctx, &def.api_slug)
            .await?
            .is_some()
        {
            return Ok((self.adopt_object(ctx, &def.api_slug).await?, true));
        }
        match self.define_object(ctx, def).await {
            Ok(meta) => Ok((meta, false)),
            Err(TinkerError::Validation(msg)) if msg.contains("table is shared") => {
                Ok((self.adopt_object(ctx, &def.api_slug).await?, true))
            }
            Err(e) => Err(e),
        }
    }

    /// Item 39 (C4): describe the ROOT organization object holding a shared
    /// slug, when some OTHER org holds it. Snapshot planning uses this to
    /// distinguish "define a new table" from "adopt the shared table", and
    /// to compute the field delta the adopter will actually need.
    ///
    /// This deliberately reads across the tenant boundary (owner pool for
    /// the lookup, then a synthetic root-org context for the describe):
    /// the caller could already discover the slug's existence via the
    /// "table is shared" define error, and an adopter sees these exact
    /// base fields live after adopting. Returns None when no other org
    /// holds the slug.
    pub async fn describe_shared_root(
        &self,
        ctx: &TenantContext,
        api_slug: &str,
    ) -> Result<Option<ObjectDescription>> {
        let mut conn = self.owner.0.acquire().await.map_err(TinkerError::Db)?;
        let root: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, organization_id FROM ontology_objects \
             WHERE api_slug=$1 AND state='active' AND scope_kind='organization' \
               AND adopted_from IS NULL AND organization_id <> $2 \
             ORDER BY created_at LIMIT 1",
        )
        .bind(api_slug)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *conn)
        .await
        .map_err(TinkerError::Db)?;
        let Some((root_id, root_org)) = root else {
            return Ok(None);
        };
        let root_ctx = TenantContext::new(
            OrganizationId(root_org),
            ctx.actor_id,
            "snapshot-shared-root",
        );
        Ok(Some(self.describe_object(&root_ctx, root_id).await?))
    }

    /// Resolve object ids to slugs through the owner pool. For rows the
    /// caller's tenant cannot see (another org's roots), the tenant RLS
    /// view is useless — this is the read-only escape hatch the
    /// snapshot planner uses to compare against a shared root's REAL
    /// relation targets.
    pub async fn slugs_for_ids(&self, ids: &[Uuid]) -> Result<HashMap<Uuid, String>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, api_slug FROM ontology_objects WHERE id = ANY($1) AND state='active'",
        )
        .bind(ids)
        .fetch_all(&self.owner.0)
        .await
        .map_err(TinkerError::Db)?;
        Ok(rows.into_iter().collect())
    }

    /// Adopt a shared object: create a metadata-only row pointing at an
    /// existing table instead of defining (and forking) it.
    ///
    /// Adopt-vs-define semantics:
    /// - `define_object` creates a NEW table and fails closed when the
    ///   slug's table already exists. It is for genuinely new objects.
    /// - `adopt_object` links to the EXISTING table. It is for the
    ///   portfolio-ontology model: a second organization uses the shared
    ///   base object (same physical table, same base fields) while keeping
    ///   its own metadata row, its own lifecycle, and its own post-adoption
    ///   fields (per-company extensions, namespaced by the adopted row).
    ///
    /// The adopted row stores `adopted_from` = the root definer's object id
    /// (adoption always flattens to the root, never chains), and field
    /// resolution unions the shared base fields — live, not a snapshot —
    /// with the adopter's own fields. Data isolation is unchanged: the
    /// shared table carries `organization_id` + RLS, so the adopter sees
    /// only its own rows.
    ///
    /// Idempotent: adopting a slug the caller already has returns the
    /// existing row; two concurrent adopts converge on one row.
    pub async fn adopt_object(&self, ctx: &TenantContext, api_slug: &str) -> Result<ObjectMeta> {
        validate_slug(api_slug)?;
        let org = ctx.organization_id.0;
        let table = format!("data.{api_slug}");

        let mut tx: Transaction<'_, Postgres> = self.owner.0.begin().await?;
        // Serialize adoption per slug; the 23505 fallback below converges
        // concurrent racers that slipped through before the lock.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("tinker:ddl:{api_slug}"))
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '10s'")
            .execute(&mut *tx)
            .await?;

        // Already have it (defined or adopted): converge, don't duplicate.
        let own: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM ontology_objects \
             WHERE api_slug=$1 AND state='active' \
               AND scope_kind='organization' AND organization_id=$2",
        )
        .bind(api_slug)
        .bind(org)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((id,)) = own {
            tx.commit().await?;
            return Ok(ObjectMeta {
                id,
                api_slug: api_slug.to_string(),
                table,
            });
        }

        // The shared object to adopt: the root definer's row (adopted_from
        // IS NULL flattens chains — adopting an adopted row adopts its
        // root, so the adopter gets the shared base, not the middleman's
        // customizations). Platform objects are already visible to every
        // tenant via describe_object_by_slug; adopting one would be a
        // redundant row, so they are excluded as sources.
        let source: Option<(Uuid, String, String)> = sqlx::query_as(
            "SELECT id, name, label FROM ontology_objects \
             WHERE api_slug=$1 AND state<>'draft' AND adopted_from IS NULL \
               AND scope_kind<>'platform' \
               AND NOT (scope_kind='organization' AND organization_id=$2) \
             ORDER BY created_at LIMIT 1",
        )
        .bind(api_slug)
        .bind(org)
        .fetch_optional(&mut *tx)
        .await?;
        let (source_id, name, label) = source.ok_or_else(|| {
            TinkerError::NotFound(format!("no shared object to adopt: {api_slug}"))
        })?;

        let object_id = Uuid::now_v7();
        let inserted = sqlx::query(
            r#"INSERT INTO ontology_objects
               (id, scope_kind, scope_id, organization_id, name, api_slug,
                label, state, adopted_from)
               VALUES ($1,'organization',$2,$2,$3,$4,$5,'active',$6)"#,
        )
        .bind(object_id)
        .bind(org)
        .bind(&name)
        .bind(api_slug)
        .bind(&label)
        .bind(source_id)
        .execute(&mut *tx)
        .await;
        let object_id = match inserted {
            Ok(_) => object_id,
            Err(sqlx::Error::Database(db)) if db.code().as_deref() == Some("23505") => {
                // A concurrent adopter won the race: converge on their row.
                let (id,): (Uuid,) = sqlx::query_as(
                    "SELECT id FROM ontology_objects \
                     WHERE api_slug=$1 AND state='active' \
                       AND scope_kind='organization' AND organization_id=$2",
                )
                .bind(api_slug)
                .bind(org)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| TinkerError::Internal("adopt raced but no row found".into()))?;
                tx.commit().await?;
                return Ok(ObjectMeta {
                    id,
                    api_slug: api_slug.to_string(),
                    table,
                });
            }
            Err(e) => return Err(TinkerError::Db(e)),
        };

        sqlx::query(
            r#"INSERT INTO ontology_changes
               (organization_id, object_id, change_kind, detail, applied_by)
               VALUES ($1,$2,'object.adopted',$3,$4)"#,
        )
        .bind(org)
        .bind(object_id)
        .bind(serde_json::json!({"api_slug": api_slug, "adopted_from": source_id}))
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(ObjectMeta {
            id: object_id,
            api_slug: api_slug.to_string(),
            table,
        })
    }

    /// Privileged platform-object definition. There is no tenant context:
    /// the caller is the pack installer (binary/CLI), never a tenant HTTP
    /// handler. Platform objects are visible to every organization; their
    /// tables still carry the composite tenant key and RLS.
    /// Owner-backed lookup of a platform object by slug. Used by the
    /// pack installer for idempotent reinstalls: a pack that is already
    /// installed resolves to its existing objects instead of forking
    /// tables. Never exposed through tenant handlers.
    pub async fn platform_object_by_slug(&self, api_slug: &str) -> Result<Option<ObjectMeta>> {
        let row: Option<(Uuid, String, String)> = sqlx::query_as(
            "SELECT id, api_slug, scope_kind FROM ontology_objects \
             WHERE api_slug=$1 AND state='active'",
        )
        .bind(api_slug)
        .fetch_optional(&self.owner.0)
        .await?;
        match row {
            None => Ok(None),
            Some((id, slug, scope_kind)) => {
                if scope_kind != "platform" {
                    return Err(TinkerError::Validation(format!(
                        "pack slug {api_slug} collides with a non-platform object"
                    )));
                }
                Ok(Some(ObjectMeta {
                    id,
                    api_slug: slug.clone(),
                    table: format!("data.{slug}"),
                }))
            }
        }
    }

    /// Owner-backed field api_names for an object. Used by the pack
    /// installer to skip fields that already exist on reinstall.
    pub async fn platform_field_api_names(&self, object_id: Uuid) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT api_name FROM ontology_fields WHERE object_id=$1 AND state='active'",
        )
        .bind(object_id)
        .fetch_all(&self.owner.0)
        .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// Owner-backed full field rows for a platform object. Used by the
    /// pack installer to reconcile drift on reinstall.
    pub async fn platform_field_rows(&self, object_id: Uuid) -> Result<Vec<PlatformFieldRow>> {
        let rows = sqlx::query(
            "SELECT api_name, field_type, name, label, required, options_json, \
             relation_target_id FROM ontology_fields \
             WHERE object_id=$1 AND state='active'",
        )
        .bind(object_id)
        .fetch_all(&self.owner.0)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| PlatformFieldRow {
                api_name: r.get("api_name"),
                field_type: r.get("field_type"),
                name: r.get("name"),
                label: r.get("label"),
                required: r.get("required"),
                options_json: r.get("options_json"),
                relation_target_id: r.get("relation_target_id"),
            })
            .collect())
    }

    /// Privileged platform-field metadata reconciliation. Metadata only
    /// (name/label/required/options) — never the physical type. The caller
    /// is the pack installer repairing drift on reinstall; the target must
    /// be an active platform object. Zero matched rows is NotFound, never
    /// a silent no-op.
    pub async fn update_platform_field_metadata(
        &self,
        object_id: Uuid,
        api_name: &str,
        name: &str,
        label: &str,
        required: bool,
        options: &serde_json::Value,
    ) -> Result<()> {
        let done = sqlx::query(
            "UPDATE ontology_fields SET name=$1, label=$2, required=$3, options_json=$4 \
             WHERE object_id=$5 AND api_name=$6 AND state='active' \
             AND EXISTS (SELECT 1 FROM ontology_objects \
                         WHERE id=$5 AND state='active' AND scope_kind='platform')",
        )
        .bind(name)
        .bind(label)
        .bind(required)
        .bind(options)
        .bind(object_id)
        .bind(api_name)
        .execute(&self.owner.0)
        .await?;
        if done.rows_affected() != 1 {
            return Err(TinkerError::NotFound(format!(
                "platform field {api_name} on object {object_id}"
            )));
        }
        Ok(())
    }

    pub async fn define_platform_object(&self, def: &ObjectDef) -> Result<ObjectMeta> {
        validate_object_def(def)?;
        if !matches!(def.scope, Scope::Platform) {
            return Err(TinkerError::Validation(
                "define_platform_object requires Scope::Platform".into(),
            ));
        }
        self.define_object_inner("platform", None, None, def).await
    }

    async fn define_object_inner(
        &self,
        scope_kind: &str,
        organization_id: Option<Uuid>,
        applied_by: Option<Uuid>,
        def: &ObjectDef,
    ) -> Result<ObjectMeta> {
        let object_id = Uuid::now_v7();
        let table = format!("data.{}", def.api_slug);

        let mut tx: Transaction<'_, Postgres> = self.owner.0.begin().await?;
        // Serialize DDL per physical object across workers.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("tinker:ddl:{}", def.api_slug))
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '10s'")
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"INSERT INTO ontology_objects
               (id, scope_kind, scope_id, organization_id, pack_id, pack_version,
                name, api_slug, label, state)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'draft')"#,
        )
        .bind(object_id)
        .bind(scope_kind)
        .bind(organization_id)
        .bind(organization_id)
        .bind(&def.pack_id)
        .bind(&def.pack_version)
        .bind(&def.name)
        .bind(&def.api_slug)
        .bind(&def.label)
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
                TinkerError::Validation(format!("object slug already exists: {}", def.api_slug))
            }
            _ => TinkerError::Db(e),
        })?;

        sqlx::query(&format!(
            r#"CREATE TABLE {table} (
                organization_id uuid NOT NULL,
                id uuid NOT NULL DEFAULT gen_random_uuid(),
                version bigint NOT NULL DEFAULT 1,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now(),
                -- Item 40 (C1): the data table holds published content
                -- only ('published' | 'archived'). In-flight drafts live
                -- in record_drafts, never here.
                lifecycle_state text NOT NULL DEFAULT 'published'
                    CHECK (lifecycle_state IN ('published','archived')),
                PRIMARY KEY (organization_id, id)
            )"#
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            // The slug namespace is portfolio-shared: a second definition of
            // the same slug fails closed here instead of forking the table.
            // The caller probably wants adopt_object: a metadata-only row
            // pointing at the existing shared table.
            sqlx::Error::Database(db) if db.code().as_deref() == Some("42P07") => {
                TinkerError::Validation(format!(
                    "object slug already exists: {} (table is shared) -- adopt the shared object with adopt_object instead of defining it",
                    def.api_slug
                ))
            }
            _ => TinkerError::Db(e),
        })?;

        // Tenant isolation on the new table: explicit predicate via RLS.
        // The app role (tinker_app) owns nothing, so this policy always applies.
        let policy = format!("{}_org_isolation", def.api_slug);
        sqlx::query(&format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
            .execute(&mut *tx)
            .await?;
        sqlx::query(&format!(
            "CREATE POLICY \"{policy}\" ON {table} \
             USING (organization_id = current_setting('app.organization_id', true)::uuid)"
        ))
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE ontology_objects SET state='active' WHERE id=$1")
            .bind(object_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            r#"INSERT INTO ontology_changes
               (organization_id, object_id, change_kind, detail, ddl_statements, applied_by)
               VALUES ($1,$2,'object.created',$3,$4,$5)"#,
        )
        .bind(organization_id)
        .bind(object_id)
        .bind(serde_json::json!({"api_slug": def.api_slug, "scope": scope_kind}))
        .bind(vec![format!("CREATE TABLE {table} (...)")])
        .bind(applied_by)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(ObjectMeta {
            id: object_id,
            api_slug: def.api_slug.clone(),
            table,
        })
    }

    /// Item 40 (C1): opt an object into the per-record lifecycle. When
    /// enabled, the governed MutationConnector refuses direct
    /// create/update — records must go through the lifecycle engine's
    /// draft → review → publish path. Existing published rows are
    /// unaffected (they are already 'published' content).
    pub async fn set_lifecycle_enabled(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        enabled: bool,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE ontology_objects SET lifecycle_enabled = $3 \
             WHERE id = $1 AND organization_id = $2 AND state = 'active'",
        )
        .bind(object_id)
        .bind(ctx.organization_id.0)
        .bind(enabled)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        tx.commit().await.map_err(TinkerError::Db)?;
        if n == 0 {
            return Err(TinkerError::NotFound(format!("object {object_id}")));
        }
        Ok(())
    }

    /// Add a field: one nullable typed column. New columns are ALWAYS
    /// nullable at the physical level; `required` is metadata enforced by
    /// the mutation service (M3), never by a blocking table rewrite.
    pub async fn add_field(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        def: &FieldDef,
    ) -> Result<FieldMeta> {
        validate_field_def(def)?;
        // Resolve the object through the OWNER pool (DDL needs it), but with
        // an explicit tenant predicate: the caller may only mutate objects
        // in their own organization. Without this, any tenant could pass a
        // sibling org's object id and alter its table. Missing (or foreign)
        // objects surface as NotFound — no existence oracle for siblings.
        // Platform objects are immutable to tenant actors; the pack
        // installer uses `add_platform_field`.
        self.add_field_inner(
            object_id,
            def,
            "organization",
            Some(ctx.organization_id.0),
            Some(ctx.organization_id.0),
            Some(ctx.actor_id),
        )
        .await
    }

    /// Privileged platform-field addition. No tenant context: the caller is
    /// the pack installer. The target must be an active platform object.
    pub async fn add_platform_field(&self, object_id: Uuid, def: &FieldDef) -> Result<FieldMeta> {
        validate_field_def(def)?;
        self.add_field_inner(object_id, def, "platform", None, None, None)
            .await
    }

    /// Shared field DDL. `scope_kind` selects which objects are mutable;
    /// `scope_org` is the required organization for organization scope;
    /// `field_org` is stamped on the field row (NULL for platform fields);
    /// `applied_by` records the actor for the change log.
    async fn add_field_inner(
        &self,
        object_id: Uuid,
        def: &FieldDef,
        scope_kind: &str,
        scope_org: Option<Uuid>,
        field_org: Option<Uuid>,
        applied_by: Option<Uuid>,
    ) -> Result<FieldMeta> {
        let field_id = Uuid::now_v7();
        let physical = new_physical_column();

        let mut tx: Transaction<'_, Postgres> = self.owner.0.begin().await?;

        let obj: Option<(String, Option<Uuid>)> = if scope_kind == "platform" {
            sqlx::query_as(
                "SELECT api_slug, adopted_from FROM ontology_objects \
                 WHERE id=$1 AND state='active' AND scope_kind='platform'",
            )
            .bind(object_id)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query_as(
                "SELECT api_slug, adopted_from FROM ontology_objects \
                 WHERE id=$1 AND state='active' \
                   AND scope_kind='organization' AND organization_id=$2",
            )
            .bind(object_id)
            .bind(scope_org)
            .fetch_optional(&mut *tx)
            .await?
        };
        let (api_slug, adopted_from) =
            obj.ok_or_else(|| TinkerError::NotFound(format!("object {object_id}")))?;
        let table = format!("data.{api_slug}");

        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("tinker:ddl:{api_slug}"))
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL lock_timeout = '10s'")
            .execute(&mut *tx)
            .await?;

        // Converge under the lock: a concurrent installer may have added
        // this api_name after our pre-lock existence check. Re-checking
        // here (the lock serializes DDL per table, and the loser's lock
        // is only granted after the winner commits) makes check-then-act
        // atomic — parallel pack installs converge instead of one dying
        // on a duplicate column. On an adopted object the check spans the
        // shared base fields too: re-adding the adopter's own field
        // converges (idempotent retry), but shadowing a shared base field
        // with a same-named adopter field fails closed — evolution is
        // additive and can never shadow a base field (M4 principle).
        let raced: Option<(Uuid, String, String, Uuid)> = if let Some(source) = adopted_from {
            sqlx::query_as(
                "SELECT id, physical_column, field_type, object_id FROM ontology_fields \
                 WHERE (object_id=$1 OR object_id=$2) AND api_name=$3 AND state='active'",
            )
            .bind(object_id)
            .bind(source)
            .bind(&def.api_name)
            .fetch_optional(&mut *tx)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, physical_column, field_type, object_id FROM ontology_fields \
                 WHERE object_id=$1 AND api_name=$2 AND state='active'",
            )
            .bind(object_id)
            .bind(&def.api_name)
            .fetch_optional(&mut *tx)
            .await?
        };
        if let Some((id, physical_column, field_type, owner)) = raced {
            if owner == object_id {
                tx.commit().await?;
                return Ok(FieldMeta {
                    id,
                    physical_column,
                    field_type,
                });
            }
            return Err(TinkerError::Validation(format!(
                "field '{}' shadows a shared base field on the adopted object",
                def.api_name
            )));
        }

        // Relation target must exist, be active, and live in the same
        // scope: a cross-tenant FK would bridge two tenants' tables.
        let mut fk_sql = String::new();
        if let FieldType::Relation { target_object_id } = &def.field_type {
            let target: Option<(String,)> = if scope_kind == "platform" {
                sqlx::query_as(
                    "SELECT api_slug FROM ontology_objects \
                     WHERE id=$1 AND state='active' AND scope_kind='platform'",
                )
                .bind(target_object_id)
                .fetch_optional(&mut *tx)
                .await?
            } else {
                sqlx::query_as(
                    "SELECT api_slug FROM ontology_objects \
                     WHERE id=$1 AND state='active' \
                       AND scope_kind='organization' AND organization_id=$2",
                )
                .bind(target_object_id)
                .bind(scope_org)
                .fetch_optional(&mut *tx)
                .await?
            };
            let (target_slug,) = target.ok_or_else(|| {
                TinkerError::NotFound(format!("relation target {target_object_id}"))
            })?;
            // Composite tenant FK, exactly as the PRD sketches.
            fk_sql = format!(
                ", ADD CONSTRAINT \"{physical}_fk\" FOREIGN KEY (organization_id, \"{physical}\") \
                 REFERENCES data.{target_slug}(organization_id, id)"
            );
        }

        // Select options become a real CHECK constraint: Postgres owns it.
        let mut check_sql = String::new();
        if let FieldType::Select = def.field_type {
            let opts: Vec<String> = def.options["options"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().replace('\'', "''"))
                .collect();
            let list = opts
                .iter()
                .map(|o| format!("'{o}'"))
                .collect::<Vec<_>>()
                .join(", ");
            check_sql = format!(
                ", ADD CONSTRAINT \"{physical}_options\" CHECK (\"{physical}\" IS NULL OR \"{physical}\" IN ({list}))"
            );
        }

        let alter = format!(
            "ALTER TABLE {table} ADD COLUMN \"{physical}\" {}{check_sql}{fk_sql}",
            def.field_type.pg_type(),
        );
        sqlx::query(&alter).execute(&mut *tx).await?;

        // Index relation columns: relation traversals are join-heavy.
        if matches!(def.field_type, FieldType::Relation { .. }) {
            sqlx::query(&format!(
                "CREATE INDEX \"{physical}_idx\" ON {table} (organization_id, \"{physical}\")"
            ))
            .execute(&mut *tx)
            .await?;
        }

        let type_name = def.field_type.kind_name().to_string();
        let relation_target = match &def.field_type {
            FieldType::Relation { target_object_id } => Some(*target_object_id),
            _ => None,
        };
        // Item 37 (C3): validation rules and write presets are field
        // metadata, persisted with the field row and versioned with the
        // schema (M4 evolution carries them in the version spec).
        let validation_json = serde_json::to_value(&def.validation).map_err(|e| {
            TinkerError::Validation(format!("cannot serialize validation rules: {e}"))
        })?;
        let preset_json = serde_json::to_value(&def.preset)
            .map_err(|e| TinkerError::Validation(format!("cannot serialize write preset: {e}")))?;
        // Item 42 (C7): the PII ceiling is closed vocabulary — a typo
        // fails here, never as a silently permissive row.
        let max_pii_class = match def.max_pii_class.as_str() {
            "none" | "pii" | "restricted" => def.max_pii_class.clone(),
            other => {
                return Err(TinkerError::Validation(format!(
                    "bad max_pii_class: {other}"
                )))
            }
        };
        sqlx::query(
            r#"INSERT INTO ontology_fields
               (id, object_id, organization_id, physical_column, name, api_name,
                label, field_type, options_json, relation_target_id, required,
                validation_json, preset_json, max_pii_class)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)"#,
        )
        .bind(field_id)
        .bind(object_id)
        .bind(field_org)
        .bind(&physical)
        .bind(&def.name)
        .bind(&def.api_name)
        .bind(&def.label)
        .bind(&type_name)
        .bind(&def.options)
        .bind(relation_target)
        .bind(def.required)
        .bind(&validation_json)
        .bind(&preset_json)
        .bind(&max_pii_class)
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.code().as_deref() == Some("23505") => {
                TinkerError::Validation(format!("field api_name already exists: {}", def.api_name))
            }
            _ => TinkerError::Db(e),
        })?;

        sqlx::query(
            r#"INSERT INTO ontology_changes
               (organization_id, object_id, change_kind, detail, ddl_statements, applied_by)
               VALUES ($1,$2,'field.added',$3,$4,$5)"#,
        )
        .bind(field_org)
        .bind(object_id)
        .bind(serde_json::json!({"api_name": def.api_name, "physical_column": physical, "type": type_name}))
        .bind(vec![alter.clone()])
        .bind(applied_by)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(FieldMeta {
            id: field_id,
            physical_column: physical,
            field_type: type_name,
        })
    }

    /// Rename an object. Stable IDs mean this touches metadata only;
    /// the physical table never moves.
    pub async fn rename_object(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        name: &str,
        label: &str,
    ) -> Result<()> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE ontology_objects SET name=$1, label=$2, version=version+1, updated_at=now() WHERE id=$3",
        )
        .bind(name)
        .bind(label)
        .bind(object_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        if n == 0 {
            return Err(TinkerError::NotFound(format!("object {object_id}")));
        }
        Ok(())
    }

    /// Resolve an object with its fields through the tenant's RLS view.
    pub async fn describe_object(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
    ) -> Result<ObjectDescription> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        // adopted_from: NULL for defined objects; the root definer's id for
        // an adopted row. Base fields resolve live from the adopted object,
        // so the adopter always sees the current shared schema.
        let obj: Option<(Uuid, String, String, String, Option<Uuid>, bool)> = sqlx::query_as(
            "SELECT id, api_slug, name, scope_kind, adopted_from, lifecycle_enabled FROM ontology_objects WHERE id=$1 AND state='active'",
        )
        .bind(object_id)
        .fetch_optional(&mut *tx)
        .await?;
        let (id, api_slug, name, scope_kind, adopted_from, lifecycle_enabled) =
            obj.ok_or_else(|| TinkerError::NotFound(format!("object {object_id}")))?;
        // Adopted objects see the shared base fields (resolved from the
        // adopted row, live -- not a snapshot) plus any fields the adopter
        // added after adopting. created_at ordering keeps base fields
        // first: they predate the adoption.
        let fields: Vec<FieldRow> = if let Some(source) = adopted_from {
            sqlx::query_as(
                "SELECT id, physical_column, api_name, label, field_type, options_json, relation_target_id, \
                 validation_json, preset_json, required, max_pii_class \
                 FROM ontology_fields WHERE (object_id=$1 OR object_id=$2) AND state='active' ORDER BY created_at",
            )
            .bind(object_id)
            .bind(source)
            .fetch_all(&mut *tx)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, physical_column, api_name, label, field_type, options_json, relation_target_id, \
                 validation_json, preset_json, required, max_pii_class \
                 FROM ontology_fields WHERE object_id=$1 AND state='active' ORDER BY created_at",
            )
            .bind(object_id)
            .fetch_all(&mut *tx)
            .await?
        };
        tx.commit().await?;
        // Item 37 (C3): governance metadata rides with the field
        // description. A corrupt row fails closed at read time rather
        // than silently dropping enforcement.
        let mut out = Vec::with_capacity(fields.len());
        for (
            id,
            physical_column,
            api_name,
            label,
            field_type,
            options_json,
            relation_target_id,
            validation_json,
            preset_json,
            required,
            max_pii_class,
        ) in fields
        {
            out.push(FieldDescription {
                id,
                physical_column,
                api_name,
                label,
                field_type,
                options_json,
                relation_target_id,
                extension_table: None,
                validation: field_validation_from_json(&validation_json)?,
                preset: field_preset_from_json(&preset_json)?,
                required,
                // Item 42 (C7): the row CHECK constrains the value; a
                // corrupt value fails closed here, never silently
                // permissive.
                max_pii_class: match max_pii_class.as_str() {
                    "none" | "pii" | "restricted" => max_pii_class,
                    other => {
                        return Err(TinkerError::Internal(format!(
                            "corrupt max_pii_class on ontology_fields: {other}"
                        )))
                    }
                },
            });
        }
        // Item 39 (C4): adopted objects inherit base field rows from the
        // defining org, so an inherited relation field's stored target is
        // the ROOT's object id — a row this tenant cannot see through
        // RLS. Rewrite those targets to the tenant's own row for the
        // same slug (adopted or defined). Same slug = same physical
        // table, so joins are unaffected and relation hops, the
        // snapshot exporter, and drift checks all consume a target the
        // tenant can actually resolve. When the tenant has no row for
        // the target slug yet, the root id is left untouched (a relation
        // hop then fails closed with NotFound, as before).
        if adopted_from.is_some() {
            self.rewrite_inherited_relation_targets(ctx, &mut out)
                .await?;
        }
        Ok(ObjectDescription {
            id,
            api_slug,
            name,
            scope_kind,
            fields: out,
            // Item 40 (C1): per-record lifecycle opt-in. When true, the
            // governed MutationConnector refuses direct writes — records
            // must go through the lifecycle engine's draft → review →
            // publish path.
            lifecycle_enabled,
        })
    }

    /// Retarget inherited relation fields at the tenant's own object
    /// rows. See the call site in [`Ontology::describe_object`].
    async fn rewrite_inherited_relation_targets(
        &self,
        ctx: &TenantContext,
        fields: &mut [FieldDescription],
    ) -> Result<()> {
        let targets: Vec<Uuid> = fields
            .iter()
            .filter(|f| f.field_type == "relation")
            .filter_map(|f| f.relation_target_id)
            .collect();
        if targets.is_empty() {
            return Ok(());
        }
        // Root rows are invisible to this tenant: resolve their slugs
        // through the owner pool, never the tenant view.
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, api_slug FROM ontology_objects WHERE id = ANY($1) AND state='active'",
        )
        .bind(&targets)
        .fetch_all(&self.owner.0)
        .await?;
        if rows.is_empty() {
            return Ok(());
        }
        // The tenant's own row for each slug (adopted or defined) is
        // visible through their RLS view.
        let mut tx = self.core.tenant_tx(ctx).await?;
        let mut own_id: HashMap<String, Uuid> = HashMap::new();
        for (_, slug) in &rows {
            let row: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM ontology_objects WHERE api_slug=$1 AND state='active'",
            )
            .bind(slug.as_str())
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(id) = row {
                own_id.insert(slug.clone(), id);
            }
        }
        tx.commit().await?;
        let slug_of: HashMap<Uuid, String> = rows.into_iter().collect();
        for f in fields.iter_mut() {
            if let Some(tid) = f.relation_target_id {
                if let Some(slug) = slug_of.get(&tid) {
                    if let Some(id) = own_id.get(slug) {
                        f.relation_target_id = Some(*id);
                    }
                }
            }
        }
        Ok(())
    }

    /// M4: describe an object with evolution fields attached. `ext` comes
    /// from the schema evolver's immutable version specs for this
    /// organization's resolved version; base fields are unchanged. Unknown
    /// ext api_names that collide with base fields are refused — evolution
    /// is additive and can never shadow a base field.
    pub async fn describe_object_with_ext(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        ext: &[ExtField],
    ) -> Result<ObjectDescription> {
        let mut desc = self.describe_object(ctx, object_id).await?;
        for e in ext {
            if desc.fields.iter().any(|f| f.api_name == e.api_name) {
                return Err(TinkerError::Validation(format!(
                    "evolved field '{}' collides with a base field",
                    e.api_name
                )));
            }
            desc.fields.push(FieldDescription {
                id: Uuid::nil(),
                physical_column: e.physical_column.clone(),
                api_name: e.api_name.clone(),
                label: e.label.clone(),
                field_type: e.field_type.clone(),
                options_json: e.options.clone(),
                relation_target_id: e.relation_target_id,
                extension_table: Some(e.extension_table.clone()),
                // Item 37 (C3): evolution carries governance metadata.
                validation: e.validation.clone(),
                preset: e.preset.clone(),
                required: e.required,
                // Item 42 (C7): evolved fields are extension-table fields,
                // skipped on write by the mutation connector, so the PII
                // ceiling never enforces here; keep the permissive default.
                max_pii_class: "restricted".to_string(),
            });
        }
        Ok(desc)
    }

    /// Tenant-scoped object lookup by slug: the caller's organization plus
    /// platform objects. A sibling org's slug is invisible (NotFound), so
    /// virtual paths can never address another tenant's tables.
    pub async fn describe_object_by_slug(
        &self,
        ctx: &TenantContext,
        api_slug: &str,
    ) -> Result<ObjectDescription> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let obj: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM ontology_objects WHERE api_slug=$1 AND state='active' \
             AND (scope_kind='platform' \
                  OR (scope_kind='organization' AND organization_id=$2))",
        )
        .bind(api_slug)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        let (id,) = obj.ok_or_else(|| TinkerError::NotFound(format!("object {api_slug}")))?;
        self.describe_object(ctx, id).await
    }

    /// Physical columns of the materialized table, straight from the catalog.
    /// Used by the M0 exit test to prove the table is real.
    pub async fn physical_columns(&self, table: &str) -> Result<Vec<(String, String, bool)>> {
        if !table.starts_with("data.") {
            return Err(TinkerError::Validation("not a data table".into()));
        }
        let rows = sqlx::query(
            "SELECT column_name, data_type, is_nullable FROM information_schema.columns \
             WHERE table_schema='data' AND table_name=$1 ORDER BY ordinal_position",
        )
        .bind(&table[5..])
        .fetch_all(&self.owner.0)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("column_name"),
                    r.get::<String, _>("data_type"),
                    r.get::<String, _>("is_nullable") == "YES",
                )
            })
            .collect())
    }
}

#[derive(Debug, Clone)]
pub struct ObjectDescription {
    pub id: Uuid,
    pub api_slug: String,
    pub name: String,
    pub scope_kind: String,
    pub fields: Vec<FieldDescription>,
    /// Item 40 (C1): when true, direct governed writes are refused and
    /// records must go through the lifecycle engine.
    pub lifecycle_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct FieldDescription {
    pub id: Uuid,
    pub physical_column: String,
    pub api_name: String,
    pub label: String,
    pub field_type: String,
    pub options_json: serde_json::Value,
    /// M4: the relation target, loaded at describe time so the compiler
    /// never needs a metadata lookup per relation hop (and so evolved
    /// relation fields — which have no ontology_fields row — resolve).
    pub relation_target_id: Option<Uuid>,
    /// M4: set for fields added by schema evolution. The column lives on
    /// the organization's extension table (not the base table), so one
    /// company's evolution never alters the shared base schema. The query
    /// compiler LEFT JOINs this table when the field is selected.
    pub extension_table: Option<String>,
    /// Item 37 (C3): server-side validation rules for this field.
    pub validation: ValidationRules,
    /// Item 37 (C3): forced default applied by the governed mutation
    /// connector before validation.
    pub preset: Option<WritePreset>,
    /// Item 37 (C3): the first-class required flag, surfaced so the
    /// mutation layer can enforce it (previously metadata-only).
    pub required: bool,
    /// Item 42 (C7): ceiling for PII classes of files linked through
    /// this field ('none' | 'pii' | 'restricted'; 'none' < 'pii' <
    /// 'restricted'). The write path rejects a file whose pii_class
    /// exceeds this ceiling, fail closed. Only enforced for `file`
    /// fields; stored for all fields for uniformity.
    pub max_pii_class: String,
}

/// M4: a field added by schema evolution, resolved from immutable version
/// specs. The evolver builds these; the ontology attaches them to the
/// object description so the query compiler sees one unified field list.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExtField {
    pub api_name: String,
    pub label: String,
    /// Field kind name, e.g. "text", "number", "relation".
    pub field_type: String,
    pub physical_column: String,
    pub extension_table: String,
    pub relation_target_id: Option<Uuid>,
    pub options: serde_json::Value,
    /// Item 37 (C3): validation rules carried through M4 evolution.
    /// Evolution is metadata-additive, so governance travels with the
    /// version spec instead of being dropped on promote.
    #[serde(default)]
    pub validation: ValidationRules,
    /// Item 37 (C3): write preset carried through M4 evolution.
    #[serde(default)]
    pub preset: Option<WritePreset>,
    /// Item 37 (C3): required flag carried through M4 evolution.
    #[serde(default)]
    pub required: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Regression: physical column names must be unique even when generated
    /// back-to-back in the same millisecond. The old implementation sliced
    /// the LEADING 12 hex chars of a v7 UUID — the millisecond timestamp —
    /// so concurrent field creations collided and `CREATE INDEX
    /// {physical}_idx` failed with 42P07 (index names share the schema
    /// namespace across tables).
    #[test]
    fn physical_column_names_are_unique_within_a_millisecond() {
        let mut seen = HashSet::new();
        for _ in 0..5_000 {
            let name = new_physical_column();
            assert!(name.starts_with("f_"), "physical prefix: {name}");
            assert_eq!(name.len(), 14, "f_ + 12 hex chars: {name}");
            assert!(
                seen.insert(name.clone()),
                "duplicate physical column name generated: {name}"
            );
        }
    }
}
