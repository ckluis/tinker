//! M4: per-organization schema evolution with immutable versions.
//!
//! A company evolves its schema (add field / add relation) as a new
//! immutable version: `draft -> preview -> canary -> active`. Promotion and
//! rollback flip the single active pointer in one transaction. Versions are
//! per (organization, object): one company's canary never touches a sibling.
//!
//! Physical storage: evolved fields become real typed columns on the org's
//! extension table `data.ext_<org12>_<obj12>` — never on the shared base
//! table. A sibling org's schema, queries, and tables are untouched by
//! construction: the extension table is RLS-isolated and only the evolving
//! org's version specs reference it. Rollback is a pointer flip, not DDL.
//!
//! Versions are append-only. Once a version leaves `draft`, its spec cannot
//! change: `add_field`/`add_relation` refuse non-draft versions.

use serde::{Deserialize, Serialize};
use sqlx::Row;
use tinker_core::{OrganizationId, Result, TenantContext, TinkerError};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::{ExtField, FieldDef, FieldType, Ontology};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which version a query resolves fields against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSel {
    /// The promoted production schema (default).
    Active,
    /// The version under explicit preview (builder only via cohort).
    Preview,
    /// The canary version (cohort-gated).
    Canary,
}

impl VersionSel {
    pub fn status_name(self) -> &'static str {
        match self {
            VersionSel::Active => "active",
            VersionSel::Preview => "preview",
            VersionSel::Canary => "canary",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SchemaVersion {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub object_id: Uuid,
    pub version_number: i32,
    pub parent_version_id: Option<Uuid>,
    pub status: String,
    pub canary_cohort: Option<Vec<Uuid>>,
    pub created_by: Option<Uuid>,
}

/// A resolved schema: the version pointer (None = pack base schema, no
/// evolution) plus the effective evolved fields for it.
#[derive(Debug, Clone)]
pub struct ResolvedVersion {
    pub version_id: Option<Uuid>,
    pub ext_fields: Vec<ExtField>,
}

/// One field recorded in a version spec (immutable once the version leaves
/// draft).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecField {
    pub api_name: String,
    pub label: String,
    pub field_type: String,
    pub physical_column: String,
    pub relation_target_id: Option<Uuid>,
    pub options: serde_json::Value,
    /// Item 37 (C3): validation rules carried through M4 evolution.
    /// `#[serde(default)]` keeps pre-item-37 version specs loadable.
    #[serde(default)]
    pub validation: tinker_ontology::ValidationRules,
    /// Item 37 (C3): write preset carried through M4 evolution.
    #[serde(default)]
    pub preset: Option<tinker_ontology::WritePreset>,
    /// Item 37 (C3): required flag carried through M4 evolution.
    #[serde(default)]
    pub required: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SchemaDiff {
    /// api_names present in `to` but not `from`.
    pub added: Vec<String>,
    /// api_names present in `from` but not `to`.
    pub removed: Vec<String>,
    /// api_names whose field type changed: (api_name, from_type, to_type).
    pub changed: Vec<(String, String, String)>,
}

/// Reference for diff endpoints: the pack base or a concrete version.
#[derive(Debug, Clone, Copy)]
pub enum VersionRef {
    Base,
    Version(Uuid),
}

// ---------------------------------------------------------------------------
// Evolver
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SchemaEvolver {
    core: CoreDb,
    owner: OwnerDb,
    ontology: Ontology,
}

impl SchemaEvolver {
    pub fn new(core: CoreDb, owner: OwnerDb, ontology: Ontology) -> Self {
        Self {
            core,
            owner,
            ontology,
        }
    }

    // -- version lifecycle -------------------------------------------------

    /// Fork a draft from the current active version (or the pack base when
    /// the org has never evolved this object).
    pub async fn create_draft(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
    ) -> Result<SchemaVersion> {
        // The object must be visible to this tenant: platform or own-org.
        // describe_object fails closed (NotFound) for siblings' objects.
        self.ontology.describe_object(ctx, object_id).await?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Serialize draft creation per org/object: without this, two
        // concurrent creators both compute MAX(version_number)+1 and one
        // dies on the unique index. The xact-scoped advisory lock makes the
        // second waiter recompute after the first commits.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1 || $2))")
            .bind(ctx.organization_id.0.to_string())
            .bind(object_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        let parent: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM schema_versions \
             WHERE organization_id=$1 AND object_id=$2 AND status='active'",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let next: (i32,) = sqlx::query_as(
            "SELECT COALESCE(MAX(version_number), 0) + 1 FROM schema_versions \
             WHERE organization_id=$1 AND object_id=$2",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO schema_versions \
             (id, organization_id, object_id, version_number, parent_version_id, \
              status, spec, created_by) \
             VALUES ($1,$2,$3,$4,$5,'draft','{\"fields\": []}',$6)",
        )
        .bind(id)
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .bind(next.0)
        .bind(parent.map(|(p,)| p))
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        self.get_version(ctx, id).await
    }

    pub async fn get_version(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
    ) -> Result<SchemaVersion> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row = sqlx::query(
            "SELECT id, organization_id, object_id, version_number, \
                    parent_version_id, status, canary_cohort, created_by \
             FROM schema_versions WHERE id=$1 AND organization_id=$2",
        )
        .bind(version_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound(format!("schema version {version_id}")))?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Self::version_from_row(row)
    }

    /// The evolved fields declared by one version's spec (not ancestors).
    /// Used by the schema builder to render a version's own additions.
    pub async fn spec_fields(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
    ) -> Result<Vec<SpecField>> {
        // get_version enforces the org predicate (NotFound for siblings).
        let v = self.get_version(ctx, version_id).await?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let row = sqlx::query("SELECT spec FROM schema_versions WHERE id=$1")
            .bind(v.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        let spec_json: serde_json::Value = row.try_get("spec").map_err(TinkerError::Db)?;
        Ok(parse_spec(&spec_json)?.fields)
    }

    pub async fn list_versions(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
    ) -> Result<Vec<SchemaVersion>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows = sqlx::query(
            "SELECT id, organization_id, object_id, version_number, \
                    parent_version_id, status, canary_cohort, created_by \
             FROM schema_versions \
             WHERE organization_id=$1 AND object_id=$2 \
             ORDER BY version_number",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        rows.into_iter().map(Self::version_from_row).collect()
    }

    fn version_from_row(row: sqlx::postgres::PgRow) -> Result<SchemaVersion> {
        let cohort_json: Option<serde_json::Value> =
            row.try_get("canary_cohort").map_err(TinkerError::Db)?;
        let canary_cohort = match cohort_json {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(
                serde_json::from_value::<Vec<Uuid>>(v)
                    .map_err(|e| TinkerError::Validation(format!("bad canary cohort: {e}")))?,
            ),
        };
        Ok(SchemaVersion {
            id: row.try_get("id").map_err(TinkerError::Db)?,
            organization_id: row.try_get("organization_id").map_err(TinkerError::Db)?,
            object_id: row.try_get("object_id").map_err(TinkerError::Db)?,
            version_number: row.try_get("version_number").map_err(TinkerError::Db)?,
            parent_version_id: row.try_get("parent_version_id").map_err(TinkerError::Db)?,
            status: row.try_get("status").map_err(TinkerError::Db)?,
            canary_cohort,
            created_by: row.try_get("created_by").map_err(TinkerError::Db)?,
        })
    }

    // -- evolution ---------------------------------------------------------

    /// Add a field to a DRAFT version. Materializes a real typed column on
    /// the org's extension table immediately, so preview/canary queries run
    /// against real storage. Non-draft versions are immutable: refused.
    pub async fn add_field(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
        def: &FieldDef,
    ) -> Result<SpecField> {
        self.add_field_inner(ctx, version_id, def, false).await
    }

    /// Add a relation to a DRAFT version: a UUID column plus a composite
    /// tenant FK to the target's table, exactly like base relations.
    pub async fn add_relation(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
        def: &FieldDef,
    ) -> Result<SpecField> {
        if !matches!(def.field_type, FieldType::Relation { .. }) {
            return Err(TinkerError::Validation(
                "add_relation requires a Relation field type".into(),
            ));
        }
        self.add_field_inner(ctx, version_id, def, true).await
    }

    async fn add_field_inner(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
        def: &FieldDef,
        _is_relation: bool,
    ) -> Result<SpecField> {
        validate_evo_field_def(def)?;
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query("SET LOCAL lock_timeout = '10s'")
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;

        // Lock the version; only drafts are mutable. RLS plus the explicit
        // organization predicate keep this strictly per-org.
        let vrow = sqlx::query(
            "SELECT id, organization_id, object_id, status, spec \
             FROM schema_versions WHERE id=$1 AND organization_id=$2 FOR UPDATE",
        )
        .bind(version_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound(format!("schema version {version_id}")))?;
        let status: String = vrow.try_get("status").map_err(TinkerError::Db)?;
        if status != "draft" {
            return Err(TinkerError::Validation(format!(
                "schema version {version_id} is {status}: versions are immutable once they leave draft"
            )));
        }
        let object_id: Uuid = vrow.try_get("object_id").map_err(TinkerError::Db)?;
        let spec_json: serde_json::Value = vrow.try_get("spec").map_err(TinkerError::Db)?;
        drop(vrow);

        // Additive only: the api_name must not exist on the base object or
        // in any ancestor version's spec.
        let base = self.ontology.describe_object(ctx, object_id).await?;
        if base.fields.iter().any(|f| f.api_name == def.api_name) {
            return Err(TinkerError::Validation(format!(
                "field '{}' already exists on the base object",
                def.api_name
            )));
        }
        let mut spec = parse_spec(&spec_json)?;
        // Walk ancestors for inherited fields.
        let inherited = self
            .ancestor_spec_fields_tx(&mut tx, ctx.organization_id, version_id)
            .await?;
        if spec.fields.iter().any(|f| f.api_name == def.api_name)
            || inherited.iter().any(|f| f.api_name == def.api_name)
        {
            return Err(TinkerError::Validation(format!(
                "field '{}' already added in this version chain",
                def.api_name
            )));
        }

        // Relation targets must be visible to this tenant (platform or
        // own-org objects); a cross-tenant FK would bridge two tenants.
        let mut fk_sql = String::new();
        let mut relation_target_id: Option<Uuid> = None;
        if let FieldType::Relation { target_object_id } = &def.field_type {
            // describe_object fails closed for invisible targets, so the
            // target is platform or owned by this org: a cross-tenant FK
            // cannot be built here.
            let target = self
                .ontology
                .describe_object(ctx, *target_object_id)
                .await?;
            relation_target_id = Some(*target_object_id);
            fk_sql = format!(
                ", ADD CONSTRAINT \"{physical}_fk\" FOREIGN KEY (organization_id, \"{physical}\") \
                 REFERENCES data.{target_slug}(organization_id, id)",
                physical = "PHYSICAL_PLACEHOLDER",
                target_slug = target.api_slug,
            );
        }

        let physical = tinker_ontology::new_physical_column();
        let ext_table = ext_table_name(ctx.organization_id.0, object_id);

        // Select options become a real CHECK constraint: Postgres owns it.
        let mut check_sql = String::new();
        if let FieldType::Select = def.field_type {
            let opts: Vec<String> = def.options["options"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .map(|v| v.as_str().unwrap_or("").replace('\'', "''"))
                        .collect()
                })
                .unwrap_or_default();
            let list = opts
                .iter()
                .map(|o| format!("'{o}'"))
                .collect::<Vec<_>>()
                .join(", ");
            check_sql = format!(
                ", ADD CONSTRAINT \"{physical}_options\" CHECK (\"{physical}\" IS NULL OR \"{physical}\" IN ({list}))"
            );
        }
        let fk_sql = fk_sql.replace("PHYSICAL_PLACEHOLDER", &physical);

        // Privileged DDL through the OWNER pool. The app role has DML on
        // future tables (ALTER DEFAULT PRIVILEGES) but never DDL — same as
        // every other platform DDL path. The owner role bypasses RLS, so the
        // tenant context is set explicitly and every table created here is
        // org-scoped by construction. This runs while the tenant tx above
        // still holds the FOR UPDATE lock on the draft version, so
        // concurrent edits to the same draft serialize.
        let mut otx = self.owner.0.begin().await.map_err(TinkerError::Db)?;
        // SET LOCAL takes a literal, not a bind param; the value is a UUID
        // we generated, so interpolation is safe.
        sqlx::query(&format!(
            "SET LOCAL app.organization_id = '{}'",
            ctx.organization_id.0
        ))
        .execute(&mut *otx)
        .await
        .map_err(TinkerError::Db)?;
        self.ensure_ext_table_tx(&mut otx, &ext_table, &base.api_slug)
            .await?;
        let alter = format!(
            "ALTER TABLE {ext_table} ADD COLUMN \"{physical}\" {}{check_sql}{fk_sql}",
            def.field_type.pg_type(),
        );
        sqlx::query(&alter)
            .execute(&mut *otx)
            .await
            .map_err(TinkerError::Db)?;
        if matches!(def.field_type, FieldType::Relation { .. }) {
            sqlx::query(&format!(
                "CREATE INDEX \"{physical}_idx\" ON {ext_table} (organization_id, \"{physical}\")"
            ))
            .execute(&mut *otx)
            .await
            .map_err(TinkerError::Db)?;
        }
        otx.commit().await.map_err(TinkerError::Db)?;

        let spec_field = SpecField {
            api_name: def.api_name.clone(),
            label: def.label.clone(),
            field_type: def.field_type.kind_name().to_string(),
            physical_column: physical.clone(),
            relation_target_id,
            options: def.options.clone(),
            // Item 37 (C3): governance travels with the version spec.
            validation: def.validation.clone(),
            preset: def.preset.clone(),
            required: def.required,
        };
        spec.fields.push(spec_field.clone());
        let spec_value = serde_json::to_value(&spec)
            .map_err(|e| TinkerError::Validation(format!("cannot serialize version spec: {e}")))?;
        sqlx::query("UPDATE schema_versions SET spec=$1 WHERE id=$2")
            .bind(&spec_value)
            .bind(version_id)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;

        sqlx::query(
            "INSERT INTO ontology_changes \
             (organization_id, object_id, change_kind, detail, ddl_statements, applied_by) \
             VALUES ($1,$2,'schema.evolution.field_added',$3,$4,$5)",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .bind(serde_json::json!({"api_name": def.api_name, "version_id": version_id}))
        .bind(vec![alter])
        .bind(ctx.actor_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;

        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(spec_field)
    }

    /// Create the org's extension table for an object if absent. Deterministic
    /// name, so concurrent creators converge instead of forking tables.
    async fn ensure_ext_table_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        ext_table: &str,
        base_slug: &str,
    ) -> Result<()> {
        let base_table = format!("data.{base_slug}");
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {ext_table} ( \
                organization_id uuid NOT NULL, \
                record_id uuid NOT NULL, \
                PRIMARY KEY (organization_id, record_id), \
                FOREIGN KEY (organization_id, record_id) \
                    REFERENCES {base_table}(organization_id, id) ON DELETE CASCADE \
             )"
        ))
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        // Idempotent: enabling twice is a no-op; the policy is dropped and
        // recreated so a half-applied earlier attempt cannot linger wrong.
        sqlx::query(&format!(
            "ALTER TABLE {ext_table} ENABLE ROW LEVEL SECURITY"
        ))
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        let policy = format!(
            "ext_org_isolation_{}",
            ext_table["data.ext_".len()..].replace('_', "")
        );
        sqlx::query(&format!(
            "DROP POLICY IF EXISTS \"{policy}\" ON {ext_table}"
        ))
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        sqlx::query(&format!(
            "CREATE POLICY \"{policy}\" ON {ext_table} \
             USING (organization_id = current_setting('app.organization_id', true)::uuid)"
        ))
        .execute(&mut **tx)
        .await
        .map_err(TinkerError::Db)?;
        Ok(())
    }

    // -- status transitions ------------------------------------------------

    /// draft -> preview: the version is queryable by explicit opt-in.
    pub async fn mark_preview(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
    ) -> Result<SchemaVersion> {
        self.transition(ctx, version_id, "draft", "preview", None)
            .await
    }

    /// draft|preview -> canary: the version serves the canary cohort.
    /// `cohort = None` means every org member may resolve the canary;
    /// otherwise only the listed actors.
    ///
    /// Every listed actor must belong to the caller's organization: a
    /// typo'd, deleted, or foreign-org UUID would otherwise make the
    /// canary silently invisible to the intended members. The roster read
    /// runs in the caller's tenant transaction, so the actors RLS policy
    /// restricts it to exactly this org's roster.
    pub async fn mark_canary(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
        cohort: Option<Vec<Uuid>>,
    ) -> Result<SchemaVersion> {
        let v = self.get_version(ctx, version_id).await?;
        if v.status != "draft" && v.status != "preview" {
            return Err(TinkerError::Validation(format!(
                "only draft/preview versions can become canary (is {})",
                v.status
            )));
        }
        let cohort_value: serde_json::Value = match cohort {
            None => serde_json::Value::Null,
            Some(ids) => {
                if ids.is_empty() {
                    return Err(TinkerError::Validation(
                        "canary cohort must not be empty; pass None for an all-members canary"
                            .into(),
                    ));
                }
                let mut unique = ids;
                unique.sort();
                unique.dedup();
                let mut tx = self.core.tenant_tx(ctx).await?;
                let (n,): (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM actors WHERE organization_id=$1 AND id = ANY($2)",
                )
                .bind(ctx.organization_id.0)
                .bind(&unique)
                .fetch_one(&mut *tx)
                .await
                .map_err(TinkerError::Db)?;
                tx.commit().await.map_err(TinkerError::Db)?;
                if n as usize != unique.len() {
                    return Err(TinkerError::Validation(format!(
                        "canary cohort contains {} unknown actor(s): every cohort member must belong to this organization",
                        unique.len() - n as usize
                    )));
                }
                serde_json::to_value(&unique)
                    .map_err(|e| TinkerError::Validation(format!("bad cohort: {e}")))?
            }
        };
        self.transition(ctx, version_id, &v.status, "canary", Some(cohort_value))
            .await
    }

    async fn transition(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
        from: &str,
        to: &str,
        cohort: Option<serde_json::Value>,
    ) -> Result<SchemaVersion> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let n = sqlx::query(
            "UPDATE schema_versions SET status=$1, canary_cohort=COALESCE($2, canary_cohort) \
             WHERE id=$3 AND organization_id=$4 AND status=$5",
        )
        .bind(to)
        .bind(cohort)
        .bind(version_id)
        .bind(ctx.organization_id.0)
        .bind(from)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .rows_affected();
        if n != 1 {
            return Err(TinkerError::Validation(format!(
                "cannot move version {version_id} from {from} to {to}"
            )));
        }
        tx.commit().await.map_err(TinkerError::Db)?;
        self.get_version(ctx, version_id).await
    }

    /// Atomically promote a preview/canary version to active. The previous
    /// active version (if any) becomes `superseded` in the same transaction:
    /// readers never see zero or two active versions.
    pub async fn promote(&self, ctx: &TenantContext, version_id: Uuid) -> Result<SchemaVersion> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let vrow = sqlx::query(
            "SELECT organization_id, object_id, status FROM schema_versions \
             WHERE id=$1 AND organization_id=$2 FOR UPDATE",
        )
        .bind(version_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound(format!("schema version {version_id}")))?;
        let status: String = vrow.try_get("status").map_err(TinkerError::Db)?;
        if status != "preview" && status != "canary" {
            return Err(TinkerError::Validation(format!(
                "only preview/canary versions can be promoted (is {status})"
            )));
        }
        let object_id: Uuid = vrow.try_get("object_id").map_err(TinkerError::Db)?;
        drop(vrow);
        sqlx::query(
            "UPDATE schema_versions SET status='superseded' \
             WHERE organization_id=$1 AND object_id=$2 AND status='active'",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        sqlx::query("UPDATE schema_versions SET status='active', canary_cohort=NULL WHERE id=$1")
            .bind(version_id)
            .execute(&mut *tx)
            .await
            .map_err(|e: sqlx::Error| {
                // Lost the race: another version became active concurrently.
                // The partial unique index makes double-active impossible;
                // surface it as a clean validation error, not a raw 500.
                if let sqlx::Error::Database(db) = &e {
                    if db.code().as_deref() == Some("23505") {
                        return TinkerError::Validation(
                            "another version became active concurrently; retry".into(),
                        );
                    }
                }
                TinkerError::Db(e)
            })?;
        tx.commit().await.map_err(TinkerError::Db)?;
        self.get_version(ctx, version_id).await
    }

    /// Roll back the ACTIVE (or canary) version: it becomes `rolled_back`
    /// and its parent is re-activated in the same transaction. A version
    /// forked from the pack base (no parent) rolls back to the base schema:
    /// no active row remains.
    pub async fn rollback(
        &self,
        ctx: &TenantContext,
        version_id: Uuid,
    ) -> Result<Option<SchemaVersion>> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let vrow = sqlx::query(
            "SELECT organization_id, object_id, status, parent_version_id \
             FROM schema_versions WHERE id=$1 AND organization_id=$2 FOR UPDATE",
        )
        .bind(version_id)
        .bind(ctx.organization_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?
        .ok_or_else(|| TinkerError::NotFound(format!("schema version {version_id}")))?;
        let status: String = vrow.try_get("status").map_err(TinkerError::Db)?;
        if status != "active" && status != "canary" {
            return Err(TinkerError::Validation(format!(
                "only the active or canary version can roll back (is {status})"
            )));
        }
        let parent: Option<Uuid> = vrow.try_get("parent_version_id").map_err(TinkerError::Db)?;
        drop(vrow);
        sqlx::query("UPDATE schema_versions SET status='rolled_back' WHERE id=$1")
            .bind(version_id)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        let restored = if let Some(parent_id) = parent {
            // The parent must belong to this org (it was captured from this
            // org's active chain at draft time); re-check the org predicate.
            let prow: Option<(String,)> = sqlx::query_as(
                "SELECT status FROM schema_versions WHERE id=$1 AND organization_id=$2",
            )
            .bind(parent_id)
            .bind(ctx.organization_id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
            let pstatus = prow
                .map(|(s,)| s)
                .ok_or_else(|| TinkerError::NotFound(format!("parent version {parent_id}")))?;
            match pstatus.as_str() {
                // Rolling back a canary while its parent is still active:
                // discard the canary, the parent stays active.
                "active" => Some(parent_id),
                "superseded" => {
                    sqlx::query(
                        "UPDATE schema_versions SET status='active' \
                         WHERE id=$1 AND organization_id=$2",
                    )
                    .bind(parent_id)
                    .bind(ctx.organization_id.0)
                    .execute(&mut *tx)
                    .await
                    .map_err(TinkerError::Db)?;
                    Some(parent_id)
                }
                other => {
                    return Err(TinkerError::Validation(format!(
                        "parent version is {other}; cannot roll back to it"
                    )))
                }
            }
        } else {
            None
        };
        tx.commit().await.map_err(TinkerError::Db)?;
        match restored {
            Some(pid) => Ok(Some(self.get_version(ctx, pid).await?)),
            None => Ok(None),
        }
    }

    // -- resolution (for the query compiler) --------------------------------

    /// Resolve which version's fields a query sees. Cohort-gated versions
    /// fail closed for actors outside the cohort.
    pub async fn resolve(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        sel: VersionSel,
    ) -> Result<ResolvedVersion> {
        let mut tx = self.core.tenant_tx(ctx).await?;
        let vrow = sqlx::query(
            "SELECT id, status, canary_cohort FROM schema_versions \
             WHERE organization_id=$1 AND object_id=$2 AND status=$3",
        )
        .bind(ctx.organization_id.0)
        .bind(object_id)
        .bind(sel.status_name())
        .fetch_optional(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        let Some(vrow) = vrow else {
            tx.commit().await.map_err(TinkerError::Db)?;
            if sel == VersionSel::Active {
                // No evolution yet: the pack base schema.
                return Ok(ResolvedVersion {
                    version_id: None,
                    ext_fields: vec![],
                });
            }
            return Err(TinkerError::Validation(format!(
                "no {} schema version for this object",
                sel.status_name()
            )));
        };
        let version_id: Uuid = vrow.try_get("id").map_err(TinkerError::Db)?;
        let cohort_json: Option<serde_json::Value> =
            vrow.try_get("canary_cohort").map_err(TinkerError::Db)?;
        drop(vrow);

        // Cohort gate: a canary/preview with an explicit cohort is invisible
        // to everyone else — fail closed, never fall back silently.
        if matches!(sel, VersionSel::Canary | VersionSel::Preview) {
            if let Some(cj) = cohort_json {
                if !cj.is_null() {
                    let cohort: Vec<Uuid> = serde_json::from_value(cj)
                        .map_err(|e| TinkerError::Validation(format!("bad canary cohort: {e}")))?;
                    if !cohort.contains(&ctx.actor_id) {
                        return Err(TinkerError::Forbidden(format!(
                            "actor is not in the {} cohort",
                            sel.status_name()
                        )));
                    }
                }
            }
        }

        let ext_fields = self
            .effective_ext_fields_tx(&mut tx, ctx.organization_id, object_id, version_id)
            .await?;
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(ResolvedVersion {
            version_id: Some(version_id),
            ext_fields,
        })
    }

    /// Effective evolved fields for a version: its own spec plus every
    /// ancestor's, child-first so a child's definition wins on collision.
    async fn effective_ext_fields_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        org: OrganizationId,
        object_id: Uuid,
        version_id: Uuid,
    ) -> Result<Vec<ExtField>> {
        let ext_table = ext_table_name(org.0, object_id);
        let chain = self.spec_chain_tx(tx, org, version_id).await?;
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for spec_field in chain.into_iter().flat_map(|s| s.fields) {
            if seen.insert(spec_field.api_name.clone()) {
                out.push(ExtField {
                    api_name: spec_field.api_name,
                    label: spec_field.label,
                    field_type: spec_field.field_type,
                    physical_column: spec_field.physical_column,
                    extension_table: ext_table.clone(),
                    relation_target_id: spec_field.relation_target_id,
                    options: spec_field.options,
                    // Item 37 (C3): governance rides into the description.
                    validation: spec_field.validation,
                    preset: spec_field.preset,
                    required: spec_field.required,
                });
            }
        }
        Ok(out)
    }

    /// Specs from the version up through its ancestors (child first).
    async fn spec_chain_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        org: OrganizationId,
        mut version_id: Uuid,
    ) -> Result<Vec<VersionSpec>> {
        let mut chain = Vec::new();
        loop {
            let row: Option<(serde_json::Value, Option<Uuid>)> = sqlx::query_as(
                "SELECT spec, parent_version_id FROM schema_versions \
                 WHERE id=$1 AND organization_id=$2",
            )
            .bind(version_id)
            .bind(org.0)
            .fetch_optional(&mut **tx)
            .await
            .map_err(TinkerError::Db)?;
            let Some((spec_json, parent)) = row else {
                break;
            };
            chain.push(parse_spec(&spec_json)?);
            match parent {
                Some(p) => version_id = p,
                None => break,
            }
        }
        Ok(chain)
    }

    async fn ancestor_spec_fields_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        org: OrganizationId,
        version_id: Uuid,
    ) -> Result<Vec<SpecField>> {
        let mut chain = self.spec_chain_tx(tx, org, version_id).await?;
        // Skip the version's own spec (index 0); ancestors only.
        chain.remove(0);
        Ok(chain.into_iter().flat_map(|s| s.fields).collect())
    }

    // -- diff ----------------------------------------------------------------

    /// Pack diff between two schema refs: what fields a version adds,
    /// removes, or changes relative to another ref.
    pub async fn diff(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        from: VersionRef,
        to: VersionRef,
    ) -> Result<SchemaDiff> {
        let from_fields = self.fields_for_ref(ctx, object_id, from).await?;
        let to_fields = self.fields_for_ref(ctx, object_id, to).await?;
        let from_map: std::collections::HashMap<&str, &ExtField> = from_fields
            .iter()
            .map(|f| (f.api_name.as_str(), f))
            .collect();
        let to_map: std::collections::HashMap<&str, &ExtField> =
            to_fields.iter().map(|f| (f.api_name.as_str(), f)).collect();
        let mut diff = SchemaDiff::default();
        for (name, to_f) in &to_map {
            match from_map.get(name) {
                None => diff.added.push((*name).to_string()),
                Some(from_f) if from_f.field_type != to_f.field_type => diff.changed.push((
                    (*name).to_string(),
                    from_f.field_type.clone(),
                    to_f.field_type.clone(),
                )),
                _ => {}
            }
        }
        for name in from_map.keys() {
            if !to_map.contains_key(name) {
                diff.removed.push((*name).to_string());
            }
        }
        diff.added.sort();
        diff.removed.sort();
        diff.changed.sort();
        Ok(diff)
    }

    async fn fields_for_ref(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        r: VersionRef,
    ) -> Result<Vec<ExtField>> {
        match r {
            VersionRef::Base => Ok(vec![]),
            VersionRef::Version(vid) => {
                // The version must belong to this org (RLS + explicit).
                let v = self.get_version(ctx, vid).await?;
                if v.object_id != object_id {
                    return Err(TinkerError::Validation(
                        "version does not belong to this object".into(),
                    ));
                }
                let mut tx = self.core.tenant_tx(ctx).await?;
                let fields = self
                    .effective_ext_fields_tx(&mut tx, ctx.organization_id, object_id, vid)
                    .await?;
                tx.commit().await.map_err(TinkerError::Db)?;
                Ok(fields)
            }
        }
    }

    /// Owner handle for the binary/CLI. Unused by tenant paths today; kept
    /// so platform tooling can evolve pack base schemas later.
    #[allow(dead_code)]
    fn _owner(&self) -> &OwnerDb {
        &self.owner
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic extension-table name: `data.ext_<h16>_<h16>`, where the
/// halves are SHA-256(org_id || object_id) split in two (16 hex chars each).
/// Deterministic so concurrent creators converge on one table; 128 bits of
/// hash make cross-org/cross-object collisions computationally infeasible,
/// unlike naive UUID-prefix truncation.
pub fn ext_table_name(org_id: Uuid, object_id: Uuid) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(org_id.as_bytes());
    h.update(object_id.as_bytes());
    let hex = format!("{:x}", h.finalize());
    format!("data.ext_{}_{}", &hex[..16], &hex[16..32])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VersionSpec {
    #[serde(default)]
    fields: Vec<SpecField>,
}

fn parse_spec(v: &serde_json::Value) -> Result<VersionSpec> {
    serde_json::from_value(v.clone())
        .map_err(|e| TinkerError::Validation(format!("corrupt version spec: {e}")))
}

fn valid_evo_slug(s: &str) -> bool {
    if s.len() < 2 || s.len() > 63 {
        return false;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => (),
        _ => return false,
    }
    s.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn validate_evo_field_def(def: &FieldDef) -> Result<()> {
    if !valid_evo_slug(&def.api_name) {
        return Err(TinkerError::Validation(format!(
            "invalid api_name: {}",
            def.api_name
        )));
    }
    if def.label.trim().is_empty() {
        return Err(TinkerError::Validation("field label is required".into()));
    }
    // Evolved fields live in ext tables the vault path does not cover
    // (docs/pii-sensitive-fields.md, "Not in v1"): refuse, never store a
    // "sensitive" value in plaintext.
    if def.sensitive {
        return Err(TinkerError::Validation(format!(
            "field '{}': sensitive fields must be defined on the base object, not evolved",
            def.api_name
        )));
    }
    if let FieldType::Select = def.field_type {
        let ok = def
            .options
            .get("options")
            .and_then(|v| v.as_array())
            .filter(|a| !a.is_empty() && a.iter().all(|v| v.as_str().is_some()))
            .is_some();
        if !ok {
            return Err(TinkerError::Validation(
                "select fields need options.options as a non-empty string array".into(),
            ));
        }
    }
    // Item 37 (C3): evolved fields carry the same governance metadata as
    // base fields, so they get the same definition-time checks.
    tinker_ontology::validate_field_def(def)?;
    Ok(())
}
