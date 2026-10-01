//! Typed query compiler skeleton (PRD §39).
//!
//! The builder, MCP, CLI, virtual files, search, and agents all produce the
//! same typed [`QueryIntent`]. Only this compiler turns it into SQL.
//!
//! Rules enforced here:
//! - Every plan carries an explicit `organization_id = $1` predicate.
//! - Identifiers come from the metadata registry only, never from input.
//! - Joins follow declared relation fields, one level.
//! - Operators are allowlisted per field kind; values become typed binds.
//! - Unknown fields fail loudly at compile time.
//! - Authorized projections (M3): a [`FieldProjection`] restricts which
//!   fields a role may see. Selected hidden fields are dropped from the
//!   output; filters/sorts on hidden fields are rejected outright (a
//!   boolean oracle would leak the hidden value). The SQL never selects
//!   a hidden column.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use tinker_core::blind_index::BlindIndexKey;
use tinker_core::{Param, Result, TenantContext, TinkerError};
use tinker_evolve::{ResolvedVersion, SchemaEvolver, VersionSel};
use tinker_ontology::sensitive::MASK;
use tinker_ontology::{FieldDescription, ObjectDescription, Ontology};
use uuid::Uuid;

mod row_policy;
pub use row_policy::{
    append_default_published_predicate, RowFilter, RowFilterDef, RowFilterOp, RowFilterValue,
    RowFilters, RowPolicy,
};
pub use tinker_core::CompiledRowPolicy;

pub mod dashboard;
pub use dashboard::{
    Dashboard, DashboardInput, DashboardService, DashboardSummary, PanelDef, PanelOutcome,
    RenderedDashboard, RenderedPanel, VisualizationKind, GRID_COLUMNS, MAX_PANELS,
};

pub mod snapshot;
pub use snapshot::{
    canonical_bytes, diff_snapshots, payload_digest_hex, sign_snapshot, signing_key_from_env,
    verify_snapshot, verifying_key_from_hex, ApplyOp, ApplyPlan, ApplyReport, FieldChangeDetail,
    FieldSnapshot, FilterSnapshot, ObjectDiff, ObjectSnapshot, RolePolicySnapshot, SignedSnapshot,
    SnapshotDiff, SnapshotDoc, SnapshotService, SIGNING_KEY_ENV, SNAPSHOT_FORMAT,
    SNAPSHOT_FORMAT_VERSION,
};

pub const DEFAULT_LIMIT: u32 = 250;
pub const MAX_LIMIT: u32 = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryIntent {
    pub from: Uuid,
    /// api_names; `"company.name"` traverses one declared relation.
    pub select: Vec<String>,
    pub filters: Vec<Filter>,
    pub order: Vec<Order>,
    pub limit: Option<u32>,
    /// M4: which schema version to resolve fields against: "active"
    /// (default), "canary", or "preview". Canary/preview are cohort-gated
    /// by the schema evolver and fail closed for outsiders.
    #[serde(default)]
    pub schema_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub field: String,
    pub op: FilterOp,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    Ne,
    Lt,
    Lte,
    Gt,
    Gte,
    In,
    Contains,
    StartsWith,
    IsNull,
    IsNotNull,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub field: String,
    pub descending: bool,
}

#[derive(Debug, Clone)]
pub struct CompiledPlan {
    pub sql: String,
    pub params: Vec<Param>,
    /// api_name per selected column, in order.
    pub output_fields: Vec<String>,
    pub object_id: Uuid,
}

/// An authorized field projection for one query: which api_names the
/// caller's role may see, per object. Built from `field_grants` rows.
///
/// Semantics: an object with NO entry is unrestricted (default-open, so
/// roles without explicit projections keep working). An object WITH an
/// entry sees only the listed fields. `__id` (record identity) is always
/// visible — invalidation and refetch depend on it.
#[derive(Debug, Clone, Default)]
pub struct FieldProjection {
    inner: HashMap<Uuid, HashSet<String>>,
}

impl FieldProjection {
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// `grants`: (object_id, allowed api_names). Objects absent from the
    /// map are unrestricted.
    pub fn allowlist(grants: HashMap<Uuid, HashSet<String>>) -> Self {
        Self { inner: grants }
    }

    pub fn allows(&self, object_id: Uuid, api_name: &str) -> bool {
        if api_name == "__id" {
            return true;
        }
        match self.inner.get(&object_id) {
            None => true,
            Some(set) => set.contains(api_name),
        }
    }
}

pub struct QueryCompiler {
    ontology: Ontology,
    evolver: Option<SchemaEvolver>,
    /// Keyed blind index for exact-match lookups on sensitive fields.
    /// Absent: such lookups fail closed (docs/pii-sensitive-fields.md).
    blind_index: Option<std::sync::Arc<BlindIndexKey>>,
}

impl QueryCompiler {
    pub fn new(ontology: Ontology) -> Self {
        Self {
            ontology,
            evolver: None,
            blind_index: None,
        }
    }

    /// Attach the blind-index key so `eq` / `ne` / `in` filters on
    /// sensitive fields compile against their digest column.
    pub fn with_blind_index(mut self, key: BlindIndexKey) -> Self {
        self.blind_index = Some(std::sync::Arc::new(key));
        self
    }

    /// Attach the M4 schema evolver. Without one, versioned queries fail
    /// closed: requesting canary/preview without an evolver is an error,
    /// never a silent fall back to the base schema.
    pub fn with_evolver(mut self, evolver: SchemaEvolver) -> Self {
        self.evolver = Some(evolver);
        self
    }

    pub async fn compile(&self, ctx: &TenantContext, intent: &QueryIntent) -> Result<CompiledPlan> {
        self.compile_with_projection(ctx, intent, &FieldProjection::unrestricted())
            .await
    }

    /// Compile with an authorized field projection (M3). Selected hidden
    /// fields are dropped from the output; filters and sorts on hidden
    /// fields are rejected — a boolean oracle on a hidden column would
    /// leak its value row by row.
    ///
    /// M4: `intent.schema_version` selects which schema version the query
    /// resolves against (`active` default, `canary`, `preview`). Evolved
    /// fields live on the org's extension tables and are pulled in via
    /// LEFT JOINs; the shared base table is never altered by evolution.
    pub async fn compile_with_projection(
        &self,
        ctx: &TenantContext,
        intent: &QueryIntent,
        projection: &FieldProjection,
    ) -> Result<CompiledPlan> {
        self.compile_with_policy(ctx, intent, projection, &RowPolicy::open(intent.from))
            .await
    }

    /// Compile with an authorized field projection (M3) AND a row-level
    /// permission policy (C2, item 38). The row policy is ANDed with the
    /// tenant predicate at SQL build time — it is part of the same WHERE
    /// clause, before any ORDER BY, so unauthorized rows can never
    /// influence ranking, and the compiler (not the caller) owns the
    /// predicate text.
    pub async fn compile_with_policy(
        &self,
        ctx: &TenantContext,
        intent: &QueryIntent,
        projection: &FieldProjection,
        policy: &RowPolicy,
    ) -> Result<CompiledPlan> {
        if intent.select.is_empty() {
            return Err(TinkerError::Validation("select is empty".into()));
        }
        let version_sel = match intent.schema_version.as_deref() {
            None | Some("active") => VersionSel::Active,
            Some("canary") => VersionSel::Canary,
            Some("preview") => VersionSel::Preview,
            Some(other) => {
                return Err(TinkerError::Validation(format!(
                    "unknown schema_version: {other}"
                )))
            }
        };
        // Resolve the schema version BEFORE describing the object, so the
        // field list already includes this org's evolved fields. Cohort
        // checks happen inside resolve: outsiders fail closed here.
        let resolved = match &self.evolver {
            Some(evolver) => evolver.resolve(ctx, intent.from, version_sel).await?,
            None => {
                if version_sel != VersionSel::Active {
                    return Err(TinkerError::Validation(
                        "versioned queries need a schema evolver".into(),
                    ));
                }
                ResolvedVersion {
                    version_id: None,
                    ext_fields: vec![],
                }
            }
        };
        let base = self
            .ontology
            .describe_object_with_ext(ctx, intent.from, &resolved.ext_fields)
            .await?;
        // The pure compilation now lives in `compile_with_inputs` so
        // callers with cached metadata can skip the resolve + describe
        // round trips; behavior for identical inputs is unchanged.
        self.compile_with_inputs(ctx, intent, projection, policy, &base, version_sel)
            .await
    }

    /// Compile against already-resolved governed inputs (item 47).
    ///
    /// The same pure compilation as [`compile_with_policy`], but the
    /// caller supplies the resolved description (base schema plus the
    /// resolved version's evolved fields) instead of the compiler
    /// re-resolving it from the database. Used with the metadata cache;
    /// for identical inputs the output is identical to
    /// `compile_with_policy`.
    pub async fn compile_with_inputs(
        &self,
        ctx: &TenantContext,
        intent: &QueryIntent,
        projection: &FieldProjection,
        policy: &RowPolicy,
        base: &ObjectDescription,
        version_sel: VersionSel,
    ) -> Result<CompiledPlan> {
        // Same fail-fast as `compile_with_policy`: an empty select is a
        // validation error, not "no visible fields".
        if intent.select.is_empty() {
            return Err(TinkerError::Validation("select is empty".into()));
        }
        let base_table = format!("data.{}", base.api_slug);

        // Fail closed on hidden filter/sort fields BEFORE touching select:
        // the intent is rejected as a whole, never partially applied.
        for f in &intent.filters {
            let (owner, leaf) = self.field_owner(ctx, base, &f.field, version_sel).await?;
            if !projection.allows(owner, &leaf) {
                return Err(TinkerError::Forbidden(format!(
                    "field '{}' is not visible to this role",
                    f.field
                )));
            }
        }
        for o in &intent.order {
            let (owner, leaf) = self.field_owner(ctx, base, &o.field, version_sel).await?;
            if !projection.allows(owner, &leaf) {
                return Err(TinkerError::Forbidden(format!(
                    "field '{}' is not visible to this role",
                    o.field
                )));
            }
        }

        // Resolve every referenced field up front: unknown names fail here,
        // never at execution. Hidden selected fields are projected out.
        // Joins are collected first and rendered once, AFTER filters and
        // order fields have had their chance to add joins — rendering joins
        // before resolving filters was the M4 join-ordering bug (a filter
        // on a relation field referenced a join alias that was never
        // emitted, producing invalid SQL).
        let mut select_cols: Vec<(String, String)> = Vec::new(); // (sql expr, api_name)
        let mut joins: Vec<Join> = Vec::new();
        for api_name in &intent.select {
            let (owner, leaf) = self.field_owner(ctx, base, api_name, version_sel).await?;
            if !projection.allows(owner, &leaf) {
                continue;
            }
            let (mut expr, out) = self
                .resolve_select(ctx, base, api_name, &mut joins, version_sel)
                .await?;
            // Sensitive fields read back masked: the plaintext never
            // leaves the vault through a query (reveal is a separate,
            // audited path), and caches only ever hold the mask.
            if self
                .sensitive_at(ctx, base, api_name, version_sel)
                .await?
                .is_some()
            {
                expr = format!("CASE WHEN {expr} IS NULL THEN NULL ELSE '{MASK}' END");
            }
            select_cols.push((expr, out));
        }
        if select_cols.is_empty() {
            return Err(TinkerError::Validation(
                "no visible fields selected for this role".into(),
            ));
        }

        // Pre-resolve filters and order exprs so every join they need
        // exists before the JOIN clause is rendered.
        let mut filter_exprs: Vec<(String, String)> = Vec::new();
        let mut filters: Vec<Filter> = Vec::new();
        for f in &intent.filters {
            let (expr, kind) = self
                .resolve_filter_field(ctx, base, &f.field, &mut joins, version_sel)
                .await?;
            match self.sensitive_at(ctx, base, &f.field, version_sel).await? {
                Some(sf) => {
                    let (expr, kind, eff) = self.sensitive_filter(ctx, &sf, &expr, f)?;
                    filter_exprs.push((expr, kind));
                    filters.push(eff);
                }
                None => {
                    filter_exprs.push((expr, kind));
                    filters.push(f.clone());
                }
            }
        }
        let mut order_exprs: Vec<String> = Vec::new();
        for o in &intent.order {
            if self
                .sensitive_at(ctx, base, &o.field, version_sel)
                .await?
                .is_some()
            {
                return Err(TinkerError::Validation(format!(
                    "field '{}' is sensitive and cannot be sorted on",
                    o.field
                )));
            }
            order_exprs.push(
                self.resolve_order_field(ctx, base, &o.field, &mut joins, version_sel)
                    .await?,
            );
        }

        let mut sql = String::from("SELECT ");
        sql.push_str(
            &select_cols
                .iter()
                .map(|(e, _)| e.clone())
                .collect::<Vec<_>>()
                .join(", "),
        );
        // Always expose the record id for write-through and unfurl,
        // unless explicitly selected already.
        if !select_cols.iter().any(|(_, o)| o == "__id") {
            sql.push_str(", \"t0\".\"id\" AS \"__id\"");
        }
        sql.push_str(&format!(" FROM {base_table} AS t0"));

        let mut join_idx = 0;
        for j in &joins {
            join_idx += 1;
            match j.kind {
                JoinKind::Relation => {
                    let src = match j.source {
                        Some(i) => format!("t{}", i + 1),
                        None => "t0".to_string(),
                    };
                    sql.push_str(&format!(
                        " LEFT JOIN {} AS t{join_idx} ON t{join_idx}.organization_id = {src}.organization_id \
                         AND t{join_idx}.id = {src}.\"{}\"",
                        j.target_table, j.via_column
                    ))
                }
                // M4: extension tables join on the record id; at most one
                // ext join per (table, source) pair. The source alias is
                // t0 for the base object, or the relation join's alias
                // when selecting an evolved field through a relation.
                JoinKind::Extension => {
                    let src = match j.source {
                        Some(i) => format!("t{}", i + 1),
                        None => "t0".to_string(),
                    };
                    sql.push_str(&format!(
                        " LEFT JOIN {} AS t{join_idx} ON t{join_idx}.organization_id = {src}.organization_id \
                         AND t{join_idx}.record_id = {src}.id",
                        j.target_table
                    ))
                }
            }
        }

        // The organization predicate is always first: $1. The row policy
        // (C2) is ANDed immediately after — same WHERE clause, before any
        // user filter, ORDER BY, or LIMIT: policy before ranking, by
        // construction.
        //
        // Item 40 (C1): default queries resolve published records. The
        // default is ANDed here, in the same clause — one enforcement
        // path, not two. `lifecycle_state` is a first-class C2 policy
        // dimension: an explicit policy filter on it overrides the
        // default (e.g. an archivist role seeing archived rows too).
        let mut params: Vec<Param> = vec![Param::Uuid(ctx.organization_id.0)];
        sql.push_str(" WHERE t0.organization_id = $1");
        policy.append_predicates(ctx, base, Some("t0"), &mut sql, &mut params)?;
        crate::row_policy::append_default_published_predicate(
            policy,
            base.lifecycle_enabled,
            &mut sql,
            &mut params,
            Some("t0"),
            &|n| format!("${n}"),
        );

        for (f, (expr, kind)) in filters.iter().zip(filter_exprs.iter()) {
            push_predicate(&mut sql, &mut params, expr, kind, f, &|n| format!("${n}"))?;
        }

        if !order_exprs.is_empty() {
            sql.push_str(" ORDER BY ");
            let parts: Vec<String> = intent
                .order
                .iter()
                .zip(order_exprs.iter())
                .map(|(o, e)| format!("{e} {}", if o.descending { "DESC" } else { "ASC" }))
                .collect();
            sql.push_str(&parts.join(", "));
        } else {
            sql.push_str(" ORDER BY \"t0\".\"created_at\" DESC");
        }

        let limit = intent.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        params.push(Param::Int(limit as i64));
        let n = params.len();
        sql.push_str(&format!(" LIMIT ${n}"));

        // The SQL always carries __id as the trailing column (see above);
        // output_fields must describe every column the executor returns,
        // or row labeling drifts from the actual column order.
        let mut output_fields: Vec<String> = select_cols.into_iter().map(|(_, o)| o).collect();
        if !output_fields.iter().any(|n| n == "__id") {
            output_fields.push("__id".to_string());
        }
        Ok(CompiledPlan {
            sql,
            params,
            output_fields,
            object_id: base.id,
        })
    }

    /// Resolve an order field to a SQL expression. Base fields read from
    /// t0; evolved fields read from the extension join. Dotted relation
    /// paths stay unsupported in ORDER BY (unchanged from M2).
    /// M4 hardening: ORDER BY accepts the same field paths as SELECT and
    /// filters, including relation traversal (`referred_by.name`). The
    /// join the traversal needs is registered here, before the JOIN
    /// clause renders — ordering must never reference a missing alias.
    async fn resolve_order_field(
        &self,
        ctx: &TenantContext,
        base: &ObjectDescription,
        field: &str,
        joins: &mut Vec<Join>,
        version_sel: VersionSel,
    ) -> Result<String> {
        let (expr, _) = self
            .resolve_select(ctx, base, field, joins, version_sel)
            .await?;
        Ok(expr)
    }

    /// Describe a relation target with the target object's evolved fields
    /// for this version attached. Without an evolver (or for the active
    /// version with no evolution), this is the plain base description.
    /// The field a select/filter/order path names, when it is sensitive.
    async fn sensitive_at(
        &self,
        ctx: &TenantContext,
        base: &ObjectDescription,
        path: &str,
        version_sel: VersionSel,
    ) -> Result<Option<FieldDescription>> {
        let field = match path.split_once('.') {
            Some((rel_name, leaf)) => {
                let Some(rel) = base
                    .fields
                    .iter()
                    .find(|f| f.api_name == rel_name && f.field_type == "relation")
                else {
                    return Ok(None);
                };
                let target = self
                    .describe_target(ctx, relation_target(rel)?, version_sel)
                    .await?;
                target.fields.into_iter().find(|f| f.api_name == leaf)
            }
            None => base.fields.iter().find(|f| f.api_name == path).cloned(),
        };
        Ok(field.filter(|f| f.sensitive))
    }

    /// Rewrite a filter on a sensitive field. Exact-match operators run
    /// against the blind-index column with the value's digest; presence
    /// checks run on the ref column; anything that would compare
    /// plaintext (ranges, contains, prefixes) is refused.
    fn sensitive_filter(
        &self,
        ctx: &TenantContext,
        sf: &FieldDescription,
        expr: &str,
        f: &Filter,
    ) -> Result<(String, String, Filter)> {
        match f.op {
            FilterOp::IsNull | FilterOp::IsNotNull => {
                return Ok((expr.to_string(), "text".to_string(), f.clone()))
            }
            FilterOp::Eq | FilterOp::Ne | FilterOp::In => {}
            _ => {
                return Err(TinkerError::Validation(format!(
                "field '{}' is sensitive: only eq, ne, in, is_null and is_not_null filters apply",
                f.field
            )))
            }
        }
        let key = self.blind_index.as_ref().ok_or_else(|| {
            TinkerError::Validation(format!(
                "field '{}' is sensitive: lookups need TINKER_BLIND_INDEX_KEY on this server",
                f.field
            ))
        })?;
        let digest = |v: &serde_json::Value| -> Result<serde_json::Value> {
            let s = v.as_str().ok_or_else(|| {
                TinkerError::Validation(format!(
                    "field '{}' is sensitive: filter values must be strings",
                    f.field
                ))
            })?;
            Ok(serde_json::Value::String(key.digest(
                ctx.organization_id.0,
                sf.id,
                &sf.field_type,
                s,
            )))
        };
        let value = match (&f.op, &f.value) {
            (FilterOp::In, serde_json::Value::Array(items)) => {
                serde_json::Value::Array(items.iter().map(digest).collect::<Result<Vec<_>>>()?)
            }
            (FilterOp::In, _) => {
                return Err(TinkerError::Validation(format!(
                    "field '{}': in takes an array",
                    f.field
                )))
            }
            (_, v) => digest(v)?,
        };
        let phys = format!("\"{}\"", sf.physical_column);
        let bidx = format!("\"{}\"", tinker_ontology::bidx_column(&sf.physical_column));
        let bidx_expr = expr.replacen(&phys, &bidx, 1);
        Ok((
            bidx_expr,
            "text".to_string(),
            Filter {
                field: f.field.clone(),
                op: f.op,
                value,
            },
        ))
    }

    async fn describe_target(
        &self,
        ctx: &TenantContext,
        target_id: Uuid,
        version_sel: VersionSel,
    ) -> Result<ObjectDescription> {
        let ext_fields = match &self.evolver {
            Some(evolver) => {
                evolver
                    .resolve(ctx, target_id, version_sel)
                    .await?
                    .ext_fields
            }
            None => vec![],
        };
        self.ontology
            .describe_object_with_ext(ctx, target_id, &ext_fields)
            .await
    }

    /// Ensure the extension join exists; return its 0-based index.
    /// `source` is the join whose alias holds the record id (`None` = t0).
    fn ensure_ext_join(
        &self,
        joins: &mut Vec<Join>,
        ext_table: &str,
        source: Option<usize>,
    ) -> usize {
        match joins.iter().position(|j| {
            j.kind == JoinKind::Extension && j.target_table == ext_table && j.source == source
        }) {
            Some(i) => i,
            None => {
                joins.push(Join {
                    target_table: ext_table.to_string(),
                    via_column: String::new(),
                    kind: JoinKind::Extension,
                    source,
                });
                joins.len() - 1
            }
        }
    }

    /// Resolve a field path to its owning object and leaf api_name.
    /// `"name"` -> (base, "name"); `"company.name"` -> (company, "name");
    /// `"__id"` -> (base, "__id"). Unknown names fail here.
    async fn field_owner(
        &self,
        ctx: &TenantContext,
        base: &ObjectDescription,
        path: &str,
        version_sel: VersionSel,
    ) -> Result<(Uuid, String)> {
        if path == "__id" && !path.contains('.') {
            return Ok((base.id, "__id".to_string()));
        }
        if let Some((rel_name, target_field)) = path.split_once('.') {
            let rel = base
                .fields
                .iter()
                .find(|f| f.api_name == rel_name && f.field_type == "relation")
                .ok_or_else(|| {
                    TinkerError::Validation(format!("not a declared relation: {rel_name}"))
                })?;
            let target_id = relation_target(rel)?;
            // The leaf must exist on the target — including the target's
            // evolved fields for this version. resolve_select re-checks,
            // but failing here keeps the error before any projection logic.
            let target = self.describe_target(ctx, target_id, version_sel).await?;
            target
                .fields
                .iter()
                .find(|f| f.api_name == target_field)
                .ok_or_else(|| TinkerError::Validation(format!("unknown field: {path}")))?;
            Ok((target_id, target_field.to_string()))
        } else {
            base.fields
                .iter()
                .find(|f| f.api_name == path)
                .ok_or_else(|| TinkerError::Validation(format!("unknown field: {path}")))?;
            Ok((base.id, path.to_string()))
        }
    }

    /// Resolve a select path. `"name"` -> base column; `"company.name"` ->
    /// join through a declared relation field, one level.
    async fn resolve_select(
        &self,
        ctx: &TenantContext,
        base: &ObjectDescription,
        path: &str,
        joins: &mut Vec<Join>,
        version_sel: VersionSel,
    ) -> Result<(String, String)> {
        // `__id` is the record id: a system column the compiler always
        // exposes. It is filterable (and selectable) like any field; the
        // tenant predicate still scopes it.
        if path == "__id" && !path.contains('.') {
            return Ok(("\"t0\".\"id\"".to_string(), "__id".to_string()));
        }
        if let Some((rel_name, target_field)) = path.split_once('.') {
            let rel = base
                .fields
                .iter()
                .find(|f| f.api_name == rel_name && f.field_type == "relation")
                .ok_or_else(|| {
                    TinkerError::Validation(format!(
                        "not a declared relation: {rel_name} (joins follow declared relations only)"
                    ))
                })?;
            let target_id = relation_target(rel)?;
            // The relation target sees its own evolved fields for this
            // version, so `referred_by.nickname` resolves after evolution.
            let target = self.describe_target(ctx, target_id, version_sel).await?;
            let tf = target
                .fields
                .iter()
                .find(|f| f.api_name == target_field)
                .ok_or_else(|| TinkerError::Validation(format!("unknown field: {path}")))?;
            // Evolved relation fields keep their FK on the org's extension
            // table: ensure that join FIRST so the relation join can read
            // the FK from its alias. Joins are append-only, so indices
            // taken here stay valid through rendering.
            let fk_source = rel
                .extension_table
                .as_ref()
                .map(|ext| self.ensure_ext_join(joins, ext, None));
            let target_table = format!("data.{}", target.api_slug);
            // Reuse an identical join rather than duplicating it.
            let idx = match joins.iter().position(|j| {
                j.kind == JoinKind::Relation
                    && j.via_column == rel.physical_column
                    && j.target_table == target_table
                    && j.source == fk_source
            }) {
                Some(i) => i,
                None => {
                    joins.push(Join {
                        via_column: rel.physical_column.clone(),
                        target_table,
                        kind: JoinKind::Relation,
                        source: fk_source,
                    });
                    joins.len() - 1
                }
            };
            let target_alias = idx + 1;
            // A leaf that is itself evolved on the target reads from the
            // target's extension table, joined on the target alias.
            let (leaf_alias, leaf_col) = match &tf.extension_table {
                Some(ext) => {
                    let eidx = self.ensure_ext_join(joins, ext, Some(idx));
                    (eidx + 1, tf.physical_column.clone())
                }
                None => (target_alias, tf.physical_column.clone()),
            };
            Ok((
                format!("\"t{leaf_alias}\".\"{leaf_col}\""),
                path.to_string(),
            ))
        } else {
            let f = base
                .fields
                .iter()
                .find(|f| f.api_name == path)
                .ok_or_else(|| TinkerError::Validation(format!("unknown field: {path}")))?;
            // M4: evolved fields live on the org's extension table, pulled
            // in via a LEFT JOIN on the record id. Missing ext rows are
            // NULL — a record created before the evolution simply has no
            // value for the new field.
            if let Some(ext_table) = &f.extension_table {
                let idx = self.ensure_ext_join(joins, ext_table, None);
                return Ok((
                    format!("\"t{}\".\"{}\"", idx + 1, f.physical_column),
                    path.to_string(),
                ));
            }
            Ok((
                format!("\"t0\".\"{}\"", f.physical_column),
                path.to_string(),
            ))
        }
    }

    async fn resolve_filter_field(
        &self,
        ctx: &TenantContext,
        base: &ObjectDescription,
        path: &str,
        joins: &mut Vec<Join>,
        version_sel: VersionSel,
    ) -> Result<(String, String)> {
        let (expr, _) = self
            .resolve_select(ctx, base, path, joins, version_sel)
            .await?;
        // Re-resolve the kind for operator allowlisting. `__id` is a
        // system column with a synthetic kind.
        if path == "__id" {
            return Ok((expr, "id".to_string()));
        }
        let kind = if let Some((rel_name, target_field)) = path.split_once('.') {
            let rel = base.fields.iter().find(|f| f.api_name == rel_name).unwrap();
            let target_id = relation_target(rel)?;
            let target = self.ontology.describe_object(ctx, target_id).await?;
            target
                .fields
                .iter()
                .find(|f| f.api_name == target_field)
                .unwrap()
                .field_type
                .clone()
        } else {
            base.fields
                .iter()
                .find(|f| f.api_name == path)
                .unwrap()
                .field_type
                .clone()
        };
        Ok((expr, kind))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum JoinKind {
    /// Declared relation: `tN.id = t0."<fk column>"`.
    Relation,
    /// M4 schema evolution: `tN.record_id = t0.id` on the org's extension
    /// table.
    Extension,
}

#[derive(Debug, Clone)]
struct Join {
    via_column: String,
    target_table: String,
    kind: JoinKind,
    /// 0-based index of the join whose alias this join hangs off.
    /// `None` means the base table `t0`.
    /// - Relation: the alias holding the FK column. Evolved relation
    ///   fields keep their FK on the org's extension table, so their
    ///   relation join reads the FK from that join's alias, not `t0`.
    /// - Extension: the alias holding the record id the extension
    ///   table's `record_id` joins to (the target alias when selecting
    ///   an evolved field through a relation).
    source: Option<usize>,
}

/// M4: the target is loaded at describe time, so relation hops never
/// touch metadata per query — and evolved relation fields (which have no
/// ontology_fields row) resolve the same way as base fields.
fn relation_target(rel: &FieldDescription) -> Result<Uuid> {
    rel.relation_target_id
        .ok_or_else(|| TinkerError::Validation(format!("relation has no target: {}", rel.api_name)))
}

fn text_like(kind: &str) -> bool {
    matches!(
        kind,
        "text" | "email" | "phone" | "url" | "select" | "richtext" | "file"
    )
}

/// Bind one typed [`Param`] to a `sqlx::query` under construction.
/// Values are bound by type, never interpolated — the shared rule every
/// hand-built statement follows.
pub fn bind_param<'q>(
    q: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    p: &'q Param,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    match p {
        Param::Text(s) => q.bind(s),
        Param::Int(n) => q.bind(n),
        Param::Float(f) => q.bind(f),
        Param::Bool(b) => q.bind(b),
        Param::Uuid(u) => q.bind(u),
        Param::Date(d) => q.bind(d),
        Param::Timestamp(t) => q.bind(t),
        Param::Json(j) => q.bind(j),
        Param::Null => q.bind(Option::<String>::None),
    }
}

/// Same typed-bind rule for `sqlx::query_as`.
pub fn bind_param_as<'q, O>(
    q: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    p: &'q Param,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
    match p {
        Param::Text(s) => q.bind(s),
        Param::Int(n) => q.bind(n),
        Param::Float(f) => q.bind(f),
        Param::Bool(b) => q.bind(b),
        Param::Uuid(u) => q.bind(u),
        Param::Date(d) => q.bind(d),
        Param::Timestamp(t) => q.bind(t),
        Param::Json(j) => q.bind(j),
        Param::Null => q.bind(Option::<String>::None),
    }
}

fn push_predicate(
    sql: &mut String,
    params: &mut Vec<Param>,
    expr: &str,
    kind: &str,
    f: &Filter,
    ph: &dyn Fn(usize) -> String,
) -> Result<()> {
    let op_sql = match f.op {
        FilterOp::Eq => "=",
        FilterOp::Ne => "<>",
        FilterOp::Lt => "<",
        FilterOp::Lte => "<=",
        FilterOp::Gt => ">",
        FilterOp::Gte => ">=",
        FilterOp::In => "IN",
        FilterOp::Contains => {
            if !text_like(kind) {
                return Err(TinkerError::Validation(format!(
                    "op contains not allowed on {kind}"
                )));
            }
            "ILIKE"
        }
        FilterOp::StartsWith => {
            if !text_like(kind) {
                return Err(TinkerError::Validation(format!(
                    "op starts_with not allowed on {kind}"
                )));
            }
            "ILIKE"
        }
        FilterOp::IsNull => {
            sql.push_str(&format!(" AND {expr} IS NULL"));
            return Ok(());
        }
        FilterOp::IsNotNull => {
            sql.push_str(&format!(" AND {expr} IS NOT NULL"));
            return Ok(());
        }
    };
    match f.op {
        FilterOp::In => {
            let arr = f
                .value
                .as_array()
                .ok_or_else(|| TinkerError::Validation("in requires an array value".into()))?;
            if arr.is_empty() {
                sql.push_str(" AND FALSE");
                return Ok(());
            }
            let placeholders: Vec<String> = arr
                .iter()
                .map(|v| push_typed_param(params, kind, v, ph))
                .collect::<Result<Vec<_>>>()?;
            sql.push_str(&format!(" AND {expr} IN ({})", placeholders.join(", ")));
            Ok(())
        }
        FilterOp::Contains | FilterOp::StartsWith => {
            let s = f
                .value
                .as_str()
                .ok_or_else(|| TinkerError::Validation("text match requires a string".into()))?;
            // Escape LIKE wildcards in the raw input, then add the intended
            // wildcards back. User input can never become a pattern.
            let raw = s
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            let pattern = if f.op == FilterOp::Contains {
                format!("%{raw}%")
            } else {
                format!("{raw}%")
            };
            let n = params.len() + 1;
            params.push(Param::Text(pattern));
            sql.push_str(&format!(" AND {expr} {op_sql} {} ESCAPE '\\'", ph(n)));
            Ok(())
        }
        _ => {
            let placeholder = push_typed_param(params, kind, &f.value, ph)?;
            sql.push_str(&format!(" AND {expr} {op_sql} {placeholder}"));
            Ok(())
        }
    }
}

/// Convert a JSON filter value to a typed bind and return its SQL
/// placeholder. The placeholder carries an explicit cast for the one
/// ambiguous kind — number/currency, where a value may become `Int` or
/// `Float`.
///
/// Why: sqlx's prepared-statement cache is keyed by SQL text alone. Without
/// the cast, `score = $2` bound once as INT8 and once as FLOAT8 reuses the
/// first preparation on a pooled connection: PostgreSQL then either rejects
/// the bytes (22P03) or, worse, parses float bytes as an integer and
/// compares garbage — silently. The cast makes the declared bind type part
/// of the statement identity, so each (text, types) shape prepares
/// separately. Every other field kind maps to exactly one `Param` variant
/// (see `Param::from_json_for_kind`), so no cast is needed there.
fn push_typed_param(
    params: &mut Vec<Param>,
    kind: &str,
    v: &serde_json::Value,
    ph: &dyn Fn(usize) -> String,
) -> Result<String> {
    // JSON null is only meaningful with IsNull/IsNotNull (handled in their
    // own branches, never reaching here). Compiling `col = $N` with a null
    // bind would silently match zero rows; reject loudly instead.
    if v.is_null() {
        return Err(TinkerError::Validation(
            "null filter value requires the is_null/is_not_null operator".into(),
        ));
    }
    let p = Param::from_json_for_kind(kind, v)?;
    let cast = match (&p, kind) {
        (Param::Int(_), "number" | "currency") => "::int8",
        (Param::Float(_), "number" | "currency") => "::float8",
        _ => "",
    };
    let n = params.len() + 1;
    params.push(p);
    Ok(format!("{}{}", ph(n), cast))
}
