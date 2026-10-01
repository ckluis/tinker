//! Row-level permission filters (C2, item 38).
//!
//! Per-role row filters compiled into the query compiler alongside the
//! tenant predicate ("policy before ranking"). Filters are stored per
//! (organization_id, object_id, role) as data — (field, operator, value)
//! shapes, never raw SQL — and the compiler ANDs them with the tenant
//! predicate at SQL build time.
//!
//! Value shapes: tenant-scoped constants, or `actor.*` references
//! (`{"actor": "id"}` in v1 — the only actor reference). No subqueries in
//! v1 filter values, ever.
//!
//! Semantics:
//! - No rows for (org, object, role) = default-open (documented choice,
//!   matching [`crate::FieldProjection`]).
//! - A filter that matches nothing returns nothing — never a
//!   "forbidden vs absent" distinction in errors.
//! - v1 operators: eq/neq/in/range(null)/null. v1 fields: base-table
//!   columns only (relation FKs live on the base table, so
//!   `owner = actor.id` works); evolved (extension-table) and computed
//!   fields are rejected with a clear error.
//! - All values become typed binds via [`tinker_core::Param`]; identifiers
//!   come from the metadata registry only.

use tinker_core::{CompiledRowPolicy, Param, Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_ontology::ObjectDescription;
use uuid::Uuid;

use crate::{push_predicate, Filter, FilterOp};

/// v1 row-filter operators. `range` is expressed as a gte+lde pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowFilterOp {
    Eq,
    Ne,
    In,
    Lt,
    Lte,
    Gt,
    Gte,
    IsNull,
    IsNotNull,
}

impl RowFilterOp {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "eq" => Ok(Self::Eq),
            // "neq" is the BACKLOG.md spelling; "ne" matches the
            // FilterOp variant name used by the query intent wire format.
            "ne" | "neq" => Ok(Self::Ne),
            "in" => Ok(Self::In),
            "lt" => Ok(Self::Lt),
            "lte" => Ok(Self::Lte),
            "gt" => Ok(Self::Gt),
            "gte" => Ok(Self::Gte),
            "is_null" => Ok(Self::IsNull),
            "is_not_null" => Ok(Self::IsNotNull),
            other => Err(TinkerError::Validation(format!(
                "unknown row filter operator: {other}"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::In => "in",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::IsNull => "is_null",
            Self::IsNotNull => "is_not_null",
        }
    }

    fn to_filter_op(self) -> FilterOp {
        match self {
            Self::Eq => FilterOp::Eq,
            Self::Ne => FilterOp::Ne,
            Self::In => FilterOp::In,
            Self::Lt => FilterOp::Lt,
            Self::Lte => FilterOp::Lte,
            Self::Gt => FilterOp::Gt,
            Self::Gte => FilterOp::Gte,
            Self::IsNull => FilterOp::IsNull,
            Self::IsNotNull => FilterOp::IsNotNull,
        }
    }
}

/// A row-filter value: a tenant-scoped constant, or a per-caller actor
/// reference resolved at compile time.
#[derive(Debug, Clone, PartialEq)]
pub enum RowFilterValue {
    Const(serde_json::Value),
    ActorId,
}

impl RowFilterValue {
    /// Parse the stored JSON value shape for an operator. Anything shaped
    /// like an actor reference other than exactly `{"actor": "id"}` fails
    /// closed — a typo must not silently become a constant.
    pub fn parse(op: RowFilterOp, v: &serde_json::Value) -> Result<Self> {
        if let serde_json::Value::Object(map) = v {
            if map.contains_key("actor") {
                if map.len() == 1
                    && map.get("actor") == Some(&serde_json::Value::String("id".into()))
                    && !matches!(
                        op,
                        RowFilterOp::IsNull | RowFilterOp::IsNotNull | RowFilterOp::In
                    )
                {
                    return Ok(Self::ActorId);
                }
                return Err(TinkerError::Validation(format!(
                    "bad actor reference in row filter value: {v}"
                )));
            }
        }
        match op {
            RowFilterOp::IsNull | RowFilterOp::IsNotNull => {
                if v.is_null() {
                    Ok(Self::Const(v.clone()))
                } else {
                    Err(TinkerError::Validation(
                        "is_null/is_not_null row filters take no value".into(),
                    ))
                }
            }
            RowFilterOp::In => {
                if v.as_array().is_some() {
                    Ok(Self::Const(v.clone()))
                } else {
                    Err(TinkerError::Validation(
                        "in row filter requires an array value".into(),
                    ))
                }
            }
            _ => {
                if v.is_null() || v.is_array() || v.is_object() {
                    Err(TinkerError::Validation(
                        "row filter requires a scalar constant or {\"actor\": \"id\"}".into(),
                    ))
                } else {
                    Ok(Self::Const(v.clone()))
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct RowFilter {
    pub field: String,
    pub op: RowFilterOp,
    pub value: RowFilterValue,
}

/// Wire shape for the admin write path (mirrors the `row_filters` table).
#[derive(Debug, Clone)]
pub struct RowFilterDef {
    pub field: String,
    pub op: String,
    pub value: Option<serde_json::Value>,
}

/// The compiled-together row policy for one (org, role, object): ANDed
/// filters applied alongside the tenant predicate.
#[derive(Debug, Clone, Default)]
pub struct RowPolicy {
    pub object_id: Uuid,
    pub filters: Vec<RowFilter>,
}

impl RowPolicy {
    /// Default-open: no filters for this (org, role, object).
    pub fn open(object_id: Uuid) -> Self {
        Self {
            object_id,
            filters: Vec::new(),
        }
    }

    pub fn is_open(&self) -> bool {
        self.filters.is_empty()
    }

    /// Whether this policy already constrains `lifecycle_state`. When it
    /// does, the compiler's default published-only predicate is
    /// suppressed — explicit policy wins (e.g. an archivist role with
    /// `lifecycle_state in ('published','archived')`).
    pub fn has_lifecycle_filter(&self) -> bool {
        self.filters.iter().any(|f| f.field == "lifecycle_state")
    }

    /// Append the policy predicates to a statement being built. Emits
    /// ` AND ...` per filter over `{alias}."<physical_column>"` (`alias`
    /// `None` = unqualified column, for hand-built single-table SQL).
    /// Placeholders are positional `$N`, numbered from the params vec —
    /// the caller owns numbering, exactly like the tenant predicate.
    pub fn append_predicates(
        &self,
        ctx: &TenantContext,
        desc: &ObjectDescription,
        alias: Option<&str>,
        sql: &mut String,
        params: &mut Vec<Param>,
    ) -> Result<()> {
        if self.object_id != desc.id {
            return Err(TinkerError::Internal(
                "row policy compiled for the wrong object".into(),
            ));
        }
        for rf in &self.filters {
            let (col, kind) = resolve_policy_field(desc, &rf.field)?;
            let expr = match alias {
                Some(a) => format!("\"{a}\".\"{col}\""),
                None => format!("\"{col}\""),
            };
            let f = Filter {
                field: rf.field.clone(),
                op: rf.op.to_filter_op(),
                value: match &rf.value {
                    RowFilterValue::Const(v) => v.clone(),
                    RowFilterValue::ActorId => serde_json::Value::String(ctx.actor_id.to_string()),
                },
            };
            push_predicate(sql, params, &expr, &kind, &f, &|n| format!("${n}"))?;
        }
        Ok(())
    }

    /// Compile the policy to a search-backend fragment: a boolean
    /// expression over the `search_index` row that holds exactly when the
    /// indexed record passes the role's row filters.
    ///
    /// Item 40 (C1): the fragment ALWAYS carries the default
    /// published-only predicate when the policy has no `lifecycle_state`
    /// filter — archived rows are indexed (they live in the data table)
    /// and must not surface in search, even for open policies. The
    /// fragment is `EXISTS` against the object's data table, so the
    /// policy restricts the candidate set in the SAME statement that
    /// performs matching and ranking — hidden rows never influence rank,
    /// snippets, or counts. Placeholders use the `{{pK}}` contract of
    /// [`CompiledRowPolicy`].
    pub fn compile_for_search(
        &self,
        ctx: &TenantContext,
        desc: &ObjectDescription,
    ) -> Result<Option<CompiledRowPolicy>> {
        if self.object_id != desc.id {
            return Err(TinkerError::Internal(
                "row policy compiled for the wrong object".into(),
            ));
        }
        // params[0] is the object guard bind; filter binds follow.
        let mut params: Vec<Param> = vec![Param::Uuid(self.object_id)];
        let mut preds = String::new();
        for rf in &self.filters {
            let (col, kind) = resolve_policy_field(desc, &rf.field)?;
            let f = Filter {
                field: rf.field.clone(),
                op: rf.op.to_filter_op(),
                value: match &rf.value {
                    RowFilterValue::Const(v) => v.clone(),
                    RowFilterValue::ActorId => serde_json::Value::String(ctx.actor_id.to_string()),
                },
            };
            push_predicate(
                &mut preds,
                &mut params,
                &format!("\"d\".\"{col}\""),
                &kind,
                &f,
                &|n| format!("{{{{p{n}}}}}"),
            )?;
        }
        // C1 default: published-only, same predicate family as the query
        // compiler. Suppressed by an explicit lifecycle_state filter.
        if !self.has_lifecycle_filter() {
            params.push(Param::Text("published".to_string()));
            let n = params.len();
            preds.push_str(&format!(" AND \"d\".\"lifecycle_state\" = {{{{p{n}}}}}"));
        }
        // Same table-name trust as the query compiler: api_slug comes from
        // the metadata registry, never from user input.
        let table = format!("data.{}", desc.api_slug);
        let sql = format!(
            "(search_index.object_id <> {{{{p1}}}} OR (EXISTS (SELECT 1 FROM {table} AS d \
             WHERE d.organization_id = search_index.organization_id \
             AND d.id = search_index.record_id{preds})))"
        );
        Ok(Some(CompiledRowPolicy {
            object_id: self.object_id,
            sql,
            params,
        }))
    }
}

/// Resolve a row-filter field to (physical_column, kind). v1: base-table
/// columns only. Relation fields are allowed — their FK lives on the base
/// table, so `owner = actor.id` compiles to a plain column comparison.
/// Evolved (extension-table) fields are rejected: they need a join the
/// policy compiler does not build in v1.
fn resolve_policy_field(desc: &ObjectDescription, field: &str) -> Result<(String, String)> {
    if field == "__id" {
        return Ok(("id".to_string(), "id".to_string()));
    }
    // Item 40 (C1): lifecycle_state is a system column, not an ontology
    // field — but it is a first-class policy dimension, so the
    // pseudo-field resolves to the physical column (text kind).
    if field == "lifecycle_state" {
        return Ok(("lifecycle_state".to_string(), "text".to_string()));
    }
    let f = desc
        .fields
        .iter()
        .find(|f| f.api_name == field)
        .ok_or_else(|| TinkerError::Validation(format!("unknown field in row filter: {field}")))?;
    if f.extension_table.is_some() {
        return Err(TinkerError::Validation(format!(
            "row filter on evolved field '{field}' is not supported in v1"
        )));
    }
    Ok((f.physical_column.clone(), f.field_type.clone()))
}

/// Append the default published-only predicate (C1, item 40) when the
/// role policy has no `lifecycle_state` filter. Default queries resolve
/// published records — in the SAME WHERE clause as the tenant predicate
/// and the C2 policy, one enforcement path, not two. The value is a
/// typed bind, never interpolated.
pub fn append_default_published_predicate(
    policy: &RowPolicy,
    lifecycle_enabled: bool,
    sql: &mut String,
    params: &mut Vec<Param>,
    alias: Option<&str>,
    ph: &dyn Fn(usize) -> String,
) {
    if !lifecycle_enabled || policy.has_lifecycle_filter() {
        return;
    }
    params.push(Param::Text("published".to_string()));
    let n = params.len();
    match alias {
        Some(a) => sql.push_str(&format!(" AND \"{a}\".\"lifecycle_state\" = {}", ph(n))),
        None => sql.push_str(&format!(" AND \"lifecycle_state\" = {}", ph(n))),
    }
}

/// Owner-handle access to `row_filters`. Writes come from the pack
/// installer or an org admin path; reads serve the query/search/record
/// endpoints. Mirrors `tinker_live::FieldGrants`.
pub struct RowFilters {
    core: CoreDb,
}

impl RowFilters {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Replace the row filters for (org, object, role) with exactly
    /// `defs`. Every def is validated against the object's live fields
    /// BEFORE anything is written: unknown fields, bad operators, bad
    /// value shapes, and non-convertible constants all fail here, never
    /// half-applied. Delete-then-insert keeps it atomic per call.
    pub async fn set_filters(
        &self,
        ctx: &TenantContext,
        desc: &ObjectDescription,
        role: &str,
        defs: &[RowFilterDef],
    ) -> Result<()> {
        if role.is_empty() || role.len() > 64 {
            return Err(TinkerError::Validation("bad role".into()));
        }
        if desc.id.is_nil() {
            return Err(TinkerError::Validation("bad object".into()));
        }
        // Validate everything up front: field exists and is v1-eligible,
        // operator known, value shape sane, constants convertible for the
        // field kind (fail fast on typos, not at query time).
        let mut validated: Vec<(String, String, serde_json::Value)> = Vec::new();
        for def in defs {
            if def.field.is_empty() || def.field.len() > 128 {
                return Err(TinkerError::Validation("bad field in row filter".into()));
            }
            let op = RowFilterOp::parse(&def.op)?;
            let (col, kind) = resolve_policy_field(desc, &def.field)?;
            let raw = def.value.clone().unwrap_or(serde_json::Value::Null);
            let value = RowFilterValue::parse(op, &raw)?;
            if let RowFilterValue::Const(c) = &value {
                if !matches!(op, RowFilterOp::IsNull | RowFilterOp::IsNotNull) {
                    match op {
                        RowFilterOp::In => {
                            for el in c.as_array().unwrap_or(&vec![]) {
                                Param::from_json_for_kind(&kind, el).map_err(|e| {
                                    TinkerError::Validation(format!(
                                        "row filter value not convertible for field '{}': {e}",
                                        def.field
                                    ))
                                })?;
                            }
                        }
                        _ => {
                            Param::from_json_for_kind(&kind, c).map_err(|e| {
                                TinkerError::Validation(format!(
                                    "row filter value not convertible for field '{}': {e}",
                                    def.field
                                ))
                            })?;
                        }
                    }
                }
            }
            let _ = col;
            validated.push((def.field.clone(), op.as_str().to_string(), raw));
        }

        let organization_id = ctx.organization_id.0;
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(
            "DELETE FROM row_filters WHERE organization_id=$1 AND object_id=$2 AND role=$3",
        )
        .bind(organization_id)
        .bind(desc.id)
        .bind(role)
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        for (pos, (field, op, value)) in validated.into_iter().enumerate() {
            sqlx::query(
                "INSERT INTO row_filters
                 (organization_id, object_id, role, field_api_name, operator, value, position)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(organization_id)
            .bind(desc.id)
            .bind(role)
            .bind(field)
            .bind(op)
            .bind(value)
            .bind(pos as i32)
            .execute(&mut *tx)
            .await
            .map_err(TinkerError::Db)?;
        }
        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(())
    }

    /// Load the row policy for a role over one object. No rows =
    /// default-open. A corrupt stored row fails closed — it is never
    /// silently dropped (that would widen access).
    pub async fn load_policy(
        &self,
        ctx: &TenantContext,
        object_id: Uuid,
        role: &str,
    ) -> Result<RowPolicy> {
        let organization_id = ctx.organization_id.0;
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(String, String, Option<serde_json::Value>)> = sqlx::query_as(
            "SELECT field_api_name, operator, value FROM row_filters
             WHERE organization_id=$1 AND object_id=$2 AND role=$3
             ORDER BY position",
        )
        .bind(organization_id)
        .bind(object_id)
        .bind(role)
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;
        tx.commit().await.map_err(TinkerError::Db)?;
        let mut filters = Vec::with_capacity(rows.len());
        for (field, op_str, value) in rows {
            let op = RowFilterOp::parse(&op_str).map_err(|_| {
                TinkerError::Internal(format!("corrupt row_filters operator: {op_str}"))
            })?;
            let raw = value.unwrap_or(serde_json::Value::Null);
            let value = RowFilterValue::parse(op, &raw).map_err(|_| {
                TinkerError::Internal(format!("corrupt row_filters value for field {field}"))
            })?;
            filters.push(RowFilter { field, op, value });
        }
        Ok(RowPolicy { object_id, filters })
    }
}
