//! Query executor: runs compiled plans with a timeout, inside the caller's
//! tenant context, and audits every execution.
//!
//! The tenant predicate is baked into the plan by the compiler (`$1`), and
//! the plan runs inside `tenant_tx`, so RLS is a second barrier. The audit
//! row is written in the same transaction context — a query can never be
//! attributed to another organization.
//!
//! Two consumption shapes: [`QueryExecutor::execute`] materializes the whole
//! result set (fine for bounded governed queries); [`QueryExecutor::execute_stream`]
//! pages rows through a server-side cursor so arbitrarily large result sets
//! stream with bounded memory.

use std::pin::Pin;
use std::task::{Context, Poll};

use sha2::{Digest, Sha256};
use sqlx::Row;
use tinker_core::{Param, Result, TenantContext, TinkerError};
use tinker_db::CoreDb;
use tinker_query::CompiledPlan;

/// Statement timeout for governed queries (PRD M2: timeout).
pub const QUERY_TIMEOUT_MS: u32 = 5_000;

/// Rows fetched per server round-trip while streaming. Bounds the memory
/// held by an open stream regardless of result-set size.
pub const STREAM_CHUNK: i64 = 500;

pub struct QueryExecutor {
    core: CoreDb,
}

impl QueryExecutor {
    pub fn new(core: CoreDb) -> Self {
        Self { core }
    }

    /// Hash identifying a plan + its bound values. The cache key pairs
    /// this with the organization id — never the hash alone.
    pub fn plan_hash(plan: &CompiledPlan) -> String {
        let mut h = Sha256::new();
        h.update(plan.sql.as_bytes());
        for p in &plan.params {
            match p {
                Param::Text(s) => {
                    h.update(b"T");
                    h.update(s.as_bytes());
                }
                Param::Int(n) => {
                    h.update(b"I");
                    h.update(n.to_be_bytes());
                }
                Param::Float(f) => {
                    h.update(b"F");
                    h.update(f.to_be_bytes());
                }
                Param::Bool(b) => {
                    h.update(b"B");
                    h.update([*b as u8]);
                }
                Param::Uuid(u) => {
                    h.update(b"U");
                    h.update(u.as_bytes());
                }
                Param::Date(d) => {
                    h.update(b"D");
                    h.update(d.format("%Y-%m-%d").to_string().as_bytes());
                }
                Param::Timestamp(t) => {
                    h.update(b"T");
                    h.update(t.timestamp_nanos_opt().unwrap_or(0).to_be_bytes());
                }
                Param::Json(j) => {
                    h.update(b"J");
                    h.update(j.to_string().as_bytes());
                }
                Param::Null => {
                    h.update(b"N");
                }
            }
        }
        hex_of(h.finalize())
    }

    /// Execute a compiled plan as `ctx`. Returns rows as JSON objects keyed
    /// by the plan's output field names (plus `__id`).
    pub async fn execute(
        &self,
        ctx: &TenantContext,
        plan: &CompiledPlan,
    ) -> Result<Vec<serde_json::Value>> {
        let started = std::time::Instant::now();
        let mut tx = self.core.tenant_tx(ctx).await?;
        sqlx::query(&format!(
            "SET LOCAL statement_timeout = '{QUERY_TIMEOUT_MS}'"
        ))
        .execute(&mut *tx)
        .await
        .map_err(TinkerError::Db)?;

        let mut q = sqlx::query(&plan.sql);
        for p in &plan.params {
            q = bind_param(q, p);
        }
        let rows = q.fetch_all(&mut *tx).await.map_err(TinkerError::Db)?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(row_to_json(&plan.output_fields, r));
        }

        // Audit in the same tenant context: attribution cannot cross orgs.
        let ms = started.elapsed().as_millis() as i32;
        insert_audit(&mut tx, ctx, plan, out.len() as i64, ms).await?;

        tx.commit().await.map_err(TinkerError::Db)?;
        Ok(out)
    }

    /// Stream a compiled plan's rows as JSON objects, one per stream item,
    /// without materializing the whole result set.
    ///
    /// Same tenant context, statement timeout, row decoding, and audit
    /// shape as [`execute`]. Rows flow through a server-side cursor in
    /// [`STREAM_CHUNK`]-row fetches, so memory stays bounded no matter how
    /// large the result set is.
    ///
    /// Audit semantics: when the stream is consumed to exhaustion, the audit
    /// row is written with the true row count and the transaction commits.
    /// If the stream is dropped early — or a fetch fails — the transaction
    /// rolls back and **no audit row is written**: an abandoned stream is
    /// not recorded as a completed execution.
    pub fn execute_stream(&self, ctx: &TenantContext, plan: &CompiledPlan) -> RowStream {
        // Bounded channel: backpressure keeps an unconsumed stream from
        // buffering the whole result set in the producer task.
        let (tx_out, rx) =
            tokio::sync::mpsc::channel::<Result<serde_json::Value>>(STREAM_CHUNK as usize * 2);
        let core = self.core.clone();
        let ctx = ctx.clone();
        let plan = plan.clone();
        tokio::spawn(async move {
            drive_stream(core, ctx, plan, tx_out).await;
        });
        RowStream { rx }
    }
}

/// A streaming execution of a compiled plan. Yields each row as a JSON
/// object keyed by the plan's output field names (plus `__id`), in plan
/// order. See [`QueryExecutor::execute_stream`] for audit semantics.
pub struct RowStream {
    rx: tokio::sync::mpsc::Receiver<Result<serde_json::Value>>,
}

impl tokio_stream::Stream for RowStream {
    type Item = Result<serde_json::Value>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_mut().get_mut().rx.poll_recv(cx)
    }
}

/// Producer half of [`RowStream`]: opens the tenant transaction, declares a
/// server-side cursor over the plan, and pumps decoded rows into the
/// channel until the cursor is exhausted. On exhaustion the audit row is
/// written and the transaction commits; any earlier exit drops the
/// transaction, which rolls back.
async fn drive_stream(
    core: CoreDb,
    ctx: TenantContext,
    plan: CompiledPlan,
    out: tokio::sync::mpsc::Sender<Result<serde_json::Value>>,
) {
    let started = std::time::Instant::now();

    let mut tx = match core.tenant_tx(&ctx).await {
        Ok(tx) => tx,
        Err(e) => {
            send_err(&out, e).await;
            return;
        }
    };
    if let Err(e) = sqlx::query(&format!(
        "SET LOCAL statement_timeout = '{QUERY_TIMEOUT_MS}'"
    ))
    .execute(&mut *tx)
    .await
    .map_err(TinkerError::Db)
    {
        send_err(&out, e).await;
        return;
    }

    // The plan's params are bound once, at DECLARE; every FETCH reuses the
    // same bound cursor inside this transaction.
    let declare_sql = format!("DECLARE tinker_stream_cur CURSOR FOR {}", plan.sql);
    let mut declare = sqlx::query(&declare_sql);
    for p in &plan.params {
        declare = bind_param(declare, p);
    }
    if let Err(e) = declare.execute(&mut *tx).await.map_err(TinkerError::Db) {
        send_err(&out, e).await;
        return;
    }

    let mut row_count: i64 = 0;
    let mut failed = false;
    loop {
        let rows = match sqlx::query(&format!(
            "FETCH FORWARD {STREAM_CHUNK} FROM tinker_stream_cur"
        ))
        .fetch_all(&mut *tx)
        .await
        .map_err(TinkerError::Db)
        {
            Ok(rows) => rows,
            Err(e) => {
                send_err(&out, e).await;
                failed = true;
                break;
            }
        };
        if rows.is_empty() {
            break;
        }
        for r in &rows {
            row_count += 1;
            if out
                .send(Ok(row_to_json(&plan.output_fields, r)))
                .await
                .is_err()
            {
                // Consumer is gone: return without audit/commit; dropping
                // `tx` rolls the cursor transaction back.
                return;
            }
        }
    }
    if failed {
        return;
    }

    let ms = started.elapsed().as_millis() as i32;
    if let Err(e) = insert_audit(&mut tx, &ctx, &plan, row_count, ms).await {
        send_err(&out, e).await;
        return;
    }
    if let Err(e) = tx.commit().await.map_err(TinkerError::Db) {
        send_err(&out, e).await;
    }
    // `out` drops here; the consumer sees `None` after the last row.
}

/// Deliver a terminal stream error to the consumer, if it is still listening.
async fn send_err(out: &tokio::sync::mpsc::Sender<Result<serde_json::Value>>, e: TinkerError) {
    let _ = out.send(Err(e)).await;
}

/// Write the query-audit row in the execution's own tenant transaction.
async fn insert_audit(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    ctx: &TenantContext,
    plan: &CompiledPlan,
    row_count: i64,
    duration_ms: i32,
) -> Result<()> {
    let hash = QueryExecutor::plan_hash(plan);
    sqlx::query(
        r#"INSERT INTO query_audit
           (organization_id, actor_id, object_id, sql_hash, row_count, duration_ms)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(ctx.organization_id.0)
    .bind(ctx.actor_id)
    .bind(plan.object_id)
    .bind(&hash)
    .bind(row_count as i32)
    .bind(duration_ms)
    .execute(&mut **tx)
    .await
    .map_err(TinkerError::Db)?;
    Ok(())
}

/// Decode one result row to a JSON object keyed by the plan's output field
/// names (plus `__id`, which the compiler appends as the trailing column
/// unless explicitly selected).
fn row_to_json(output_fields: &[String], row: &sqlx::postgres::PgRow) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for (i, name) in output_fields.iter().enumerate() {
        obj.insert(name.clone(), column_json(row, i));
    }
    if !output_fields.iter().any(|n| n == "__id") {
        obj.insert("__id".to_string(), column_json(row, output_fields.len()));
    }
    serde_json::Value::Object(obj)
}

fn hex_of(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Bind one typed [`Param`] to a SQLx query.
///
/// This is the single canonical `Param` → SQLx binding path: the executor,
/// the row streamer, and any test harness executing compiled plans must all
/// go through here so the declared bind type for each `Param` variant stays
/// identical everywhere. (sqlx's prepared-statement cache is keyed by SQL
/// text alone — a second, divergent binder is how INT4/INT8 cache poisoning
/// starts.)
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

/// Decode a result column to JSON without knowing its type statically.
/// Dispatches on the Postgres type name so NUMERIC (the ontology's
/// number/currency) decodes exactly; everything else falls back to the
/// natural JSON mapping, then to text.
fn column_json(row: &sqlx::postgres::PgRow, idx: usize) -> serde_json::Value {
    use sqlx::{Column, TypeInfo, ValueRef};
    let type_name = row
        .columns()
        .get(idx)
        .map(|c| c.type_info().name().to_string())
        .unwrap_or_default();

    if type_name == "NUMERIC" {
        if let Ok(v) = row.try_get::<bigdecimal::BigDecimal, _>(idx) {
            let s = v.to_string();
            if let Ok(n) = s.parse::<i64>() {
                return serde_json::json!(n);
            }
            if let Ok(n) = s.parse::<f64>() {
                return serde_json::json!(n);
            }
            return serde_json::Value::String(s);
        }
        return serde_json::Value::Null;
    }

    let raw = row.try_get_raw(idx);
    let Ok(raw) = raw else {
        return serde_json::Value::Null;
    };
    if raw.is_null() {
        return serde_json::Value::Null;
    }
    if let Ok(v) = raw.as_str() {
        return serde_json::Value::String(v.to_string());
    }
    if let Ok(v) = row.try_get::<bool, _>(idx) {
        return serde_json::Value::Bool(v);
    }
    if let Ok(v) = row.try_get::<i32, _>(idx) {
        return serde_json::json!(v);
    }
    if let Ok(v) = row.try_get::<i64, _>(idx) {
        return serde_json::json!(v);
    }
    if let Ok(v) = row.try_get::<f64, _>(idx) {
        return serde_json::json!(v);
    }
    if let Ok(v) = row.try_get::<uuid::Uuid, _>(idx) {
        return serde_json::json!(v.to_string());
    }
    if let Ok(v) = row.try_get::<chrono::DateTime<chrono::Utc>, _>(idx) {
        return serde_json::json!(v.to_rfc3339());
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDate, _>(idx) {
        return serde_json::json!(v.to_string());
    }
    if let Ok(v) = row.try_get::<chrono::NaiveDateTime, _>(idx) {
        return serde_json::json!(v.to_string());
    }
    // TEXT[] (the ontology's multi_select): decode to a JSON array instead
    // of falling through to Null.
    if let Ok(v) = row.try_get::<Vec<String>, _>(idx) {
        return serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect());
    }
    if let Ok(v) = row.try_get::<serde_json::Value, _>(idx) {
        return v;
    }
    serde_json::Value::Null
}
