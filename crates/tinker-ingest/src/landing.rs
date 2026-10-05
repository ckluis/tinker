//! Source-shaped landing tables.
//!
//! Each stream lands in a real Postgres table: `data.ingest_landing_<hex>`.
//! Landing preserves source values, source timestamps, deletions, and raw
//! identifiers. It is inspectable evidence — never a JSON blob — and not
//! yet a canonical record.
//!
//! Writes are idempotent: rows upsert on the source record id, so a
//! replayed page converges instead of duplicating. DDL runs on the owner
//! handle; DML runs tenant-scoped with RLS as the backstop.

use std::collections::HashMap;
use tinker_core::{Result, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use uuid::Uuid;

use crate::connector::SourceRecord;
use crate::ident;

/// Content hash of one source record: sha256 over the source id, the
/// deletion flag, the source timestamp, and the canonicalized fields
/// (sorted by name, JSON-serialized). Two records hash equal iff the
/// mirror has nothing new to store for them — the basis of the
/// snapshot-diff strategy for non-monotonic sources.
pub fn record_content_hash(r: &SourceRecord) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(r.source_id.as_bytes());
    h.update([u8::from(r.deleted)]);
    h.update(r.updated_at.to_rfc3339().as_bytes());
    let mut names: Vec<&String> = r.fields.keys().collect();
    names.sort();
    for n in names {
        h.update(n.as_bytes());
        h.update([0]);
        // serde_json::Map is a BTreeMap (deterministic key order) unless
        // the preserve_order feature is on; nested objects therefore
        // serialize canonically.
        h.update(
            serde_json::to_string(&r.fields[n])
                .unwrap_or_default()
                .as_bytes(),
        );
        h.update([0]);
    }
    format!("{:x}", h.finalize())
}

/// Physical table name for a stream. Hex of the stream UUID keeps it a
/// valid, injection-proof identifier (no user input reaches DDL).
pub struct LandingWriter {
    core: CoreDb,
    owner: OwnerDb,
}

impl LandingWriter {
    pub fn new(core: CoreDb, owner: OwnerDb) -> Self {
        Self { core, owner }
    }

    /// Physical table name for a stream. Hex of the stream UUID keeps it a
    /// valid, injection-proof identifier (no user input reaches DDL).
    pub fn table_for(stream_id: Uuid) -> String {
        format!("data.ingest_landing_{}", stream_id.simple())
    }

    /// Create the landing table for the given source field names. Field
    /// names are validated identifiers (letters, digits, underscore).
    pub async fn ensure_table(&self, stream_id: Uuid, fields: &[String]) -> Result<String> {
        for f in fields {
            ident::ident("landing field", f)?;
        }
        let table = Self::table_for(stream_id);
        let mut cols = vec![
            "_source_id TEXT NOT NULL".to_string(),
            "_source_updated_at TIMESTAMPTZ NOT NULL".to_string(),
            "_deleted BOOLEAN NOT NULL DEFAULT false".to_string(),
            "_ingested_at TIMESTAMPTZ NOT NULL DEFAULT now()".to_string(),
            // Content hash of the landed record (see record_content_hash).
            // Lets snapshot-mode streams land only the diff instead of
            // rewriting every row on every run.
            "_record_hash TEXT".to_string(),
            "organization_id UUID NOT NULL".to_string(),
        ];
        for f in fields {
            cols.push(format!("\"{f}\" JSONB"));
        }
        cols.push("PRIMARY KEY (organization_id, _source_id)".to_string());
        let mut conn = self
            .owner
            .0
            .acquire()
            .await
            .map_err(tinker_core::TinkerError::Db)?;
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {table} ({})",
            cols.join(", ")
        ))
        .execute(&mut *conn)
        .await
        .map_err(tinker_core::TinkerError::Db)?;
        // Tenant backstop: the NULLIF guard keeps recycled connections with
        // an empty GUC from erroring (see 0017).
        let pol = format!("tenant_isolation_ingest_landing_{}", stream_id.simple());
        for stmt in [
            format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"),
            format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"),
            format!("DROP POLICY IF EXISTS \"{pol}\" ON {table}"),
            format!(
                "CREATE POLICY \"{pol}\" ON {table}
                 USING (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)
                 WITH CHECK (organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid)"
            ),
            // Belt-and-braces: default privileges (0001) already grant the
            // app role DML on future owner-created tables, but an explicit
            // grant here keeps landing usable even if defaults were altered.
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ".to_string()
                + &table
                + " TO tinker_app",
        ] {
            sqlx::query(&stmt)
                .execute(&mut *conn)
                .await
                .map_err(tinker_core::TinkerError::Db)?;
        }
        // Landing tables created before the snapshot-diff hardening have
        // no _record_hash column; backfill it idempotently here so every
        // stream (old or new) carries the column before any diff runs.
        sqlx::query(&format!(
            "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS _record_hash TEXT"
        ))
        .execute(&mut *conn)
        .await
        .map_err(tinker_core::TinkerError::Db)?;
        // Existing rows predate hashing and keep a NULL hash, which the
        // snapshot diff treats as "changed": the first snapshot run after
        // this change re-lands them once (idempotent upserts) and stores
        // their hashes, after which diffs are stable.
        Ok(table)
    }

    /// Add columns for newly observed source fields (additive drift).
    /// Historical rows keep NULL for the new columns.
    pub async fn add_columns(&self, stream_id: Uuid, fields: &[String]) -> Result<()> {
        for f in fields {
            ident::ident("landing field", f)?;
        }
        if fields.is_empty() {
            return Ok(());
        }
        let table = Self::table_for(stream_id);
        let mut conn = self
            .owner
            .0
            .acquire()
            .await
            .map_err(tinker_core::TinkerError::Db)?;
        for f in fields {
            sqlx::query(&format!(
                "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS \"{f}\" JSONB"
            ))
            .execute(&mut *conn)
            .await
            .map_err(tinker_core::TinkerError::Db)?;
        }
        Ok(())
    }

    /// Idempotent batch write: upsert on `_source_id`. A replayed page
    /// converges (latest source values win) instead of duplicating.
    /// Returns the number of rows written.
    /// Land one page of source records with a single multi-row INSERT
    /// (plus ON CONFLICT upsert): one round trip per batch instead of one
    /// per record. Same transaction and same
    /// `ON CONFLICT (organization_id, _source_id) DO UPDATE` semantics as
    /// the old per-row loop — landing upserts still converge on replay,
    /// and a failed batch still rolls back atomically.
    pub async fn write_batch(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        fields: &[String],
        records: &[SourceRecord],
    ) -> Result<u64> {
        if records.is_empty() {
            return Ok(0);
        }
        let table = Self::table_for(stream_id);
        for f in fields {
            ident::ident("landing field", f)?;
        }
        // Fixed column list, shared by every row: 5 bookkeeping columns
        // then the source fields. A missing source field binds SQL NULL
        // (not JSONB null) so COUNT(col) measures presence.
        let cols: Vec<String> = [
            "_source_id",
            "_source_updated_at",
            "_deleted",
            "_record_hash",
            "organization_id",
        ]
        .into_iter()
        .map(|c| c.to_string())
        .chain(fields.iter().map(|f| format!("\"{f}\"")))
        .collect();
        let per_row = 5 + fields.len();
        let set_clause: Vec<String> = ["_source_updated_at", "_deleted", "_record_hash"]
            .into_iter()
            .map(|c| format!("{c}=EXCLUDED.{c}"))
            .chain(fields.iter().map(|f| format!("\"{f}\"=EXCLUDED.\"{f}\"")))
            .collect();
        let mut tx = self.core.tenant_tx(ctx).await?;
        // Stay under Postgres's 65535-parameter limit no matter how wide
        // the source is: one statement per chunk, same transaction.
        for chunk in records.chunks(1000) {
            let mut tuples: Vec<String> = Vec::with_capacity(chunk.len());
            for (ri, _) in chunk.iter().enumerate() {
                let base = ri * per_row;
                let ph: Vec<String> = (1..=per_row).map(|i| format!("${}", base + i)).collect();
                tuples.push(format!("({})", ph.join(", ")));
            }
            let sql = format!(
                "INSERT INTO {table} ({}) VALUES {} \
                 ON CONFLICT (organization_id, _source_id) DO UPDATE SET {}",
                cols.join(", "),
                tuples.join(", "),
                set_clause.join(", ")
            );
            let mut q = sqlx::query(&sql);
            for r in chunk {
                q = q
                    .bind(&r.source_id)
                    .bind(r.updated_at)
                    .bind(r.deleted)
                    .bind(record_content_hash(r))
                    .bind(ctx.organization_id.0);
                for f in fields {
                    q = q.bind(r.fields.get(f).cloned());
                }
            }
            q.execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(records.len() as u64)
    }

    /// Stored content hashes for the given source ids (this org), for
    /// snapshot-diff comparison. Missing rows — and rows that landed
    /// before hashing existed (NULL) — come back as None, which the
    /// caller treats as "changed".
    pub async fn record_hashes(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        source_ids: &[String],
    ) -> Result<HashMap<String, Option<String>>> {
        let table = Self::table_for(stream_id);
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(&format!(
            "SELECT _source_id, _record_hash FROM {table}
             WHERE organization_id=$1 AND _source_id = ANY($2)"
        ))
        .bind(ctx.organization_id.0)
        .bind(source_ids)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut out: HashMap<String, Option<String>> = HashMap::new();
        for (id, h) in rows {
            out.insert(id, h);
        }
        Ok(out)
    }

    /// Snapshot-diff deletion sweep: mark landed (non-deleted) rows whose
    /// source ids were NOT seen in the just-completed full snapshot as
    /// deleted. In snapshot mode the scan covers the whole source, so
    /// absence is evidence of deletion — unlike incremental mode, where
    /// absence from a page window means nothing. Returns the count marked.
    /// Canonical rows already promoted are NOT removed: the mirror records
    /// the deletion; canonical tombstone policy is a separate design
    /// decision.
    pub async fn mark_missing_deleted(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        seen_source_ids: &[String],
    ) -> Result<u64> {
        let table = Self::table_for(stream_id);
        let mut tx = self.core.tenant_tx(ctx).await?;
        // One statement over the whole id list (a single array bind, not
        // one parameter per id — no 65535-parameter ceiling). An empty list
        // means the snapshot was empty: ANY('{}') matches nothing, so
        // NOT (...) is true for every landed row — the intended semantics.
        let marked = sqlx::query(&format!(
            "UPDATE {table} SET _deleted=true
             WHERE organization_id=$1 AND _deleted=false
               AND NOT (_source_id = ANY($2))"
        ))
        .bind(ctx.organization_id.0)
        .bind(seen_source_ids)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        tx.commit().await?;
        Ok(marked)
    }

    /// Landed row count for this org (reconciliation input).
    pub async fn landed_count(&self, ctx: &TenantContext, stream_id: Uuid) -> Result<i64> {
        let table = Self::table_for(stream_id);
        let mut tx = self.core.tenant_tx(ctx).await?;
        let (n,): (i64,) = sqlx::query_as(&format!(
            "SELECT count(*) FROM {table} WHERE organization_id=$1 AND _deleted=false"
        ))
        .bind(ctx.organization_id.0)
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(n)
    }

    /// Fetch landed rows for promotion, paged by source id.
    pub async fn fetch_page(
        &self,
        ctx: &TenantContext,
        stream_id: Uuid,
        fields: &[String],
        after_source_id: Option<&str>,
        limit: i64,
    ) -> Result<Vec<HashMap<String, serde_json::Value>>> {
        for f in fields {
            ident::ident("landing field", f)?;
        }
        let table = Self::table_for(stream_id);
        let select_cols: Vec<String> = std::iter::once("_source_id".to_string())
            .chain(std::iter::once("_source_updated_at".to_string()))
            .chain(std::iter::once("_deleted".to_string()))
            .chain(fields.iter().map(|f| format!("\"{f}\"")))
            .collect();
        let mut tx = self.core.tenant_tx(ctx).await?;
        let rows: Vec<sqlx::postgres::PgRow> = sqlx::query(&format!(
            "SELECT {} FROM {table}
             WHERE organization_id=$1 AND (_deleted=false)
               AND ($2 IS NULL OR _source_id > $2)
             ORDER BY _source_id LIMIT $3",
            select_cols.join(", ")
        ))
        .bind(ctx.organization_id.0)
        .bind(after_source_id)
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        use sqlx::Row;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let mut map = HashMap::new();
            map.insert(
                "_source_id".to_string(),
                serde_json::Value::String(row.get("_source_id")),
            );
            let ts: chrono::DateTime<chrono::Utc> = row.get("_source_updated_at");
            map.insert(
                "_source_updated_at".to_string(),
                serde_json::json!(ts.to_rfc3339()),
            );
            for f in fields {
                let v: Option<serde_json::Value> = row.try_get(f.as_str()).unwrap_or(None);
                map.insert(f.clone(), v.unwrap_or(serde_json::Value::Null));
            }
            out.push(map);
        }
        Ok(out)
    }
}
