//! Connector contract: discover, page, count.
//!
//! A connector discovers objects and fields without ingesting data,
//! captures a consistent starting point, then increments by durable cursor.
//! Batches are written idempotently with source record IDs and versions.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tinker_core::{Result, TinkerError};

/// One source record: raw id, source timestamps, deletion flag, fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRecord {
    pub source_id: String,
    pub updated_at: DateTime<Utc>,
    pub deleted: bool,
    pub fields: HashMap<String, serde_json::Value>,
}

/// A discovered source object and its fields.
#[derive(Debug, Clone)]
pub struct SourceObject {
    pub name: String,
    pub fields: Vec<SourceField>,
}

#[derive(Debug, Clone)]
pub struct SourceField {
    pub name: String,
    pub type_name: String,
}

/// One page of records plus the cursor to resume after it.
#[derive(Debug, Clone)]
pub struct RecordPage {
    pub records: Vec<SourceRecord>,
    pub next_cursor: Option<String>,
}

/// The connector contract every source adapter implements.
#[async_trait]
pub trait SourceConnector: Send + Sync {
    /// Discover objects and fields without ingesting data.
    async fn discover(&self) -> Result<Vec<SourceObject>>;
    /// Fetch one page after `cursor` (None = from the start).
    async fn fetch_page(
        &self,
        object: &str,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<RecordPage>;
    /// Total non-deleted record count (for reconciliation).
    async fn count(&self, object: &str) -> Result<u64>;
}

/// A deterministic in-memory Salesforce stand-in for tests and development.
/// Real adapters (Salesforce REST/Bulk API) implement [`SourceConnector`]
/// against live endpoints; the pipeline only depends on the trait.
#[derive(Debug, Default)]
pub struct FakeSalesforce {
    inner: Mutex<FakeState>,
}

#[derive(Debug, Default)]
struct FakeState {
    objects: HashMap<String, Vec<SourceRecord>>,
    schemas: HashMap<String, Vec<SourceField>>,
}

impl FakeSalesforce {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed one object with records. Records are served in `updated_at`
    /// order; the cursor is the last served `updated_at` + source id.
    pub fn seed_object(&self, object: &str, fields: Vec<SourceField>, records: Vec<SourceRecord>) {
        let mut st = self.inner.lock().unwrap();
        st.schemas.insert(object.to_string(), fields);
        let mut recs = records;
        recs.sort_by(|a, b| {
            a.updated_at
                .cmp(&b.updated_at)
                .then_with(|| a.source_id.cmp(&b.source_id))
        });
        st.objects.insert(object.to_string(), recs);
    }

    /// Append records to an existing object (simulates source changes).
    pub fn append_records(&self, object: &str, records: Vec<SourceRecord>) {
        let mut st = self.inner.lock().unwrap();
        let entry = st.objects.entry(object.to_string()).or_default();
        entry.extend(records);
        entry.sort_by(|a, b| {
            a.updated_at
                .cmp(&b.updated_at)
                .then_with(|| a.source_id.cmp(&b.source_id))
        });
    }

    /// Reorder one object's serve order WITHOUT re-sorting (simulates a
    /// non-monotonic source: pages arrive in an order unrelated to
    /// `updated_at`, e.g. a bulk API that returns creation batches).
    /// `order` is a permutation of `0..len`; unknown objects are ignored.
    pub fn permute(&self, object: &str, order: &[usize]) {
        let mut st = self.inner.lock().unwrap();
        if let Some(recs) = st.objects.get_mut(object) {
            let src = std::mem::take(recs);
            let mut out = Vec::with_capacity(src.len());
            for &i in order {
                if let Some(r) = src.get(i) {
                    out.push(r.clone());
                }
            }
            // Any indices the permutation skipped keep their records (the
            // source still has them; they just arrive late).
            for (i, r) in src.into_iter().enumerate() {
                if !order.contains(&i) {
                    out.push(r);
                }
            }
            *recs = out;
        }
    }

    /// Rewrite a record in place WITHOUT re-sorting (simulates rewritten
    /// history: new content with an `updated_at` that can move BACKWARDS —
    /// exactly what a monotonic cursor would miss). Returns false when the
    /// record is not found.
    pub fn rewrite_record(
        &self,
        object: &str,
        source_id: &str,
        updated_at: &str,
        fields: Vec<(&str, serde_json::Value)>,
    ) -> bool {
        let mut st = self.inner.lock().unwrap();
        let Some(recs) = st.objects.get_mut(object) else {
            return false;
        };
        let Some(r) = recs.iter_mut().find(|r| r.source_id == source_id) else {
            return false;
        };
        r.updated_at = updated_at.parse().unwrap();
        r.fields = fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        true
    }

    /// Remove a record from the source entirely (simulates a hard delete
    /// with no tombstone: the record simply stops appearing in snapshots).
    /// Returns false when the record is not found.
    pub fn remove_record(&self, object: &str, source_id: &str) -> bool {
        let mut st = self.inner.lock().unwrap();
        let Some(recs) = st.objects.get_mut(object) else {
            return false;
        };
        let before = recs.len();
        recs.retain(|r| r.source_id != source_id);
        recs.len() != before
    }

    /// Add a field to an object's schema (simulates additive drift).
    pub fn add_field(&self, object: &str, field: SourceField) {
        let mut st = self.inner.lock().unwrap();
        if let Some(fields) = st.schemas.get_mut(object) {
            if !fields.iter().any(|f| f.name == field.name) {
                fields.push(field);
            }
        }
    }

    fn cursor_for(r: &SourceRecord) -> String {
        format!("{}|{}", r.updated_at.to_rfc3339(), r.source_id)
    }
}

#[async_trait]
impl SourceConnector for FakeSalesforce {
    async fn discover(&self) -> Result<Vec<SourceObject>> {
        let st = self.inner.lock().unwrap();
        Ok(st
            .schemas
            .iter()
            .map(|(name, fields)| SourceObject {
                name: name.clone(),
                fields: fields.clone(),
            })
            .collect())
    }

    async fn fetch_page(
        &self,
        object: &str,
        cursor: Option<&str>,
        page_size: usize,
    ) -> Result<RecordPage> {
        let st = self.inner.lock().unwrap();
        let records = st
            .objects
            .get(object)
            .ok_or_else(|| TinkerError::NotFound(format!("source object {object}")))?;
        let start = match cursor {
            None => 0,
            Some(c) => records
                .iter()
                .position(|r| Self::cursor_for(r) == c)
                .map(|i| i + 1)
                .unwrap_or(0),
        };
        let page: Vec<SourceRecord> = records
            .iter()
            .skip(start)
            .take(page_size)
            .cloned()
            .collect();
        let next_cursor = if start + page.len() < records.len() {
            page.last().map(Self::cursor_for)
        } else {
            None
        };
        Ok(RecordPage {
            records: page,
            next_cursor,
        })
    }

    async fn count(&self, object: &str) -> Result<u64> {
        let st = self.inner.lock().unwrap();
        Ok(st
            .objects
            .get(object)
            .map(|rs| rs.iter().filter(|r| !r.deleted).count() as u64)
            .unwrap_or(0))
    }
}

/// Shared ownership helper for tests and the web layer.
pub type SharedConnector = Arc<dyn SourceConnector>;
