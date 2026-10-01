//! Virtual files: paths are views over governed queries.
//!
//! "Data tables are everything; virtual files are views." A virtual path
//! never carries the organization — the caller's tenant context supplies
//! it, so the same path resolves to different rows per organization and a
//! colliding record ID in another org is unreachable by construction.
//!
//! Supported shapes:
//! - `/objects/{api_slug}` → all rows (default select, default order)
//! - `/objects/{api_slug}/{record_id}` → the single row with that id

use tinker_core::{Result, TenantContext, TinkerError};
use tinker_ontology::Ontology;
use tinker_query::{Filter, FilterOp, QueryIntent};
use uuid::Uuid;

/// Resolve a virtual path to a typed query intent for `ctx`'s organization.
pub async fn resolve_vpath(
    ontology: &Ontology,
    ctx: &TenantContext,
    path: &str,
) -> Result<QueryIntent> {
    let path = path.trim_matches('/');
    let mut parts = path.split('/');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("objects"), Some(slug), None, None) => {
            let obj = ontology.describe_object_by_slug(ctx, slug).await?;
            let select: Vec<String> = obj.fields.iter().map(|f| f.api_name.clone()).collect();
            Ok(QueryIntent {
                from: obj.id,
                select,
                filters: vec![],
                order: vec![],
                limit: Some(250),
                schema_version: None,
            })
        }
        (Some("objects"), Some(slug), Some(id), None) => {
            let obj = ontology.describe_object_by_slug(ctx, slug).await?;
            let record_id: Uuid = id
                .parse()
                .map_err(|_| TinkerError::Validation("bad record id".into()))?;
            // `__id` is the compiler's system column for the record id;
            // the tenant predicate still scopes it.
            let select: Vec<String> = obj.fields.iter().map(|f| f.api_name.clone()).collect();
            Ok(QueryIntent {
                from: obj.id,
                select,
                filters: vec![Filter {
                    field: "__id".to_string(),
                    op: FilterOp::Eq,
                    value: serde_json::json!(record_id.to_string()),
                }],
                order: vec![],
                limit: Some(1),
                schema_version: None,
            })
        }
        _ => Err(TinkerError::Validation(format!(
            "unknown virtual path: {path}"
        ))),
    }
}
