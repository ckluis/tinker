//! M6 — managed ingestion and master data.
//!
//! The ingest hub makes bringing data in boring: managed connectors,
//! incremental capture via durable cursors, schema history, repairable
//! state, and queryable landing tables. Canonicalization is a separate,
//! governed step.
//!
//! Pipeline: **Extract** (connector pages) → **Land** (source-shaped real
//! tables, namespaced per stream) → **Profile** (schema fingerprint, drift
//! detection) → **Model** (field mappings, replayable) → **Promote**
//! (identity resolution → survivorship → canonical tables with provenance).
//!
//! Key invariants:
//! - Landing preserves source values, timestamps, deletions, and raw ids.
//!   It is inspectable evidence, never a JSON blob, and not yet canonical.
//! - Ingestion may continue while mappings are under review, but promotion
//!   uses only activated mappings.
//! - Ambiguous identities NEVER auto-merge: they land in the review queue.
//! - Every winning canonical value retains field-level provenance.
//! - Resync is idempotent: landing upserts on source id, promotion is
//!   converge-not-duplicate.

pub mod connector;
pub mod control;
pub mod ident;
pub mod identity;
pub mod landing;
pub mod mapping;
pub mod pipeline;
pub mod reconcile;
pub mod schema;
pub mod survivorship;

pub use connector::{FakeSalesforce, SourceConnector, SourceField, SourceObject, SourceRecord};
pub use control::{IngestControl, NewConnection, NewStream};
pub use identity::{IdentityEngine, MatchCandidate};
pub use landing::LandingWriter;
pub use mapping::{
    FieldMapping, FieldSuggestion, MappingEngine, MappingSource, MappingSourceField,
    MappingSuggestions,
};
pub use pipeline::{IngestPipeline, PipelineReport, SnapshotDiff};
pub use reconcile::Reconciler;
pub use schema::{diff_schemas, drift_check, fingerprint_schema, SchemaDrift};
pub use survivorship::{Provenance, Survivorship};
