//! Governed reactivity loop (PRD M2).
//!
//! One typed query feeds `rt-grid` over SSE. Every path the data touches —
//! query, cache, job, search, virtual file, SSE — is tenant-scoped, so
//! colliding record IDs can never cross organizations.
//!
//! - [`exec`]: executes compiled plans with a statement timeout and audit.
//! - [`cache`]: tenant-scoped result cache keyed by `(org, plan hash)`.
//! - [`signal`]: per-org change bus; id-only invalidation envelopes.
//! - [`vfile`]: virtual files as tenant-scoped views over queries.

pub mod cache;
pub mod exec;
pub mod grants;
pub mod meta;
pub mod signal;
pub mod vfile;

pub use cache::QueryCache;
pub use exec::{bind_param, QueryExecutor, RowStream, STREAM_CHUNK};
pub use grants::FieldGrants;
pub use meta::{MetaCache, QueryInputs, META_MAX_ENTRIES, META_TTL};
pub use signal::{Signal, SignalBus, SignalKind};
pub use vfile::resolve_vpath;
