//! M7: context and agents.
//!
//! One semantic access layer for every consumer (virtual files, MCP, CLI,
//! apps, exports). Pipeline per read:
//!
//!   Identify (actor + purpose) → Authorize (row + field) →
//!   Transform (rules first, model only for richtext) → Emit → Audit.
//!
//! Rules-only degradation: a failed or over-budget transform omits the
//! field or emits an explicit unavailable marker — never the raw value.
//! Transform never expands access: forbidden rows/fields are removed
//! BEFORE any value reaches a model prompt.

pub mod actions;
pub mod adapters;
pub mod approval;
pub mod audit;
pub mod budgets;
pub mod cache;
pub mod costs;
pub mod expand;
pub mod files;
pub mod gateway;
pub mod mcp;
pub mod mcp_stdio;
pub mod profiles;
pub mod renewal;
pub mod transforms;
pub mod vfile;

pub use actions::{ActionDef, ActionRegistry};
pub use approval::{ApprovalEngine, ApprovalPolicy, ApprovalRequest};
pub use audit::{AuditWriter, DisclosureRecord};
pub use budgets::{BudgetLedger, ExpansionBudget, SpendBudget};
pub use cache::TransformCache;
pub use expand::{
    ExpansionEngine, ExpansionManifest, RankingRecord, SemanticRanker, FANOUT_CAP, RANK_POOL_CAP,
};
pub use gateway::{
    cosine_similarity, Completion, EmbeddingAdapter, FakeEmbeddingAdapter, FakeModelAdapter,
    HostileModelAdapter, ModelAdapter, ModelGateway, UnavailableEmbeddingAdapter,
    UnavailableModelAdapter,
};
pub use profiles::{ContextProfile, ProfileEngine};
pub use renewal::RenewalAgent;
pub use transforms::{FieldTransform, TransformEngine};
pub use vfile::{VirtualFileReader, VirtualPath};
