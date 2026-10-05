//! M8 — Authority transfer and hardening.
//!
//! This crate implements the strangler-migration plane (PRD v0.6 §22),
//! the host/portfolio operator plane (PRD v0.6 §34), the two-store
//! recovery rehearsal (PRD v0.6 §41), the self-promotion soak (PRD v0.6
//! §38), and the multi-instance session/cache contract (PRD v0.6 §43).
//!
//! Everything here is tenant-scoped: every write goes through a
//! [`tinker_db::CoreDb::tenant_tx`] so RLS is the backstop behind the
//! code-level checks.

pub mod host;
pub mod model;
pub mod ops;
pub mod redis_store;
pub mod scanner;
pub mod sessions;
pub mod transfer;

pub use host::{AggregateQuery, SupportEngine, Telemetry, TelemetryPoint};
pub use model::*;
pub use ops::{
    PromotionOutcome, PromotionResult, PromotionSoak, RehearsalReport, RestoreRehearsal,
    RetentionEngine, RetentionOutcome,
};
pub use redis_store::RedisSessionStore;
pub use scanner::{DependencyEdge, DependencyScanner, ReplacementDashboard};
pub use sessions::{InMemorySessionStore, SessionStore};
pub use transfer::TransferEngine;
