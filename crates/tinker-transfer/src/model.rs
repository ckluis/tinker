//! Shared types for the M8 transfer plane.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tinker_core::Result;
use uuid::Uuid;

/// Authority state machine for one external system (PRD v0.6 §22).
///
/// ```text
/// connected -> mirrored -> augmented -> controlled -> primary
///     -> draining -> retired (terminal)
/// ```
/// Rollback returns to `mirrored` from `primary` or `draining`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Connected,
    Mirrored,
    Augmented,
    Controlled,
    Primary,
    Draining,
    Retired,
}

impl TransferState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "connected",
            Self::Mirrored => "mirrored",
            Self::Augmented => "augmented",
            Self::Controlled => "controlled",
            Self::Primary => "primary",
            Self::Draining => "draining",
            Self::Retired => "retired",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "connected" => Ok(Self::Connected),
            "mirrored" => Ok(Self::Mirrored),
            "augmented" => Ok(Self::Augmented),
            "controlled" => Ok(Self::Controlled),
            "primary" => Ok(Self::Primary),
            "draining" => Ok(Self::Draining),
            "retired" => Ok(Self::Retired),
            other => Err(tinker_core::TinkerError::Validation(format!(
                "unknown transfer state: {other}"
            ))),
        }
    }

    /// Forward transitions allowed without a gate run.
    pub fn forward(self) -> Option<Self> {
        match self {
            Self::Connected => Some(Self::Mirrored),
            Self::Mirrored => Some(Self::Augmented),
            Self::Augmented => Some(Self::Controlled),
            Self::Controlled => Some(Self::Primary),
            Self::Primary => Some(Self::Draining),
            Self::Draining => Some(Self::Retired),
            Self::Retired => None,
        }
    }
}

/// Which field authority a record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    Tinker,
    External,
}

impl Authority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tinker => "tinker",
            Self::External => "external",
        }
    }
}

/// Cutover operation kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CutoverKind {
    Cutover,
    Rollback,
    Retire,
}

impl CutoverKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cutover => "cutover",
            Self::Rollback => "rollback",
            Self::Retire => "retire",
        }
    }
}

/// One checklist item with real evidence: who verified it, when, and what
/// the evidence was. A bare boolean is not evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecklistItem {
    pub verified: bool,
    pub by: Uuid,
    pub at: DateTime<Utc>,
    pub evidence: String,
}

/// The full cutover gate (PRD v0.6 §22): no source is retired — or cut
/// over — without export verification, a rollback procedure, ownership
/// sign-off, a dependency scan, and a period of clean reconciliation.
pub const FULL_GATE: &[&str] = &[
    "export_verified",
    "rollback_procedure",
    "owner_signoff",
    "dependency_scan",
    "reconciliation_clean",
];

/// Rollback needs a plan and an owner, not the full evidence set.
pub const ROLLBACK_GATE: &[&str] = &["rollback_procedure", "owner_signoff"];

/// Max evidence text per checklist item.
pub const CHECKLIST_ITEM_MAX_EVIDENCE: usize = 4096;

/// Actor modes for the operator plane (PRD v0.6 §34).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorMode {
    /// Ordinary tenant actor: normal row/field policy.
    Tenant,
    /// Support actor inside a time-boxed, reason-bound, masked session.
    Support,
    /// Aggregate actor: token-blind metric resources only.
    Aggregate,
}

/// A PII reference resolution outcome. Missing PII fails closed as
/// unavailable — never stale plaintext, never a bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefStatus {
    Available,
    Unavailable,
}

/// Sync health for one system, rendered on the replacement dashboard.
/// Sourced from the ingest control plane when wired; the dashboard takes
/// it as data rather than reaching across crates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncHealth {
    pub system_key: String,
    pub last_sync_at: Option<DateTime<Utc>>,
    pub lag_seconds: Option<i64>,
    pub errors_24h: i64,
    pub retries_24h: i64,
    pub reconciliation_drift: i64,
}
