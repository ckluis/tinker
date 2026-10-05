//! Tinker core primitives: tenant context, stable identifiers, and the shared
//! error type. Every layer builds on these; no layer redefines them.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod blind_index;
pub mod handles;

/// The primary tenancy boundary. Every durable row carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OrganizationId(pub Uuid);

impl OrganizationId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for OrganizationId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for OrganizationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Complete tenant context carried by every request and job. There is no
/// ambient "current organization" in application memory; the context is
/// passed explicitly and bound to the database transaction with SET LOCAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantContext {
    pub organization_id: OrganizationId,
    pub actor_id: Uuid,
    /// Why this access is happening (e.g. "app.view", "workflow.run",
    /// "mcp.read"). Recorded in audit and used by the semantic layer.
    pub purpose: String,
    pub authenticated_at: DateTime<Utc>,
}

impl TenantContext {
    pub fn new(
        organization_id: OrganizationId,
        actor_id: Uuid,
        purpose: impl Into<String>,
    ) -> Self {
        Self {
            organization_id,
            actor_id,
            purpose: purpose.into(),
            authenticated_at: Utc::now(),
        }
    }

    /// SQL statements that pin this context to the current transaction.
    /// Transaction-local: cannot survive a pool return (by design).
    pub fn set_local_statements(&self) -> [String; 3] {
        [
            format!(
                "SET LOCAL app.organization_id = '{}'",
                self.organization_id.0
            ),
            format!("SET LOCAL app.actor_id = '{}'", self.actor_id),
            format!(
                "SET LOCAL app.purpose = '{}'",
                self.purpose.replace('\'', "''")
            ),
        ]
    }
}

/// Optimistic-concurrency conflict. Workflows treat this as an explicit
/// retry/merge/escalate event, never a silent overwrite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionConflict {
    pub object: String,
    pub record_id: Uuid,
    pub expected_version: i64,
    pub current_version: i64,
}

/// The one error type for the platform. Variants are stable; callers match
/// on them (especially `Conflict`) rather than parsing messages.
#[derive(Debug, thiserror::Error)]
pub enum TinkerError {
    #[error(
        "record version conflict on {object} {record_id}: expected {expected}, found {current}"
    )]
    Conflict {
        object: String,
        record_id: Uuid,
        expected: i64,
        current: i64,
    },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("resource busy: {0}")]
    Busy(String),
    #[error("duplicate effect suppressed: {0}")]
    DuplicateEffect(String),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("internal error: {0}")]
    Internal(String),
}

impl TinkerError {
    pub fn conflict(c: VersionConflict) -> Self {
        Self::Conflict {
            object: c.object,
            record_id: c.record_id,
            expected: c.expected_version,
            current: c.current_version,
        }
    }

    /// Machine-readable code for API and audit surfaces.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Conflict { .. } => "VERSION_CONFLICT",
            Self::NotFound(_) => "NOT_FOUND",
            Self::Forbidden(_) => "FORBIDDEN",
            Self::Validation(_) => "VALIDATION",
            Self::DuplicateEffect(_) => "DUPLICATE_EFFECT",
            Self::Busy(_) => "BUSY",
            Self::Db(_) => "DB",
            Self::Serde(_) => "SERDE",
            Self::Internal(_) => "INTERNAL",
        }
    }

    /// Classify a per-record write failure.
    ///
    /// `true` = the failure is attributable to the record's data: a human
    /// can inspect and fix it, so the pipeline should quarantine the
    /// record (conflict review) and continue the run.
    ///
    /// `false` = the failure is infrastructural: pool exhaustion, lost
    /// connections, serialization failures, authz misconfiguration, serde
    /// corruption. Quarantining the record would paint an outage as a
    /// green run with reviews pending, so the pipeline must fail the run
    /// loudly instead.
    ///
    /// PostgreSQL data-integrity violations arrive as `Db` errors but are
    /// data errors: the constraint is Postgres owning the record's
    /// invalidity (e.g. a select-options CHECK on a canonical column).
    pub fn is_record_data_error(&self) -> bool {
        match self {
            Self::Validation(_) | Self::Conflict { .. } | Self::NotFound(_) => true,
            Self::Db(sqlx::Error::Database(db)) => {
                matches!(db.code().as_deref(), Some(c) if DATA_SQLSTATES.contains(&c))
            }
            _ => false,
        }
    }
}

/// SQLSTATEs Postgres uses to report *data* problems: the record is
/// invalid, but the database itself is healthy.
const DATA_SQLSTATES: &[&str] = &[
    "23514", // check_violation (e.g. select-options CHECK)
    "23505", // unique_violation
    "23503", // foreign_key_violation
    "23502", // not_null_violation
    "22001", // string_data_right_truncation
    "22P02", // invalid_text_representation
    "22003", // numeric_value_out_of_range
];

pub type Result<T> = std::result::Result<T, TinkerError>;

/// A typed bind parameter. The query compiler and the durable runtime share
/// this so values are bound by type everywhere — never interpolated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Param {
    Text(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    Uuid(uuid::Uuid),
    Date(chrono::NaiveDate),
    Timestamp(chrono::DateTime<chrono::Utc>),
    Json(serde_json::Value),
    Null,
}

/// A compiler-built row-policy predicate for the search backends (C2,
/// item 38).
///
/// Produced ONLY by `tinker_query::RowPolicy::compile_for_search`:
/// identifiers come from the metadata registry, values are typed binds.
/// Backends splice `sql` into their match/rank statement and bind `params`
/// in order. Never construct this from user input.
///
/// Placeholder contract: `sql` uses `{{p1}}`, `{{p2}}`, ... for the binds
/// in `params` (1-based, in order). The backend substitutes each with its
/// own positional `$N`. `{{pK}}` markers are unambiguous (unlike `$N`,
/// `{{p1}}` is not a prefix of `{{p10}}`), so substitution cannot corrupt
/// numbering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledRowPolicy {
    pub object_id: Uuid,
    pub sql: String,
    pub params: Vec<Param>,
}

impl CompiledRowPolicy {
    /// Substitute `{{pK}}` markers with positional `$N` placeholders
    /// starting at `first`. Returns the substituted SQL.
    pub fn substitute(&self, first: usize) -> String {
        let mut out = self.sql.clone();
        for (i, _) in self.params.iter().enumerate() {
            let marker = format!("{{{{p{}}}}}", i + 1);
            out = out.replace(&marker, &format!("${}", first + i));
        }
        out
    }
}

impl Param {
    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        match v {
            serde_json::Value::String(s) => Ok(Self::Text(s.clone())),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(Self::Int(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(Self::Float(f))
                } else {
                    Err(TinkerError::Validation("unsupported number".into()))
                }
            }
            serde_json::Value::Bool(b) => Ok(Self::Bool(*b)),
            serde_json::Value::Null => Ok(Self::Null),
            other => Ok(Self::Json(other.clone())),
        }
    }

    /// Field-kind-aware conversion of a JSON filter value to a typed bind.
    /// Kinds are the ontology `FieldType::kind_name` strings (`text`,
    /// `number`, `date`, `relation`, ...) plus `id` for record identity.
    ///
    /// Strict by design: a value that cannot be represented in the field's
    /// physical Postgres type is a `Validation` error here — never a
    /// Postgres operator/type error mid-query, and never silent coercion.
    /// `Null` always passes through (for `IS NULL` / `IS NOT NULL` filters).
    /// Unknown kinds fall back to the kind-agnostic [`Param::from_json`].
    pub fn from_json_for_kind(kind: &str, v: &serde_json::Value) -> Result<Self> {
        if v.is_null() {
            return Ok(Self::Null);
        }
        match kind {
            "id" | "relation" => match v {
                serde_json::Value::String(s) => {
                    s.parse::<uuid::Uuid>().map(Self::Uuid).map_err(|_| {
                        TinkerError::Validation(format!("{kind} filter requires a uuid value"))
                    })
                }
                _ => Err(TinkerError::Validation(format!(
                    "{kind} filter requires a uuid value"
                ))),
            },
            "number" | "currency" => match v {
                serde_json::Value::Number(_) => match Self::from_json(v)? {
                    p @ (Self::Int(_) | Self::Float(_)) => Ok(p),
                    _ => Err(TinkerError::Validation("unsupported number".into())),
                },
                serde_json::Value::String(s) => {
                    let t = s.trim();
                    if let Ok(i) = t.parse::<i64>() {
                        Ok(Self::Int(i))
                    } else if let Ok(f) = t.parse::<f64>() {
                        Ok(Self::Float(f))
                    } else {
                        Err(TinkerError::Validation(format!(
                            "{kind} filter requires a numeric value"
                        )))
                    }
                }
                _ => Err(TinkerError::Validation(format!(
                    "{kind} filter requires a numeric value"
                ))),
            },
            "boolean" => match v {
                serde_json::Value::Bool(b) => Ok(Self::Bool(*b)),
                serde_json::Value::String(s) => match s.trim().to_lowercase().as_str() {
                    "true" => Ok(Self::Bool(true)),
                    "false" => Ok(Self::Bool(false)),
                    _ => Err(TinkerError::Validation(
                        "boolean filter requires true/false".into(),
                    )),
                },
                _ => Err(TinkerError::Validation(
                    "boolean filter requires true/false".into(),
                )),
            },
            "date" => match v {
                serde_json::Value::String(s) => {
                    chrono::NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
                        .map(Self::Date)
                        .map_err(|_| {
                            TinkerError::Validation("date filter requires YYYY-MM-DD".into())
                        })
                }
                _ => Err(TinkerError::Validation(
                    "date filter requires YYYY-MM-DD".into(),
                )),
            },
            "datetime" => match v {
                serde_json::Value::String(s) => parse_timestamp(s.trim())
                    .map(Self::Timestamp)
                    .ok_or_else(|| {
                        TinkerError::Validation("datetime filter requires RFC 3339".into())
                    }),
                _ => Err(TinkerError::Validation(
                    "datetime filter requires RFC 3339".into(),
                )),
            },
            "text" | "email" | "phone" | "url" | "select" | "file" => match v {
                serde_json::Value::String(s) => Ok(Self::Text(s.clone())),
                _ => Err(TinkerError::Validation(format!(
                    "{kind} filter requires a string value"
                ))),
            },
            "richtext" => Ok(Self::Json(v.clone())),
            "multi_select" => match v {
                serde_json::Value::Array(_) => Ok(Self::Json(v.clone())),
                _ => Err(TinkerError::Validation(
                    "multi_select filter requires an array value".into(),
                )),
            },
            _ => Self::from_json(v),
        }
    }
}

/// Parse an RFC 3339 timestamp, tolerating a missing offset by assuming UTC.
fn parse_timestamp(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    if let Ok(dt) = s.parse::<chrono::DateTime<chrono::Utc>>() {
        return Some(dt);
    }
    // Naive `YYYY-MM-DDTHH:MM:SS` (no offset): assume UTC.
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(naive.and_utc());
    }
    // Naive `YYYY-MM-DD HH:MM:SS` (no offset): assume UTC.
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(naive.and_utc());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tenant_context_emits_transaction_local_settings() {
        let org = OrganizationId(Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap());
        let actor = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let ctx = TenantContext::new(org, actor, "test");
        let stmts = ctx.set_local_statements();
        assert!(stmts[0].starts_with("SET LOCAL app.organization_id = '11111111-"));
        assert!(stmts[1].starts_with("SET LOCAL app.actor_id = '22222222-"));
        // Must be SET LOCAL (transaction-scoped), never SET (session-scoped).
        for s in stmts {
            assert!(s.starts_with("SET LOCAL "), "leaked session state: {s}");
        }
    }

    #[test]
    fn record_data_error_classification() {
        // Data errors: quarantine the record, continue the run.
        assert!(TinkerError::Validation("bad".into()).is_record_data_error());
        assert!(TinkerError::NotFound("gone".into()).is_record_data_error());
        assert!(TinkerError::conflict(VersionConflict {
            object: "o".into(),
            record_id: Uuid::nil(),
            expected_version: 1,
            current_version: 2,
        })
        .is_record_data_error());
        // Infrastructure errors: fail the run loudly, never quarantine.
        assert!(!TinkerError::Forbidden("no".into()).is_record_data_error());
        assert!(!TinkerError::Busy("taken".into()).is_record_data_error());
        assert!(!TinkerError::Internal("bug".into()).is_record_data_error());
        assert!(!TinkerError::DuplicateEffect("already applied".into()).is_record_data_error());
        let serde_err: TinkerError = serde_json::from_str::<serde_json::Value>("{oops")
            .unwrap_err()
            .into();
        assert!(!serde_err.is_record_data_error());
        // A bare sqlx transport failure (no database payload at all) is
        // infrastructural by construction.
        let transport: TinkerError = sqlx::Error::PoolTimedOut.into();
        assert!(!transport.is_record_data_error());
    }

    #[test]
    fn param_from_json_for_kind_uuid_fields_are_strict() {
        let good = serde_json::json!("11111111-1111-1111-1111-111111111111");
        for kind in ["id", "relation"] {
            let p = Param::from_json_for_kind(kind, &good).unwrap();
            assert!(matches!(p, Param::Uuid(_)), "{kind}");
            assert!(Param::from_json_for_kind(kind, &serde_json::json!("nope")).is_err());
            assert!(Param::from_json_for_kind(kind, &serde_json::json!(42)).is_err());
            // Null passes through for IS NULL / IS NOT NULL filters.
            assert!(matches!(
                Param::from_json_for_kind(kind, &serde_json::Value::Null).unwrap(),
                Param::Null
            ));
        }
    }

    #[test]
    fn param_from_json_for_kind_number_accepts_strings() {
        let p = Param::from_json_for_kind("number", &serde_json::json!(7)).unwrap();
        assert!(matches!(p, Param::Int(7)));
        let p = Param::from_json_for_kind("number", &serde_json::json!(2.5)).unwrap();
        assert!(matches!(p, Param::Float(_)));
        let p = Param::from_json_for_kind("currency", &serde_json::json!("42")).unwrap();
        assert!(matches!(p, Param::Int(42)));
        let p = Param::from_json_for_kind("number", &serde_json::json!("3.25")).unwrap();
        assert!(matches!(p, Param::Float(_)));
        assert!(Param::from_json_for_kind("number", &serde_json::json!("abc")).is_err());
        assert!(Param::from_json_for_kind("number", &serde_json::json!(true)).is_err());
        assert!(Param::from_json_for_kind("number", &serde_json::json!([1])).is_err());
    }

    #[test]
    fn param_from_json_for_kind_boolean_accepts_strings() {
        let p = Param::from_json_for_kind("boolean", &serde_json::json!(true)).unwrap();
        assert!(matches!(p, Param::Bool(true)));
        let p = Param::from_json_for_kind("boolean", &serde_json::json!("FALSE")).unwrap();
        assert!(matches!(p, Param::Bool(false)));
        assert!(Param::from_json_for_kind("boolean", &serde_json::json!("yes")).is_err());
        assert!(Param::from_json_for_kind("boolean", &serde_json::json!(1)).is_err());
    }

    #[test]
    fn param_from_json_for_kind_date_and_datetime() {
        let p = Param::from_json_for_kind("date", &serde_json::json!("2026-09-24")).unwrap();
        assert!(matches!(
            p,
            Param::Date(d) if d == chrono::NaiveDate::from_ymd_opt(2026, 9, 24).unwrap()
        ));
        assert!(Param::from_json_for_kind("date", &serde_json::json!("09/24/2026")).is_err());
        assert!(Param::from_json_for_kind("date", &serde_json::json!(20260924)).is_err());

        let p = Param::from_json_for_kind("datetime", &serde_json::json!("2026-09-24T12:00:00Z"))
            .unwrap();
        assert!(matches!(p, Param::Timestamp(_)));
        // Naive timestamps assume UTC rather than failing.
        let p = Param::from_json_for_kind("datetime", &serde_json::json!("2026-09-24T12:00:00"))
            .unwrap();
        assert!(matches!(p, Param::Timestamp(_)));
        assert!(Param::from_json_for_kind("datetime", &serde_json::json!("tomorrow")).is_err());
    }

    #[test]
    fn param_from_json_for_kind_text_fields_reject_non_strings() {
        for kind in ["text", "email", "phone", "url", "select", "file"] {
            let p = Param::from_json_for_kind(kind, &serde_json::json!("hi")).unwrap();
            assert!(matches!(p, Param::Text(_)), "{kind}");
            // Strict: a number on a text field is a validation error here,
            // not a Postgres `operator does not exist` mid-query.
            assert!(
                Param::from_json_for_kind(kind, &serde_json::json!(42)).is_err(),
                "{kind}"
            );
        }
        let p = Param::from_json_for_kind("richtext", &serde_json::json!({"a": 1})).unwrap();
        assert!(matches!(p, Param::Json(_)));
        let p = Param::from_json_for_kind("multi_select", &serde_json::json!(["a"])).unwrap();
        assert!(matches!(p, Param::Json(_)));
        assert!(Param::from_json_for_kind("multi_select", &serde_json::json!("a")).is_err());
        // Unknown kinds keep the old kind-agnostic behavior.
        let p = Param::from_json_for_kind("mystery", &serde_json::json!("x")).unwrap();
        assert!(matches!(p, Param::Text(_)));
    }
}
