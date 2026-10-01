//! Strict identifier validation for every dynamic SQL fragment in ingest.
//!
//! Landing tables, canonical targets, and mapped columns are all
//! interpolated into SQL text (bind parameters cannot name tables or
//! columns). Every such interpolation goes through this module: an
//! identifier is `[A-Za-z_][A-Za-z0-9_]{0,119}`, and a table reference is
//! exactly `data.<identifier>`. Anything else is a [`Validation`] error,
//! never SQL.

use tinker_core::{Result, TinkerError};

/// True for safe SQL identifiers: letter/underscore start, ASCII
/// alphanumerics and underscores, max 120 chars (matches the CHECK
/// constraints on the control-plane name columns).
pub fn is_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 120 && {
        let mut chars = s.chars();
        let first = chars.next().unwrap();
        (first.is_ascii_alphabetic() || first == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
}

/// Validate a bare identifier, returning it unchanged for interpolation.
pub fn ident<'a>(label: &str, s: &'a str) -> Result<&'a str> {
    if is_ident(s) {
        Ok(s)
    } else {
        Err(TinkerError::Validation(format!(
            "bad {label} identifier: {s:?}"
        )))
    }
}

/// Validate a `data.<table>` reference. The schema is pinned to `data`;
/// anything else (other schemas, qualified injections, trailing SQL) is
/// rejected.
pub fn data_table(s: &str) -> Result<&str> {
    match s.split_once('.') {
        Some(("data", table)) if is_ident(table) && !s[5..].contains('.') => Ok(s),
        _ => Err(TinkerError::Validation(format!(
            "bad data table reference: {s:?}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_table_refs_rejected() {
        for bad in [
            "data.m6_account; DROP TABLE x; --",
            "data.\"m6_account\"",
            "public.m6_account",
            "data.m6_account.foo",
            "data.",
            "m6_account",
            "",
            "data.1abc",
            "data.a-b",
        ] {
            assert!(data_table(bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(data_table("data.crm_contact").unwrap(), "data.crm_contact");
        assert_eq!(
            data_table("data.ingest_landing_abc123").unwrap(),
            "data.ingest_landing_abc123"
        );
    }

    #[test]
    fn hostile_idents_rejected() {
        for bad in [
            "",
            "1a",
            "a-b",
            "a b",
            "a\"b",
            "a'b",
            "a;b",
            &"a".repeat(121),
        ] {
            assert!(!is_ident(bad), "accepted {bad:?}");
            assert!(ident("field", bad).is_err());
        }
        assert!(is_ident("_ok"));
        assert!(is_ident("f_0k9"));
    }
}
