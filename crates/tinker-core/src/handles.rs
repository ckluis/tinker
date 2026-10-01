//! Actor handle normalization for @-mentions (item 31).
//!
//! The SQL twin of [`normalize_handle`] is `normalize_actor_handle(text)`
//! in migration `0036_actor_handles.sql` — the two must stay in sync.
//! Both implement the recorded rules:
//!
//! - lowercase (non-ASCII letters are not in the allowed set and become
//!   separators, exactly like the SQL `lower()` + `^[a-z0-9._-]$` filter);
//! - allowed characters: `a-z 0-9 . _ -` (kept verbatim, including runs
//!   of `-` — only *other* characters act as separators);
//! - any other character acts as a separator; separator runs collapse to
//!   a single `-`;
//! - leading/trailing `-` and `.` are stripped;
//! - truncated to [`MAX_HANDLE_LEN`] characters (a truncation-exposed
//!   trailing separator is stripped too);
//! - an empty result becomes `"actor"`.
//!
//! Collision policy (applied by callers, not here): deterministic suffix,
//! GitHub-style — the first claimant keeps the bare handle, later
//! claimants get `handle-2`, `handle-3`, ...

/// Maximum handle length in characters (all kept characters are ASCII, so
/// this is also the byte length).
pub const MAX_HANDLE_LEN: usize = 64;

/// Normalize a display name (or any raw string) into a mention handle.
pub fn normalize_handle(raw: &str) -> String {
    let mut out = String::new();
    let mut need_sep = false;
    for ch in raw.chars() {
        let c = ch.to_ascii_lowercase();
        if matches!(c, 'a'..='z' | '0'..='9' | '.' | '_' | '-') {
            if need_sep && !out.is_empty() {
                out.push('-');
            }
            need_sep = false;
            out.push(c);
        } else {
            need_sep = true;
        }
    }
    let trimmed = out.trim_matches(['-', '.']);
    let mut s: String = trimmed.chars().take(MAX_HANDLE_LEN).collect();
    while s.ends_with('-') || s.ends_with('.') {
        s.pop();
    }
    if s.is_empty() {
        s.push_str("actor");
    }
    s
}

/// Build the deterministic-suffix candidate for attempt `n` (`n = 1` is
/// the bare base handle, `n = 2` appends `-2`, ...).
pub fn suffixed_handle(base: &str, n: u32) -> String {
    if n <= 1 {
        base.to_string()
    } else {
        format!("{base}-{n}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_rules() {
        assert_eq!(normalize_handle("Bob Smith"), "bob-smith");
        assert_eq!(normalize_handle("  spaces  "), "spaces");
        assert_eq!(normalize_handle("UPPER_CASE.9-x"), "upper_case.9-x");
        assert_eq!(normalize_handle("a!!b"), "a-b");
        // '-' is an allowed char: kept verbatim, separators collapse around it.
        assert_eq!(normalize_handle("a  -  b"), "a---b");
        assert_eq!(normalize_handle("...dots..."), "dots");
        assert_eq!(normalize_handle("---"), "actor");
        assert_eq!(normalize_handle(""), "actor");
        assert_eq!(normalize_handle("!!!"), "actor");
        assert_eq!(normalize_handle("éclair"), "clair");
        assert_eq!(normalize_handle("machine: backup"), "machine-backup");
        // Trailing separator exposed by truncation is stripped.
        let long = format!("{}!", "a".repeat(70));
        let h = normalize_handle(&long);
        assert_eq!(h.len(), MAX_HANDLE_LEN);
        assert!(!h.ends_with('-'));
    }

    #[test]
    fn suffix_candidates() {
        assert_eq!(suffixed_handle("bob", 1), "bob");
        assert_eq!(suffixed_handle("bob", 2), "bob-2");
        assert_eq!(suffixed_handle("bob", 11), "bob-11");
    }
}
