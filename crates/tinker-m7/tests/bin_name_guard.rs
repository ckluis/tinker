//! Item 35 regression guard: two binaries must never again share one
//! target path.
//!
//! The workspace once shipped two binaries both named `tinker` (the
//! web server in tinker-web and the CLI in tinker-m7) linking to the
//! same `target/debug/tinker` path — last writer wins. The CLI was
//! renamed to `tinker-cli`. This test fails if anyone re-introduces
//! a same-named `[[bin]]` in either manifest, by:
//!
//! 1. Asserting the declared `[[bin]]` names across tinker-web and
//!    tinker-m7 are pairwise distinct (a duplicate would relink over
//!    the sibling's output).
//! 2. Pinning the chosen names: server stays `tinker`, CLI is
//!    `tinker-cli`.
//! 3. Asserting the built binary artifact Cargo hands the harness
//!    (`CARGO_BIN_EXE_tinker-cli`) actually lives at its own
//!    `tinker-cli` path, not at the server's.

use std::collections::HashSet;

fn bin_names(manifest_path: &str) -> Vec<String> {
    let text = std::fs::read_to_string(manifest_path)
        .unwrap_or_else(|_| panic!("cannot read {manifest_path}"));
    let manifest: toml::Value = toml::from_str(&text).expect("Cargo.toml must parse");
    manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .unwrap_or_else(|| panic!("{manifest_path} declares no [[bin]]"))
        .iter()
        .map(|b| {
            b.get("name")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| panic!("[[bin]] without name in {manifest_path}"))
                .to_string()
        })
        .collect()
}

#[test]
fn workspace_bin_names_are_distinct() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let web_bins = bin_names(&format!("{manifest_dir}/../tinker-web/Cargo.toml"));
    let m7_bins = bin_names(&format!("{manifest_dir}/Cargo.toml"));

    // The chosen, product-visible names.
    assert_eq!(
        web_bins,
        vec!["tinker".to_string()],
        "server bin name drifted"
    );
    assert_eq!(
        m7_bins,
        vec!["tinker-cli".to_string()],
        "CLI bin name drifted"
    );

    // Distinctness across the workspace: a repeated name would make two
    // packages link to the same target/debug/<name> path again.
    let mut seen = HashSet::new();
    for (pkg, name) in [("tinker-web", &web_bins[0]), ("tinker-m7", &m7_bins[0])] {
        assert!(
            seen.insert((name.as_str(),)),
            "bin name collision: {pkg} also declares `{name}`"
        );
    }
}

#[test]
fn cli_artifact_lives_at_its_own_path() {
    let bin = env!("CARGO_BIN_EXE_tinker-cli");
    assert!(
        bin.ends_with("/tinker-cli"),
        "CLI artifact must be target/<profile>/tinker-cli, got {bin}"
    );
    assert!(
        std::path::Path::new(bin).is_file(),
        "CLI artifact missing at {bin}"
    );
}
