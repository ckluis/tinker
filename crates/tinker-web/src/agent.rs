//! Item 44 (agent front door, Part 3): `tinker agent` — install and verify
//! the version-matched agent skill.
//!
//! The skill ships as a source file with version placeholders
//! (`skills/tinker/SKILL.md`, embedded at compile time). `install`
//! substitutes the running binary's versions and writes the skill into
//! the standard agent-skills location; `verify` reads an installed skill
//! back and fails loudly when its pinned versions drift from the binary.
//!
//! Install locations (the agent-skills convention: a project-local
//! `.claude/skills/` directory plus a personal `~/.claude/skills/`):
//! - default: `./.claude/skills/tinker/` — project-local, travels with
//!   the repo the agent works in;
//! - `--global`: `~/.claude/skills/tinker/` — personal, every project.
//! `--dir <path>` overrides the skills root for hermetic installs and
//! tests. Nothing outside `<root>/tinker/` is ever touched.

use std::path::{Path, PathBuf};

use tinker_core::{Result, TinkerError};

/// The skill directory name inside a skills root.
pub const SKILL_DIR_NAME: &str = "tinker";
/// The skill file name inside the skill directory.
pub const SKILL_FILE_NAME: &str = "SKILL.md";

/// Placeholders in the source skill, substituted at install time with
/// the building binary's versions. The source file is version-agnostic
/// so releases don't churn it; the INSTALLED file is pinned.
const TINKER_VERSION_PLACEHOLDER: &str = "__TINKER_VERSION__";
const ONTOLOGY_VERSION_PLACEHOLDER: &str = "__ONTOLOGY_VERSION__";

/// The skill source, embedded at compile time.
pub const SKILL_SOURCE: &str = include_str!("../skills/tinker/SKILL.md");

/// Versions pinned in an installed skill's frontmatter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillVersions {
    pub tinker_version: String,
    pub ontology_version: String,
}

/// The versions this binary pins skills against.
pub fn current_versions() -> SkillVersions {
    SkillVersions {
        tinker_version: crate::describe::tinker_version().to_string(),
        ontology_version: crate::describe::ontology_version(),
    }
}

/// Render the skill with the binary's versions substituted. The installed
/// file must contain no placeholders — a placeholder that survives is a
/// build/install bug, and `verify` would (correctly) report drift.
pub fn render_skill() -> String {
    let current = current_versions();
    SKILL_SOURCE
        .replace(TINKER_VERSION_PLACEHOLDER, &current.tinker_version)
        .replace(ONTOLOGY_VERSION_PLACEHOLDER, &current.ontology_version)
}

/// Default skills root: project-local `./.claude/skills`, or the
/// personal `~/.claude/skills` with `--global`.
pub fn default_skills_root(global: bool) -> Result<PathBuf> {
    if !global {
        return Ok(PathBuf::from(".claude/skills"));
    }
    let home = std::env::var("HOME").map_err(|_| {
        TinkerError::Internal("HOME is not set; cannot resolve --global skills dir".into())
    })?;
    Ok(PathBuf::from(home).join(".claude/skills"))
}

/// Install (or refresh) the skill under `<skills_root>/tinker/`.
/// Idempotent: re-running overwrites with the current versions.
/// Returns the installed `SKILL.md` path.
pub fn install_skill(skills_root: &Path) -> Result<PathBuf> {
    let dir = skills_root.join(SKILL_DIR_NAME);
    std::fs::create_dir_all(&dir)
        .map_err(|e| TinkerError::Internal(format!("creating skill dir {}: {e}", dir.display())))?;
    let path = dir.join(SKILL_FILE_NAME);
    let rendered = render_skill();
    debug_assert!(
        !rendered.contains(TINKER_VERSION_PLACEHOLDER)
            && !rendered.contains(ONTOLOGY_VERSION_PLACEHOLDER),
        "render_skill left a version placeholder behind"
    );
    std::fs::write(&path, rendered)
        .map_err(|e| TinkerError::Internal(format!("writing skill {}: {e}", path.display())))?;
    Ok(path)
}

/// Parse `tinker_version` / `ontology_version` from a skill's YAML
/// frontmatter (the block between the first two `---` lines). Minimal
/// line parser — the frontmatter is machine-written by `install_skill`,
/// never hand-edited prose.
pub fn parse_skill_versions(text: &str) -> Result<SkillVersions> {
    let mut lines = text.lines();
    let first = lines.next().unwrap_or("");
    if first.trim() != "---" {
        return Err(TinkerError::Validation(
            "skill has no YAML frontmatter (expected '---' on the first line)".into(),
        ));
    }
    let mut tinker_version = None;
    let mut ontology_version = None;
    for line in lines {
        if line.trim() == "---" {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "tinker_version" => tinker_version = Some(value.trim().to_string()),
            "ontology_version" => ontology_version = Some(value.trim().to_string()),
            _ => {}
        }
    }
    match (tinker_version, ontology_version) {
        (Some(t), Some(o)) if !t.is_empty() && !o.is_empty() => Ok(SkillVersions {
            tinker_version: t,
            ontology_version: o,
        }),
        _ => Err(TinkerError::Validation(
            "skill frontmatter is missing tinker_version and/or ontology_version".into(),
        )),
    }
}

/// Verify the skill installed at `<skills_root>/tinker/SKILL.md` against
/// this binary's versions. Fails loudly on drift: the error names both
/// sides so the fix (re-install) is obvious.
pub fn verify_skill(skills_root: &Path) -> Result<SkillVersions> {
    let path = skills_root.join(SKILL_DIR_NAME).join(SKILL_FILE_NAME);
    let text = std::fs::read_to_string(&path).map_err(|_| {
        TinkerError::NotFound(format!(
            "no installed skill at {} — run `tinker agent install` first",
            path.display()
        ))
    })?;
    let installed = parse_skill_versions(&text)?;
    let current = current_versions();
    if installed != current {
        return Err(TinkerError::Internal(format!(
            "skill version drift: installed skill pins tinker {} / ontology {}, \
             but this binary is tinker {} / ontology {} — \
             re-run `tinker agent install` to refresh the skill",
            installed.tinker_version,
            installed.ontology_version,
            current.tinker_version,
            current.ontology_version,
        )));
    }
    Ok(installed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_substitutes_both_placeholders() {
        let rendered = render_skill();
        assert!(!rendered.contains(TINKER_VERSION_PLACEHOLDER));
        assert!(!rendered.contains(ONTOLOGY_VERSION_PLACEHOLDER));
        let current = current_versions();
        assert!(rendered.contains(&format!("tinker_version: {}", current.tinker_version)));
        assert!(rendered.contains(&format!("ontology_version: {}", current.ontology_version)));
    }

    #[test]
    fn parse_round_trips_rendered_skill() {
        let parsed = parse_skill_versions(&render_skill()).unwrap();
        assert_eq!(parsed, current_versions());
    }

    #[test]
    fn parse_rejects_missing_frontmatter() {
        let err = parse_skill_versions("no frontmatter here").unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)));
    }

    #[test]
    fn parse_rejects_missing_keys() {
        let err = parse_skill_versions("---\nname: tinker\n---\nbody\n").unwrap_err();
        assert!(matches!(err, TinkerError::Validation(_)));
    }

    #[test]
    fn install_then_verify_round_trip() {
        let root = std::env::temp_dir().join(format!("tinker-skill-ut-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = install_skill(&root).unwrap();
        assert_eq!(path, root.join("tinker").join("SKILL.md"));
        assert!(path.is_file());
        let verified = verify_skill(&root).unwrap();
        assert_eq!(verified, current_versions());
        // Idempotent: re-install overwrites cleanly and still verifies.
        install_skill(&root).unwrap();
        verify_skill(&root).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_fails_loudly_on_drift() {
        let root = std::env::temp_dir().join(format!("tinker-skill-drift-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        install_skill(&root).unwrap();
        // Tamper the installed pin: simulate a stale skill.
        let path = root.join("tinker").join("SKILL.md");
        let text = std::fs::read_to_string(&path).unwrap();
        let current = current_versions();
        let tampered = text.replacen(
            &format!("tinker_version: {}", current.tinker_version),
            "tinker_version: 0.0.0-stale",
            1,
        );
        assert_ne!(tampered, text);
        std::fs::write(&path, tampered).unwrap();
        let err = verify_skill(&root).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("drift"), "expected drift message, got: {msg}");
        assert!(msg.contains("0.0.0-stale"));
        assert!(msg.contains(&current.tinker_version));
        assert!(msg.contains("tinker agent install"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_missing_skill_names_install() {
        let root =
            std::env::temp_dir().join(format!("tinker-skill-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let err = verify_skill(&root).unwrap_err();
        assert!(err.to_string().contains("tinker agent install"));
    }

    #[test]
    fn default_roots() {
        assert_eq!(
            default_skills_root(false).unwrap(),
            PathBuf::from(".claude/skills")
        );
        let global = default_skills_root(true).unwrap();
        assert!(global.ends_with(".claude/skills"));
    }
}
