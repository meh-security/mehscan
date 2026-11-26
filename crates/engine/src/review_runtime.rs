//! Bound the actual trusted skill package, including referenced code and policy.
use crate::EngineError;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn skill_bundle_id(root: &Path) -> Result<String, EngineError> {
    bundle_digest(root, false)
}

/// Validate attempts made with the original full-distribution digest as well.
pub fn matches_skill_bundle(root: &Path, expected: &str) -> Result<bool, EngineError> {
    Ok(bundle_digest(root, expected.starts_with("mehscanSkillBundle/v1:"))? == expected)
}

fn bundle_digest(root: &Path, legacy: bool) -> Result<String, EngineError> {
    #[derive(serde::Deserialize)]
    struct FilePolicy {
        distribution_only: Vec<String>,
    }
    fn visit(
        root: &Path,
        directory: &Path,
        rows: &mut Vec<(String, String)>,
        entries: &mut usize,
        bytes: &mut u64,
        excluded: &[String],
    ) -> Result<(), EngineError> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            *entries += 1;
            if *entries > 1024 {
                return Err(EngineError("skill package exceeds entry limit".into()));
            }
            let name = entry.file_name();
            if name == ".git" || name == "__pycache__" {
                continue;
            }
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(EngineError(
                    "trusted skill package cannot contain symlinks".into(),
                ));
            }
            if metadata.is_dir() {
                visit(root, &path, rows, entries, bytes, excluded)?;
            } else if metadata.is_file() {
                *bytes += metadata.len();
                if *bytes > 8 * 1024 * 1024 {
                    return Err(EngineError("skill package exceeds byte limit".into()));
                }
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_str()
                    .ok_or_else(|| EngineError("skill package paths must be UTF-8".into()))?
                    .replace('\\', "/");
                if excluded.contains(&relative) {
                    continue;
                }
                rows.push((
                    relative,
                    format!("{:x}", Sha256::digest(std::fs::read(path)?)),
                ));
            } else {
                return Err(EngineError("skill package requires regular files".into()));
            }
        }
        Ok(())
    }
    let root = std::fs::canonicalize(root)?;
    let mut rows = Vec::new();
    let policy: FilePolicy =
        serde_json::from_str(include_str!("../../../scripts/skill-runtime-v2.json"))
            .map_err(|error| EngineError(error.to_string()))?;
    let (version, excluded): (&str, &[String]) = if legacy {
        ("mehscanSkillBundle/v1", &[])
    } else {
        ("mehscanSkillBundle/v2", &policy.distribution_only)
    };
    visit(&root, &root, &mut rows, &mut 0, &mut 0, excluded)?;
    if !rows.iter().any(|(path, _)| path == "SKILL.md") {
        return Err(EngineError("skill package requires SKILL.md".into()));
    }
    rows.sort();
    let bytes =
        serde_json::to_vec(&(version, rows)).map_err(|error| EngineError(error.to_string()))?;
    Ok(format!("{version}:{:x}", Sha256::digest(bytes)))
}
