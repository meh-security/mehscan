//! Bound the actual trusted skill package, including referenced code and policy.
use crate::EngineError;
use sha2::{Digest, Sha256};
use std::path::Path;

pub fn skill_bundle_id(root: &Path) -> Result<String, EngineError> {
    fn visit(
        root: &Path,
        directory: &Path,
        rows: &mut Vec<(String, String)>,
        entries: &mut usize,
        bytes: &mut u64,
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
                visit(root, &path, rows, entries, bytes)?;
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
    visit(&root, &root, &mut rows, &mut 0, &mut 0)?;
    if !rows.iter().any(|(path, _)| path == "SKILL.md") {
        return Err(EngineError("skill package requires SKILL.md".into()));
    }
    rows.sort();
    let bytes = serde_json::to_vec(&("mehscanSkillBundle/v1", rows))
        .map_err(|error| EngineError(error.to_string()))?;
    Ok(format!("mehscanSkillBundle/v1:{:x}", Sha256::digest(bytes)))
}
