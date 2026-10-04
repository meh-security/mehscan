//! Prepare explicit Roslyn inputs from an existing NuGet restore graph. No restore/build.
use crate::{
    EngineError,
    csharp_semantic::{digest, source_path},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

/// Resolve only the selected target's compile metadata. Sources/options/framework
/// references remain supplied by the caller; project-reference placeholders are gaps.
pub fn prepare(root: &Path, seed_path: &Path, output: &Path) -> Result<Value, EngineError> {
    let seed_bytes = read(seed_path)?;
    let mut document: Value = serde_json::from_slice(&seed_bytes).map_err(err)?;
    if document.get("input_files").is_some() {
        return Err(err("Use the original context seed, not a prepared context"));
    }
    let mut inputs = vec![file_hash(seed_path, &seed_bytes)?];
    if let Some(files) = document.get("context_files") {
        for path in strings(files)? {
            inputs.push(file_hash(Path::new(&path), &read(Path::new(&path))?)?);
        }
    }
    let projects = document
        .get_mut("projects")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| err("Context requires projects"))?;
    let mut summaries = Vec::new();
    for project in projects {
        for path in strings(&project["sources"])? {
            source_path(root, &path)?;
        }
        let id = text(&project["id"])?;
        let framework = text(&project["target_framework"])?;
        let assets_path = PathBuf::from(text(&project["assets_file"])?);
        if !assets_path.is_absolute() {
            return Err(err("assets_file must be absolute"));
        }
        let target_key = text(&project["assets_target"])?;
        if target_key.split('/').next() != Some(framework.as_str()) {
            return Err(err(
                "assets_target must match target_framework (modern short target keys only)",
            ));
        }
        let bytes = read(&assets_path)?;
        let assets: Value = serde_json::from_slice(&bytes).map_err(err)?;
        let target = assets["targets"][&target_key].as_object().ok_or_else(|| {
            err(format!(
                "Selected assets target is unavailable: {target_key}"
            ))
        })?;
        if assets["project"]["frameworks"].get(&framework).is_none() {
            return Err(err("Assets framework does not match the explicit context"));
        }
        let roots = if let Some(roots) = project.get("package_roots") {
            strings(roots)?
        } else {
            assets["packageFolders"]
                .as_object()
                .ok_or_else(|| err("Assets require packageFolders"))?
                .keys()
                .cloned()
                .collect()
        };
        if roots.iter().any(|p| !Path::new(p).is_absolute()) {
            return Err(err("Package roots must be absolute"));
        }
        let mut references: BTreeSet<_> = strings(&project["references"])?
            .into_iter()
            .map(PathBuf::from)
            .collect();
        let mut missing = BTreeSet::new();
        let mut resolved = 0;
        for (library, entry) in target {
            let Some(compile) = entry.get("compile").and_then(Value::as_object) else {
                continue;
            };
            for asset in compile.keys().filter(|p| p.ends_with(".dll")) {
                if entry["type"] != "package" {
                    missing.insert(format!(
                        "{library}: project compile reference requires explicit source or metadata"
                    ));
                    continue;
                }
                let package = text(&assets["libraries"][library]["path"])?;
                if !package.eq_ignore_ascii_case(library) {
                    return Err(err(
                        "Package path does not match the resolved package/version",
                    ));
                }
                let relative = safe_relative(&package)?.join(safe_relative(asset)?);
                let found = roots
                    .iter()
                    .map(|r| Path::new(r).join(&relative))
                    .find(|p| p.is_file());
                if let Some(path) = found {
                    references.insert(path.canonicalize()?);
                    resolved += 1;
                } else {
                    missing.insert(format!("{library}: {asset}"));
                }
            }
        }
        for log in assets
            .get("logs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if log["level"] == "Error" {
                missing.insert(format!(
                    "assets restore error: {}",
                    log["code"].as_str().unwrap_or("unknown")
                ));
            }
        }
        inputs.push(file_hash(&assets_path, &bytes)?);
        let object = project
            .as_object_mut()
            .ok_or_else(|| err("Invalid context project"))?;
        for name in ["assets_file", "assets_target", "package_roots"] {
            object.remove(name);
        }
        object.insert("references".into(), json!(references));
        object.insert("unresolved_references".into(), json!(missing));
        summaries.push(json!({"project_id": id, "assets_target": target_key,
            "resolved_compile_assets": resolved, "unresolved_references": missing}));
    }
    document.as_object_mut().unwrap().remove("context_files");
    if output.exists()
        && inputs.iter().any(|i| {
            Path::new(i["path"].as_str().unwrap()).canonicalize().ok() == output.canonicalize().ok()
        })
    {
        return Err(err("Context output must not overwrite its input metadata"));
    }
    document["input_files"] = json!(inputs);
    std::fs::write(output, serde_json::to_vec_pretty(&document).map_err(err)?)?;
    Ok(json!({"context": output, "projects": summaries,
        "scope": "Explicit sources/options/framework refs; existing compile assets only. Project tasks, generators and restore are not executed."}))
}

fn safe_relative(path: &str) -> Result<PathBuf, EngineError> {
    let normalized = path.replace('\\', "/");
    if normalized.is_empty()
        || Path::new(&normalized).is_absolute()
        || normalized.split('/').any(|p| p == ".." || p.contains(':'))
    {
        return Err(err("Invalid package/compile asset path"));
    }
    Ok(PathBuf::from(normalized))
}
fn text(value: &Value) -> Result<String, EngineError> {
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| err("Required context/assets string is missing"))
}
fn strings(value: &Value) -> Result<Vec<String>, EngineError> {
    value
        .as_array()
        .ok_or_else(|| err("Required context/assets array is missing"))?
        .iter()
        .map(text)
        .collect()
}
fn read(path: &Path) -> Result<Vec<u8>, EngineError> {
    if std::fs::metadata(path)?.len() > 32 * 1024 * 1024 {
        return Err(err("Context/assets metadata exceeds 32 MiB"));
    }
    Ok(std::fs::read(path)?)
}
fn file_hash(path: &Path, bytes: &[u8]) -> Result<Value, EngineError> {
    Ok(json!({"path": path.canonicalize()?, "sha256": digest(bytes)}))
}
fn err(error: impl std::fmt::Display) -> EngineError {
    EngineError(error.to_string())
}
