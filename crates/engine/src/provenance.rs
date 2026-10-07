//! Read-only code provenance candidates. These never change security admission.
use crate::{EngineError, repository::discover_text};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, io::Read, path::Path};

mod build_scope;
pub(crate) use build_scope::build_only;

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub path: String,
    pub suggested_lane: &'static str,
    pub evidence_kind: &'static str,
    pub evidence_path: String,
    pub evidence_sha256: String,
    pub evidence_hash_scope: &'static str,
    pub line: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    pub unresolved_sources: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unresolved_references: Vec<String>,
    pub sources_truncated: bool,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub root: String,
    pub operation: &'static str,
    pub candidates_only: bool,
    pub scanned_files: usize,
    pub header_files_inspected: usize,
    pub inventory_scope_only: bool,
    pub excluded_subtrees: Vec<String>,
    pub candidate_count: usize,
    pub truncated: bool,
    pub candidates: Vec<Candidate>,
    pub skipped_inputs: usize,
    pub diagnostics: Vec<String>,
}

/// Discovery honors repository ignores and does not follow symlinks. No target
/// scripts/plugins are evaluated; references must resolve to discovered files.
pub fn inspect(
    root: &Path,
    prefix: Option<&str>,
    limit: Option<usize>,
) -> Result<Report, EngineError> {
    inspect_review_paths(root, prefix, limit, None)
}

/// Inventory paths limit header I/O and returned candidates only. They are not
/// a validated inventory, a cached proof, or a change to review admission.
pub fn inspect_review_paths(
    root: &Path,
    prefix: Option<&str>,
    limit: Option<usize>,
    paths: Option<&BTreeSet<String>>,
) -> Result<Report, EngineError> {
    let limit = limit.unwrap_or(200);
    if !(1..=1000).contains(&limit) {
        return Err(EngineError(
            "provenance limit must be between 1 and 1000".into(),
        ));
    }
    let discovery = discover_text(root, prefix)?;
    if !discovery.root.is_dir() {
        return Err(EngineError(
            "provenance requires a repository directory".into(),
        ));
    }
    let files: BTreeSet<_> = discovery
        .files
        .iter()
        .filter(|f| f.reason != Some("symbolic link is not followed"))
        .map(|f| f.relative.clone())
        .collect();
    let mut report = Report {
        root: discovery.root.to_string_lossy().into_owned(),
        operation: "code_provenance",
        candidates_only: true,
        scanned_files: files.len(),
        header_files_inspected: 0,
        inventory_scope_only: paths.is_some(),
        excluded_subtrees: discovery.ignored_subtrees.clone(),
        candidate_count: 0,
        truncated: false,
        candidates: vec![],
        skipped_inputs: 0,
        diagnostics: vec![],
    };
    for file in &discovery.files {
        if !files.contains(&file.relative) {
            continue;
        }
        let name = Path::new(&file.relative)
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("");
        if name == "package.json" || name.ends_with(".map") {
            let bytes = match bounded_read(&file.absolute, 2 * 1024 * 1024) {
                Ok(bytes) => bytes,
                Err(error) => {
                    skipped(&mut report, format!("{}: {error}", file.relative));
                    continue;
                }
            };
            let value: Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(_) => {
                    skipped(&mut report, format!("{}: invalid JSON", file.relative));
                    continue;
                }
            };
            let digest = format!("{:x}", Sha256::digest(&bytes));
            let parent = parent(&file.relative);
            if name == "package.json" {
                for (field, entry) in [("main", value.get("main")), ("bin", value.get("bin"))] {
                    let entries: Vec<_> = match entry {
                        Some(Value::String(v)) => vec![v.as_str()],
                        Some(Value::Object(v)) => v.values().filter_map(Value::as_str).collect(),
                        _ => vec![],
                    };
                    for entry in entries {
                        if let Some(path) = resolve(parent, entry, &files) {
                            report.candidates.push(candidate(
                                path,
                                "application",
                                "package_entry",
                                &file.relative,
                                &digest,
                                format!("package {field} entry; inspect deployment/use"),
                            ));
                        }
                    }
                }
                if let Some(scripts) = value.get("scripts").and_then(Value::as_object) {
                    for (name, script) in scripts {
                        let Some(script) = script.as_str() else {
                            continue;
                        };
                        let build = matches!(
                            name.as_str(),
                            "build" | "prebuild" | "postbuild" | "prepare" | "generate"
                        ) || name.starts_with("build:")
                            || name.starts_with("generate:");
                        let runtime = matches!(name.as_str(), "start" | "dev" | "serve");
                        if !build && !runtime {
                            continue;
                        }
                        // Only literal, existing path tokens. No shell parsing, glob expansion or execution.
                        for token in script.split_whitespace() {
                            let token = token.trim_matches(['\'', '"']);
                            if token.contains(['$', '*', '`', ';', '|', '&']) {
                                continue;
                            }
                            if let Some(path) = resolve(parent, token, &files) {
                                report.candidates.push(candidate(
                                    path,
                                    if build { "build" } else { "application" },
                                    "package_script",
                                    &file.relative,
                                    &digest,
                                    format!("package scripts.{name} directly references this file"),
                                ));
                            }
                        }
                    }
                }
            } else if value.get("version").and_then(Value::as_u64) == Some(3) {
                let output = match value.get("file").and_then(Value::as_str) {
                    Some(file) => resolve(parent, file, &files),
                    None => {
                        let stem = file.relative.strip_suffix(".map").unwrap();
                        let outputs: Vec<_> =
                            [stem.to_owned(), format!("{stem}.js"), format!("{stem}.css")]
                                .into_iter()
                                .filter(|p| files.contains(p))
                                .collect();
                        (outputs.len() == 1).then(|| outputs[0].clone())
                    }
                };
                if let Some(output) = output {
                    let mut item = candidate(output, "generated", "source_map", &file.relative, &digest,
                        "Source-map relationship; original existence does not prove artifact equivalence".into());
                    let source_root = value
                        .get("sourceRoot")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    for source in value
                        .get("sources")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                    {
                        let resolved = source.as_str().and_then(|s| {
                            let reference = if source_root.is_empty() {
                                s.to_owned()
                            } else {
                                format!("{source_root}/{s}")
                            };
                            resolve(parent, &reference, &files)
                        });
                        match resolved {
                            Some(source) if item.sources.len() < 8 => item.sources.push(source),
                            Some(_) => item.sources_truncated = true,
                            None => {
                                item.unresolved_sources += 1;
                                if item.unresolved_references.len() < 8 {
                                    item.unresolved_references.push(
                                        source
                                            .as_str()
                                            .unwrap_or("invalid source reference")
                                            .chars()
                                            .take(256)
                                            .collect(),
                                    );
                                } else {
                                    item.sources_truncated = true;
                                }
                            }
                        }
                    }
                    item.sources.sort();
                    item.sources.dedup();
                    if item.sources.is_empty() && item.unresolved_sources == 0 {
                        item.unresolved_sources = 1;
                    }
                    report.candidates.push(item);
                }
            }
        } else if source_extension(&file.relative)
            && paths.is_none_or(|paths| paths.contains(&file.relative))
        {
            report.header_files_inspected += 1;
            // Header checks need only a bounded prefix, including for large/minified files.
            let bytes = match fs::File::open(&file.absolute).and_then(|f| {
                let mut bytes = vec![];
                f.take(8192).read_to_end(&mut bytes)?;
                Ok(bytes)
            }) {
                Ok(bytes) => bytes,
                Err(error) => {
                    skipped(&mut report, format!("{}: {error}", file.relative));
                    continue;
                }
            };
            let header = String::from_utf8_lossy(&bytes);
            let lines: Vec<_> = header.lines().take(20).collect();
            let comments: Vec<_> = lines
                .iter()
                .enumerate()
                .filter(|(_, line)| {
                    let line = line.trim_start();
                    line.starts_with(['/', '*', '#']) || line.starts_with("<!--")
                })
                .collect();
            let digest = format!("{:x}", Sha256::digest(&bytes));
            if let Some((line, _)) = comments.iter().find(|(_, line)| {
                let line = line.to_lowercase();
                line.contains("@generated")
                    || line.contains("<auto-generated")
                    || line.contains("code generated") && line.contains("do not edit")
                    || line.contains("automatically generated") && line.contains("do not edit")
            }) {
                let mut item = candidate(
                    file.relative.clone(),
                    "generated",
                    "generated_header",
                    &file.relative,
                    &digest,
                    "Generated marker; find generator/original before deferring".into(),
                );
                item.line = line + 1;
                item.evidence_hash_scope = "first_8192_bytes";
                item.unresolved_sources = 1;
                report.candidates.push(item);
            }
            let ownership = comments
                .iter()
                .any(|(_, line)| line.to_lowercase().contains("copyright"));
            if ownership
                && let Some((line, text)) = comments
                    .iter()
                    .find(|(_, line)| line.contains("https://") || line.contains("http://"))
            {
                let mut item = candidate(
                    file.relative.clone(),
                    "dependency",
                    "distribution_header",
                    &file.relative,
                    &digest,
                    format!(
                        "Ownership/header candidate, confirm package versus authored code: {}",
                        text.trim().chars().take(180).collect::<String>()
                    ),
                );
                item.line = line + 1;
                item.evidence_hash_scope = "first_8192_bytes";
                report.candidates.push(item);
            }
        }
    }
    if let Some(prefix) = prefix {
        let prefix = prefix.replace('\\', "/");
        let prefix = prefix
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect::<Vec<_>>()
            .join("/");
        if !prefix.is_empty() {
            report
                .candidates
                .retain(|c| c.path == prefix || c.path.starts_with(&format!("{prefix}/")));
        }
    }
    if let Some(paths) = paths {
        report.candidates.retain(|c| paths.contains(&c.path));
    }
    report.candidates.sort_by(|a, b| {
        (&a.path, a.evidence_kind, &a.evidence_path, &a.detail).cmp(&(
            &b.path,
            b.evidence_kind,
            &b.evidence_path,
            &b.detail,
        ))
    });
    report.candidates.dedup_by(|a, b| {
        a.path == b.path
            && a.evidence_kind == b.evidence_kind
            && a.evidence_path == b.evidence_path
            && a.detail == b.detail
    });
    report.candidate_count = report.candidates.len();
    report.truncated = report.candidate_count > limit;
    report.candidates.truncate(limit);
    Ok(report)
}

fn candidate(
    path: String,
    lane: &'static str,
    kind: &'static str,
    evidence: &str,
    digest: &str,
    detail: String,
) -> Candidate {
    Candidate {
        path,
        suggested_lane: lane,
        evidence_kind: kind,
        evidence_path: evidence.into(),
        evidence_sha256: digest.into(),
        evidence_hash_scope: "file",
        line: 1,
        sources: vec![],
        unresolved_sources: 0,
        unresolved_references: vec![],
        sources_truncated: false,
        detail,
    }
}
fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}
fn resolve(base: &str, reference: &str, files: &BTreeSet<String>) -> Option<String> {
    let reference = reference.replace('\\', "/");
    if reference.starts_with('/') || reference.contains([':', '?', '#', '%', '$']) {
        return None;
    }
    let mut components: Vec<_> = base.split('/').filter(|v| !v.is_empty()).collect();
    for part in reference.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                components.pop()?;
            }
            _ => components.push(part),
        }
    }
    let path = components.join("/");
    files.contains(&path).then_some(path)
}
fn source_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|v| v.to_str())
        .is_some_and(|v| {
            matches!(
                v,
                "js" | "jsx"
                    | "mjs"
                    | "cjs"
                    | "ts"
                    | "tsx"
                    | "cs"
                    | "go"
                    | "rs"
                    | "py"
                    | "java"
                    | "kt"
                    | "c"
                    | "h"
                    | "cpp"
                    | "php"
                    | "vue"
                    | "svelte"
            )
        })
}
fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, std::io::Error> {
    let mut bytes = vec![];
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("exceeds 2 MiB input bound"));
    }
    Ok(bytes)
}
fn skipped(report: &mut Report, message: String) {
    report.skipped_inputs += 1;
    if report.diagnostics.len() < 20 {
        report.diagnostics.push(message);
    }
}
