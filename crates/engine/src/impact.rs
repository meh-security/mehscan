use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use mehscan_core::{
    ChangedFile, ChangedFileStatus, ChangedLineRange, ImpactScanScope, ImpactScopeFile, ScanResult,
};

use crate::repository::{DiscoveredFile, FileClass};
use crate::{EngineError, ImpactDiffMode, ImpactScopeRequest};

const MAX_CHANGED_FILES: usize = 100;
const MAX_BOUNDED_FILES: usize = 250;

pub(crate) struct ImpactPlan {
    included: Option<BTreeSet<String>>,
    pub scope: Option<ImpactScanScope>,
}

impl ImpactPlan {
    pub(crate) fn includes(&self, path: &str) -> bool {
        self.included
            .as_ref()
            .is_none_or(|included| included.contains(path))
    }
}

pub fn changed_files_from_list(
    root: &Path,
    paths: impl IntoIterator<Item = String>,
) -> Result<ImpactScopeRequest, EngineError> {
    let root = canonical_directory(root)?;
    let mut changed = BTreeMap::new();
    for raw in paths {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            continue;
        }
        let path = normalize_relative_input(&root, raw)?;
        let absolute = root.join(Path::new(&path));
        let status = if absolute.is_file() {
            ChangedFileStatus::Unknown
        } else {
            ChangedFileStatus::Deleted
        };
        changed.insert(
            path.clone(),
            ChangedFile {
                path,
                status,
                previous_path: None,
                changed_lines: Vec::new(),
            },
        );
    }
    Ok(ImpactScopeRequest {
        mode: "file_list".to_string(),
        base: None,
        changed_files: changed.into_values().collect(),
        diff_mode: ImpactDiffMode::Full,
    })
}

pub fn changed_files_from_git(root: &Path, base: &str) -> Result<ImpactScopeRequest, EngineError> {
    if base.trim().is_empty() || base.starts_with('-') {
        return Err(EngineError(
            "--changed-from requires a non-empty Git revision that does not start with '-'"
                .to_string(),
        ));
    }
    let scan_root = canonical_directory(root)?;
    let git_root_text = run_git(&scan_root, &["rev-parse", "--show-toplevel"])?;
    let git_root = fs::canonicalize(git_root_text.trim()).map_err(|error| {
        EngineError(format!(
            "cannot resolve Git worktree root {}: {error}",
            git_root_text.trim()
        ))
    })?;
    let scan_prefix = scan_root.strip_prefix(&git_root).map_err(|_| {
        EngineError(format!(
            "scan root {} is outside Git worktree {}",
            scan_root.display(),
            git_root.display()
        ))
    })?;
    let scan_prefix = slash_path(scan_prefix);

    let output = Command::new("git")
        .arg("-C")
        .arg(&git_root)
        .args(["diff", "--name-status", "-z", "--find-renames", base, "--"])
        .output()
        .map_err(|error| EngineError(format!("could not execute git diff: {error}")))?;
    if !output.status.success() {
        return Err(EngineError(format!(
            "git diff {base:?} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mut changed = parse_name_status(&output.stdout, &scan_prefix);
    let untracked = Command::new("git")
        .arg("-C")
        .arg(&git_root)
        .args(["ls-files", "--others", "--exclude-standard", "-z", "--"])
        .output()
        .map_err(|error| EngineError(format!("could not enumerate untracked files: {error}")))?;
    if !untracked.status.success() {
        return Err(EngineError(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&untracked.stderr).trim()
        )));
    }
    for path in zero_fields(&untracked.stdout) {
        let Some(path) = within_scan_root(&path, &scan_prefix) else {
            continue;
        };
        let line_count = fs::read_to_string(scan_root.join(Path::new(&path)))
            .map(|source| source.lines().count().max(1))
            .unwrap_or(1);
        changed.entry(path.clone()).or_insert(ChangedFile {
            path,
            status: ChangedFileStatus::Untracked,
            previous_path: None,
            changed_lines: vec![ChangedLineRange {
                start: 1,
                end: line_count,
            }],
        });
    }

    for item in changed.values_mut().filter(|item| {
        !matches!(
            item.status,
            ChangedFileStatus::Deleted | ChangedFileStatus::Untracked
        )
    }) {
        item.changed_lines = git_changed_lines(&git_root, base, &item.path, &scan_prefix)?;
    }

    Ok(ImpactScopeRequest {
        mode: "git_diff".to_string(),
        base: Some(base.to_string()),
        changed_files: changed.into_values().collect(),
        diff_mode: ImpactDiffMode::Full,
    })
}

pub(crate) fn plan_impact_scope(
    files: &[DiscoveredFile],
    request: Option<&ImpactScopeRequest>,
) -> ImpactPlan {
    let Some(request) = request else {
        return ImpactPlan {
            included: None,
            scope: None,
        };
    };
    let analyzable = files
        .iter()
        .filter(|file| is_analyzable(file.class))
        .collect::<Vec<_>>();
    let analyzable_paths = analyzable
        .iter()
        .map(|file| file.relative.as_str())
        .collect::<BTreeSet<_>>();
    if request.diff_mode == ImpactDiffMode::Full {
        let invalidates_local_filter = request.changed_files.iter().any(|changed| {
            matches!(
                changed.status,
                ChangedFileStatus::Deleted | ChangedFileStatus::Renamed
            ) || is_project_wide_path(&changed.path)
        });
        return ImpactPlan {
            included: None,
            scope: Some(ImpactScanScope {
                mode: request.mode.clone(),
                base: request.base.clone(),
                strategy: if invalidates_local_filter {
                    "full_scan_all_results"
                } else {
                    "full_scan_changed_results"
                }
                .to_string(),
                result_policy: if invalidates_local_filter {
                    "all"
                } else {
                    "changed_locations"
                }
                .to_string(),
                full_scan: true,
                included_file_count: analyzable.len(),
                changed_files: request.changed_files.clone(),
                included_files: Vec::new(),
                reasons: vec![if invalidates_local_filter {
                    "a deletion, rename, project configuration, or central entrypoint change can affect unchanged code; all full-scan results are returned"
                        .to_string()
                } else {
                    "complete repository context was analyzed; results are limited to changed locations"
                        .to_string()
                }],
            }),
        };
    }
    let mut reasons = Vec::new();
    let mut force_full = request.changed_files.len() > MAX_CHANGED_FILES;
    if force_full {
        reasons.push(format!(
            "{} changed files exceed the bounded impact limit of {MAX_CHANGED_FILES}",
            request.changed_files.len()
        ));
    }
    for changed in &request.changed_files {
        if matches!(
            changed.status,
            ChangedFileStatus::Deleted | ChangedFileStatus::Renamed
        ) {
            force_full = true;
            reasons.push(format!(
                "{} is {:?}; removed definitions or controls can affect unchanged callers",
                changed.path, changed.status
            ));
        }
        if is_project_wide_path(&changed.path) {
            force_full = true;
            reasons.push(format!(
                "{} is project-wide configuration or an entrypoint",
                changed.path
            ));
        }
    }
    reasons.sort();
    reasons.dedup();

    if force_full {
        return full_plan(files, request, reasons);
    }

    let mut included = BTreeMap::<String, String>::new();
    for changed in &request.changed_files {
        if analyzable_paths.contains(changed.path.as_str()) {
            included.insert(changed.path.clone(), "changed".to_string());
        }
    }
    for changed in &request.changed_files {
        let directory = Path::new(&changed.path)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        let siblings = analyzable
            .iter()
            .filter(|file| Path::new(&file.relative).parent() == Some(directory))
            .take(21)
            .collect::<Vec<_>>();
        if siblings.len() <= 20 {
            for sibling in siblings {
                included
                    .entry(sibling.relative.clone())
                    .or_insert_with(|| "same_directory_context".to_string());
            }
        }
        for candidate in &analyzable {
            if included.contains_key(&candidate.relative) {
                continue;
            }
            if source_imports_changed_file(&candidate.absolute, &changed.path) {
                included.insert(candidate.relative.clone(), "direct_dependent".to_string());
            }
        }
    }

    if included.len() > MAX_BOUNDED_FILES
        || (analyzable.len() >= 20 && included.len() * 2 > analyzable.len())
    {
        reasons.push(format!(
            "bounded expansion selected {} of {} analyzable files",
            included.len(),
            analyzable.len()
        ));
        return full_plan(files, request, reasons);
    }

    let included_files = included
        .iter()
        .map(|(path, reason)| ImpactScopeFile {
            path: path.clone(),
            reason: reason.clone(),
        })
        .collect::<Vec<_>>();
    let included_set = included.into_keys().collect::<BTreeSet<_>>();
    ImpactPlan {
        included: Some(included_set),
        scope: Some(ImpactScanScope {
            mode: request.mode.clone(),
            base: request.base.clone(),
            strategy: if request.changed_files.is_empty() {
                "no_changes"
            } else {
                "changed_and_bounded_dependents"
            }
            .to_string(),
            result_policy: "impact_scope".to_string(),
            full_scan: false,
            included_file_count: included_files.len(),
            changed_files: request.changed_files.clone(),
            included_files,
            reasons,
        }),
    }
}

/// Applies the declared post-scan result policy. Full fallbacks and bounded
/// impact scans already contain exactly the result scope they promise.
pub fn apply_result_policy(result: &mut ScanResult) {
    let Some(scope) = result.impact_scope.as_ref() else {
        return;
    };
    if scope.result_policy != "changed_locations" {
        return;
    }
    let changed = scope.changed_files.clone();
    let retained_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.steps
                .iter()
                .any(|step| location_is_changed(&step.location, &changed))
        })
        .map(|path| path.id.clone())
        .collect::<BTreeSet<_>>();
    let mut required_evidence = BTreeSet::new();
    for path in result
        .security_paths
        .iter()
        .filter(|path| retained_paths.contains(&path.id))
    {
        required_evidence.insert(path.source_evidence_id.clone());
        required_evidence.insert(path.sink_evidence_id.clone());
        required_evidence.extend(path.protection_evidence_ids.iter().cloned());
        required_evidence.extend(
            path.steps
                .iter()
                .filter_map(|step| step.evidence_id.clone()),
        );
    }
    for evidence in &result.evidence {
        if location_is_changed(&evidence.location, &changed) {
            required_evidence.insert(evidence.id.clone());
            required_evidence.extend(evidence.related_evidence.iter().cloned());
        }
    }
    result
        .security_paths
        .retain(|path| retained_paths.contains(&path.id));
    result.evidence.retain(|evidence| {
        location_is_changed(&evidence.location, &changed)
            || required_evidence.contains(&evidence.id)
    });
}

fn location_is_changed(location: &mehscan_core::Location, changed: &[ChangedFile]) -> bool {
    changed.iter().any(|file| {
        file.path == location.path
            && (file.changed_lines.is_empty()
                || file.changed_lines.iter().any(|range| {
                    location.start.line <= range.end && location.end.line >= range.start
                }))
    })
}

fn full_plan(
    files: &[DiscoveredFile],
    request: &ImpactScopeRequest,
    reasons: Vec<String>,
) -> ImpactPlan {
    ImpactPlan {
        included: None,
        scope: Some(ImpactScanScope {
            mode: request.mode.clone(),
            base: request.base.clone(),
            strategy: "full_fallback".to_string(),
            result_policy: "all".to_string(),
            full_scan: true,
            included_file_count: files
                .iter()
                .filter(|file| is_analyzable(file.class))
                .count(),
            changed_files: request.changed_files.clone(),
            included_files: Vec::new(),
            reasons,
        }),
    }
}

fn canonical_directory(root: &Path) -> Result<PathBuf, EngineError> {
    let root = fs::canonicalize(root).map_err(|error| {
        EngineError(format!(
            "cannot access scan root {}: {error}",
            root.display()
        ))
    })?;
    if !root.is_dir() {
        return Err(EngineError(
            "impact-aware scans require a repository directory root".to_string(),
        ));
    }
    Ok(root)
}

fn run_git(root: &Path, arguments: &[&str]) -> Result<String, EngineError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .map_err(|error| EngineError(format!("could not execute git: {error}")))?;
    if !output.status.success() {
        return Err(EngineError(format!(
            "git {} failed: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn parse_name_status(bytes: &[u8], scan_prefix: &str) -> BTreeMap<String, ChangedFile> {
    let fields = zero_fields(bytes);
    let mut index = 0;
    let mut changed = BTreeMap::new();
    while index < fields.len() {
        let status = &fields[index];
        index += 1;
        let code = status.chars().next().unwrap_or('M');
        if matches!(code, 'R' | 'C') {
            if index + 1 >= fields.len() {
                break;
            }
            let old = within_scan_root(&fields[index], scan_prefix);
            let new = within_scan_root(&fields[index + 1], scan_prefix);
            index += 2;
            if let Some(path) = new {
                changed.insert(
                    path.clone(),
                    ChangedFile {
                        path,
                        status: ChangedFileStatus::Renamed,
                        previous_path: old,
                        changed_lines: Vec::new(),
                    },
                );
            }
            continue;
        }
        if index >= fields.len() {
            break;
        }
        let candidate = within_scan_root(&fields[index], scan_prefix);
        index += 1;
        let Some(path) = candidate else {
            continue;
        };
        let status = match code {
            'A' => ChangedFileStatus::Added,
            'D' => ChangedFileStatus::Deleted,
            'M' | 'T' | 'U' => ChangedFileStatus::Modified,
            _ => ChangedFileStatus::Unknown,
        };
        changed.insert(
            path.clone(),
            ChangedFile {
                path,
                status,
                previous_path: None,
                changed_lines: Vec::new(),
            },
        );
    }
    changed
}

fn git_changed_lines(
    git_root: &Path,
    base: &str,
    scan_relative: &str,
    scan_prefix: &str,
) -> Result<Vec<ChangedLineRange>, EngineError> {
    let git_path = if scan_prefix.is_empty() {
        scan_relative.to_string()
    } else {
        format!("{scan_prefix}/{scan_relative}")
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(git_root)
        .args(["diff", "--unified=0", "--no-color", base, "--", &git_path])
        .output()
        .map_err(|error| EngineError(format!("could not obtain changed lines: {error}")))?;
    if !output.status.success() {
        return Err(EngineError(format!(
            "git diff changed-line query failed for {scan_relative}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(parse_changed_ranges(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_changed_ranges(diff: &str) -> Vec<ChangedLineRange> {
    let mut ranges = Vec::new();
    for line in diff.lines().filter(|line| line.starts_with("@@")) {
        let Some(plus) = line.split_whitespace().find(|part| part.starts_with('+')) else {
            continue;
        };
        let mut parts = plus.trim_start_matches('+').split(',');
        let Some(start) = parts.next().and_then(|value| value.parse::<usize>().ok()) else {
            continue;
        };
        let count = parts
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1);
        if count > 0 {
            ranges.push(ChangedLineRange {
                start,
                end: start + count - 1,
            });
        }
    }
    ranges
}

fn zero_fields(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| String::from_utf8_lossy(field).replace('\\', "/"))
        .collect()
}

fn within_scan_root(path: &str, scan_prefix: &str) -> Option<String> {
    let path = path.trim_start_matches("./");
    if scan_prefix.is_empty() {
        return Some(path.to_string());
    }
    path.strip_prefix(scan_prefix)
        .and_then(|path| path.strip_prefix('/'))
        .map(str::to_string)
}

fn normalize_relative_input(root: &Path, raw: &str) -> Result<String, EngineError> {
    let input = Path::new(raw);
    let relative = if input.is_absolute() {
        input
            .strip_prefix(root)
            .map_err(|_| EngineError(format!("changed path {raw:?} is outside scan root")))?
    } else {
        input
    };
    let mut safe = PathBuf::new();
    for component in relative.components() {
        match component {
            std::path::Component::Normal(value) => safe.push(value),
            std::path::Component::CurDir => {}
            _ => {
                return Err(EngineError(format!(
                    "changed path {raw:?} must remain inside the scan root"
                )));
            }
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(EngineError(format!("invalid changed path {raw:?}")));
    }
    Ok(slash_path(&safe))
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_matches('/')
        .to_string()
}

fn is_analyzable(class: FileClass) -> bool {
    matches!(
        class,
        FileClass::Supported(_)
            | FileClass::EmbeddedJavascriptTemplate
            | FileClass::Razor
            | FileClass::WebForms
    )
}

fn is_project_wide_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    if Path::new(&lower).extension().is_none() {
        // This covers extensionless build/entrypoint files and changed Git
        // submodule paths. Neither can be bounded safely as one source file.
        return true;
    }
    let name = Path::new(&lower)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    matches!(
        name,
        "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "tsconfig.json"
            | "pom.xml"
            | "build.gradle"
            | "build.gradle.kts"
            | "settings.gradle"
            | "settings.gradle.kts"
            | "cargo.toml"
            | "cargo.lock"
            | "go.mod"
            | "go.sum"
            | "pyproject.toml"
            | "requirements.txt"
            | "poetry.lock"
            | "appsettings.json"
            | "web.config"
            | "server.ts"
            | "server.js"
            | "app.ts"
            | "app.js"
            | "startup.cs"
            | "program.cs"
            | "main.rs"
            | "main.go"
    ) || lower.ends_with(".csproj")
        || lower.ends_with(".sln")
}

fn source_imports_changed_file(candidate: &Path, changed: &str) -> bool {
    let Ok(metadata) = fs::metadata(candidate) else {
        return false;
    };
    if metadata.len() > 2 * 1024 * 1024 {
        return false;
    }
    let Ok(source) = fs::read_to_string(candidate) else {
        return false;
    };
    let changed_path = Path::new(changed);
    let stem = changed_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or_default();
    if stem.is_empty() {
        return false;
    }
    source.lines().any(|line| {
        let trimmed = line.trim_start();
        let import_like = trimmed.starts_with("import ")
            || trimmed.starts_with("from ")
            || trimmed.starts_with("use ")
            || trimmed.starts_with("mod ")
            || trimmed.starts_with("#include")
            || trimmed.contains("require(")
            || trimmed.contains("import(");
        import_like && contains_identifier(line, stem)
    })
}

fn contains_identifier(text: &str, identifier: &str) -> bool {
    text.match_indices(identifier).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let end = start + identifier.len();
        let after = text[end..].chars().next();
        before.is_none_or(|character| !is_identifier_character(character))
            && after.is_none_or(|character| !is_identifier_character(character))
    })
}

fn is_identifier_character(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::{normalize_relative_input, parse_changed_ranges};

    #[test]
    fn parses_added_line_ranges_from_zero_context_diff() {
        let ranges =
            parse_changed_ranges("@@ -2,0 +3,2 @@\n+one\n+two\n@@ -9 +11 @@\n-old\n+new\n");
        assert_eq!(ranges.len(), 2);
        assert_eq!((ranges[0].start, ranges[0].end), (3, 4));
        assert_eq!((ranges[1].start, ranges[1].end), (11, 11));
    }

    #[test]
    fn accepts_missing_nested_paths_without_allowing_parent_traversal() {
        let root = std::env::current_dir().expect("current directory");
        let path = normalize_relative_input(&root, "removed/nested/file.rs")
            .expect("missing nested path remains representable");
        assert_eq!(path, "removed/nested/file.rs");
        assert!(normalize_relative_input(&root, "../outside.rs").is_err());
    }
}
