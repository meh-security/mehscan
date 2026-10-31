use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use mehscan_core::{
    ChangeComparison, ChangedFile, ChangedFileStatus, ChangedLineRange, ImpactScanScope,
    ImpactScopeFile, ScanResult,
};

use crate::repository::{DiscoveredFile, FileClass};
use crate::{EngineError, ImpactDiffMode, ImpactScopeRequest};
use sha2::{Digest, Sha256};

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
    let changed_files = changed.into_values().collect::<Vec<_>>();
    let snapshot_fingerprint = changed_content_fingerprint(&root, &changed_files)?;
    Ok(ImpactScopeRequest {
        mode: "file_list".to_string(),
        base: None,
        comparison: None,
        snapshot_fingerprint,
        changed_files,
        diff_mode: ImpactDiffMode::Full,
    })
}

pub fn changed_files_from_git(root: &Path, base: &str) -> Result<ImpactScopeRequest, EngineError> {
    changed_files_from_git_comparison(root, base, None, false)
}

pub fn changed_files_from_git_comparison(
    root: &Path,
    base: &str,
    target: Option<&str>,
    merge_base: bool,
) -> Result<ImpactScopeRequest, EngineError> {
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

    let base_commit = resolve_commit(&git_root, base)?;
    let head_commit = resolve_commit(&git_root, "HEAD")?;
    let target_commit = target
        .map(|value| resolve_commit(&git_root, value))
        .transpose()?
        .unwrap_or_else(|| head_commit.clone());
    if target.is_some() {
        if target_commit != head_commit {
            return Err(EngineError(
                "--target must match the checkout's HEAD; checkout the requested commit first"
                    .into(),
            ));
        }
        let status = git_bytes(
            &git_root,
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=none",
            ],
        )?;
        if !status.is_empty() {
            return Err(EngineError(
                "--target requires a clean checkout, including nonignored untracked files".into(),
            ));
        }
    }
    if !git_bytes(&git_root, &["ls-files", "--unmerged", "-z"])?.is_empty() {
        return Err(EngineError(
            "cannot review an unresolved Git conflict".into(),
        ));
    }
    let merge_base_commit = if merge_base {
        let bases = run_git(
            &git_root,
            &["merge-base", "--all", &base_commit, &target_commit],
        )?;
        let bases = bases.lines().collect::<Vec<_>>();
        if bases.len() != 1 {
            return Err(EngineError(
                "comparison requires exactly one merge base; supply explicit endpoints".into(),
            ));
        }
        Some(bases[0].to_string())
    } else {
        None
    };
    let diff_base = merge_base_commit.as_deref().unwrap_or(&base_commit);
    let mut diff_args = vec![
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--ignore-submodules=none",
        "--name-status",
        "-z",
        "--find-renames",
        diff_base,
    ];
    if target.is_some() {
        diff_args.push(&target_commit);
    }
    diff_args.push("--");
    let mut changed = parse_name_status(&git_bytes(&git_root, &diff_args)?, &scan_prefix)?;

    let untracked = if target.is_none() {
        git_bytes(
            &git_root,
            &["ls-files", "--others", "--exclude-standard", "-z", "--"],
        )?
    } else {
        Vec::new()
    };
    for path in zero_fields(&untracked)? {
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
        item.changed_lines = git_changed_lines(
            &git_root,
            diff_base,
            target.map(|_| target_commit.as_str()),
            &item.path,
            &scan_prefix,
        )?;
    }

    let changed_files = changed.into_values().collect::<Vec<_>>();
    let snapshot_fingerprint = changed_content_fingerprint(&scan_root, &changed_files)?;
    Ok(ImpactScopeRequest {
        mode: "git_diff".to_string(),
        base: Some(base.to_string()),
        comparison: Some(ChangeComparison {
            requested_base: base.to_string(),
            base_commit,
            head_commit,
            requested_target: target.map(str::to_string),
            target_commit,
            merge_base_commit,
            working_tree: target.is_none(),
        }),
        snapshot_fingerprint,
        changed_files,
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
    if request.diff_mode == ImpactDiffMode::Files {
        let included_files = request
            .changed_files
            .iter()
            .filter(|changed| analyzable_paths.contains(changed.path.as_str()))
            .map(|changed| ImpactScopeFile {
                path: changed.path.clone(),
                reason: "changed".into(),
            })
            .collect::<Vec<_>>();
        return ImpactPlan {
            included: Some(included_files.iter().map(|file| file.path.clone()).collect()),
            scope: Some(ImpactScanScope {
                mode: request.mode.clone(),
                base: request.base.clone(),
                comparison: request.comparison.clone(),
                snapshot_fingerprint: Some(request.snapshot_fingerprint.clone()),
                strategy: if request.changed_files.is_empty() { "no_changes" } else { "changed_files_only" }.into(),
                result_policy: "changed_files".into(),
                full_scan: false,
                included_file_count: included_files.len(),
                changed_files: request.changed_files.clone(),
                included_files,
                reasons: vec!["Whole existing changed files only; unchanged code is outside native analysis. A change pass and targeted context research are required to assess removed controls and cross-file effects; zero candidates is not a cleared diff.".into()],
            }),
        };
    }
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
                comparison: request.comparison.clone(),
                snapshot_fingerprint: Some(request.snapshot_fingerprint.clone()),
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
            comparison: request.comparison.clone(),
            snapshot_fingerprint: Some(request.snapshot_fingerprint.clone()),
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

pub(crate) fn location_is_changed(
    location: &mehscan_core::Location,
    changed: &[ChangedFile],
) -> bool {
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
            comparison: request.comparison.clone(),
            snapshot_fingerprint: Some(request.snapshot_fingerprint.clone()),
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
    String::from_utf8(git_bytes(root, arguments)?)
        .map_err(|_| EngineError("Git returned undecodable UTF-8 output".into()))
}

fn git_bytes(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, EngineError> {
    let output = Command::new("git")
        .arg("--literal-pathspecs")
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
    Ok(output.stdout)
}

fn resolve_commit(root: &Path, revision: &str) -> Result<String, EngineError> {
    if revision.trim().is_empty() || revision.starts_with('-') {
        return Err(EngineError(
            "Git comparison requires a non-empty revision that does not start with '-'".into(),
        ));
    }
    Ok(run_git(
        root,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{revision}^{{commit}}"),
        ],
    )?
    .trim()
    .to_string())
}

/// Re-resolve refs and the change set before reusing an inventory/bundle. Source
/// hashing alone cannot detect moved refs, a changed HEAD or deletion-only scope.
pub fn validate_scope(root: &Path, scope: &ImpactScanScope) -> Result<(), EngineError> {
    if let Some(expected) = &scope.snapshot_fingerprint {
        if &changed_content_fingerprint(&canonical_directory(root)?, &scope.changed_files)?
            != expected
        {
            return Err(EngineError("review change scope is stale: changed-path content moved; regenerate the inventory".into()));
        }
    }
    if let Some(comparison) = &scope.comparison {
        let current = changed_files_from_git_comparison(
            root,
            &comparison.requested_base,
            comparison.requested_target.as_deref(),
            comparison.merge_base_commit.is_some(),
        )?;
        if current.comparison.as_ref() != Some(comparison)
            || current.changed_files != scope.changed_files
        {
            return Err(EngineError("review change scope is stale: Git endpoints or changed files moved; regenerate the inventory".into()));
        }
    }
    Ok(())
}

fn changed_content_fingerprint(root: &Path, files: &[ChangedFile]) -> Result<String, EngineError> {
    let mut hash = Sha256::new();
    hash.update(b"mehscan-changed-content/v1\0");
    for changed in files {
        let relative = Path::new(&changed.path);
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(EngineError(
                "changed snapshot path must remain inside the scan root".into(),
            ));
        }
        let record = serde_json::to_vec(changed).map_err(|e| EngineError(e.to_string()))?;
        hash.update((record.len() as u64).to_le_bytes());
        hash.update(record);
        let path = root.join(relative);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                hash.update(b"missing\0");
                continue;
            }
            Err(e) => {
                return Err(EngineError(format!(
                    "cannot bind changed path {:?}: {e}",
                    changed.path
                )));
            }
        };
        // Bind symlink pointers without reading their targets; parent aliases
        // must still stay within the authorized source root.
        if !fs::canonicalize(path.parent().unwrap_or(root))?.starts_with(root) {
            return Err(EngineError(
                "changed snapshot path resolves outside the scan root".into(),
            ));
        }
        if metadata.file_type().is_symlink() {
            let link = fs::read_link(&path)?;
            let target = link.to_str().ok_or_else(|| {
                EngineError("changed symlink target must be decodable UTF-8".into())
            })?;
            hash.update(b"symlink\0");
            hash.update((target.len() as u64).to_le_bytes());
            hash.update(target.as_bytes());
        } else if metadata.is_file() {
            hash.update(b"file\0");
            let mut source = fs::File::open(&path)?;
            let mut content = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let count = source.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                content.update(&buffer[..count]);
            }
            hash.update(content.finalize());
        } else if metadata.is_dir() {
            // Gitlink/directory contents are outside native file analysis;
            // Git comparison validation retains their pointer/status metadata.
            hash.update(b"directory\0");
        } else {
            return Err(EngineError(
                "changed snapshot contains an unsupported filesystem object".into(),
            ));
        }
    }
    Ok(format!("changed-content-v1-{:x}", hash.finalize()))
}

fn parse_name_status(
    bytes: &[u8],
    scan_prefix: &str,
) -> Result<BTreeMap<String, ChangedFile>, EngineError> {
    let fields = zero_fields(bytes)?;
    let mut index = 0;
    let mut changed = BTreeMap::new();
    while index < fields.len() {
        let status = &fields[index];
        index += 1;
        let code = status.chars().next().unwrap_or('M');
        if matches!(code, 'R' | 'C') {
            if index + 1 >= fields.len() {
                return Err(EngineError("incomplete Git rename record".into()));
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
            } else if let Some(path) = old {
                changed.insert(
                    path.clone(),
                    ChangedFile {
                        path,
                        status: ChangedFileStatus::Deleted,
                        previous_path: None,
                        changed_lines: Vec::new(),
                    },
                );
            }
            continue;
        }
        if index >= fields.len() {
            return Err(EngineError("incomplete Git change record".into()));
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
    Ok(changed)
}

fn git_changed_lines(
    git_root: &Path,
    base: &str,
    target: Option<&str>,
    scan_relative: &str,
    scan_prefix: &str,
) -> Result<Vec<ChangedLineRange>, EngineError> {
    let git_path = if scan_prefix.is_empty() {
        scan_relative.to_string()
    } else {
        format!("{scan_prefix}/{scan_relative}")
    };
    let mut arguments = vec![
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--unified=0",
        "--no-color",
        base,
    ];
    if let Some(target) = target {
        arguments.push(target);
    }
    arguments.extend(["--", &git_path]);
    Ok(parse_changed_ranges(&String::from_utf8_lossy(&git_bytes(
        git_root, &arguments,
    )?)))
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

fn zero_fields(bytes: &[u8]) -> Result<Vec<String>, EngineError> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .map(|field| {
            let value = std::str::from_utf8(field).map_err(|_| {
                EngineError(
                    "Git paths must be decodable UTF-8; refusing ambiguous path aliases".into(),
                )
            })?;
            Ok(if cfg!(windows) {
                value.replace('\\', "/")
            } else {
                value.to_string()
            })
        })
        .collect()
}

fn within_scan_root(path: &str, scan_prefix: &str) -> Option<String> {
    let path = path.strip_prefix("./").unwrap_or(path);
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
    let absolute = root.join(&safe);
    if absolute.exists() && !fs::canonicalize(&absolute)?.starts_with(root) {
        return Err(EngineError(format!(
            "changed path {raw:?} resolves outside the scan root"
        )));
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
            | FileClass::Vue
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
    use super::{normalize_relative_input, parse_changed_ranges, parse_name_status};

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

    #[test]
    fn git_records_preserve_hidden_and_unusual_literal_paths() {
        let changes =
            parse_name_status(b"M\0.hidden/[input] file.js\0A\0newline\nfile.js\0", "").unwrap();
        assert!(changes.contains_key(".hidden/[input] file.js"));
        assert!(changes.contains_key("newline\nfile.js"));
        assert!(parse_name_status(b"M\0bad\xff.js\0", "").is_err());
        assert!(parse_name_status(b"R100\0old.js\0", "").is_err());
    }

    #[test]
    fn moving_a_file_out_of_a_subdirectory_preserves_the_deletion() {
        let changes = parse_name_status(b"R100\0app/old.js\0outside/new.js\0", "app").unwrap();
        assert_eq!(
            changes["old.js"].status,
            mehscan_core::ChangedFileStatus::Deleted
        );
        let changes = parse_name_status(b"R100\0outside/old.js\0app/new.js\0", "app").unwrap();
        assert_eq!(
            changes["new.js"].status,
            mehscan_core::ChangedFileStatus::Renamed
        );
    }
}
