use mehscan_core::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Component, Path};
use std::process::Command;

pub(super) fn template(
    binding: &ReviewStateBinding,
    policy: ReviewCompletionPolicy,
) -> ReviewCompletionDraft {
    ReviewCompletionDraft {
        schema_version: "1".into(),
        policy,
        runtime: None,
        selected_review_ids: binding.subjects.keys().cloned().collect(),
        deferred_review_ids: BTreeMap::new(),
        change_pass: binding
            .impact_scope
            .as_ref()
            .map_or_else(Vec::new, |scope| {
                scope
                    .changed_files
                    .iter()
                    .map(|file| ReviewChangePassDraftEntry {
                        path: file.path.clone(),
                        status: ReviewChangePassStatus::Unassessed,
                        summary: String::new(),
                        questions: Vec::new(),
                        native_review_ids: Vec::new(),
                        evidence: Vec::new(),
                    })
                    .collect()
            }),
    }
}

fn relative(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
        || Path::new(path)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
        || path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".." | ".git"))
    {
        return Err("change evidence path must be canonical and inside the authorized root".into());
    }
    Ok(())
}

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["-c", "core.hooksPath=", "-c", "core.fsmonitor=false"])
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err("could not read pinned base source".into());
    }
    if output.stdout.len() > 10 * 1024 * 1024 {
        return Err("base source exceeds bounded reader limit".into());
    }
    Ok(output.stdout)
}

pub(super) fn evidence(
    root: &Path,
    binding: &ReviewStateBinding,
    source: &ReviewChangeSourceReference,
) -> Result<ReviewChangeEvidence, String> {
    relative(&source.path)?;
    if source.start_line == 0
        || source.end_line < source.start_line
        || source.end_line - source.start_line >= 400
    {
        return Err("change evidence requires a bounded one-based source range".into());
    }
    let (text, revision) = match source.side {
        ReviewChangeEvidenceSide::Current => {
            let result = super::engine(mehscan_engine::investigation::get_source(
                root,
                &source.path,
                source.start_line,
                source.end_line,
            ))?;
            let line_count = result.results.text.lines().count().max(1);
            if result.truncated || line_count != source.end_line - source.start_line + 1 {
                return Err(
                    "change evidence range is truncated or outside available source".into(),
                );
            }
            (result.results.text, None)
        }
        ReviewChangeEvidenceSide::Base => {
            let comparison = binding
                .impact_scope
                .as_ref()
                .and_then(|scope| scope.comparison.as_ref())
                .ok_or("base evidence requires a verified Git comparison")?;
            let base = comparison
                .merge_base_commit
                .as_ref()
                .unwrap_or(&comparison.base_commit);
            let repository = String::from_utf8(git(root, &["rev-parse", "--show-toplevel"])?)
                .map_err(|_| "Git root is not UTF-8")?;
            let repository = std::fs::canonicalize(repository.trim_end_matches(['\r', '\n']))
                .map_err(|error| error.to_string())?;
            let root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
            let prefix = root
                .strip_prefix(&repository)
                .map_err(|_| "source boundary is outside Git repository")?;
            let path = prefix
                .join(&source.path)
                .to_str()
                .ok_or("base path is not UTF-8")?
                .replace('\\', "/");
            let object = format!("{base}:{path}");
            let bytes = git(&repository, &["cat-file", "blob", &object])?;
            let full = String::from_utf8(bytes).map_err(|_| "base evidence is not UTF-8 text")?;
            let lines = if full.is_empty() {
                vec![""]
            } else {
                full.lines().collect::<Vec<_>>()
            };
            if source.end_line > lines.len() {
                return Err("base evidence range is outside available source".into());
            }
            let text = lines[source.start_line - 1..source.end_line].join("\n");
            if text.len() > 64 * 1024 {
                return Err("base evidence exceeds bounded slice limit".into());
            }
            (text, Some(base.clone()))
        }
    };
    let bytes = serde_json::to_vec(&(
        &binding.inventory_input_fingerprint,
        source,
        &revision,
        &text,
    ))
    .map_err(|error| error.to_string())?;
    Ok(ReviewChangeEvidence {
        artifact_id: format!("mehscanChangeEvidence/v1:{:x}", Sha256::digest(bytes)),
        source: source.clone(),
        revision,
        text,
    })
}

pub(super) fn materialize(
    root: &Path,
    binding: &ReviewStateBinding,
    cache: &mehscan_engine::investigation::ReviewInventory,
    draft: ReviewCompletionDraft,
) -> Result<ReviewCompletionPlan, String> {
    let mut entries = Vec::new();
    for entry in draft.change_pass {
        let mut artifacts = Vec::new();
        for reference in &entry.evidence {
            artifacts.push(evidence(root, binding, reference)?);
        }
        entries.push(ReviewChangePassEntry {
            path: entry.path,
            status: entry.status,
            summary: entry.summary,
            questions: entry.questions,
            native_review_ids: entry.native_review_ids,
            evidence: artifacts,
        });
    }
    let native_coverage_limits = binding.impact_scope.as_ref().map_or_else(
        || {
            cache
                .scan
                .coverage
                .files
                .iter()
                .filter(|file| file.status != FileStatus::Scanned)
                .map(|file| ReviewCompletionCoverageLimit {
                    path: file.path.clone(),
                    reason: file
                        .reason
                        .clone()
                        .unwrap_or_else(|| format!("{:?}", file.status)),
                })
                .collect()
        },
        |scope| {
            scope
                .changed_files
                .iter()
                .filter_map(|file| {
                    let coverage = cache
                        .scan
                        .coverage
                        .files
                        .iter()
                        .find(|coverage| coverage.path == file.path);
                    if coverage.is_some_and(|coverage| coverage.status == FileStatus::Scanned) {
                        return None;
                    }
                    Some(ReviewCompletionCoverageLimit {
                        path: file.path.clone(),
                        reason: coverage.map_or_else(
                            || "no native analysis for this changed path".into(),
                            |coverage| {
                                coverage
                                    .reason
                                    .clone()
                                    .unwrap_or_else(|| format!("{:?}", coverage.status))
                            },
                        ),
                    })
                })
                .collect()
        },
    );
    Ok(ReviewCompletionPlan {
        schema_version: draft.schema_version,
        inventory_input_fingerprint: binding.inventory_input_fingerprint.clone(),
        policy: draft.policy,
        runtime: draft.runtime,
        selected_review_ids: draft.selected_review_ids,
        deferred_review_ids: draft.deferred_review_ids,
        change_pass: entries,
        native_coverage_limits,
    })
}

pub(super) fn explanation(value: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err("completion explanations must be nonempty bounded text".into());
    }
    Ok(())
}

pub(super) fn validate(
    binding: &ReviewStateBinding,
    plan: &ReviewCompletionPlan,
) -> Result<(), String> {
    use std::collections::BTreeSet;
    if let Some(runtime) = &plan.runtime {
        runtime.validate(plan.policy)?;
    }
    if plan.schema_version != "1"
        || plan.inventory_input_fingerprint != binding.inventory_input_fingerprint
    {
        return Err("completion plan does not match the current inventory binding".into());
    }
    let selected = plan.selected_review_ids.iter().collect::<BTreeSet<_>>();
    let deferred = plan.deferred_review_ids.keys().collect::<BTreeSet<_>>();
    let catalog = binding.subjects.keys().collect::<BTreeSet<_>>();
    if selected.len() != plan.selected_review_ids.len()
        || !selected.is_disjoint(&deferred)
        || selected.union(&deferred).copied().collect::<BTreeSet<_>>() != catalog
    {
        return Err("completion plan must partition every native ID exactly once into selected or deferred work".into());
    }
    if plan.policy == ReviewCompletionPolicy::Comprehensive && !deferred.is_empty() {
        return Err("Comprehensive cannot defer admitted native IDs".into());
    }
    for reason in plan.deferred_review_ids.values() {
        explanation(reason)?;
    }
    let changed = binding
        .impact_scope
        .as_ref()
        .map_or_else(BTreeMap::new, |scope| {
            scope
                .changed_files
                .iter()
                .map(|file| (&file.path, file))
                .collect()
        });
    let actual = plan
        .change_pass
        .iter()
        .map(|entry| &entry.path)
        .collect::<BTreeSet<_>>();
    if actual.len() != plan.change_pass.len() || actual != changed.keys().copied().collect() {
        return Err("change pass must account for every changed path exactly once".into());
    }
    for entry in &plan.change_pass {
        if entry.status != ReviewChangePassStatus::Unassessed {
            explanation(&entry.summary)?;
        }
        for question in &entry.questions {
            explanation(question)?;
        }
        if (entry.status == ReviewChangePassStatus::NeedsReview && entry.questions.is_empty())
            || (entry.status == ReviewChangePassStatus::Reviewed && !entry.questions.is_empty())
        {
            return Err("pending effects need specific questions; reviewed entries cannot hide unresolved questions".into());
        }
        let ids = entry.native_review_ids.iter().collect::<BTreeSet<_>>();
        if ids.len() != entry.native_review_ids.len() || !ids.is_subset(&catalog) {
            return Err("change pass references unknown or repeated native IDs".into());
        }
        let file = changed[&entry.path];
        let mut current = false;
        let mut base = false;
        for artifact in &entry.evidence {
            relative(&artifact.source.path)?;
            if artifact.source.start_line == 0
                || artifact.source.end_line < artifact.source.start_line
                || artifact.source.end_line - artifact.source.start_line >= 400
                || artifact.text.len() > 64 * 1024
            {
                return Err("invalid bounded change evidence".into());
            }
            let expected_base = binding
                .impact_scope
                .as_ref()
                .and_then(|scope| scope.comparison.as_ref())
                .map(|comparison| {
                    comparison
                        .merge_base_commit
                        .as_ref()
                        .unwrap_or(&comparison.base_commit)
                });
            match artifact.source.side {
                ReviewChangeEvidenceSide::Current => {
                    if artifact.revision.is_some() {
                        return Err("current source must remain checkout-bound".into());
                    }
                    current |= artifact.source.path == entry.path;
                }
                ReviewChangeEvidenceSide::Base => {
                    if expected_base.is_none() || artifact.revision.as_ref() != expected_base {
                        return Err("base evidence revision differs from pinned comparison".into());
                    }
                    base |=
                        artifact.source.path == *file.previous_path.as_ref().unwrap_or(&file.path);
                }
            }
            let bytes = serde_json::to_vec(&(
                &binding.inventory_input_fingerprint,
                &artifact.source,
                &artifact.revision,
                &artifact.text,
            ))
            .map_err(|error| error.to_string())?;
            if artifact.artifact_id
                != format!("mehscanChangeEvidence/v1:{:x}", Sha256::digest(bytes))
            {
                return Err("change evidence integrity check failed".into());
            }
        }
        if matches!(
            entry.status,
            ReviewChangePassStatus::Reviewed | ReviewChangePassStatus::NeedsReview
        ) {
            if file.status != ChangedFileStatus::Deleted && !current {
                return Err(
                    "assessed change requires evidence from the current primary file".into(),
                );
            }
            if binding
                .impact_scope
                .as_ref()
                .is_some_and(|scope| scope.comparison.is_some())
                && matches!(
                    file.status,
                    ChangedFileStatus::Deleted
                        | ChangedFileStatus::Modified
                        | ChangedFileStatus::Renamed
                )
                && !base
            {
                return Err(
                    "removed/modified/renamed change requires pinned base-side evidence".into(),
                );
            }
            if file.status == ChangedFileStatus::Deleted && !base {
                return Err(
                    "deletion without available base evidence remains a coverage gap".into(),
                );
            }
        }
    }
    Ok(())
}
