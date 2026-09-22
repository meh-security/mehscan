use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use mehscan_core::{Capability, EvidenceFilter, EvidenceKind, Language};

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(arguments: impl IntoIterator<Item = String>) -> Result<(), String> {
    let mut arguments = arguments.into_iter();
    let Some(command) = arguments.next() else {
        print_help();
        return Ok(());
    };
    match command.as_str() {
        "--help" | "-h" | "help" => {
            print_help();
            Ok(())
        }
        "--version" | "-V" | "version" => {
            println!("mehscan {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "scan" => run_scan(arguments),
        "report" => run_report(arguments),
        "benchmark" => run_benchmark(arguments),
        "evaluate" => run_evaluation(arguments),
        "investigate" => run_investigation(arguments),
        _ => Err(format!(
            "unknown command {command:?}; expected 'scan', 'report', 'benchmark', 'evaluate', or 'investigate'"
        )),
    }
}

fn run_report(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let mut parsed = ParsedArguments::parse(arguments)?;
    if parsed.help {
        print_report_help();
        return Ok(());
    }
    let run = PathBuf::from(parsed.required("--run")?);
    let responses = parsed.optional("--responses").map(PathBuf::from);
    let allow_partial = parsed.optional_bool("--allow-partial")?.unwrap_or(false);
    let format = match parsed.optional("--format").as_deref().unwrap_or("json") {
        "json" => ReportOutputFormat::Json,
        "sarif" => ReportOutputFormat::Sarif,
        "markdown" | "md" => ReportOutputFormat::Markdown,
        value => return Err(format!("unsupported report format {value:?}")),
    };
    let reviewer = parsed.optional("--reviewer");
    let output = parsed.optional("--output").map(PathBuf::from);
    let include_dismissed = parsed
        .optional_bool("--include-dismissed")?
        .unwrap_or(false);
    let scope = parse_report_scope(&mut parsed);
    parsed.finish()?;

    let (manifest, bundle_responses, work) =
        read_complete_bundle_responses(&run, responses.as_deref(), allow_partial)?;
    let mut report = engine(
        mehscan_engine::investigation::build_finding_report_from_manifest_with_work(
            &manifest,
            env!("CARGO_PKG_VERSION"),
            reviewer,
            &bundle_responses,
            include_dismissed,
            work,
        ),
    )?;
    for label in scope {
        // Explicit handoff labels replace inherited labels of the same kind;
        // selection and coverage limitations remain intact.
        if let Some((kind, _)) = label.split_once(": ") {
            let prefix = format!("{kind}: ");
            report
                .scan
                .scope
                .retain(|entry| !entry.starts_with(&prefix));
        }
        report.scan.scope.push(label);
    }
    match format {
        ReportOutputFormat::Json => write_json(&report, output.as_deref()),
        ReportOutputFormat::Sarif => write_json(
            &mehscan_core::FindingSarifLog::from_finding_report(&report),
            output.as_deref(),
        ),
        ReportOutputFormat::Markdown => write_text(&report.to_markdown(), output.as_deref()),
    }
}

/// Explicit, portable handoff metadata; it is not a security fact supplied to AI.
fn parse_report_scope(parsed: &mut ParsedArguments) -> Vec<String> {
    [
        ("--scope-label", "Scope label"),
        ("--project", "Project label"),
        ("--revision", "Source revision label"),
    ]
    .into_iter()
    .filter_map(|(option, label)| {
        parsed
            .optional(option)
            .map(|value| format!("{label}: {value}"))
    })
    .collect()
}

fn run_evaluation(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(operation) = arguments.next() else {
        print_evaluation_help();
        return Ok(());
    };
    if matches!(operation.as_str(), "--help" | "-h" | "help") {
        print_evaluation_help();
        return Ok(());
    }
    let mut root = None;
    let mut manifest = if operation.starts_with("review-") {
        PathBuf::from("benchmarks/cross-language-review-verdicts.yml")
    } else {
        PathBuf::from("benchmarks/v2-ai-eval.yml")
    };
    let mut responses = None;
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--manifest" => {
                manifest = PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--manifest requires a path".to_string())?,
                );
            }
            "--responses" => {
                responses = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--responses requires a path".to_string())?,
                ));
            }
            "--help" | "-h" => {
                print_evaluation_help();
                return Ok(());
            }
            value if value.starts_with('-') => return Err(format!("unknown option {value:?}")),
            value if root.is_none() => root = Some(PathBuf::from(value)),
            value => return Err(format!("unexpected argument {value:?}")),
        }
    }
    let root = root.unwrap_or_else(|| PathBuf::from("."));
    match operation.as_str() {
        "prepare" => {
            if responses.is_some() {
                return Err("--responses is only valid for evaluation scoring".to_string());
            }
            let pack = engine(mehscan_engine::evaluation::prepare_evaluation(
                &root, &manifest,
            ))?;
            print_json(&pack)
        }
        "score" => {
            let responses = responses.ok_or_else(|| {
                "evaluation score requires --responses PATH with the provider result set"
                    .to_string()
            })?;
            let source = fs::read_to_string(&responses).map_err(|error| {
                format!(
                    "could not read evaluation responses {}: {error}",
                    responses.display()
                )
            })?;
            let response_set: mehscan_core::EvaluationResponseSet = serde_json::from_str(&source)
                .map_err(|error| {
                format!(
                    "evaluation responses {} are invalid: {error}",
                    responses.display()
                )
            })?;
            let report = engine(mehscan_engine::evaluation::score_evaluation(
                &root,
                &manifest,
                &response_set,
            ))?;
            print_json(&report)
        }
        "review-prepare" => {
            if responses.is_some() {
                return Err("--responses is only valid for evaluation scoring".to_string());
            }
            let pack = engine(
                mehscan_engine::evaluation::prepare_review_verdict_evaluation(&root, &manifest),
            )?;
            print_json(&pack)
        }
        "review-score" => {
            let responses = responses.ok_or_else(|| {
                "evaluation review-score requires --responses PATH with the model result set"
                    .to_string()
            })?;
            let source = fs::read_to_string(&responses).map_err(|error| {
                format!(
                    "could not read review-verdict responses {}: {error}",
                    responses.display()
                )
            })?;
            let response_set: mehscan_core::ReviewVerdictEvaluationResponseSet =
                serde_json::from_str(&source).map_err(|error| {
                    format!(
                        "review-verdict responses {} are invalid: {error}",
                        responses.display()
                    )
                })?;
            let report = engine(mehscan_engine::evaluation::score_review_verdict_evaluation(
                &root,
                &manifest,
                &response_set,
            ))?;
            print_json(&report)
        }
        _ => Err(format!(
            "unknown evaluation operation {operation:?}; expected 'prepare', 'score', 'review-prepare', or 'review-score'"
        )),
    }
}

fn run_scan(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let mut root = None;
    let mut format = ScanOutputFormat::Text;
    let mut timings = false;
    let mut include_tests = false;
    let mut jobs = None;
    let mut changed_from = None;
    let mut files_from = None;
    let mut diff_mode = mehscan_engine::ImpactDiffMode::Full;
    let mut diff_mode_explicit = false;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--timings" => timings = true,
            "--include-tests" => include_tests = true,
            "--changed-from" => {
                changed_from = Some(
                    arguments
                        .next()
                        .ok_or_else(|| "--changed-from requires a Git revision".to_string())?,
                );
            }
            "--files-from" => {
                files_from = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--files-from requires a path".to_string())?,
                ));
            }
            "--diff-mode" => {
                diff_mode_explicit = true;
                let value = arguments
                    .next()
                    .ok_or_else(|| "--diff-mode requires 'full' or 'impact'".to_string())?;
                diff_mode = match value.as_str() {
                    "full" => mehscan_engine::ImpactDiffMode::Full,
                    "impact" => mehscan_engine::ImpactDiffMode::Impact,
                    _ => return Err(format!("unsupported diff mode {value:?}")),
                };
            }
            "--jobs" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--jobs requires a positive integer".to_string())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --jobs value {value:?}"))?;
                if parsed == 0 {
                    return Err("--jobs requires a positive integer".to_string());
                }
                jobs = Some(parsed);
            }
            "--format" => {
                let value = arguments.next().ok_or_else(|| {
                    "--format requires text, json, candidates, or sarif-candidates".to_string()
                })?;
                format = match value.as_str() {
                    "json" => ScanOutputFormat::Json,
                    "text" => ScanOutputFormat::Text,
                    "candidates" => ScanOutputFormat::Candidates,
                    "sarif" | "sarif-candidates" => ScanOutputFormat::Sarif,
                    _ => return Err(format!("unsupported output format {value:?}")),
                };
            }
            "--help" | "-h" => {
                print_scan_help();
                return Ok(());
            }
            value if value.starts_with('-') => return Err(format!("unknown option {value:?}")),
            value if root.is_none() => root = Some(PathBuf::from(value)),
            value => return Err(format!("unexpected argument {value:?}")),
        }
    }

    let root = root.unwrap_or_else(|| PathBuf::from("."));
    if changed_from.is_some() && files_from.is_some() {
        return Err("--changed-from and --files-from cannot be used together".to_string());
    }
    if diff_mode_explicit && changed_from.is_none() && files_from.is_none() {
        return Err("--diff-mode requires --changed-from or --files-from".to_string());
    }
    let mut impact_scope = if let Some(base) = changed_from {
        Some(engine(mehscan_engine::impact::changed_files_from_git(
            &root, &base,
        ))?)
    } else if let Some(path) = files_from {
        let source = fs::read_to_string(&path).map_err(|error| {
            format!(
                "could not read changed-file list {}: {error}",
                path.display()
            )
        })?;
        Some(engine(mehscan_engine::impact::changed_files_from_list(
            &root,
            source.lines().map(str::to_string),
        ))?)
    } else {
        None
    };
    if let Some(scope) = impact_scope.as_mut() {
        scope.diff_mode = diff_mode;
    }
    let options = mehscan_engine::ScanOptions {
        include_tests,
        jobs,
        scan_secrets: false,
        impact_scope,
    };
    let (mut result, profile) = if timings {
        let (result, profile) = engine(mehscan_engine::scan_path_profiled_with_options(
            &root, options,
        ))?;
        (result, Some(profile))
    } else {
        (
            engine(mehscan_engine::scan_path_with_options(&root, options))?,
            None,
        )
    };
    mehscan_engine::impact::apply_result_policy(&mut result);
    // Serialized CLI artifacts must be portable and must not disclose a
    // developer or CI runner's absolute checkout path. Evidence locations are
    // already relative to this logical root.
    result.root = ".".to_string();
    let output = match format {
        ScanOutputFormat::Json => print_json(&result),
        ScanOutputFormat::Text => {
            print_summary(&result);
            Ok(())
        }
        ScanOutputFormat::Candidates => {
            let report = mehscan_core::CandidateReport::from_scan(&result)
                .map_err(|error| format!("could not build candidate report: {error}"))?;
            print_json(&report)
        }
        ScanOutputFormat::Sarif => {
            let report = mehscan_core::SarifLog::from_scan(&result)
                .map_err(|error| format!("could not build SARIF report: {error}"))?;
            print_json(&report)
        }
    };
    if let Some(profile) = profile {
        eprintln!(
            "{}",
            serde_json::to_string(&profile)
                .map_err(|error| format!("could not serialize scan timings: {error}"))?
        );
    }
    output
}

fn run_benchmark(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let mut root = None;
    let mut manifest = PathBuf::from("benchmarks/v2-sast.yml");
    let mut include_optional = false;
    let mut format = OutputFormat::Text;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--manifest" => {
                manifest = PathBuf::from(
                    arguments
                        .next()
                        .ok_or_else(|| "--manifest requires a path".to_string())?,
                );
            }
            "--include-optional" => include_optional = true,
            "--format" => {
                let value = arguments
                    .next()
                    .ok_or_else(|| "--format requires 'json' or 'text'".to_string())?;
                format = match value.as_str() {
                    "json" => OutputFormat::Json,
                    "text" => OutputFormat::Text,
                    _ => return Err(format!("unsupported output format {value:?}")),
                };
            }
            "--help" | "-h" => {
                print_benchmark_help();
                return Ok(());
            }
            value if value.starts_with('-') => return Err(format!("unknown option {value:?}")),
            value if root.is_none() => root = Some(PathBuf::from(value)),
            value => return Err(format!("unexpected argument {value:?}")),
        }
    }

    let root = root.unwrap_or_else(|| PathBuf::from("."));
    let report = engine(mehscan_engine::benchmark::run_manifest(
        &root,
        &manifest,
        include_optional,
    ))?;
    match format {
        OutputFormat::Json => print_json(&report)?,
        OutputFormat::Text => print_benchmark_summary(&report),
    }
    if report.passed {
        Ok(())
    } else {
        Err("benchmark expectations did not match".to_string())
    }
}

fn run_investigation(mut arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(operation) = arguments.next() else {
        print_investigation_help();
        return Ok(());
    };
    if matches!(operation.as_str(), "--help" | "-h" | "help") {
        print_investigation_help();
        return Ok(());
    }
    let mut parsed = ParsedArguments::parse(arguments)?;
    if parsed.help {
        print_investigation_help();
        return Ok(());
    }
    let root = parsed.root.clone();
    match operation.as_str() {
        "funnel" => {
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::relationship_funnel(&root),
            )?)
        }
        "review-jobs" => {
            let limit = parsed.optional_usize("--limit")?;
            let context_lines = parsed.optional_usize("--context-lines")?;
            let offset = parsed.optional_usize("--offset")?.unwrap_or(0);
            let include_review_material = parsed
                .optional_bool("--include-review-material")?
                .unwrap_or(false);
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::build_path_review_jobs_page(
                    &root,
                    context_lines,
                    limit,
                    offset,
                    include_review_material,
                ),
            )?)
        }
        "review-tasks" => {
            let limit = parsed.optional_usize("--limit")?;
            let context_lines = parsed.optional_usize("--context-lines")?;
            let offset = parsed.optional_usize("--offset")?.unwrap_or(0);
            let include_review_material = parsed
                .optional_bool("--include-review-material")?
                .unwrap_or(false);
            parsed.finish()?;
            let job = engine(mehscan_engine::investigation::build_path_review_jobs_page(
                &root,
                context_lines,
                limit,
                offset,
                include_review_material,
            ))?;
            print_json(&mehscan_engine::investigation::path_review_tasks(&job))
        }
        "review-bundles" => {
            let output = PathBuf::from(parsed.required("--output")?);
            let max_bytes = parsed.optional_usize("--max-bytes")?;
            let max_reviews = parsed.optional_usize("--max-reviews")?;
            let max_total_reviews = parsed.optional_usize("--max-total-reviews")?;
            let context_lines = parsed.optional_usize("--context-lines")?;
            let include_review_material = parsed
                .optional_bool("--include-review-material")?
                .unwrap_or(false);
            let scope = parse_report_scope(&mut parsed);
            parsed.finish()?;
            let job = engine(mehscan_engine::investigation::build_all_path_review_jobs(
                &root,
                context_lines,
                include_review_material,
            ))?;
            let mut bundle_set = engine(
                mehscan_engine::investigation::build_path_review_bundles_with_run_limit(
                    &job,
                    max_bytes,
                    max_reviews,
                    max_total_reviews,
                ),
            )?;
            bundle_set.manifest.scope.extend(scope);
            write_path_review_bundles(&output, &bundle_set)?;
            print_json(&bundle_set.manifest)
        }
        "review-bundle-diff" => {
            let before = PathBuf::from(parsed.required("--before")?);
            let after = PathBuf::from(parsed.required("--after")?);
            parsed.finish()?;
            print_json(&diff_path_review_bundle_runs(&before, &after)?)
        }
        "review-response-schema" => {
            let path = PathBuf::from(parsed.required("--bundle")?);
            let output = parsed.optional("--output").map(PathBuf::from);
            parsed.finish()?;
            let bundle: mehscan_core::PathReviewBundle = serde_json::from_str(
                &fs::read_to_string(&path)
                    .map_err(|e| format!("could not read bundle {}: {e}", path.display()))?,
            )
            .map_err(|e| format!("invalid bundle: {e}"))?;
            let ids = &bundle.review_ids;
            if ids.is_empty()
                || bundle.bundle_fingerprint.is_empty()
                || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
            {
                return Err("bundle must contain a fingerprint and distinct review IDs".to_string());
            }
            let position_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["line", "column", "byte_offset"],
                "properties": {
                    "line": {"type": "integer", "minimum": 0},
                    "column": {"type": "integer", "minimum": 0},
                    "byte_offset": {"type": "integer", "minimum": 0}
                }
            });
            let location_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["path", "start", "end"],
                "properties": {
                    "path": {"type": "string"},
                    "start": position_schema,
                    "end": position_schema
                }
            });
            let artifact_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["artifact_id", "location", "excerpt"],
                "properties": {
                    "artifact_id": {"type": "string", "minLength": 1, "maxLength": 120},
                    "location": location_schema,
                    "excerpt": {"type": "string", "minLength": 1, "maxLength": 4000}
                }
            });
            let lookup_request_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["operation", "arguments", "questions", "purpose"],
                "properties": {
                    "operation": {"type": "string", "enum": ["source", "references"]},
                    "arguments": {"type": "object", "additionalProperties": {"type": "string"}},
                    "questions": {"type": "array", "minItems": 1, "items": {"type": "string"}},
                    "purpose": {"type": "string", "minLength": 1, "maxLength": 500}
                }
            });
            let lookup_attempt_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["outcome", "artifacts", "detail"],
                "oneOf": [
                    {"required": ["request_index"], "not": {"required": ["escalation"]}},
                    {"required": ["escalation"], "not": {"required": ["request_index"]}}
                ],
                "properties": {
                    "request_index": {"type": "integer", "minimum": 0},
                    "escalation": lookup_request_schema,
                    "outcome": {"type": "string", "enum": ["answered", "no_relevant_result", "unavailable", "truncated", "budget_exhausted", "failed"]},
                    "artifacts": {"type": "array", "items": artifact_schema},
                    "detail": {"type": "string", "minLength": 1, "maxLength": 500}
                }
            });
            let investigation_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["lookup_attempts", "citations", "reviewer_inferences", "blockers"],
                "properties": {
                    "lookup_attempts": {"type": "array", "items": lookup_attempt_schema},
                    "citations": {"type": "array", "items": {
                        "type": "object", "additionalProperties": false,
                        "required": ["artifact_id", "claim"],
                        "properties": {
                            "artifact_id": {"type": "string"},
                            "claim": {"type": "string", "minLength": 1, "maxLength": 500}
                        }
                    }},
                    "reviewer_inferences": {"type": "array", "items": {
                        "type": "object", "additionalProperties": false,
                        "required": ["claim", "artifact_ids"],
                        "properties": {
                            "claim": {"type": "string", "minLength": 1, "maxLength": 500},
                            "artifact_ids": {"type": "array", "minItems": 1, "items": {"type": "string"}}
                        }
                    }},
                    "blockers": {"type": "array", "items": {"type": "string"}}
                }
            });
            let schema = serde_json::json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object", "additionalProperties": false,
                "required": ["schema_version", "bundle_fingerprint", "results"],
                "properties": {
                    "schema_version": {"type": "string", "const": mehscan_core::PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION},
                    "bundle_fingerprint": {"type": "string", "const": bundle.bundle_fingerprint},
                    "results": {"type": "array", "minItems": ids.len(), "maxItems": ids.len(), "items": {
                        "type": "object", "additionalProperties": false,
                        "required": ["review_id", "decision", "confidence", "summary", "checks", "investigation"],
                        "properties": {
                            "review_id": {"type": "string", "enum": ids},
                            "decision": {"type": "string", "enum": ["issue", "not_issue", "needs_review"]},
                            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
                            "summary": {"type": "string", "maxLength": 450},
                            "checks": {"type": "array", "items": {"type": "string"}},
                            "investigation": investigation_schema
                        }
                    }}
                }
            });
            write_json(&schema, output.as_deref())
        }
        "review-bundle-triage" => {
            let bundle_path = PathBuf::from(parsed.required("--bundle")?);
            let responses_path = PathBuf::from(parsed.required("--responses")?);
            parsed.finish()?;
            let bundle_source = fs::read_to_string(&bundle_path).map_err(|error| {
                format!(
                    "could not read path-review bundle {}: {error}",
                    bundle_path.display()
                )
            })?;
            let bundle: mehscan_core::PathReviewBundle = serde_json::from_str(&bundle_source)
                .map_err(|error| {
                    format!(
                        "path-review bundle {} is invalid: {error}",
                        bundle_path.display()
                    )
                })?;
            let response_source = fs::read_to_string(&responses_path).map_err(|error| {
                format!(
                    "could not read path-review bundle response {}: {error}",
                    responses_path.display()
                )
            })?;
            let responses: mehscan_core::PathReviewBundleResponseSet =
                serde_json::from_str(&response_source).map_err(|error| {
                    format!(
                        "path-review bundle response {} is invalid: {error}",
                        responses_path.display()
                    )
                })?;
            let report = mehscan_engine::investigation::validate_path_review_bundle_response(
                &bundle, &responses,
            )
            .map_err(|error| format!("invalid reviewer work: {error}"))?;
            print_json(&report)
        }
        "review-bundle-summary" => {
            let run = PathBuf::from(parsed.required("--run")?);
            let responses = parsed.optional("--responses").map(PathBuf::from);
            let allow_partial = parsed.optional_bool("--allow-partial")?.unwrap_or(false);
            parsed.finish()?;
            let (manifest, bundle_responses, work) =
                read_complete_bundle_responses(&run, responses.as_deref(), allow_partial)?;
            let mut summary = engine(
                mehscan_engine::investigation::summarize_path_review_bundle_manifest_run_with_work(
                    &manifest,
                    &bundle_responses,
                    work,
                ),
            )?;
            summary.quality_warnings.extend(
                manifest
                    .scope
                    .iter()
                    .filter(|s| s.starts_with("Partial triage:"))
                    .cloned(),
            );
            print_json(&summary)
        }
        "review-triage" => {
            let responses = PathBuf::from(parsed.required("--responses")?);
            let limit = parsed.optional_usize("--limit")?;
            let context_lines = parsed.optional_usize("--context-lines")?;
            let offset = parsed.optional_usize("--offset")?.unwrap_or(0);
            let include_review_material = parsed
                .optional_bool("--include-review-material")?
                .unwrap_or(false);
            parsed.finish()?;
            let source = fs::read_to_string(&responses).map_err(|error| {
                format!(
                    "could not read path-review triage responses {}: {error}",
                    responses.display()
                )
            })?;
            let response_set: mehscan_core::PathReviewTriageResponseSet =
                serde_json::from_str(&source).map_err(|error| {
                    format!(
                        "path-review triage responses {} are invalid: {error}",
                        responses.display()
                    )
                })?;
            let job = engine(mehscan_engine::investigation::build_path_review_jobs_page(
                &root,
                context_lines,
                limit,
                offset,
                include_review_material,
            ))?;
            print_json(&engine(
                mehscan_engine::investigation::validate_path_review_triage(&job, &response_set),
            )?)
        }
        "review-progress" => {
            let responses = PathBuf::from(parsed.required("--responses")?);
            let limit = parsed.optional_usize("--limit")?;
            let context_lines = parsed.optional_usize("--context-lines")?;
            let offset = parsed.optional_usize("--offset")?.unwrap_or(0);
            let include_review_material = parsed
                .optional_bool("--include-review-material")?
                .unwrap_or(false);
            parsed.finish()?;
            let source = fs::read_to_string(&responses).map_err(|error| {
                format!(
                    "could not read path-review progress responses {}: {error}",
                    responses.display()
                )
            })?;
            let response_set: mehscan_core::PathReviewTriageResponseSet =
                serde_json::from_str(&source).map_err(|error| {
                    format!(
                        "path-review progress responses {} are invalid: {error}",
                        responses.display()
                    )
                })?;
            let job = engine(mehscan_engine::investigation::build_path_review_jobs_page(
                &root,
                context_lines,
                limit,
                offset,
                include_review_material,
            ))?;
            print_json(&engine(
                mehscan_engine::investigation::validate_path_review_progress(&job, &response_set),
            )?)
        }
        "neighborhoods" => {
            let language = parse_language(&parsed.required("--language")?)?;
            if language != Language::Csharp {
                return Err(
                    "review neighborhoods currently support only --language csharp".to_string(),
                );
            }
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::build_csharp_review_neighborhoods(&root, limit),
            )?)
        }
        "triage" => {
            let language = parse_language(&parsed.required("--language")?)?;
            if language != Language::Csharp {
                return Err("review triage currently supports only --language csharp".to_string());
            }
            let responses = PathBuf::from(parsed.required("--responses")?);
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            let source = fs::read_to_string(&responses).map_err(|error| {
                format!(
                    "could not read review triage responses {}: {error}",
                    responses.display()
                )
            })?;
            let response_set: mehscan_core::ReviewTriageResponseSet = serde_json::from_str(&source)
                .map_err(|error| {
                    format!(
                        "review triage responses {} are invalid: {error}",
                        responses.display()
                    )
                })?;
            let job = engine(
                mehscan_engine::investigation::build_csharp_review_neighborhoods(&root, limit),
            )?;
            print_json(&engine(
                mehscan_engine::investigation::validate_review_triage(&job, &response_set),
            )?)
        }
        "outline" => {
            let path = parsed.required("--path")?;
            parsed.finish()?;
            print_json(&engine(mehscan_engine::investigation::get_file_outline(
                &root, &path,
            ))?)
        }
        "source" => {
            let path = parsed.required("--path")?;
            let start_line = parsed.required_usize("--start-line")?;
            let end_line = parsed.required_usize("--end-line")?;
            parsed.finish()?;
            print_json(&engine(mehscan_engine::investigation::get_source(
                &root, &path, start_line, end_line,
            ))?)
        }
        "enclosing" => {
            let evidence_id = parsed.required("--evidence-id")?;
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::get_enclosing_symbol(&root, &evidence_id),
            )?)
        }
        "evidence" => {
            let filter = EvidenceFilter {
                kind: parsed
                    .optional("--kind")
                    .map(|value| parse_evidence_kind(&value))
                    .transpose()?,
                capability: parsed
                    .optional("--capability")
                    .map(|value| parse_capability(&value))
                    .transpose()?,
                language: parsed
                    .optional("--language")
                    .map(|value| parse_language(&value))
                    .transpose()?,
                path: parsed.optional("--path"),
            };
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(mehscan_engine::investigation::find_evidence(
                &root, filter, limit,
            ))?)
        }
        "units" => {
            let filter = EvidenceFilter {
                kind: parsed
                    .optional("--kind")
                    .map(|value| parse_evidence_kind(&value))
                    .transpose()?,
                capability: parsed
                    .optional("--capability")
                    .map(|value| parse_capability(&value))
                    .transpose()?,
                language: parsed
                    .optional("--language")
                    .map(|value| parse_language(&value))
                    .transpose()?,
                path: parsed.optional("--path"),
            };
            let context_lines = parsed.optional_usize("--context-lines")?;
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::build_investigation_job(
                    &root,
                    filter,
                    context_lines,
                    limit,
                ),
            )?)
        }
        "symbol" => {
            let name = parsed.required("--name")?;
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(mehscan_engine::investigation::find_symbol(
                &root, &name, limit,
            ))?)
        }
        "imports" => {
            let name = parsed.required("--name")?;
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(mehscan_engine::investigation::find_imports(
                &root, &name, limit,
            ))?)
        }
        "references" => {
            let symbol = parsed.required("--symbol")?;
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::find_text_references(&root, &symbol, limit),
            )?)
        }
        "native-call-sites" => {
            let callee = parsed.required("--callee")?;
            let path = parsed.optional("--path");
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::find_native_call_sites(
                    &root,
                    &callee,
                    path.as_deref(),
                    limit,
                ),
            )?)
        }
        "structural" => {
            let language = parse_language(&parsed.required("--language")?)?;
            let pattern = parsed.required("--pattern")?;
            let path = parsed.optional("--path");
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::run_structural_query(
                    &root,
                    language,
                    &pattern,
                    path.as_deref(),
                    limit,
                ),
            )?)
        }
        _ => Err(format!(
            "unknown investigation operation {operation:?}; run 'mehscan investigate --help'"
        )),
    }
}

fn engine<T>(result: Result<T, mehscan_engine::EngineError>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

fn read_complete_bundle_responses(
    run: &Path,
    responses: Option<&Path>,
    allow_partial: bool,
) -> Result<
    (
        mehscan_core::PathReviewBundleManifest,
        Vec<(
            mehscan_core::PathReviewBundle,
            mehscan_core::PathReviewBundleResponseSet,
        )>,
        mehscan_core::ReviewWorkSummary,
    ),
    String,
> {
    let manifest_path = run.join("manifest.json");
    let manifest_source = fs::read_to_string(&manifest_path).map_err(|error| {
        format!(
            "could not read path-review bundle manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let mut manifest: mehscan_core::PathReviewBundleManifest =
        serde_json::from_str(&manifest_source).map_err(|error| {
            format!(
                "path-review bundle manifest {} is invalid: {error}",
                manifest_path.display()
            )
        })?;
    let response_directory = responses
        .map(Path::to_path_buf)
        .unwrap_or_else(|| run.join("responses"));
    if manifest.bundle_count != manifest.bundles.len()
        || manifest.review_count
            != manifest
                .bundles
                .iter()
                .map(|e| e.review_count)
                .sum::<usize>()
        || (manifest.admitted_review_count != 0
            && manifest.admitted_review_count
                != manifest.review_count + manifest.deferred_review_ids.len())
    {
        return Err("review manifest count does not match the run".to_string());
    }
    let scheduled_ids = manifest
        .bundles
        .iter()
        .flat_map(|entry| entry.review_ids.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let deferred_ids = manifest
        .deferred_review_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if deferred_ids.len() != manifest.deferred_review_ids.len()
        || !scheduled_ids.is_disjoint(&deferred_ids)
    {
        return Err("review manifest scheduled and deferred identities are invalid".to_string());
    }
    let scheduled_bundle_count = manifest.bundle_count;
    let scheduled_review_count = manifest.review_count;
    let admitted_review_count = if manifest.admitted_review_count == 0 {
        manifest.review_count + manifest.deferred_review_ids.len()
    } else {
        manifest.admitted_review_count
    };
    let mut bundle_responses = Vec::new();
    let mut selected = Vec::new();
    let mut missing_review_ids = Vec::new();
    for entry in &manifest.bundles {
        let request_path = run.join("requests").join(&entry.filename);
        let response_path = response_directory.join(&entry.filename);
        let request_source = fs::read_to_string(&request_path).map_err(|error| {
            format!(
                "could not read path-review bundle {}: {error}",
                request_path.display()
            )
        })?;
        let bundle: mehscan_core::PathReviewBundle = serde_json::from_str(&request_source)
            .map_err(|error| {
                format!(
                    "path-review bundle {} is invalid: {error}",
                    request_path.display()
                )
            })?;
        if bundle.job_fingerprint != manifest.job_fingerprint
            || bundle.review_ids != entry.review_ids
            || bundle.review_ids.len() != entry.review_count
        {
            return Err(format!(
                "path-review bundle {} does not match its manifest identity or review count",
                request_path.display()
            ));
        }
        if bundle.bundle_fingerprint != entry.bundle_fingerprint {
            return Err(format!(
                "path-review bundle {} does not match its manifest fingerprint",
                request_path.display()
            ));
        }
        let response_source = match fs::read_to_string(&response_path) {
            Ok(source) => source,
            Err(error) if allow_partial && error.kind() == std::io::ErrorKind::NotFound => {
                missing_review_ids.extend(entry.review_ids.iter().cloned());
                continue;
            }
            Err(error) => {
                return Err(format!(
                    "could not read complete path-review bundle response {}: {error}",
                    response_path.display()
                ));
            }
        };
        let response_set: mehscan_core::PathReviewBundleResponseSet =
            serde_json::from_str(&response_source).map_err(|error| {
                format!(
                    "path-review bundle response {} is invalid reviewer work: {error}",
                    response_path.display()
                )
            })?;
        mehscan_engine::investigation::validate_path_review_bundle_response(&bundle, &response_set)
            .map_err(|error| {
                format!(
                    "path-review bundle response {} is invalid reviewer work for reviews {}: {error}",
                    response_path.display(),
                    entry.review_ids.join(", ")
                )
            })?;
        selected.push(entry.clone());
        bundle_responses.push((bundle, response_set));
    }
    let completed_bundle_count = selected.len();
    let completed_review_count = selected
        .iter()
        .map(|entry| entry.review_count)
        .sum::<usize>();
    missing_review_ids.sort();
    missing_review_ids.dedup();
    let mut deferred_review_ids = manifest.deferred_review_ids.clone();
    deferred_review_ids.extend(missing_review_ids.iter().cloned());
    deferred_review_ids.sort();
    deferred_review_ids.dedup();
    let work = mehscan_core::ReviewWorkSummary {
        complete: missing_review_ids.is_empty()
            && deferred_review_ids.is_empty()
            && completed_bundle_count == scheduled_bundle_count
            && completed_review_count == scheduled_review_count,
        admitted_review_count,
        scheduled_bundle_count,
        scheduled_review_count,
        completed_bundle_count,
        completed_review_count,
        accepted_investigation_count: 0,
        deferred_review_ids,
        blocked_review_ids: Vec::new(),
        truncated_review_ids: Vec::new(),
        missing_review_ids,
        invalid_review_ids: Vec::new(),
    };
    if selected.len() != manifest.bundle_count {
        manifest.scope.push(format!("Partial triage: {}/{} bundles and {}/{} reviews completed; unreviewed bundles are excluded, not dismissed.", selected.len(), manifest.bundle_count, selected.iter().map(|e| e.review_count).sum::<usize>(), manifest.review_count));
        manifest.bundle_count = selected.len();
        manifest.review_count = selected.iter().map(|e| e.review_count).sum();
        manifest.bundles = selected;
    }
    Ok((manifest, bundle_responses, work))
}

fn write_json<T: serde::Serialize>(value: &T, output: Option<&Path>) -> Result<(), String> {
    match output {
        Some(path) => {
            let portable = portable_json_value(value)?;
            let bytes = serde_json::to_vec_pretty(&portable)
                .map_err(|error| format!("could not serialize portable report: {error}"))?;
            fs::write(path, bytes)
                .map_err(|error| format!("could not write report {}: {error}", path.display()))
        }
        None => print_json(value),
    }
}

fn write_text(value: &str, output: Option<&Path>) -> Result<(), String> {
    match output {
        Some(path) => fs::write(path, value)
            .map_err(|error| format!("could not write report {}: {error}", path.display())),
        None => {
            print!("{value}");
            Ok(())
        }
    }
}

fn write_path_review_bundles(
    output: &std::path::Path,
    bundle_set: &mehscan_core::PathReviewBundleSet,
) -> Result<(), String> {
    let requests = output.join("requests");
    let responses = output.join("responses");
    fs::create_dir_all(&requests).map_err(|error| {
        format!(
            "could not create review request directory {}: {error}",
            requests.display()
        )
    })?;
    fs::create_dir_all(&responses).map_err(|error| {
        format!(
            "could not create review response directory {}: {error}",
            responses.display()
        )
    })?;
    for (entry, bundle) in bundle_set.manifest.bundles.iter().zip(&bundle_set.bundles) {
        let bytes = serde_json::to_vec(bundle)
            .map_err(|error| format!("could not serialize review bundle: {error}"))?;
        if bytes.len() != entry.input_bytes {
            return Err(format!(
                "review bundle size changed while writing {:?}",
                entry.filename
            ));
        }
        fs::write(requests.join(&entry.filename), bytes).map_err(|error| {
            format!(
                "could not write review bundle {:?}: {error}",
                entry.filename
            )
        })?;
    }
    let manifest = serde_json::to_vec_pretty(&bundle_set.manifest)
        .map_err(|error| format!("could not serialize review bundle manifest: {error}"))?;
    fs::write(output.join("manifest.json"), manifest).map_err(|error| {
        format!(
            "could not write review bundle manifest {}: {error}",
            output.join("manifest.json").display()
        )
    })
}

struct ReviewBundleRunSnapshot {
    job_fingerprint: String,
    max_input_bytes: usize,
    max_reviews_per_bundle: usize,
    bundle_count: usize,
    reviews: BTreeMap<String, serde_json::Value>,
    bundle_by_review: BTreeMap<String, String>,
    bundle_review_ids: BTreeMap<String, Vec<String>>,
    goal: Option<String>,
    triage_contract: Option<serde_json::Value>,
}

fn read_review_bundle_run(run: &Path) -> Result<ReviewBundleRunSnapshot, String> {
    let manifest_path = run.join("manifest.json");
    let manifest_source = fs::read_to_string(&manifest_path).map_err(|error| {
        format!(
            "could not read path-review bundle manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let manifest: mehscan_core::PathReviewBundleManifest = serde_json::from_str(&manifest_source)
        .map_err(|error| {
        format!(
            "path-review bundle manifest {} is invalid: {error}",
            manifest_path.display()
        )
    })?;
    let mut reviews = BTreeMap::new();
    let mut bundle_by_review = BTreeMap::new();
    let mut bundle_review_ids = BTreeMap::new();
    let mut goal = None;
    let mut triage_contract = None;
    for entry in &manifest.bundles {
        let request_path = run.join("requests").join(&entry.filename);
        let request_source = fs::read_to_string(&request_path).map_err(|error| {
            format!(
                "could not read path-review bundle {}: {error}",
                request_path.display()
            )
        })?;
        // Diff historical reviewer payloads as JSON rather than requiring
        // every nested review to deserialize into today's schema. Envelope
        // identity and exact review IDs remain strictly validated below.
        let bundle: serde_json::Value = serde_json::from_str(&request_source).map_err(|error| {
            format!(
                "path-review bundle {} is invalid: {error}",
                request_path.display()
            )
        })?;
        let bundle_fingerprint = bundle
            .get("bundle_fingerprint")
            .and_then(serde_json::Value::as_str);
        let job_fingerprint = bundle
            .get("job_fingerprint")
            .and_then(serde_json::Value::as_str);
        if bundle_fingerprint != Some(entry.bundle_fingerprint.as_str())
            || job_fingerprint != Some(manifest.job_fingerprint.as_str())
        {
            return Err(format!(
                "path-review bundle {} does not match its manifest identity",
                request_path.display()
            ));
        }
        let bundle_goal = bundle
            .get("goal")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                format!(
                    "path-review bundle {} has no string goal",
                    request_path.display()
                )
            })?
            .to_string();
        if goal.as_ref().is_some_and(|value| value != &bundle_goal) {
            return Err(format!(
                "path-review run {} contains inconsistent review goals",
                run.display()
            ));
        }
        goal.get_or_insert(bundle_goal);
        let contract = bundle.get("triage_contract").cloned().ok_or_else(|| {
            format!(
                "path-review bundle {} has no triage contract",
                request_path.display()
            )
        })?;
        if triage_contract
            .as_ref()
            .is_some_and(|value| value != &contract)
        {
            return Err(format!(
                "path-review run {} contains inconsistent triage contracts",
                run.display()
            ));
        }
        triage_contract.get_or_insert(contract);

        let declared_review_ids = bundle
            .get("review_ids")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                format!(
                    "path-review bundle {} has no review ID array",
                    request_path.display()
                )
            })?
            .iter()
            .map(|id| {
                id.as_str().map(str::to_string).ok_or_else(|| {
                    format!(
                        "path-review bundle {} contains a non-string review ID",
                        request_path.display()
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let payload_reviews = bundle
            .get("reviews")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                format!(
                    "path-review bundle {} has no reviews array",
                    request_path.display()
                )
            })?
            .iter()
            .map(|review| {
                let id = review
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        format!(
                            "path-review bundle {} contains a review without a string ID",
                            request_path.display()
                        )
                    })?;
                Ok((id.to_string(), review.clone()))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let payload_ids = payload_reviews
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        if payload_ids != declared_review_ids || payload_ids != entry.review_ids {
            return Err(format!(
                "path-review bundle {} review IDs do not match its manifest",
                request_path.display()
            ));
        }
        if bundle_review_ids
            .insert(entry.filename.clone(), payload_ids.clone())
            .is_some()
        {
            return Err(format!(
                "path-review run {} repeats bundle filename {:?}",
                run.display(),
                entry.filename
            ));
        }
        for (id, review) in payload_reviews {
            if reviews.insert(id.clone(), review).is_some() {
                return Err(format!(
                    "path-review run {} repeats review ID {id}",
                    run.display()
                ));
            }
            bundle_by_review.insert(id, entry.filename.clone());
        }
    }
    if reviews.len() != manifest.review_count {
        return Err(format!(
            "path-review run {} contains {} reviews but its manifest declares {}",
            run.display(),
            reviews.len(),
            manifest.review_count
        ));
    }
    Ok(ReviewBundleRunSnapshot {
        job_fingerprint: manifest.job_fingerprint,
        max_input_bytes: manifest.max_input_bytes,
        max_reviews_per_bundle: manifest.max_reviews_per_bundle,
        bundle_count: manifest.bundle_count,
        reviews,
        bundle_by_review,
        bundle_review_ids,
        goal,
        triage_contract,
    })
}

fn membership_changed_after_bundles(
    before: &BTreeMap<String, Vec<String>>,
    after: &BTreeMap<String, Vec<String>>,
) -> BTreeSet<String> {
    let before_memberships = before.values().cloned().collect::<BTreeSet<_>>();
    after
        .iter()
        .filter(|(_, review_ids)| !before_memberships.contains(*review_ids))
        .map(|(filename, _)| filename.clone())
        .collect()
}

fn diff_path_review_bundle_runs(
    before_run: &Path,
    after_run: &Path,
) -> Result<serde_json::Value, String> {
    let before = read_review_bundle_run(before_run)?;
    let after = read_review_bundle_run(after_run)?;
    let before_ids = before.reviews.keys().cloned().collect::<BTreeSet<_>>();
    let after_ids = after.reviews.keys().cloned().collect::<BTreeSet<_>>();
    let added_review_ids = after_ids
        .difference(&before_ids)
        .cloned()
        .collect::<Vec<_>>();
    let removed_review_ids = before_ids
        .difference(&after_ids)
        .cloned()
        .collect::<Vec<_>>();
    let changed_review_ids = before_ids
        .intersection(&after_ids)
        .filter(|id| before.reviews.get(*id) != after.reviews.get(*id))
        .cloned()
        .collect::<Vec<_>>();
    let unchanged_review_count = before_ids
        .intersection(&after_ids)
        .filter(|id| before.reviews.get(*id) == after.reviews.get(*id))
        .count();
    let contract_changed =
        before.goal != after.goal || before.triage_contract != after.triage_contract;
    let bundle_layout_changed = before.max_input_bytes != after.max_input_bytes
        || before.max_reviews_per_bundle != after.max_reviews_per_bundle;
    let changed_or_added = changed_review_ids
        .iter()
        .chain(&added_review_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let membership_changed_after_bundles =
        membership_changed_after_bundles(&before.bundle_review_ids, &after.bundle_review_ids);
    let changed_after_bundles = if contract_changed || bundle_layout_changed {
        after
            .bundle_by_review
            .values()
            .cloned()
            .collect::<BTreeSet<_>>()
    } else if changed_or_added.is_empty() {
        BTreeSet::new()
    } else {
        let mut bundles = changed_or_added
            .iter()
            .filter_map(|id| after.bundle_by_review.get(id).cloned())
            .collect::<BTreeSet<_>>();
        bundles.extend(membership_changed_after_bundles.iter().cloned());
        bundles
    };
    let model_validation = if contract_changed || bundle_layout_changed {
        "full_pack"
    } else if changed_after_bundles.is_empty() {
        "not_required"
    } else {
        "changed_bundles"
    };
    let reason = match model_validation {
        "full_pack" if contract_changed => "The shared goal or triage contract changed.",
        "full_pack" => "The model-visible bundle layout changed.",
        "changed_bundles" => {
            "Only added or reviewer-visible changed reviews need targeted model validation."
        }
        _ if !removed_review_ids.is_empty() => {
            "Only review admission removed items; deterministic baselines are sufficient."
        }
        _ => "Reviewer-visible review content is unchanged.",
    };
    Ok(serde_json::json!({
        "schema_version": "1.0",
        "before": {
            "job_fingerprint": before.job_fingerprint,
            "review_count": before.reviews.len(),
            "bundle_count": before.bundle_count,
            "max_input_bytes": before.max_input_bytes,
            "max_reviews_per_bundle": before.max_reviews_per_bundle
        },
        "after": {
            "job_fingerprint": after.job_fingerprint,
            "review_count": after.reviews.len(),
            "bundle_count": after.bundle_count,
            "max_input_bytes": after.max_input_bytes,
            "max_reviews_per_bundle": after.max_reviews_per_bundle
        },
        "contract_changed": contract_changed,
        "bundle_layout_changed": bundle_layout_changed,
        "added_review_ids": added_review_ids,
        "removed_review_ids": removed_review_ids,
        "changed_review_ids": changed_review_ids,
        "unchanged_review_count": unchanged_review_count,
        "membership_changed_after_bundles": membership_changed_after_bundles,
        "changed_after_bundles": changed_after_bundles,
        "recommended_model_validation": model_validation,
        "reason": reason
    }))
}

struct ParsedArguments {
    root: PathBuf,
    options: BTreeMap<String, String>,
    help: bool,
}

impl ParsedArguments {
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut root = None;
        let mut options = BTreeMap::new();
        let mut help = false;
        let mut arguments = arguments.peekable();
        while let Some(argument) = arguments.next() {
            if matches!(argument.as_str(), "--help" | "-h") {
                help = true;
                continue;
            }
            if argument.starts_with('-') {
                let value = arguments
                    .next()
                    .ok_or_else(|| format!("{argument} requires a value"))?;
                if value.starts_with('-') {
                    return Err(format!("{argument} requires a value"));
                }
                if options.insert(argument.clone(), value).is_some() {
                    return Err(format!("option {argument:?} was supplied more than once"));
                }
            } else if root.is_none() {
                root = Some(PathBuf::from(argument));
            } else {
                return Err(format!("unexpected argument {argument:?}"));
            }
        }
        Ok(Self {
            root: root.unwrap_or_else(|| PathBuf::from(".")),
            options,
            help,
        })
    }

    fn required(&mut self, name: &str) -> Result<String, String> {
        self.options
            .remove(name)
            .ok_or_else(|| format!("{name} is required"))
    }

    fn optional(&mut self, name: &str) -> Option<String> {
        self.options.remove(name)
    }

    fn required_usize(&mut self, name: &str) -> Result<usize, String> {
        parse_usize(name, &self.required(name)?)
    }

    fn optional_usize(&mut self, name: &str) -> Result<Option<usize>, String> {
        self.optional(name)
            .map(|value| parse_usize(name, &value))
            .transpose()
    }

    fn optional_bool(&mut self, name: &str) -> Result<Option<bool>, String> {
        self.optional(name)
            .map(|value| match value.to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" => Ok(true),
                "false" | "no" | "0" => Ok(false),
                _ => Err(format!("{name} requires true or false")),
            })
            .transpose()
    }

    fn finish(self) -> Result<(), String> {
        if let Some(name) = self.options.keys().next() {
            Err(format!("unknown option {name:?}"))
        } else {
            Ok(())
        }
    }
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|_| format!("{name} requires a positive integer"))
}

fn parse_language(value: &str) -> Result<Language, String> {
    match value.to_ascii_lowercase().as_str() {
        "csharp" | "c#" | "cs" => Ok(Language::Csharp),
        "java" => Ok(Language::Java),
        "kotlin" | "kt" | "kts" => Ok(Language::Kotlin),
        "javascript" | "js" => Ok(Language::Javascript),
        "typescript" | "ts" => Ok(Language::Typescript),
        "tsx" => Ok(Language::Tsx),
        "python" | "py" => Ok(Language::Python),
        "go" | "golang" => Ok(Language::Go),
        _ => Err(format!("unsupported language {value:?}")),
    }
}

fn parse_evidence_kind(value: &str) -> Result<EvidenceKind, String> {
    match value {
        "entrypoint" => Ok(EvidenceKind::Entrypoint),
        "source" => Ok(EvidenceKind::Source),
        "sink" => Ok(EvidenceKind::Sink),
        "guard" => Ok(EvidenceKind::Guard),
        "sanitizer" => Ok(EvidenceKind::Sanitizer),
        "validation" => Ok(EvidenceKind::Validation),
        "resource" => Ok(EvidenceKind::Resource),
        "sensitive_operation" => Ok(EvidenceKind::SensitiveOperation),
        "security_configuration" => Ok(EvidenceKind::SecurityConfiguration),
        "literal" => Ok(EvidenceKind::Literal),
        "secret" => Ok(EvidenceKind::Secret),
        _ => Err(format!("unsupported evidence kind {value:?}")),
    }
}

fn parse_capability(value: &str) -> Result<Capability, String> {
    serde_json::from_value(serde_json::Value::String(value.to_string()))
        .map_err(|_| format!("unsupported capability {value:?}"))
}

fn print_json(value: &impl serde::Serialize) -> Result<(), String> {
    let portable = portable_json_value(value)?;
    let json = serde_json::to_string_pretty(&portable)
        .map_err(|error| format!("could not serialize portable result: {error}"))?;
    println!("{json}");
    Ok(())
}

fn portable_json_value(value: &impl serde::Serialize) -> Result<serde_json::Value, String> {
    let mut value = serde_json::to_value(value)
        .map_err(|error| format!("could not serialize result: {error}"))?;
    make_json_paths_portable(&mut value)?;
    Ok(value)
}

fn is_absolute_artifact_path(path: &str) -> bool {
    Path::new(path).is_absolute()
        || path.starts_with('/')
        || path.starts_with("\\\\")
        || matches!(
            path.as_bytes(),
            [drive, b':', separator, ..]
                if drive.is_ascii_alphabetic() && matches!(separator, b'/' | b'\\')
        )
}

fn make_json_paths_portable(value: &mut serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Object(fields) => {
            let is_http_route = fields.contains_key("method") && fields.contains_key("access");
            for (name, value) in fields {
                if matches!(name.as_str(), "root" | "scanRoot")
                    && value.as_str().is_some_and(is_absolute_artifact_path)
                {
                    *value = serde_json::Value::String(".".to_string());
                } else if matches!(name.as_str(), "path" | "uri")
                    && !is_http_route
                    && value.as_str().is_some_and(is_absolute_artifact_path)
                {
                    return Err(format!(
                        "refusing to serialize absolute artifact location {:?}",
                        value.as_str().unwrap_or_default()
                    ));
                }
                make_json_paths_portable(value)?;
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                make_json_paths_portable(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum OutputFormat {
    Json,
    Text,
}

#[derive(Clone, Copy)]
enum ScanOutputFormat {
    Json,
    Text,
    Candidates,
    Sarif,
}

enum ReportOutputFormat {
    Json,
    Sarif,
    Markdown,
}

fn print_summary(result: &mehscan_core::ScanResult) {
    println!("root: {}", result.root);
    if let Some(scope) = &result.impact_scope {
        println!(
            "diff scope: {} (result policy: {}, {} files analyzed)",
            scope.strategy, scope.result_policy, scope.included_file_count
        );
        for reason in &scope.reasons {
            println!("  scope reason: {reason}");
        }
    }
    println!("evidence: {}", result.evidence.len());
    println!("security paths: {}", result.security_paths.len());
    println!(
        "files: {} code scanned, {} secret-only scanned, {} secret-only skipped, {} parse failed, {} unsupported, {} ignored",
        result.coverage.totals.scanned,
        result.coverage.totals.secret_scanned,
        result.coverage.totals.secret_skipped,
        result.coverage.totals.parse_failed,
        result.coverage.totals.unsupported,
        result.coverage.totals.ignored
    );
    if result.coverage.totals.secret_suppressed > 0 {
        println!(
            "secret observations suppressed: {}",
            result.coverage.totals.secret_suppressed
        );
    }
    for evidence in &result.evidence {
        println!(
            "{}:{}:{}  {:?}  {}",
            evidence.location.path,
            evidence.location.start.line,
            evidence.location.start.column,
            evidence.capability,
            evidence.rule_id
        );
    }
    if !result.coverage.ignored_subtrees.is_empty() {
        println!(
            "ignored subtrees: {}",
            result.coverage.ignored_subtrees.join(", ")
        );
    }
}

fn print_benchmark_summary(report: &mehscan_engine::benchmark::BenchmarkReport) {
    println!("benchmark manifest: v{}", report.manifest_version);
    println!("passed: {}", report.passed);
    for case in &report.cases {
        println!(
            "{}: {} ({} ms)",
            case.id,
            if case.passed { "passed" } else { "failed" },
            case.elapsed_milliseconds
        );
        for mismatch in &case.mismatches {
            println!("  mismatch: {mismatch}");
        }
    }
    for corpus in &report.optional_corpora {
        println!(
            "{}: {} ({} ms)",
            corpus.id,
            if corpus.passed { "passed" } else { "failed" },
            corpus.elapsed_milliseconds
        );
        for mismatch in &corpus.mismatches {
            println!("  mismatch: {mismatch}");
        }
        if let Some(truth) = &corpus.truth {
            println!(
                "  truth: {} TP, {} FN, {} FP, {} TN ({} cases; baseline {})",
                truth.true_positives,
                truth.false_negatives,
                truth.false_positives,
                truth.true_negatives,
                truth.cases,
                if truth.baseline_matched {
                    "matched"
                } else {
                    "changed"
                }
            );
        }
    }
    println!(
        "known unsupported cases: {}",
        report.known_unsupported.len()
    );
}

fn print_help() {
    println!(
        "mehscan - deterministic security evidence scanner\n\nUSAGE:\n  mehscan --version\n  mehscan scan [PATH] [--format text|json|candidates|sarif-candidates] [--jobs N] [--include-tests] [--changed-from REF | --files-from PATH] [--diff-mode full|impact]\n  mehscan report --run DIR [--responses DIR] [--allow-partial true|false] [--format json|sarif|markdown] [--output PATH]\n  mehscan benchmark [ROOT] [--manifest PATH] [--include-optional] [--format text|json]\n  mehscan evaluate <prepare|score> [ROOT] [OPTIONS]\n  mehscan investigate <OPERATION> [PATH] [OPTIONS]\n\nRun a command with --help for details."
    );
}

fn print_report_help() {
    println!(
        "USAGE:\n  mehscan report --run DIR [--responses DIR] [--allow-partial true|false] [--format json|sarif|markdown] [--output PATH] [--reviewer NAME] [--include-dismissed true|false] [--scope-label TEXT] [--project NAME] [--revision REF]\n\nBuilds canonical post-triage findings by joining validated bundle responses to deterministic review evidence. JSON is the full-fidelity consumer artifact. SARIF 2.1.0 contains confirmed issues only. Markdown is the human-readable summary and prioritizes unresolved review checks before confirmed and dismissed results; use --include-dismissed true to include not-issue summaries. --responses defaults to DIR/responses. --allow-partial true skips missing response files only and labels completed versus total review coverage; present responses must still validate as complete bundles. Scope, project and revision labels are user-supplied handoff metadata, not verified security facts."
    );
}

fn print_scan_help() {
    println!(
        "USAGE:\n  mehscan scan [PATH] [--format text|json|candidates|sarif-candidates] [--timings] [--jobs N] [--include-tests] [--changed-from REF | --files-from PATH] [--diff-mode full|impact]\n\n'json' preserves raw evidence and SecurityPath data. 'candidates' emits only reviewable bounded relationships plus coverage. 'sarif-candidates' emits one SARIF 2.1.0 review result per candidate, never one result per raw observation; legacy 'sarif' remains an alias. Use 'mehscan report --format sarif' for confirmed post-triage findings. Secret detection is currently disabled; secret-only text is reported as ignored. '--timings' emits one machine-readable phase profile to stderr without changing stdout. Directory scans honor repository-local .gitignore, nested .gitignore, .ignore, and .git/info/exclude rules, but not global user ignores. Built-in dependency and generated-tree exclusions remain mandatory. By default, test, fixture, sample, generated, and bundled sources are excluded from SAST. '--include-tests' promotes those supported source files into full SAST. '--jobs N' overrides automatic per-file worker selection. '--changed-from REF' includes tracked changes since REF and untracked files. '--files-from PATH' accepts one repository-relative path per line; a missing path is treated as a deletion. Diff mode 'full' is the default: analyze the complete repository, then return evidence and paths touching changed lines. Diff mode 'impact' analyzes changed files, small same-directory context, and direct importers. Both modes return all full-scan results when deletions, renames, project-wide configuration, or central entrypoint changes make changed-location filtering unsafe; impact mode also falls back for large or broad expansions. Scope, result policy, fallback reasons, and Git changed-line ranges are retained in JSON, candidate, and SARIF run metadata."
    );
}

fn print_benchmark_help() {
    println!(
        "SAST BENCHMARK\n\nUSAGE:\n  mehscan benchmark [ROOT] [--manifest PATH] [--include-optional] [--format text|json]\n\nThe default manifest is benchmarks/v2-sast.yml beneath ROOT. Fixture cases always run twice to verify deterministic evidence, paths, and coverage. Optional corpora are skipped unless --include-optional is supplied. No external scanner is downloaded or executed."
    );
}

fn print_evaluation_help() {
    println!(
        "PROVIDER-NEUTRAL MATCHED EVALUATION\n\nUSAGE:\n  mehscan evaluate prepare [ROOT] [--manifest PATH]\n  mehscan evaluate score [ROOT] [--manifest PATH] --responses PATH\n  mehscan evaluate review-prepare [ROOT] [--manifest PATH]\n  mehscan evaluate review-score [ROOT] [--manifest PATH] --responses PATH\n\n'prepare' emits matched AI-only, evidence-assisted, and candidate-assisted trials. 'review-prepare' emits a small cross-language issue/not_issue/needs_review pack without oracle decisions; 'review-score' validates exactly one compact result per selected case against the hidden manifest truth and exact pack fingerprint. Known secret ranges are masked. No model or external service is called by these commands."
    );
}

fn print_investigation_help() {
    println!(
        r#"AI-NATIVE INVESTIGATION QUERIES (JSON output)

USAGE:
  mehscan investigate funnel [ROOT]
  mehscan investigate review-jobs [ROOT] [--context-lines N] [--limit N] [--offset N] [--include-review-material true|false]
  mehscan investigate review-tasks [ROOT] [--context-lines N] [--limit N] [--offset N] [--include-review-material true|false]
  mehscan investigate review-bundles [ROOT] --output DIR [--context-lines N] [--max-bytes N] [--max-reviews N] [--max-total-reviews N] [--include-review-material true|false] [--scope-label TEXT] [--project NAME] [--revision REF]
  mehscan investigate review-bundle-diff --before DIR --after DIR
  mehscan investigate review-response-schema --bundle PATH [--output PATH]
  mehscan investigate review-bundle-triage --bundle PATH --responses PATH
  mehscan investigate review-bundle-summary --run DIR [--responses DIR] [--allow-partial true|false]
  mehscan investigate review-triage [ROOT] --responses PATH [--context-lines N] [--limit N] [--offset N] [--include-review-material true|false]
  mehscan investigate review-progress [ROOT] --responses PATH [--context-lines N] [--limit N] [--offset N] [--include-review-material true|false]
  mehscan investigate neighborhoods [ROOT] --language csharp [--limit N]
  mehscan investigate triage [ROOT] --language csharp --responses PATH [--limit N]
  mehscan investigate outline [ROOT] --path FILE
  mehscan investigate source [ROOT] --path FILE --start-line N --end-line N
  mehscan investigate enclosing [ROOT] --evidence-id ID
  mehscan investigate evidence [ROOT] [--kind KIND] [--capability NAME] [--language LANG] [--path FILE] [--limit N]
  mehscan investigate units [ROOT] [--kind KIND] [--capability NAME] [--language LANG] [--path FILE] [--context-lines N] [--limit N]
  mehscan investigate symbol [ROOT] --name NAME [--limit N]
  mehscan investigate imports [ROOT] --name NAME [--limit N]
  mehscan investigate references [ROOT] --symbol NAME [--limit N]
  mehscan investigate native-call-sites [ROOT] --callee NAME [--path FILE] [--limit N]
  mehscan investigate structural [ROOT] --language LANG --pattern PATTERN [--path FILE] [--limit N]

Review jobs package bounded security-path candidates and non-path observation neighborhoods with source excerpts, relevant configuration facts, open questions, a stable fingerprint, and a compact cross-language response contract. Each security path includes compact rule-derived review_basis semantics. Context-only source, guard, sanitizer, validation, literal, and resource observations do not become standalone verdict jobs. review-bundles scans once, groups admitted review work by review kind and capability, retains the CWE union as category metadata, and writes self-contained requests with readable semantic filenames under DIR/requests plus manifest.json. Requests default to independent ceilings of 512 KiB and 20 reviews; --max-reviews changes only that per-request transport ceiling. --max-total-reviews sets a separate run ceiling, schedules capabilities round-robin, requires room for at least one review from every admitted capability, and preserves deferred review IDs in the manifest. A bundle response is accepted or retried as a whole by review-bundle-triage. Response schema 1.2 records family-calibrated budgets, bounded lookup attempts, one exact follow-on source/reference lookup, retrieved artifacts, citations, reviewer inference and exact blockers; schemas 1.0 and 1.1 remain readable. Accepted results receive stable response fingerprints, and partial summaries distinguish admitted, scheduled, completed, deferred, blocked, truncated, missing, and invalid review work. review-bundle-summary validates every manifest response by default; --allow-partial true summarizes available complete responses and reports incomplete triage coverage. It deduplicates issue decisions across path and observation streams by capability, exact sink range, and the rule-defined security invariant. review-tasks and review-progress remain available as low-level diagnostics. Complete paths are ordered first, followed by production observation neighborhoods. Teaching/code-fix source payloads are excluded by default and can be admitted explicitly with --include-review-material true. Review pages contain at most 100 items and expose next_offset for stable continuation with --offset. The funnel summarizes linked and unlinked compatible source/sink observations for AI routing. C# project summaries can produce security paths for unique exact-parameter controller-to-service and controller-to-service-to-repository handoffs; unresolved neighborhoods remain review facts. Triage commands must repeat the exact page offset and material policy. Query limits default to 200 and cannot exceed 1000. Investigation units default to 25 and cannot exceed 100. Source retrieval is capped at 400 lines and 64 KiB. Native call-sites is a C/C++ syntax inventory only: it does not resolve types, overloads, aliases, macros, control flow, call graphs, or value flow and never changes scan evidence or review admission. Structural queries support every scanner language as bounded ephemeral syntax lookup; repository-wide queries skip and report malformed files, while an explicitly requested malformed file fails clearly. Structural patterns are never persisted as rules or promoted to findings."#
    );
}

#[cfg(test)]
mod tests {
    use super::{membership_changed_after_bundles, parse_capability, portable_json_value};
    use mehscan_core::Capability;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn detects_bundle_membership_changes_independently_of_filenames() {
        let before = BTreeMap::from([
            (
                "old-a.json".to_string(),
                vec!["a".to_string(), "b".to_string()],
            ),
            (
                "old-b.json".to_string(),
                vec!["c".to_string(), "d".to_string()],
            ),
        ]);
        let renamed_only = BTreeMap::from([
            (
                "new-a.json".to_string(),
                vec!["a".to_string(), "b".to_string()],
            ),
            (
                "new-b.json".to_string(),
                vec!["c".to_string(), "d".to_string()],
            ),
        ]);
        assert!(membership_changed_after_bundles(&before, &renamed_only).is_empty());

        let shifted = BTreeMap::from([
            (
                "new-a.json".to_string(),
                vec!["new".to_string(), "a".to_string()],
            ),
            (
                "new-b.json".to_string(),
                vec!["b".to_string(), "c".to_string()],
            ),
            ("new-c.json".to_string(), vec!["d".to_string()]),
        ]);
        assert_eq!(
            membership_changed_after_bundles(&before, &shifted),
            BTreeSet::from([
                "new-a.json".to_string(),
                "new-b.json".to_string(),
                "new-c.json".to_string(),
            ])
        );
    }

    #[test]
    fn portable_json_hides_roots_and_rejects_absolute_locations() {
        let portable = portable_json_value(&serde_json::json!({
            "root": "C:/private/checkout",
            "scanRoot": "/private/checkout",
            "location": { "path": "src/main.rs" }
        }))
        .expect("relative location should serialize");
        assert_eq!(portable["root"], ".");
        assert_eq!(portable["scanRoot"], ".");

        for absolute in [
            "C:/private/checkout/src/main.rs",
            "/private/checkout/src/main.rs",
            r"\\server\share\src\main.rs",
        ] {
            assert!(
                portable_json_value(&serde_json::json!({
                    "location": { "path": absolute }
                }))
                .is_err(),
                "absolute path should be rejected: {absolute}"
            );
        }
    }

    #[test]
    fn portable_json_keeps_absolute_style_http_route_paths() {
        let portable = portable_json_value(&serde_json::json!({
            "context": {
                "http_routes": [{
                    "method": "GET",
                    "path": "/accounts/{1}",
                    "access": "authenticated"
                }]
            }
        }))
        .expect("HTTP route paths are not artifact paths");
        assert_eq!(
            portable["context"]["http_routes"][0]["path"],
            "/accounts/{1}"
        );
    }

    #[test]
    fn capability_filters_follow_the_serialized_cross_language_contract() {
        for (name, expected) in [
            ("template_evaluation", Capability::TemplateEvaluation),
            ("browser_message_send", Capability::BrowserMessageSend),
            ("buffer_write", Capability::BufferWrite),
            (
                "signed_size_memory_operation",
                Capability::SignedSizeMemoryOperation,
            ),
            ("local_heap_deallocation", Capability::LocalHeapDeallocation),
            ("cpp_heap_deallocation", Capability::CppHeapDeallocation),
            ("cpp_raii_owner", Capability::CppRaiiOwner),
            ("arithmetic_division", Capability::ArithmeticDivision),
            (
                "count_controlled_memory_operation",
                Capability::CountControlledMemoryOperation,
            ),
            (
                "arithmetic_multiplication",
                Capability::ArithmeticMultiplication,
            ),
            (
                "allocation_size_computation",
                Capability::AllocationSizeComputation,
            ),
            ("post_return_dereference", Capability::PostReturnDereference),
        ] {
            assert_eq!(parse_capability(name), Ok(expected));
        }
        assert!(parse_capability("not_a_capability").is_err());
    }
}
