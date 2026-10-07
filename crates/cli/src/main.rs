use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use mehscan_core::{Capability, EvidenceFilter, EvidenceKind, Language};
use serde::{Deserialize, Serialize};

mod review_sweep;

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
    let source_root = parsed.optional("--source-root").map(PathBuf::from);
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

    let (manifest, bundle_responses, work) = read_complete_bundle_responses(
        &run,
        responses.as_deref(),
        allow_partial,
        source_root.as_deref(),
    )?;
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
    let mut csharp_semantic = None;
    let mut csharp_context = None;
    let mut typescript_semantic = None;
    let mut typescript_context = None;
    let mut arguments = arguments.peekable();
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--typescript-semantic" => {
                typescript_semantic = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--typescript-semantic requires a snapshot")?,
                ))
            }
            "--typescript-context" => {
                typescript_context = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--typescript-context requires a context")?,
                ))
            }
            "--csharp-semantic" => {
                csharp_semantic = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--csharp-semantic requires a snapshot")?,
                ))
            }
            "--csharp-context" => {
                csharp_context = Some(PathBuf::from(
                    arguments
                        .next()
                        .ok_or("--csharp-context requires a context file")?,
                ))
            }
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
    if typescript_semantic.is_some() != typescript_context.is_some() {
        return Err(
            "--typescript-semantic and --typescript-context must be supplied together".into(),
        );
    }
    if typescript_semantic.is_some() && diff_mode == mehscan_engine::ImpactDiffMode::Impact {
        return Err(
            "TypeScript snapshot import requires full scan context; use --diff-mode full".into(),
        );
    }
    if csharp_semantic.is_some() != csharp_context.is_some() {
        return Err("--csharp-semantic and --csharp-context must be supplied together".into());
    }
    if csharp_semantic.is_some() && diff_mode == mehscan_engine::ImpactDiffMode::Impact {
        return Err(
            "Roslyn snapshot import currently requires full scan context; use --diff-mode full"
                .into(),
        );
    }
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
    if let (Some(facts), Some(context)) = (csharp_semantic, csharp_context) {
        let snapshot = engine(mehscan_engine::csharp_semantic::load(&facts))?;
        engine(mehscan_engine::csharp_semantic::enrich(
            &root,
            &context,
            &snapshot,
            &mut result,
        ))?;
    }
    if let (Some(facts), Some(context)) = (typescript_semantic, typescript_context) {
        let snapshot = engine(mehscan_engine::typescript_semantic::load(&facts))?;
        engine(mehscan_engine::typescript_semantic::enrich(
            &root,
            &context,
            &snapshot,
            &mut result,
        ))?;
    }
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
    let journal = parsed.optional("--journal").map(PathBuf::from);
    let query_options = parsed.options.clone();
    let started = Instant::now();
    if journal.is_some()
        && !matches!(
            operation.as_str(),
            "outline"
                | "source"
                | "enclosing"
                | "enclosing-at"
                | "evidence"
                | "units"
                | "symbol"
                | "imports"
                | "references"
                | "paths"
                | "provenance"
                | "native-call-sites"
                | "structural"
        )
    {
        return Err("--journal is available only for read-only investigation queries".to_string());
    }
    match operation.as_str() {
        "provenance" => {
            let prefix = parsed.optional("--path-prefix");
            let limit = parsed.optional_usize("--limit")?;
            let inventory = parsed.optional("--inventory");
            parsed.finish()?;
            let paths = inventory
                .map(|directory| -> Result<BTreeSet<String>, String> {
                    let value: serde_json::Value = serde_json::from_slice(
                        &fs::read(Path::new(&directory).join("inventory.json"))
                            .map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    value["entries"]
                        .as_array()
                        .ok_or("inventory entries are missing".into())
                        .and_then(|entries| {
                            entries
                                .iter()
                                .map(|entry| {
                                    entry["path"]
                                        .as_str()
                                        .map(str::to_owned)
                                        .ok_or("inventory entry path is missing".into())
                                })
                                .collect()
                        })
                })
                .transpose()?;
            print_logged_query(
                engine(mehscan_engine::provenance::inspect_review_paths(
                    &root,
                    prefix.as_deref(),
                    limit,
                    paths.as_ref(),
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "funnel" => {
            parsed.finish()?;
            print_json(&engine(
                mehscan_engine::investigation::relationship_funnel(&root),
            )?)
        }
        "csharp-context" => {
            let seed = PathBuf::from(parsed.required("--context")?);
            let output = PathBuf::from(parsed.required("--output")?);
            parsed.finish()?;
            print_json(&engine(mehscan_engine::csharp_context::prepare(
                &root, &seed, &output,
            ))?)
        }
        "typescript-semantic" => {
            let context = PathBuf::from(parsed.required("--context")?);
            let backend = PathBuf::from(parsed.required("--backend")?);
            let output = PathBuf::from(parsed.required("--output")?);
            let inventory = parsed.optional("--inventory").map(PathBuf::from);
            let selected = parsed.optional("--evidence-ids");
            parsed.finish()?;
            let scan = semantic_scan(&root, inventory.as_deref(), selected.as_deref())?;
            let requested = mehscan_engine::typescript_semantic::queries(&scan).len();
            if selected.is_some() && requested != scan.evidence.len() {
                return Err(
                    "selected evidence includes an unsupported TypeScript/JavaScript operand"
                        .into(),
                );
            }
            let snapshot = engine(mehscan_engine::typescript_semantic::collect(
                &root, &context, &backend, &scan,
            ))?;
            let covered = snapshot
                .observations
                .iter()
                .map(|o| &o.evidence_id)
                .collect::<BTreeSet<_>>()
                .len();
            fs::write(
                &output,
                serde_json::to_vec_pretty(&snapshot).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            print_json(
                &serde_json::json!({"snapshot": output, "backend": snapshot.backend,
                "requested_operands": requested, "covered_operands": covered,
                "scan_reused": inventory.is_some(),
                "selected_observations": selected.as_ref().map(|_| &snapshot.observations),
                "uncovered_operands": requested.saturating_sub(covered),
                "observations": snapshot.observations.len(), "diagnostics": snapshot.diagnostics.len()}),
            )
        }
        "csharp-semantic" => {
            let context = PathBuf::from(parsed.required("--context")?);
            let backend = PathBuf::from(parsed.required("--backend")?);
            let output = PathBuf::from(parsed.required("--output")?);
            let inventory = parsed.optional("--inventory").map(PathBuf::from);
            let selected = parsed.optional("--evidence-ids");
            parsed.finish()?;
            let scan = semantic_scan(&root, inventory.as_deref(), selected.as_deref())?;
            let requested = mehscan_engine::csharp_semantic::queries(&scan).len();
            if selected.is_some() && requested != scan.evidence.len() {
                return Err("selected evidence includes an unsupported C# operand".into());
            }
            let snapshot = engine(mehscan_engine::csharp_semantic::collect(
                &root, &context, &backend, &scan,
            ))?;
            let covered = snapshot
                .observations
                .iter()
                .map(|o| &o.evidence_id)
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            fs::write(
                &output,
                serde_json::to_vec_pretty(&snapshot).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            print_json(
                &serde_json::json!({"snapshot": output, "backend": snapshot.backend,
                "requested_operands": requested, "covered_operands": covered,
                "scan_reused": inventory.is_some(),
                "selected_observations": selected.as_ref().map(|_| &snapshot.observations),
                "uncovered_operands": requested.saturating_sub(covered),
                "observations": snapshot.observations.len(), "diagnostics": snapshot.diagnostics.len()}),
            )
        }
        "review-inventory" => {
            let output = PathBuf::from(parsed.required("--output")?);
            let include_review_material = parsed
                .optional_bool("--include-review-material")?
                .unwrap_or(false);
            let semantic = parsed.optional("--csharp-semantic").map(PathBuf::from);
            let context = parsed.optional("--csharp-context").map(PathBuf::from);
            let backend = parsed.optional("--csharp-backend").map(PathBuf::from);
            let ts_semantic = parsed.optional("--typescript-semantic").map(PathBuf::from);
            let ts_context = parsed.optional("--typescript-context").map(PathBuf::from);
            let ts_backend = parsed.optional("--typescript-backend").map(PathBuf::from);
            let timings = parsed.optional_bool("--timings")?.unwrap_or(false);
            if semantic.is_some() && backend.is_some() {
                return Err("supply --csharp-semantic or --csharp-backend, not both".into());
            }
            if (semantic.is_some() || backend.is_some()) != context.is_some() {
                return Err(
                    "supply --csharp-context with --csharp-semantic or --csharp-backend".into(),
                );
            }
            if ts_semantic.is_some() && ts_backend.is_some() {
                return Err(
                    "supply --typescript-semantic or --typescript-backend, not both".into(),
                );
            }
            if (ts_semantic.is_some() || ts_backend.is_some()) != ts_context.is_some() {
                return Err("supply --typescript-context with --typescript-semantic or --typescript-backend".into());
            }
            let ts_input = if let Some((snapshot, context)) =
                ts_semantic.as_deref().zip(ts_context.as_deref())
            {
                Some(mehscan_engine::typescript_semantic::Input::Snapshot(
                    snapshot, context,
                ))
            } else {
                ts_context
                    .as_deref()
                    .zip(ts_backend.as_deref())
                    .map(|(context, backend)| {
                        mehscan_engine::typescript_semantic::Input::Backend(context, backend)
                    })
            };
            parsed.finish()?;
            let mut profile = mehscan_engine::investigation::ReviewInventoryProfile::default();
            let inventory = engine(
                mehscan_engine::investigation::build_review_inventory_with_native_backends(
                    &root,
                    include_review_material,
                    semantic.as_deref().zip(context.as_deref()),
                    context.as_deref().zip(backend.as_deref()),
                    ts_input,
                    timings.then_some(&mut profile),
                ),
            )?;
            fs::create_dir_all(&output).map_err(|error| {
                format!(
                    "could not create inventory directory {}: {error}",
                    output.display()
                )
            })?;
            let summary = serde_json::json!({
                "schema_version": inventory.schema_version,
                "source_fingerprint": inventory.source_fingerprint,
                "input_fingerprint": engine(inventory.input_fingerprint())?,
                "include_review_material": inventory.include_review_material,
                "review_count": inventory.entries.len(),
                "coverage": inventory.scan.coverage.totals,
                "entries": inventory.entries,
                "admission_audit": inventory.admission_audit,
            });
            let mut by_capability = BTreeMap::<String, usize>::new();
            let mut by_cwe = BTreeMap::<String, usize>::new();
            let mut by_area = BTreeMap::<String, usize>::new();
            let mut by_operand_fact = BTreeMap::<String, usize>::new();
            let mut value_deferrals_by_reason = BTreeMap::<String, usize>::new();
            for entry in &inventory.entries {
                if let Some(hint) = &entry.value_hint {
                    *value_deferrals_by_reason
                        .entry(hint.reason.clone())
                        .or_default() += 1;
                }
                let kinds = entry
                    .operand_facts
                    .iter()
                    .map(|fact| {
                        serde_json::to_value(&fact.kind)
                            .map(|value| value.as_str().unwrap().to_string())
                    })
                    .collect::<Result<BTreeSet<_>, _>>()
                    .map_err(|error| error.to_string())?;
                for kind in kinds {
                    *by_operand_fact.entry(kind).or_default() += 1;
                }
                if entry.operand_facts.is_empty() {
                    *by_operand_fact.entry("unclassified".into()).or_default() += 1;
                }
                let capability =
                    serde_json::to_value(entry.capability).map_err(|error| error.to_string())?;
                *by_capability
                    .entry(capability.as_str().unwrap_or("unknown").to_string())
                    .or_default() += 1;
                for cwe in &entry.cwe_candidates {
                    *by_cwe.entry(cwe.clone()).or_default() += 1;
                }
                let area = entry.path.split('/').take(2).collect::<Vec<_>>().join("/");
                *by_area.entry(area).or_default() += 1;
            }
            let mut top_areas = by_area.into_iter().collect::<Vec<_>>();
            top_areas
                .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            top_areas.truncate(40);
            let overview = serde_json::json!({
                "schema_version": inventory.schema_version,
                "source_fingerprint": inventory.source_fingerprint,
                "input_fingerprint": engine(inventory.input_fingerprint())?,
                "review_count": inventory.entries.len(),
                "coverage": inventory.scan.coverage.totals,
                "by_capability": by_capability,
                "by_cwe": by_cwe,
                "by_operand_fact": by_operand_fact,
                "deterministic_operand_closures": inventory.admission_audit.closed_operands.len(),
                "value_deferred_count": inventory.entries.iter().filter(|entry| entry.value_hint.is_some()).count(),
                "value_active_count": inventory.entries.iter().filter(|entry| entry.value_hint.is_none()).count(),
                "value_deferrals_by_reason": value_deferrals_by_reason,
                "value_conditional_count": inventory.entries.iter().filter(|entry| entry.value_hint.as_ref().is_some_and(|hint| hint.depends_on.is_some() || matches!(hint.reason.as_str(), "ordinary_php_sink_inventory" | "ordinary_browser_request_inventory"))).count(),
                "value_dependency_count": inventory.entries.iter().filter_map(|entry| entry.value_hint.as_ref()?.depends_on.as_deref()).collect::<BTreeSet<_>>().len(),
                "top_areas": top_areas,
            });
            fs::write(
                output.join("inventory.json"),
                serde_json::to_vec_pretty(&summary).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("could not write inventory: {error}"))?;
            fs::write(
                output.join("overview.json"),
                serde_json::to_vec_pretty(&overview).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("could not write inventory overview: {error}"))?;
            fs::write(
                output.join("scan-cache.json"),
                serde_json::to_vec(&inventory).map_err(|error| error.to_string())?,
            )
            .map_err(|error| format!("could not write scan cache: {error}"))?;
            if timings {
                eprintln!(
                    "{}",
                    serde_json::to_string(&profile).map_err(|e| e.to_string())?
                );
            }
            print_json(
                &serde_json::json!({"overview": output.join("overview.json"), "inventory": output.join("inventory.json"), "review_count": inventory.entries.len()}),
            )
        }
        "review-inventory-list" => {
            let inventory_dir = PathBuf::from(parsed.required("--inventory")?);
            let ledger_path = parsed.optional("--ledger").map(PathBuf::from);
            let capability = parsed.optional("--capability");
            let cwe = parsed.optional("--cwe");
            let path_prefix = parsed.optional("--path-prefix");
            let operand_kind = parsed.optional("--operand-kind");
            let contract = parsed.optional("--contract");
            let group_by = parsed.optional("--group-by");
            let selection = parsed
                .optional("--selection")
                .unwrap_or_else(|| "all".into());
            if !matches!(selection.as_str(), "all" | "value" | "deferred") {
                return Err("invalid --selection; use all, value, or deferred".into());
            }
            if group_by
                .as_deref()
                .is_some_and(|value| !matches!(value, "contract" | "implementation"))
            {
                return Err("invalid --group-by; use contract or implementation".into());
            }
            if operand_kind.as_deref().is_some_and(|kind| {
                !matches!(
                    kind,
                    "fixed_code_relative_path"
                        | "fixed_filesystem_path"
                        | "temporary_filesystem_path"
                        | "immutable_filesystem_operand"
                        | "encoded_html_operand"
                        | "shared_outbound_destination"
                        | "shared_filesystem_producer"
                        | "configured_root_path"
                        | "repository_code_target"
                        | "output_context"
                        | "encoding_call"
                        | "local_operand_origin"
                        | "operand_boundary"
                        | "query_structure"
                        | "process_shell_mode"
                        | "native_operand_declaration"
                        | "prepared_statement_use"
                        | "semantic_identity"
                        | "semantic_definition"
                        | "receiver_reference"
                        | "local_call_argument"
                        | "unclassified"
                        | "browser_request_context"
                )
            }) {
                return Err("invalid --operand-kind; use fixed_code_relative_path, fixed_filesystem_path, temporary_filesystem_path, immutable_filesystem_operand, shared_filesystem_producer, shared_outbound_destination, encoded_html_operand, configured_root_path, repository_code_target, encoding_call, output_context, local_operand_origin, operand_boundary, query_structure, process_shell_mode, native_operand_declaration, local_call_argument, prepared_statement_use, semantic_identity, semantic_definition, receiver_reference, or unclassified".into());
            }
            let limit = parsed.optional_usize("--limit")?.unwrap_or(50).min(200);
            let offset = parsed.optional_usize("--offset")?.unwrap_or(0);
            parsed.finish()?;
            let source = fs::read(inventory_dir.join("inventory.json"))
                .map_err(|error| format!("could not read inventory: {error}"))?;
            let inventory: serde_json::Value = serde_json::from_slice(&source)
                .map_err(|error| format!("invalid inventory: {error}"))?;
            let entries = inventory["entries"]
                .as_array()
                .ok_or("inventory entries are missing")?;
            let ledger = ledger_path
                .as_deref()
                .map(|path| load_review_ledger(path, &inventory))
                .transpose()?;
            let mut matching =
                entries
                    .iter()
                    .filter(|entry| {
                        ledger.as_ref().is_none_or(|ledger| {
                            entry["review_id"]
                                .as_str()
                                .is_some_and(|id| !ledger.reviewed.contains_key(id))
                        }) && capability.as_ref().is_none_or(|value| {
                            entry["capability"].as_str() == Some(value.as_str())
                        }) && cwe.as_ref().is_none_or(|value| {
                            entry["cwe_candidates"].as_array().is_some_and(|cwes| {
                                cwes.iter()
                                    .any(|item| item.as_str() == Some(value.as_str()))
                            })
                        }) && path_prefix.as_ref().is_none_or(|value| {
                            entry["path"]
                                .as_str()
                                .is_some_and(|path| path.starts_with(value))
                        }) && contract.as_ref().is_none_or(|key| {
                            review_sweep::contract_keys(entry)
                                .iter()
                                .any(|item| &item.0 == key)
                        }) && operand_kind.as_ref().is_none_or(|kind| {
                            let facts = entry["operand_facts"].as_array();
                            if kind == "unclassified" {
                                facts.is_none_or(|facts| facts.is_empty())
                            } else {
                                facts.is_some_and(|facts| {
                                    facts
                                        .iter()
                                        .any(|fact| fact["kind"].as_str() == Some(kind.as_str()))
                                })
                            }
                        })
                    })
                    .collect::<Vec<_>>();
            let scope_count = matching.len();
            let reopen_surfaces = entries
                .iter()
                .filter(|entry| {
                    entry["review_id"].as_str().is_some_and(|id| {
                        ledger.as_ref().is_some_and(|ledger| {
                            ledger.reviewed.get(id).is_some_and(|decision| {
                                matches!(decision.as_str(), "issue" | "needs_review")
                            }) || ledger.conflicts.iter().any(|conflict| conflict == id)
                        })
                    })
                })
                .map(|entry| (entry["path"].as_str(), entry["rule_id"].as_str()))
                .collect::<BTreeSet<_>>();
            let reopened = |entry: &&serde_json::Value| {
                (matches!(
                    entry["value_hint"]["reason"].as_str(),
                    Some(
                        "ordinary_php_sink_inventory"
                            | "local_bound_query_inventory"
                            | "ordinary_browser_request_inventory"
                    )
                ) && reopen_surfaces
                    .contains(&(entry["path"].as_str(), entry["rule_id"].as_str())))
                    || entry["value_hint"]["depends_on"]
                        .as_str()
                        .is_some_and(|id| {
                            ledger.as_ref().is_some_and(|ledger| {
                                ledger.reviewed.get(id).is_some_and(|decision| {
                                    matches!(decision.as_str(), "issue" | "needs_review")
                                }) || ledger.conflicts.iter().any(|conflict| conflict == id)
                            })
                        })
            };
            let dependency_review_ids = matching
                .iter()
                .filter_map(|entry| {
                    entry["value_hint"]["depends_on"].as_str().filter(|id| {
                        ledger
                            .as_ref()
                            .is_none_or(|ledger| !ledger.reviewed.contains_key(*id))
                    })
                })
                .collect::<BTreeSet<_>>();
            let reopened_count = matching.iter().filter(|entry| reopened(entry)).count();
            let deferred_count = matching
                .iter()
                .filter(|entry| !entry["value_hint"].is_null() && !reopened(entry))
                .count();
            matching.retain(|entry| match selection.as_str() {
                "value" => entry["value_hint"].is_null() || reopened(entry),
                "deferred" => !entry["value_hint"].is_null() && !reopened(entry),
                _ => true,
            });
            if group_by.is_some() {
                let queue_builder = if group_by.as_deref() == Some("implementation") {
                    review_sweep::implementation_queue
                } else {
                    review_sweep::contract_queue
                };
                let mut queue =
                    queue_builder(&matching, &inventory["source_fingerprint"], offset, limit);
                queue["selection"] = serde_json::json!(selection);
                queue["scope_count"] = serde_json::json!(scope_count);
                queue["deferred_count"] = serde_json::json!(deferred_count);
                queue["reopened_count"] = serde_json::json!(reopened_count);
                queue["dependency_review_ids"] = serde_json::json!(dependency_review_ids);
                return print_json(&queue);
            }
            print_json(
                &serde_json::json!({"selection": selection, "scope_count": scope_count, "deferred_count": deferred_count, "reopened_count": reopened_count, "dependency_review_ids": dependency_review_ids, "matching_count": matching.len(), "reviewed_count": ledger.as_ref().map_or(0, |ledger| ledger.reviewed.len()), "offset": offset, "entries": matching.into_iter().skip(offset).take(limit).collect::<Vec<_>>()}),
            )
        }
        "review-ledger" => {
            let inventory_dir = PathBuf::from(parsed.required("--inventory")?);
            let history = parsed.required("--history")?;
            let output = PathBuf::from(parsed.required("--output")?);
            parsed.finish()?;
            let ledger = build_review_ledger(&inventory_dir, &history)?;
            write_json(&ledger, Some(&output))?;
            print_json(&serde_json::json!({
                "source_fingerprint": ledger.source_fingerprint,
                "inventory_count": ledger.inventory_count,
                "reviewed_count": ledger.reviewed.len(),
                "conflicts": ledger.conflicts,
                "output": output,
            }))
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
            let started = std::time::Instant::now();
            let output = PathBuf::from(parsed.required("--output")?);
            let inventory_dir = parsed.optional("--inventory").map(PathBuf::from);
            let ledger_path = parsed.optional("--ledger").map(PathBuf::from);
            let selected_ids = parsed.optional("--review-ids");
            let max_bytes = parsed.optional_usize("--max-bytes")?;
            let max_reviews = parsed.optional_usize("--max-reviews")?;
            let max_total_reviews = parsed.optional_usize("--max-total-reviews")?;
            let context_lines = parsed.optional_usize("--context-lines")?;
            let timings = parsed.optional_bool("--timings")?.unwrap_or(false);
            let include_review_material = parsed
                .optional_bool("--include-review-material")?
                .unwrap_or(false);
            let scope = parse_report_scope(&mut parsed);
            parsed.finish()?;
            if inventory_dir.is_some() != selected_ids.is_some() {
                return Err("--inventory and --review-ids must be used together".to_string());
            }
            if ledger_path.is_some() && inventory_dir.is_none() {
                return Err("--ledger requires --inventory and --review-ids".to_string());
            }
            if inventory_dir.is_some() && max_total_reviews.is_some() {
                return Err(
                    "--max-total-reviews cannot be used with selected review IDs".to_string(),
                );
            }
            let mut input_fingerprint = None;
            let mut source_fingerprint = None;
            let (job, job_profile) =
                if let (Some(inventory_dir), Some(ids)) = (inventory_dir, selected_ids) {
                    let cache_path = inventory_dir.join("scan-cache.json");
                    let inventory: mehscan_engine::investigation::ReviewInventory =
                        serde_json::from_slice(&fs::read(&cache_path).map_err(|error| {
                            format!("could not read {}: {error}", cache_path.display())
                        })?)
                        .map_err(|error| format!("invalid review inventory: {error}"))?;
                    input_fingerprint = Some(engine(inventory.input_fingerprint())?);
                    source_fingerprint = Some(inventory.source_fingerprint.clone());
                    let ids = ids
                        .split(',')
                        .map(str::trim)
                        .filter(|id| !id.is_empty())
                        .map(str::to_string)
                        .collect::<BTreeSet<_>>();
                    if let Some(ledger_path) = ledger_path.as_deref() {
                        let inventory_summary: serde_json::Value = serde_json::from_slice(
                            &fs::read(inventory_dir.join("inventory.json"))
                                .map_err(|error| format!("could not read inventory: {error}"))?,
                        )
                        .map_err(|error| format!("invalid inventory: {error}"))?;
                        let ledger = load_review_ledger(ledger_path, &inventory_summary)?;
                        if let Some(id) = ids.iter().find(|id| ledger.reviewed.contains_key(*id)) {
                            return Err(format!(
                                "review ID {id:?} is already finalized in the ledger"
                            ));
                        }
                    }
                    if timings {
                        let (job, profile) = engine(
                            mehscan_engine::investigation::build_selected_review_jobs_profiled(
                                &root,
                                &inventory,
                                &ids,
                                context_lines,
                            ),
                        )?;
                        (job, Some(profile))
                    } else {
                        (
                            engine(mehscan_engine::investigation::build_selected_review_jobs(
                                &root,
                                &inventory,
                                &ids,
                                context_lines,
                            ))?,
                            None,
                        )
                    }
                } else if timings {
                    let (job, profile) = engine(
                        mehscan_engine::investigation::build_all_path_review_jobs_profiled(
                            &root,
                            context_lines,
                            include_review_material,
                        ),
                    )?;
                    (job, Some(profile))
                } else {
                    (
                        engine(mehscan_engine::investigation::build_all_path_review_jobs(
                            &root,
                            context_lines,
                            include_review_material,
                        ))?,
                        None,
                    )
                };
            let review_jobs_milliseconds = started.elapsed().as_millis();
            let mut bundle_set = engine(
                mehscan_engine::investigation::build_path_review_bundles_with_run_limit(
                    &job,
                    max_bytes,
                    max_reviews,
                    max_total_reviews,
                ),
            )?;
            let bundle_build_milliseconds =
                started.elapsed().as_millis() - review_jobs_milliseconds;
            bundle_set.manifest.scope.extend(scope);
            write_path_review_bundles(&output, &bundle_set)?;
            {
                let source_fingerprint = match source_fingerprint {
                    Some(value) => value,
                    None => {
                        engine(mehscan_engine::investigation::review_repository_fingerprint(&root))?
                    }
                };
                let mut requests = BTreeMap::new();
                for entry in &bundle_set.manifest.bundles {
                    let bytes = fs::read(output.join("requests").join(&entry.filename))
                        .map_err(|e| e.to_string())?;
                    requests.insert(
                        entry.filename.clone(),
                        mehscan_engine::investigation::review_content_fingerprint(&bytes),
                    );
                }
                fs::write(
                    output.join("input-binding.json"),
                    serde_json::to_vec_pretty(&ReviewChunkBinding {
                        input_fingerprint,
                        source_fingerprint,
                        requests,
                    })
                    .map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
            }
            if timings {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "review_jobs_milliseconds": review_jobs_milliseconds,
                        "review_job_phases": job_profile.as_ref().map(|profile| serde_json::json!({
                            "inventory_validation_milliseconds": profile.inventory_validation_milliseconds,
                            "scan_milliseconds": profile.scan_milliseconds,
                            "source_load_milliseconds": profile.source_load_milliseconds,
                            "context_admission_milliseconds": profile.context_admission_milliseconds,
                            "path_reviews_milliseconds": profile.path_reviews_milliseconds,
                            "observation_reviews_milliseconds": profile.observation_reviews_milliseconds,
                            "observation_index_milliseconds": profile.observation_index_milliseconds,
                            "observation_pre_origin_milliseconds": profile.observation_pre_origin_milliseconds,
                            "observation_origin_milliseconds": profile.observation_origin_milliseconds,
                            "observation_post_origin_milliseconds": profile.observation_post_origin_milliseconds,
                            "observation_review_count": profile.observation_review_count,
                            "finalization_milliseconds": profile.finalization_milliseconds,
                        })),
                        "bundle_build_milliseconds": bundle_build_milliseconds,
                        "write_milliseconds": started.elapsed().as_millis() - review_jobs_milliseconds - bundle_build_milliseconds,
                        "total_milliseconds": started.elapsed().as_millis(),
                    })
                );
            }
            print_json(&bundle_set.manifest)
        }
        "review-bundle-diff" => {
            let before = PathBuf::from(parsed.required("--before")?);
            let after = PathBuf::from(parsed.required("--after")?);
            parsed.finish()?;
            print_json(&diff_path_review_bundle_runs(&before, &after)?)
        }
        "review-bundle-list" => {
            let path = PathBuf::from(parsed.required("--bundle")?);
            parsed.finish()?;
            let bundle: mehscan_core::PathReviewBundle =
                serde_json::from_slice(&fs::read(&path).map_err(|error| {
                    format!("could not read bundle {}: {error}", path.display())
                })?)
                .map_err(|error| format!("invalid bundle: {error}"))?;
            print_json(&serde_json::json!({
                "bundle_fingerprint": bundle.bundle_fingerprint,
                "review_count": bundle.review_ids.len(),
                "review_ids": bundle.review_ids
            }))
        }
        "review-card" => {
            let path = PathBuf::from(parsed.required("--bundle")?);
            let review_id = parsed.required("--review-id")?;
            parsed.finish()?;
            let bundle: mehscan_core::PathReviewBundle =
                serde_json::from_slice(&fs::read(&path).map_err(|error| {
                    format!("could not read bundle {}: {error}", path.display())
                })?)
                .map_err(|error| format!("invalid bundle: {error}"))?;
            print_json(&review_card(&bundle, &review_id)?)
        }
        "review-sweep" => {
            let path = PathBuf::from(parsed.required("--bundle")?);
            parsed.finish()?;
            let bundle: mehscan_core::PathReviewBundle = serde_json::from_slice(
                &fs::read(&path).map_err(|error| format!("could not read bundle: {error}"))?,
            )
            .map_err(|error| format!("invalid bundle: {error}"))?;
            let value = serde_json::to_value(&bundle).map_err(|error| error.to_string())?;
            let cards = bundle
                .review_ids
                .iter()
                .map(|id| review_card_from_value(&bundle, id, &value))
                .collect::<Result<Vec<_>, _>>()?;
            let sweep =
                portable_json_value(&review_sweep::sweep(&bundle.bundle_fingerprint, cards)?)?;
            println!(
                "{}",
                serde_json::to_string(&sweep).map_err(|error| error.to_string())?
            );
            Ok(())
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
            if bundle.schema_version != mehscan_core::PATH_REVIEW_BUNDLE_SCHEMA_VERSION
                || bundle.playbook_version != "triage-buckets-v3"
                || ids
                    .iter()
                    .any(|id| !bundle.review_playbooks.contains_key(id))
            {
                return Err("unsupported or incomplete review bundle contract".to_string());
            }
            if ids.is_empty()
                || bundle.bundle_fingerprint.is_empty()
                || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
            {
                return Err("bundle must contain a fingerprint and distinct review IDs".to_string());
            }
            let selected_anchor_ids = ids
                .iter()
                .map(|review_id| {
                    engine(mehscan_engine::investigation::bundle_selected_anchor_id(
                        &bundle, review_id,
                    ))
                    .map(str::to_string)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let result_fields = vec![
                "review_id",
                "selected_anchor_id",
                "decision",
                "confidence",
                "summary",
                "checks",
                "investigation",
            ];
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
            let reviewer_origin_lead_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["question", "security_relevance", "distinct_from_review", "location", "artifact_ids"],
                "properties": {
                    "question": {"type": "string", "minLength": 1, "maxLength": 500},
                    "security_relevance": {"type": "string", "minLength": 1, "maxLength": 500},
                    "distinct_from_review": {"type": "string", "minLength": 1, "maxLength": 500},
                    "location": location_schema,
                    "artifact_ids": {"type": "array", "minItems": 1, "maxItems": 4, "items": {"type": "string"}}
                }
            });
            let investigation_schema = serde_json::json!({
                "type": "object", "additionalProperties": false,
                "required": ["decisive_artifacts", "journal_summary", "citations", "reviewer_inferences", "reviewer_origin_leads", "blockers"],
                "properties": {
                    "decisive_artifacts": {"type": "array", "items": artifact_schema},
                    "journal_summary": {"anyOf": [
                        {"type": "null"},
                        {"type": "object", "additionalProperties": false,
                         "required": ["file", "query_count", "failed_count", "empty_count", "truncated_count", "elapsed_ms"],
                         "properties": {
                             "file": {"type": "string"},
                             "query_count": {"type": "integer", "minimum": 0},
                             "failed_count": {"type": "integer", "minimum": 0},
                             "empty_count": {"type": "integer", "minimum": 0},
                             "truncated_count": {"type": "integer", "minimum": 0},
                             "elapsed_ms": {"type": "integer", "minimum": 0}
                         }}
                    ]},
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
                    "reviewer_origin_leads": {"type": "array", "maxItems": 3, "items": reviewer_origin_lead_schema},
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
                        "required": result_fields,
                        "properties": {
                            "review_id": {"type": "string", "enum": ids},
                            "selected_anchor_id": {"type": "string", "enum": selected_anchor_ids},
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
            let source_root = parsed.optional("--source-root").map(PathBuf::from);
            let summary = parsed.optional_bool("--summary")?.unwrap_or(false);
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
            if let Some(source_root) = source_root.as_deref() {
                validate_review_artifact_source_text(source_root, &responses)?;
            }
            if summary {
                print_json(&serde_json::json!({
                    "complete": report.complete,
                    "issue_count": report.issue_count,
                    "not_issue_count": report.not_issue_count,
                    "needs_review_count": report.needs_review_count,
                    "response_fingerprint": report.response_fingerprint,
                    "review_ids": report.results.iter().map(|result| result.review_id.as_str()).collect::<Vec<_>>()
                }))
            } else {
                print_json(&report)
            }
        }
        "review-bundle-finalize" => {
            let bundle_path = PathBuf::from(parsed.required("--bundle")?);
            let draft_path = PathBuf::from(parsed.required("--draft")?);
            let journal_dir = PathBuf::from(parsed.required("--journal-dir")?);
            let output_path = PathBuf::from(parsed.required("--output")?);
            let source_root = PathBuf::from(parsed.required("--source-root")?);
            parsed.finish()?;
            let bundle: mehscan_core::PathReviewBundle =
                serde_json::from_slice(&fs::read(&bundle_path).map_err(|error| {
                    format!("could not read bundle {}: {error}", bundle_path.display())
                })?)
                .map_err(|error| format!("invalid bundle {}: {error}", bundle_path.display()))?;
            let draft: serde_json::Value =
                serde_json::from_slice(&fs::read(&draft_path).map_err(|error| {
                    format!("could not read draft {}: {error}", draft_path.display())
                })?)
                .map_err(|error| format!("invalid draft {}: {error}", draft_path.display()))?;
            let mut responses: mehscan_core::PathReviewBundleResponseSet =
                if draft.get("schema_version").is_some() {
                    serde_json::from_value(draft)
                        .map_err(|error| format!("invalid full draft: {error}"))?
                } else {
                    let brief: BriefReviewSet = serde_json::from_value(draft)
                        .map_err(|error| format!("invalid brief draft: {error}"))?;
                    expand_brief_reviews(&bundle, &brief, &source_root)?
                };
            if responses.schema_version != "1.3" {
                return Err("review-bundle-finalize requires a schema 1.3 draft".to_string());
            }
            for result in &mut responses.results {
                if result
                    .review_id
                    .bytes()
                    .any(|byte| byte == b'/' || byte == 92)
                    || result.review_id.contains("..")
                {
                    return Err("review ID cannot be used as a journal filename".to_string());
                }
                let trace = result.investigation.as_mut().ok_or_else(|| {
                    format!("review {:?} has no investigation object", result.review_id)
                })?;
                if trace.journal_summary.is_some() {
                    return Err(format!(
                        "review {:?} draft must leave journal_summary null",
                        result.review_id
                    ));
                }
                let filename = format!("{}.jsonl", result.review_id);
                trace.journal_summary = Some(summarize_query_journal(
                    &journal_dir.join(&filename),
                    &filename,
                    &source_root,
                )?);
            }
            mehscan_engine::investigation::validate_path_review_bundle_response(
                &bundle, &responses,
            )
            .map_err(|error| format!("invalid reviewer work: {error}"))?;
            validate_review_artifact_source_text(&source_root, &responses)?;
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    format!(
                        "could not create response directory {}: {error}",
                        parent.display()
                    )
                })?;
            }
            write_json(&responses, Some(&output_path))
        }
        "review-bundle-summary" => {
            let run = PathBuf::from(parsed.required("--run")?);
            let responses = parsed.optional("--responses").map(PathBuf::from);
            let source_root = parsed.optional("--source-root").map(PathBuf::from);
            let allow_partial = parsed.optional_bool("--allow-partial")?.unwrap_or(false);
            parsed.finish()?;
            let (manifest, bundle_responses, work) = read_complete_bundle_responses(
                &run,
                responses.as_deref(),
                allow_partial,
                source_root.as_deref(),
            )?;
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
        "outline" => {
            let path = parsed.required("--path")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::get_file_outline(
                    &root, &path,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "source" => {
            let path = parsed.required("--path")?;
            let start_line = parsed.required_usize("--start-line")?;
            let end_line = parsed.required_usize("--end-line")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::get_source(
                    &root, &path, start_line, end_line,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "enclosing" => {
            let evidence_id = parsed.required("--evidence-id")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::get_enclosing_symbol(
                    &root,
                    &evidence_id,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "enclosing-at" => {
            let path = parsed.required("--path")?;
            let line = parsed.required_usize("--line")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::get_enclosing_at(
                    &root, &path, line,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
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
            print_logged_query(
                engine(mehscan_engine::investigation::find_evidence(
                    &root, filter, limit,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
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
            print_logged_query(
                engine(mehscan_engine::investigation::build_investigation_job(
                    &root,
                    filter,
                    context_lines,
                    limit,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "symbol" => {
            let name = parsed.required("--name")?;
            let path = parsed.optional("--path");
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::find_symbol(
                    &root,
                    &name,
                    path.as_deref(),
                    limit,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "imports" => {
            let name = parsed.required("--name")?;
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::find_imports(
                    &root, &name, limit,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "references" => {
            let symbol = parsed.required("--symbol")?;
            let path = parsed.optional("--path");
            let path_prefix = parsed.optional("--path-prefix");
            let limit = parsed.optional_usize("--limit")?;
            let summary = parsed.optional_bool("--summary")?.unwrap_or(false);
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::find_text_references(
                    &root,
                    &symbol,
                    path.as_deref(),
                    path_prefix.as_deref(),
                    limit,
                ))
                .and_then(|result| {
                    let value = serde_json::to_value(result).map_err(|e| e.to_string())?;
                    Ok(if summary {
                        compact_references(value)
                    } else {
                        value
                    })
                }),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "paths" => {
            let name = parsed.required("--name")?;
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::find_source_paths(
                    &root, &name, limit,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "native-call-sites" => {
            let callee = parsed.required("--callee")?;
            let path = parsed.optional("--path");
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::find_native_call_sites(
                    &root,
                    &callee,
                    path.as_deref(),
                    limit,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        "structural" => {
            let language = parse_language(&parsed.required("--language")?)?;
            let pattern = parsed.required("--pattern")?;
            let path = parsed.optional("--path");
            let limit = parsed.optional_usize("--limit")?;
            parsed.finish()?;
            print_logged_query(
                engine(mehscan_engine::investigation::run_structural_query(
                    &root,
                    language,
                    &pattern,
                    path.as_deref(),
                    limit,
                )),
                journal.as_deref(),
                &operation,
                &root,
                &query_options,
                started,
            )
        }
        _ => Err(format!(
            "unknown investigation operation {operation:?}; run 'mehscan investigate --help'"
        )),
    }
}

fn engine<T>(result: Result<T, mehscan_engine::EngineError>) -> Result<T, String> {
    result.map_err(|error| error.to_string())
}

fn print_logged_query<T: serde::Serialize>(
    result: Result<T, String>,
    journal: Option<&Path>,
    operation: &str,
    root: &Path,
    arguments: &BTreeMap<String, String>,
    started: Instant,
) -> Result<(), String> {
    let output = if journal.is_some() {
        result.as_ref().ok().map(portable_json_value).transpose()?
    } else {
        None
    };
    if let Some(path) = journal {
        let entry = serde_json::json!({
            "operation": operation,
            "root": root.to_string_lossy(),
            "arguments": arguments,
            "elapsed_ms": started.elapsed().as_millis(),
            "status": if result.is_ok() { "ok" } else { "error" },
            "output": &output,
            "error": result.as_ref().err(),
        });
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "could not create query journal directory {}: {error}",
                    parent.display()
                )
            })?;
        }
        let mut record = serde_json::to_vec(&entry).map_err(|error| {
            format!(
                "could not serialize query journal {}: {error}",
                path.display()
            )
        })?;
        record.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            // Windows locking requires read or generic write access; append
            // access alone cannot acquire a byte-range lock.
            .read(true)
            .append(true)
            .open(path)
            .map_err(|error| format!("could not open query journal {}: {error}", path.display()))?;
        // Separate CLI processes can share an ID's journal. Keep the whole
        // record under one OS lock, including any partial writes.
        fs2::FileExt::lock_exclusive(&file)
            .map_err(|error| format!("could not lock query journal {}: {error}", path.display()))?;
        file.write_all(&record).map_err(|error| {
            format!("could not write query journal {}: {error}", path.display())
        })?;
        // Closing the handle releases the lock, also on an error above.
    }
    match result {
        Ok(value) => {
            if let Some(output) = output {
                let json = serde_json::to_string_pretty(&output)
                    .map_err(|error| format!("could not serialize portable result: {error}"))?;
                println!("{json}");
                Ok(())
            } else {
                print_json(&value)
            }
        }
        Err(error) => Err(error),
    }
}

/// Locations/previews for navigation, not a complete caller graph or proof.
fn compact_references(mut value: serde_json::Value) -> serde_json::Value {
    let mut files = BTreeMap::<String, Vec<serde_json::Value>>::new();
    for reference in value["results"].as_array().into_iter().flatten() {
        if let Some(path) = reference["location"]["path"].as_str() {
            files
                .entry(path.into())
                .or_default()
                .push(reference.clone());
        }
    }
    let mut truncated_locations = false;
    value["results"] = serde_json::Value::Array(files.into_iter().map(|(path, references)| {
        let lines = references.iter().filter_map(|r| r["location"]["start"]["line"].as_u64()).collect::<BTreeSet<_>>();
        let locations_truncated = lines.len() > 20;
        truncated_locations |= locations_truncated;
        let previews = references.iter().filter_map(|r| {
            Some((r["location"]["start"]["line"].as_u64()?, r["text"].as_str()?))
        }).collect::<BTreeMap<_,_>>().into_iter().take(2).map(|(line,text)| {
            serde_json::json!({"line":line,"text":text.chars().take(160).collect::<String>(),"clipped":text.chars().count()>160})
        }).collect::<Vec<_>>();
        serde_json::json!({"path":path,"returned_occurrences":references.len(),
            "lines":lines.into_iter().take(20).collect::<Vec<_>>(),"locations_truncated":locations_truncated,"previews":previews})
    }).collect());
    value["summary"] = serde_json::json!(true);
    value["truncated"] =
        serde_json::json!(value["truncated"].as_bool().unwrap_or(false) || truncated_locations);
    value
}

fn summarize_query_journal(
    path: &Path,
    filename: &str,
    source_root: &Path,
) -> Result<mehscan_core::ReviewQueryJournalSummary, String> {
    let mut summary = mehscan_core::ReviewQueryJournalSummary {
        file: filename.to_string(),
        query_count: 0,
        failed_count: 0,
        empty_count: 0,
        truncated_count: 0,
        elapsed_ms: 0,
    };
    if !path.exists() {
        return Ok(summary);
    }
    let expected_root = fs::canonicalize(source_root).map_err(|error| {
        format!(
            "could not resolve source root {}: {error}",
            source_root.display()
        )
    })?;
    let content = fs::read_to_string(path)
        .map_err(|error| format!("could not read query journal {}: {error}", path.display()))?;
    for (index, line) in content.lines().enumerate() {
        let item: serde_json::Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "query journal {} line {} is invalid: {error}",
                path.display(),
                index + 1
            )
        })?;
        let root = item["root"].as_str().ok_or_else(|| {
            format!(
                "query journal {} line {} has no root",
                path.display(),
                index + 1
            )
        })?;
        if fs::canonicalize(root).map_err(|error| {
            format!(
                "query journal {} line {} root cannot be resolved: {error}",
                path.display(),
                index + 1
            )
        })? != expected_root
        {
            return Err(format!(
                "query journal {} line {} uses another source root",
                path.display(),
                index + 1
            ));
        }
        let elapsed = item["elapsed_ms"].as_u64().ok_or_else(|| {
            format!(
                "query journal {} line {} has no elapsed_ms",
                path.display(),
                index + 1
            )
        })?;
        summary.query_count += 1;
        summary.elapsed_ms = summary.elapsed_ms.saturating_add(elapsed);
        if item["status"] == "error" {
            summary.failed_count += 1;
        } else if item["status"] != "ok" {
            return Err(format!(
                "query journal {} line {} has invalid status",
                path.display(),
                index + 1
            ));
        } else if item["output"]["truncated"] == true {
            summary.truncated_count += 1;
        } else if item["output"]["results"]
            .as_array()
            .is_some_and(Vec::is_empty)
        {
            summary.empty_count += 1;
        }
    }
    Ok(summary)
}

fn read_complete_bundle_responses(
    run: &Path,
    responses: Option<&Path>,
    allow_partial: bool,
    source_root: Option<&Path>,
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
        if let Some(source_root) = source_root {
            validate_review_artifact_source_text(source_root, &response_set).map_err(|error| {
                format!(
                    "path-review bundle response {} has invalid source evidence: {error}",
                    response_path.display()
                )
            })?;
        }
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
    let deferred_review_ids = manifest.deferred_review_ids.clone();
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

/// Reuse a source-bound scan, then select operands without rebuilding bundles
/// or application analysis. Backend project sources/caller scope stay intact.
fn semantic_scan(
    root: &Path,
    inventory: Option<&Path>,
    evidence_ids: Option<&str>,
) -> Result<mehscan_core::ScanResult, String> {
    let mut scan = if let Some(directory) = inventory {
        let inventory: mehscan_engine::investigation::ReviewInventory = serde_json::from_slice(
            &fs::read(directory.join("scan-cache.json")).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("invalid review inventory: {e}"))?;
        engine(
            mehscan_engine::investigation::validate_review_inventory_for_collection(
                root, &inventory,
            ),
        )?;
        inventory.scan
    } else {
        engine(mehscan_engine::scan_path(root))?
    };
    if let Some(ids) = evidence_ids {
        let ids: BTreeSet<_> = ids
            .split(',')
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        if ids.is_empty() {
            return Err("select at least one evidence ID".into());
        }
        let known: BTreeSet<_> = scan.evidence.iter().map(|e| e.id.as_str()).collect();
        for id in &ids {
            if !known.contains(id) {
                return Err(format!("unknown evidence ID {id:?} in scan"));
            }
        }
        scan.evidence.retain(|e| ids.contains(e.id.as_str()));
    }
    Ok(scan)
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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewLedger {
    schema_version: String,
    source_fingerprint: String,
    input_fingerprint: String,
    inventory_count: usize,
    reviewed: BTreeMap<String, String>,
    conflicts: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewChunkBinding {
    input_fingerprint: Option<String>,
    source_fingerprint: String,
    requests: BTreeMap<String, String>,
}

fn load_review_ledger(path: &Path, inventory: &serde_json::Value) -> Result<ReviewLedger, String> {
    let ledger: ReviewLedger = serde_json::from_slice(
        &fs::read(path)
            .map_err(|error| format!("could not read ledger {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid review ledger: {error}"))?;
    let fingerprint = inventory["source_fingerprint"]
        .as_str()
        .ok_or("inventory source fingerprint is missing")?;
    let count = inventory["entries"]
        .as_array()
        .ok_or("inventory entries are missing")?
        .len();
    if ledger.schema_version != "2"
        || ledger.source_fingerprint != fingerprint
        || inventory["input_fingerprint"].as_str() != Some(ledger.input_fingerprint.as_str())
        || ledger.inventory_count != count
    {
        return Err("review ledger does not match this inventory; rebuild it".to_string());
    }
    let known = inventory["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["review_id"].as_str())
        .collect::<BTreeSet<_>>();
    if ledger.reviewed.iter().any(|(id, decision)| {
        !known.contains(id.as_str())
            || !matches!(decision.as_str(), "issue" | "not_issue" | "needs_review")
    }) || ledger
        .conflicts
        .iter()
        .any(|id| !known.contains(id.as_str()) || ledger.reviewed.contains_key(id))
    {
        return Err("review ledger contains unknown IDs or invalid decisions".to_string());
    }
    Ok(ledger)
}

fn review_run_directories(
    root: &Path,
    depth: usize,
    runs: &mut Vec<PathBuf>,
) -> Result<(), String> {
    if root.join("manifest.json").is_file() {
        runs.push(root.to_path_buf());
    }
    if depth == 0 {
        return Ok(());
    }
    for entry in fs::read_dir(root)
        .map_err(|error| format!("could not inspect history {}: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
            && entry.file_name() != "inventory"
        {
            review_run_directories(&entry.path(), depth - 1, runs)?;
        }
    }
    Ok(())
}

fn build_review_ledger(inventory_dir: &Path, history: &str) -> Result<ReviewLedger, String> {
    let cache: mehscan_engine::investigation::ReviewInventory = serde_json::from_slice(
        &fs::read(inventory_dir.join("scan-cache.json"))
            .map_err(|e| format!("could not read inventory cache: {e}"))?,
    )
    .map_err(|e| format!("invalid inventory cache: {e}"))?;
    let history_validator = engine(mehscan_engine::investigation::ReviewHistoryValidator::new(
        Path::new(&cache.scan.root),
        &cache,
    ))?;
    let input_fingerprint = engine(cache.input_fingerprint())?;
    let inventory: serde_json::Value = serde_json::from_slice(
        &fs::read(inventory_dir.join("inventory.json"))
            .map_err(|error| format!("could not read inventory: {error}"))?,
    )
    .map_err(|error| format!("invalid inventory: {error}"))?;
    if inventory["input_fingerprint"].as_str() != Some(input_fingerprint.as_str()) {
        return Err(
            "inventory summary does not match its source/semantic cache; regenerate it".into(),
        );
    }
    let fingerprint = inventory["source_fingerprint"]
        .as_str()
        .ok_or("inventory source fingerprint is missing")?;
    let entries = inventory["entries"]
        .as_array()
        .ok_or("inventory entries are missing")?;
    let known = entries
        .iter()
        .filter_map(|entry| entry["review_id"].as_str())
        .collect::<BTreeSet<_>>();
    let mut reviewed = BTreeMap::<String, String>::new();
    let mut conflicts = BTreeSet::<String>::new();
    let mut roots = 0;
    for path in history
        .split(',')
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        roots += 1;
        let root = Path::new(path);
        let overview: serde_json::Value = serde_json::from_slice(
            &fs::read(root.join("inventory").join("overview.json")).map_err(|error| {
                format!(
                    "history {} needs an inventory overview: {error}",
                    root.display()
                )
            })?,
        )
        .map_err(|error| format!("invalid history inventory: {error}"))?;
        if overview["source_fingerprint"].as_str() != Some(fingerprint) {
            return Err(format!(
                "history {} has a different source fingerprint",
                root.display()
            ));
        }
        if overview["input_fingerprint"].as_str() != Some(input_fingerprint.as_str()) {
            return Err(format!(
                "history {} has different review inputs; re-review it",
                root.display()
            ));
        }
        let mut runs = Vec::new();
        review_run_directories(root, 3, &mut runs)?;
        for run in runs {
            let binding_path = run.join("input-binding.json");
            let binding: Option<ReviewChunkBinding> = if binding_path.exists() {
                Some(
                    serde_json::from_slice(&fs::read(&binding_path).map_err(|e| e.to_string())?)
                        .map_err(|e| format!("invalid history chunk binding: {e}"))?,
                )
            } else {
                None
            };
            if binding.as_ref().is_none_or(|b| {
                b.source_fingerprint != fingerprint
                    || b.input_fingerprint
                        .as_ref()
                        .is_some_and(|value| value != &input_fingerprint)
                    || (cache.semantic_inputs.is_some() || cache.typescript_inputs.is_some())
                        && b.input_fingerprint.is_none()
            }) {
                return Err(format!(
                    "history chunk {} has different or missing semantic input binding; re-review it",
                    run.display()
                ));
            }
            let (manifest, responses, _) = read_complete_bundle_responses(
                &run,
                None,
                true,
                Some(Path::new(&cache.scan.root)),
            )?;
            if let Some(binding) = &binding {
                for entry in &manifest.bundles {
                    let bytes = fs::read(run.join("requests").join(&entry.filename))
                        .map_err(|e| e.to_string())?;
                    if binding.requests.get(&entry.filename)
                        != Some(&mehscan_engine::investigation::review_content_fingerprint(
                            &bytes,
                        ))
                    {
                        return Err(
                            "history chunk request changed after input binding; re-review it"
                                .into(),
                        );
                    }
                }
            }
            for (bundle, response) in responses {
                engine(history_validator.validate_bundle(&bundle))?;
                for result in response.results {
                    if !known.contains(result.review_id.as_str()) {
                        return Err(format!(
                            "history review ID {:?} is absent from inventory",
                            result.review_id
                        ));
                    }
                    let decision = serde_json::to_value(result.decision)
                        .map_err(|error| error.to_string())?
                        .as_str()
                        .ok_or("invalid review decision")?
                        .to_string();
                    if reviewed
                        .get(&result.review_id)
                        .is_some_and(|old| old != &decision)
                    {
                        conflicts.insert(result.review_id.clone());
                    }
                    reviewed.insert(result.review_id, decision);
                }
            }
        }
    }
    if roots == 0 {
        return Err("--history requires at least one run root".to_string());
    }
    for id in &conflicts {
        reviewed.remove(id);
    }
    Ok(ReviewLedger {
        schema_version: "2".to_string(),
        source_fingerprint: fingerprint.to_string(),
        input_fingerprint,
        inventory_count: entries.len(),
        reviewed,
        conflicts: conflicts.into_iter().collect(),
    })
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
        "c" => Ok(Language::C),
        "cpp" | "c++" => Ok(Language::Cpp),
        "csharp" | "c#" | "cs" => Ok(Language::Csharp),
        "java" => Ok(Language::Java),
        "kotlin" | "kt" | "kts" => Ok(Language::Kotlin),
        "javascript" | "js" => Ok(Language::Javascript),
        "typescript" | "ts" => Ok(Language::Typescript),
        "tsx" => Ok(Language::Tsx),
        "python" | "py" => Ok(Language::Python),
        "go" | "golang" => Ok(Language::Go),
        "php" => Ok(Language::Php),
        "rust" | "rs" => Ok(Language::Rust),
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

fn validate_review_artifact_source_text(
    source_root: &Path,
    responses: &mehscan_core::PathReviewBundleResponseSet,
) -> Result<(), String> {
    let root = fs::canonicalize(source_root).map_err(|error| {
        format!(
            "could not resolve source root {}: {error}",
            source_root.display()
        )
    })?;
    let mut sources = BTreeMap::<PathBuf, String>::new();
    for result in &responses.results {
        let Some(trace) = &result.investigation else {
            continue;
        };
        for artifact in &trace.decisive_artifacts {
            let relative = Path::new(&artifact.location.path);
            if is_absolute_artifact_path(&artifact.location.path)
                || matches!(
                    artifact.location.path.as_bytes(),
                    [drive, b':', ..] if drive.is_ascii_alphabetic()
                )
                || relative.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::ParentDir
                            | std::path::Component::Prefix(_)
                            | std::path::Component::RootDir
                    )
                })
            {
                return Err(format!(
                    "retrieved artifact {:?} for {:?} has a non-relative source path",
                    artifact.artifact_id, result.review_id
                ));
            }
            let path = fs::canonicalize(root.join(relative)).map_err(|error| {
                format!(
                    "could not resolve retrieved artifact {:?} source {:?}: {error}",
                    artifact.artifact_id, artifact.location.path
                )
            })?;
            if !path.starts_with(&root) {
                return Err(format!(
                    "retrieved artifact {:?} for {:?} resolves outside the source root",
                    artifact.artifact_id, result.review_id
                ));
            }
            if !sources.contains_key(&path) {
                let source = fs::read_to_string(&path).map_err(|error| {
                    format!(
                        "could not read retrieved artifact {:?} source {:?}: {error}",
                        artifact.artifact_id, artifact.location.path
                    )
                })?;
                sources.insert(path.clone(), source.replace("\r\n", "\n"));
            }
            let source = &sources[&path];
            let excerpt = artifact.excerpt.replace("\r\n", "\n");
            if !source.contains(&excerpt) {
                return Err(format!(
                    "retrieved artifact {:?} for {:?} is not exact source text in {:?}",
                    artifact.artifact_id, result.review_id, artifact.location.path
                ));
            }
        }
    }
    Ok(())
}

fn print_json(value: &impl serde::Serialize) -> Result<(), String> {
    let portable = portable_json_value(value)?;
    let json = serde_json::to_string_pretty(&portable)
        .map_err(|error| format!("could not serialize portable result: {error}"))?;
    println!("{json}");
    Ok(())
}

fn review_card(
    bundle: &mehscan_core::PathReviewBundle,
    review_id: &str,
) -> Result<serde_json::Value, String> {
    if !bundle.review_ids.iter().any(|id| id == review_id) {
        return Err(format!("review ID {review_id:?} is not in this bundle"));
    }
    let value = serde_json::to_value(bundle)
        .map_err(|error| format!("could not serialize review bundle: {error}"))?;
    review_card_from_value(bundle, review_id, &value)
}

// Receiver navigation can precede producer facts in a native snapshot. Prefer
// the selected operand's question; array order must not redirect it to the
// command receiver when the unresolved value is the query/path/etc.
fn operand_lookup_fact<'a>(
    facts: &'a [serde_json::Value],
    captures: &serde_json::Value,
) -> Option<&'a serde_json::Value> {
    facts
        .iter()
        .filter(|fact| {
            matches!(
                fact["kind"].as_str(),
                Some("operand_boundary" | "local_operand_origin")
            )
        })
        .min_by_key(|fact| {
            let role = fact["role"].as_str().unwrap_or_default();
            let role_rank = if captures.get(role).is_some() {
                0
            } else if matches!(role, "receiver" | "sink") {
                2
            } else {
                1
            };
            (role_rank, u8::from(fact["kind"] != "operand_boundary"))
        })
}

fn review_card_from_value(
    bundle: &mehscan_core::PathReviewBundle,
    review_id: &str,
    value: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let selected_anchor_id = engine(mehscan_engine::investigation::bundle_selected_anchor_id(
        bundle, review_id,
    ))?;
    let review = value["reviews"]
        .as_array()
        .and_then(|reviews| {
            reviews
                .iter()
                .find(|review| review["id"].as_str() == Some(review_id))
        })
        .ok_or_else(|| format!("review {review_id:?} is missing from bundle payload"))?;
    let anchor = review["evidence"]
        .as_array()
        .and_then(|evidence| {
            evidence
                .iter()
                .find(|entry| entry["id"].as_str() == Some(selected_anchor_id))
        })
        .or_else(|| {
            ["sink", "source"]
                .iter()
                .filter_map(|key| review["candidate"].get(*key))
                .find(|entry| entry["id"].as_str() == Some(selected_anchor_id))
        })
        .ok_or_else(|| format!("selected anchor {selected_anchor_id:?} is missing"))?;
    let anchor_path = anchor["location"]["path"].as_str();
    let context = review["facts"].as_array().and_then(|facts| {
        facts.iter().find(|fact| {
            fact["role"].as_str() == Some("source_context")
                && fact["location"]["path"].as_str() == anchor_path
        })
    });
    let context = context.map(|fact| {
        let excerpt = fact["excerpt"].as_str().unwrap_or_default();
        let lines: Vec<&str> = excerpt.lines().collect();
        let first_line = fact["location"]["start"]["line"].as_u64().unwrap_or(1);
        let anchor_line = anchor["location"]["start"]["line"]
            .as_u64()
            .unwrap_or(first_line);
        let center_line = anchor["captures"]
            .as_object()
            .and_then(|captures| {
                captures.values().find_map(|capture| {
                    capture["location"]["start"]["line"].as_u64()
                })
            })
            .unwrap_or(anchor_line);
        let center = center_line.saturating_sub(first_line) as usize;
        let start = center.saturating_sub(2).min(lines.len());
        let end = (center + 5).min(lines.len());
        let full_excerpt = lines[start..end].join("\n");
        let truncated = full_excerpt.chars().count() > 700 || center >= lines.len();
        let excerpt = full_excerpt
            .chars()
            .take(700)
            .collect::<String>();
        serde_json::json!({
            "evidence_id": fact["evidence_id"],
            "location": {"path": fact["location"]["path"], "start_line": first_line + start as u64, "end_line": first_line + start as u64 + excerpt.lines().count().saturating_sub(1) as u64},
            "excerpt": excerpt,
            "truncated": truncated,
        })
    });
    let nearby_locations: Vec<_> = review["facts"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|fact| {
            fact["location"]["path"].as_str() != anchor_path && !fact["location"]["path"].is_null()
        })
        .filter(|fact| fact["role"].as_str() != Some("framework_context"))
        .take(2)
        .map(|fact| {
            serde_json::json!({
                "role": fact["role"],
                "symbol": fact["symbol"],
                "location": brief_location(&fact["location"]),
            })
        })
        .collect();
    let mut lookups: Vec<_> = review["investigation"]["lookup_requests"]
        .as_array()
        .into_iter()
        .flatten()
        .take(2)
        .map(|lookup| {
            serde_json::json!({
                "operation": lookup["operation"],
                "arguments": lookup["arguments"],
                "purpose": lookup["purpose"],
            })
        })
        .collect();
    if let Some(target) = anchor["context"]["operand_facts"]
        .as_array()
        .and_then(|facts| {
            facts
                .iter()
                .find(|fact| {
                    matches!(
                        fact["kind"].as_str(),
                        Some("fixed_code_relative_path" | "repository_code_target")
                    )
                })
                .and_then(|fact| fact["value"].as_str())
        })
    {
        lookups = vec![serde_json::json!({
            "operation": "source",
            "arguments": {"path": target, "start-line": "1", "end-line": "40"},
            "purpose": "Inspect the repository target and content-generation boundary; source-defined defaults may differ at runtime."
        })];
    }
    if let Some(fact) = anchor["context"]["operand_facts"]
        .as_array()
        .and_then(|facts| operand_lookup_fact(facts, &anchor["captures"]))
    {
        if let (Some(path), Some(line), Some(end)) = (
            fact["location"]["path"].as_str(),
            fact["location"]["start"]["line"].as_u64(),
            fact["location"]["end"]["line"].as_u64(),
        ) {
            lookups.insert(0, serde_json::json!({
                "operation": "source", "arguments": {"path": path, "start-line": line.saturating_sub(3).max(1).to_string(), "end-line": end.saturating_add(5).min(line.saturating_add(40)).to_string()},
                "purpose": format!("Inspect the {} initializer or intervening write/reference; reaching value and control flow remain unproved.", fact["role"].as_str().unwrap_or("operand"))
            }));
            lookups.truncate(2);
        }
    }
    let captures = anchor["captures"].as_object().map(|captures| {
        captures
            .iter()
            .map(|(name, capture)| {
                (
                    name.clone(),
                    serde_json::json!(capture["text"].as_str().unwrap_or_default()),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>()
    });
    Ok(serde_json::json!({
        "bundle_fingerprint": bundle.bundle_fingerprint,
        "review_id": review_id,
        "selected_anchor_id": selected_anchor_id,
        "operand_facts": anchor["context"]["operand_facts"].as_array().cloned().unwrap_or_default(),
        "category": bundle.category,
        "playbook": bundle.review_playbooks.get(review_id),
        "security_question": review["review_basis"]["security_question"],
        "relationship": review["review_basis"]["relationship"],
        "decision_facts": review["decision_facts"],
        "anchor": {
            "id": anchor["id"],
            "rule_id": anchor["rule_id"],
            "kind": anchor["kind"],
            "capability": anchor["capability"],
            "location": brief_location(&anchor["location"]),
            "captures": captures,
        },
        "source_context": context,
        "nearby_locations": nearby_locations,
        "suggested_lookups": lookups,
        "truncation": review["truncation"],
    }))
}

fn brief_location(location: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "path": location["path"],
        "start_line": location["start"]["line"],
        "end_line": location["end"]["line"],
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BriefReviewSet {
    results: Vec<BriefReview>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BriefReview {
    review_id: String,
    decision: mehscan_core::ReviewDecision,
    confidence: mehscan_core::ReviewConfidence,
    summary: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    checks: Vec<String>,
    #[serde(default)]
    evidence: Vec<BriefSourceRef>,
    #[serde(default)]
    blockers: Vec<String>,
    #[serde(default)]
    reviewer_origin_leads: Vec<mehscan_core::ReviewerOriginLead>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BriefSourceRef {
    path: String,
    start_line: usize,
    end_line: usize,
}

fn expand_brief_reviews(
    bundle: &mehscan_core::PathReviewBundle,
    brief: &BriefReviewSet,
    source_root: &Path,
) -> Result<mehscan_core::PathReviewBundleResponseSet, String> {
    let mut results = Vec::with_capacity(brief.results.len());
    for review in &brief.results {
        let anchor = engine(mehscan_engine::investigation::bundle_selected_anchor_id(
            bundle,
            &review.review_id,
        ))?
        .to_string();
        let mut artifact_ids = vec![anchor.clone()];
        let mut artifacts = Vec::with_capacity(review.evidence.len());
        for (index, source_ref) in review.evidence.iter().enumerate() {
            let artifact_id = format!("review-source-{}", index + 1);
            let (location, excerpt) =
                read_brief_source(source_root, source_ref).map_err(|error| {
                    format!(
                        "review {} evidence {} ({}:{}-{}): {error}",
                        review.review_id,
                        index + 1,
                        source_ref.path,
                        source_ref.start_line,
                        source_ref.end_line
                    )
                })?;
            artifacts.push(mehscan_core::ReviewRetrievedArtifact {
                artifact_id: artifact_id.clone(),
                location,
                excerpt,
            });
            artifact_ids.push(artifact_id);
        }
        let citations = artifact_ids
            .iter()
            .map(|artifact_id| mehscan_core::ReviewArtifactCitation {
                artifact_id: artifact_id.clone(),
                claim: if artifact_id == &anchor {
                    "Selected operation under review.".to_string()
                } else {
                    "Source used for the verdict.".to_string()
                },
            })
            .collect();
        let reviewer_inferences = if review.reason.trim().is_empty() {
            Vec::new()
        } else {
            vec![mehscan_core::ReviewerInference {
                claim: review.reason.clone(),
                artifact_ids,
            }]
        };
        results.push(mehscan_core::PathReviewTriageResult {
            review_id: review.review_id.clone(),
            selected_anchor_id: Some(anchor),
            decision: review.decision,
            confidence: review.confidence,
            summary: review.summary.clone(),
            checks: review.checks.clone(),
            investigation: Some(mehscan_core::ReviewInvestigationTrace {
                decisive_artifacts: artifacts,
                journal_summary: None,
                citations,
                reviewer_inferences,
                reviewer_origin_leads: review.reviewer_origin_leads.clone(),
                blockers: review.blockers.clone(),
            }),
        });
    }
    Ok(mehscan_core::PathReviewBundleResponseSet {
        schema_version: mehscan_core::PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        bundle_fingerprint: bundle.bundle_fingerprint.clone(),
        results,
    })
}

fn read_brief_source(
    source_root: &Path,
    source_ref: &BriefSourceRef,
) -> Result<(mehscan_core::Location, String), String> {
    let relative = Path::new(&source_ref.path);
    if is_absolute_artifact_path(&source_ref.path)
        || relative.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir
                    | std::path::Component::Prefix(_)
                    | std::path::Component::RootDir
            )
        })
    {
        return Err(format!(
            "brief evidence path must be relative: {:?}",
            source_ref.path
        ));
    }
    let root = fs::canonicalize(source_root)
        .map_err(|error| format!("could not resolve source root: {error}"))?;
    let path = fs::canonicalize(root.join(relative)).map_err(|error| {
        format!(
            "could not resolve brief evidence {:?}: {error}",
            source_ref.path
        )
    })?;
    if !path.starts_with(&root) {
        return Err(format!(
            "brief evidence path leaves source root: {:?}",
            source_ref.path
        ));
    }
    if source_ref.start_line == 0
        || source_ref.end_line < source_ref.start_line
        || source_ref.end_line - source_ref.start_line >= 40
    {
        return Err("brief evidence must select 1 to 40 source lines".to_string());
    }
    let source = fs::read_to_string(&path).map_err(|error| {
        format!(
            "could not read brief evidence {:?}: {error}",
            source_ref.path
        )
    })?;
    let lines = source.split_inclusive('\n').collect::<Vec<_>>();
    if source_ref.end_line > lines.len() {
        return Err(format!(
            "brief evidence line is past end of {:?}",
            source_ref.path
        ));
    }
    let start_offset = lines[..source_ref.start_line - 1]
        .iter()
        .map(|line| line.len())
        .sum();
    let excerpt = lines[source_ref.start_line - 1..source_ref.end_line].concat();
    if excerpt.trim().is_empty() || excerpt.chars().count() > 4000 {
        return Err("brief evidence excerpt is empty or exceeds 4000 characters".to_string());
    }
    let end_offset = start_offset + excerpt.len();
    let (end_line, end_column) = if excerpt.ends_with('\n') {
        (source_ref.end_line + 1, 1)
    } else {
        (
            source_ref.end_line,
            lines[source_ref.end_line - 1].chars().count() + 1,
        )
    };
    Ok((
        mehscan_core::Location {
            path: source_ref.path.replace('\\', "/"),
            start: mehscan_core::Position {
                line: source_ref.start_line,
                column: 1,
                byte_offset: start_offset,
            },
            end: mehscan_core::Position {
                line: end_line,
                column: end_column,
                byte_offset: end_offset,
            },
        },
        excerpt,
    ))
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
        "mehscan - deterministic security evidence scanner\n\nUSAGE:\n  mehscan --version\n  mehscan scan [PATH] [--format text|json|candidates|sarif-candidates] [--jobs N] [--include-tests] [--changed-from REF | --files-from PATH] [--diff-mode full|impact]\n  mehscan report --run DIR [--responses DIR] [--source-root ROOT] [--allow-partial true|false] [--format json|sarif|markdown] [--output PATH]\n  mehscan benchmark [ROOT] [--manifest PATH] [--include-optional] [--format text|json]\n  mehscan evaluate <prepare|score> [ROOT] [OPTIONS]\n  mehscan investigate <OPERATION> [PATH] [OPTIONS]\n\nRun a command with --help for details."
    );
}

fn print_report_help() {
    println!(
        "USAGE:\n  mehscan report --run DIR [--responses DIR] [--source-root ROOT] [--allow-partial true|false] [--format json|sarif|markdown] [--output PATH] [--reviewer NAME] [--include-dismissed true|false] [--scope-label TEXT] [--project NAME] [--revision REF]\n\nBuilds canonical post-triage findings by joining validated bundle responses to deterministic review evidence. JSON is the full-fidelity consumer artifact. SARIF 2.1.0 contains confirmed issues only. Markdown is the human-readable summary and prioritizes unresolved review checks before confirmed and dismissed results; use --include-dismissed true to include not-issue summaries. --responses defaults to DIR/responses. --allow-partial true skips missing response files only and labels completed versus total review coverage; present responses must still validate as complete bundles. Scope, project and revision labels are user-supplied handoff metadata, not verified security facts."
    );
}

fn print_scan_help() {
    println!(
        "Optional C# facts: --csharp-semantic SNAPSHOT --csharp-context CONTEXT (full scan context only)."
    );
    println!(
        "Optional TS/JS facts: --typescript-semantic SNAPSHOT --typescript-context CONTEXT (full scan context only)."
    );
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
  mehscan investigate csharp-context [ROOT] --context SEED --output FILE
  mehscan investigate csharp-semantic [ROOT] --context FILE --backend EXE --output FILE [--inventory DIR] [--evidence-ids ID,ID]
  mehscan investigate typescript-semantic [ROOT] --context FILE --backend SCRIPT --output FILE [--inventory DIR] [--evidence-ids ID,ID]
  mehscan investigate review-inventory [ROOT] --output DIR [--include-review-material true|false] [--csharp-backend EXE --csharp-context FILE | --csharp-semantic FILE --csharp-context FILE] [--timings true|false]
    Optional TS/JS: [--typescript-backend SCRIPT --typescript-context FILE | --typescript-semantic FILE --typescript-context FILE]
  mehscan investigate review-inventory-list --inventory DIR [--ledger FILE] [--selection all|value|deferred] [--capability NAME] [--cwe CWE] [--path-prefix PATH] [--operand-kind KIND] [--group-by contract|implementation] [--contract KEY] [--limit N] [--offset N]
  mehscan investigate review-ledger --inventory DIR --history RUN_ROOT[,RUN_ROOT] --output FILE
  mehscan investigate review-jobs [ROOT] [--context-lines N] [--limit N] [--offset N] [--include-review-material true|false]
  mehscan investigate review-tasks [ROOT] [--context-lines N] [--limit N] [--offset N] [--include-review-material true|false]
  mehscan investigate review-bundles [ROOT] --output DIR [--inventory DIR --review-ids ID,ID --ledger FILE] [--context-lines N] [--max-bytes N] [--max-reviews N] [--max-total-reviews N] [--timings true|false] [--include-review-material true|false] [--scope-label TEXT] [--project NAME] [--revision REF]
  mehscan investigate review-bundle-diff --before DIR --after DIR
  mehscan investigate review-bundle-list --bundle PATH
  mehscan investigate review-card --bundle PATH --review-id ID
  mehscan investigate review-sweep --bundle PATH
  mehscan investigate review-response-schema --bundle PATH [--output PATH]
  mehscan investigate review-bundle-finalize --bundle PATH --draft PATH --journal-dir DIR --output PATH --source-root ROOT
  mehscan investigate review-bundle-triage --bundle PATH --responses PATH [--source-root ROOT] [--summary true|false]
  mehscan investigate review-bundle-summary --run DIR [--responses DIR] [--source-root ROOT] [--allow-partial true|false]
  mehscan investigate outline [ROOT] --path FILE
  mehscan investigate source [ROOT] --path FILE --start-line N --end-line N
  mehscan investigate enclosing [ROOT] --evidence-id ID
  mehscan investigate enclosing-at [ROOT] --path FILE --line N
  mehscan investigate evidence [ROOT] [--kind KIND] [--capability NAME] [--language LANG] [--path FILE] [--limit N]
  mehscan investigate units [ROOT] [--kind KIND] [--capability NAME] [--language LANG] [--path FILE] [--context-lines N] [--limit N]
  mehscan investigate symbol [ROOT] --name NAME [--path FILE] [--limit N]
  mehscan investigate imports [ROOT] --name NAME [--limit N]
  mehscan investigate references [ROOT] --symbol NAME [--path FILE | --path-prefix DIR] [--limit N] [--summary true]
  mehscan investigate provenance [ROOT] [--inventory DIR] [--path-prefix DIR] [--limit N]
  mehscan investigate paths [ROOT] --name TEXT [--limit N]
  mehscan investigate native-call-sites [ROOT] --callee NAME [--path FILE] [--limit N]
  mehscan investigate structural [ROOT] --language LANG --pattern PATTERN [--path FILE] [--limit N]

Add --journal FILE to a read-only query to append its exact arguments, output or error, and elapsed time as JSONL. Use one file per review. Response schema 1.3 cites only decisive source in investigation.decisive_artifacts; review-bundle-finalize attaches journal counts and checks the response. Source reads are capped at 400 lines and 64 KiB. References default to 20 results; other result limits default to 200. The maximum is 1000."#
    );
}

#[cfg(test)]
mod tests {
    use super::{
        BriefSourceRef, membership_changed_after_bundles, operand_lookup_fact, parse_capability,
        portable_json_value, read_brief_source, validate_review_artifact_source_text,
    };
    use mehscan_core::Capability;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn operand_navigation_prefers_captured_value_over_receiver_regardless_of_fact_order() {
        let receiver = serde_json::json!({"role": "receiver", "kind": "operand_boundary"});
        let query = serde_json::json!({"role": "query", "kind": "operand_boundary"});
        let origin = serde_json::json!({"role": "query", "kind": "local_operand_origin"});
        let captures = serde_json::json!({"query": {"text": "sql"}});
        for facts in [
            vec![receiver.clone(), query.clone()],
            vec![query.clone(), receiver.clone()],
        ] {
            assert_eq!(operand_lookup_fact(&facts, &captures), Some(&query));
        }
        assert_eq!(
            operand_lookup_fact(&[receiver.clone(), origin.clone()], &captures),
            Some(&origin)
        );
        assert_eq!(
            operand_lookup_fact(&[origin, query.clone()], &captures),
            Some(&query)
        );
        assert_eq!(
            operand_lookup_fact(&[receiver.clone()], &captures),
            Some(&receiver)
        );
        assert!(operand_lookup_fact(&[], &captures).is_none());
    }

    #[test]
    fn brief_source_accepts_context_over_twenty_lines_but_remains_bounded() {
        let directory = std::env::temp_dir().join(format!(
            "mehscan-brief-source-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("source.ts"), "const x = 1;\n".repeat(41)).unwrap();
        let range = |end_line| BriefSourceRef {
            path: "source.ts".to_string(),
            start_line: 1,
            end_line,
        };
        assert!(read_brief_source(&directory, &range(27)).is_ok());
        assert!(read_brief_source(&directory, &range(40)).is_ok());
        assert!(
            read_brief_source(&directory, &range(41))
                .unwrap_err()
                .contains("1 to 40 source lines")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn source_audit_rejects_paraphrases_and_paths_outside_root() {
        let directory = std::env::temp_dir().join(format!(
            "mehscan-source-audit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).expect("create source audit root");
        std::fs::write(directory.join("source.ts"), "const answer = 42;\r\n")
            .expect("write source");
        let mut responses: mehscan_core::PathReviewBundleResponseSet = serde_json::from_value(
            serde_json::json!({
                "schema_version": "1.3",
                "bundle_fingerprint": "test",
                "results": [{
                    "review_id": "review-test",
                    "decision": "issue",
                    "confidence": "medium",
                    "summary": "test",
                    "checks": [],
                    "investigation": {
                        "decisive_artifacts": [{
                                "artifact_id": "source-1",
                                "location": {"path": "source.ts", "start": {"line": 1, "column": 1, "byte_offset": 0}, "end": {"line": 1, "column": 19, "byte_offset": 18}},
                                "excerpt": "const answer = 42;\n"
                        }],
                        "citations": [], "reviewer_inferences": [], "reviewer_origin_leads": [], "blockers": []
                    }
                }]
            }),
        )
        .expect("response fixture");
        assert!(validate_review_artifact_source_text(&directory, &responses).is_ok());
        responses.results[0]
            .investigation
            .as_mut()
            .unwrap()
            .decisive_artifacts[0]
            .excerpt = "const answer = 43;".to_string();
        assert!(
            validate_review_artifact_source_text(&directory, &responses)
                .unwrap_err()
                .contains("not exact source text")
        );
        let artifact = &mut responses.results[0]
            .investigation
            .as_mut()
            .unwrap()
            .decisive_artifacts[0];
        artifact.excerpt = "const answer = 42;".to_string();
        artifact.location.path = "../outside.ts".to_string();
        assert!(
            validate_review_artifact_source_text(&directory, &responses)
                .unwrap_err()
                .contains("non-relative source path")
        );
        responses.results[0]
            .investigation
            .as_mut()
            .unwrap()
            .decisive_artifacts[0]
            .location
            .path = "C:source.ts".to_string();
        assert!(
            validate_review_artifact_source_text(&directory, &responses)
                .unwrap_err()
                .contains("non-relative source path")
        );
        std::fs::remove_file(directory.join("source.ts")).expect("remove test source");
        std::fs::remove_dir(directory).expect("remove test root");
    }

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
