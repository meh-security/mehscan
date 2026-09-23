use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Instant;

use mehscan_core::{
    Capability, Coverage, CweCoverage, CweSupportLevel, Diagnostic, DiagnosticLevel, Evidence,
    FileCoverage, FileStatus, Language, OmittedExtensionCoverage, ProducerCoverage,
    RelationContract, Rule, SCHEMA_VERSION, ScanResult,
};

use crate::code::comments::CommentRanges;
use crate::code::csharp_handoff::CsharpHandoffProjectContext;
use crate::code::csharp_model::CsharpModelProjectContext;
use crate::code::csharp_rpc::CsharpRpcProjectContext;
use crate::code::dotnet_project::DotnetProjectContext;
use crate::code::go_context::GoProjectContext;
use crate::code::java_context::JavaProjectContext;
use crate::code::matcher::{ParseOutcome, ScanDependencies, scan_source};
use crate::code::native_drogon::DrogonProjectContext;
use crate::code::native_invalidation::NativeInvalidationProjectContext;
use crate::code::node_context::NodeProjectContext;
use crate::code::object_input::ObjectInputProjectContext;
use crate::code::python_context::PythonProjectContext;
use crate::code::rust_project::RustProjectContext;
use crate::code::symbols::ProjectSymbolEnvironment;
use crate::repository::{FileClass, discover_with_options, is_generated_javascript_source};
use crate::rules::{CompiledRule, compile_for_language, parser_language};
use crate::secrets::load_allowlist;
use crate::{EngineError, ScanOptions};
use serde::Serialize;

const MAX_SECRET_TEXT_BYTES: u64 = 2 * 1024 * 1024;
const MAX_AUTOMATIC_WORKERS: usize = 32;

fn omitted_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .filter(|extension| !extension.is_empty())
        .map(|extension| format!(".{}", extension.to_ascii_lowercase()))
        .unwrap_or_else(|| "(no extension)".to_string())
}

fn trace_scan_phase(name: &str, microseconds: u128) {
    if std::env::var_os("MEHSCAN_TRACE_PHASES").is_some() {
        eprintln!("mehscan_phase {name} {microseconds}");
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ScanProfile {
    pub total_microseconds: u128,
    pub rule_loading_microseconds: u128,
    pub discovery_microseconds: u128,
    pub rule_compilation_microseconds: u128,
    pub source_loading_and_secret_scan_microseconds: u128,
    pub project_symbols_microseconds: u128,
    pub node_project_context_microseconds: u128,
    pub object_input_context_microseconds: u128,
    pub csharp_model_context_microseconds: u128,
    pub csharp_rpc_context_microseconds: u128,
    pub java_project_context_microseconds: u128,
    pub go_project_context_microseconds: u128,
    pub drogon_project_context_microseconds: u128,
    pub native_invalidation_context_microseconds: u128,
    pub python_project_context_microseconds: u128,
    pub worker_count: usize,
    pub file_analysis: FileAnalysisProfile,
    pub finalization_microseconds: u128,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct FileAnalysisProfile {
    pub files: usize,
    pub total_microseconds: u128,
    pub parse_context_microseconds: u128,
    pub declarative_rules_microseconds: u128,
    pub symbol_rules_microseconds: u128,
    pub summaries_microseconds: u128,
    pub security_paths_microseconds: u128,
    pub declarative_patterns_considered: usize,
    pub declarative_patterns_skipped: usize,
    pub declarative_patterns_executed: usize,
}

pub(crate) fn scan_profiled(
    root: &Path,
    rules: &[Rule],
    relations: &[RelationContract],
    options: ScanOptions,
) -> Result<(ScanResult, ScanProfile), EngineError> {
    let total_started = Instant::now();
    let discovery_started = Instant::now();
    let discovery = discover_with_options(root, options.include_tests)?;
    let impact_plan =
        crate::impact::plan_impact_scope(&discovery.files, options.impact_scope.as_ref());
    let impact_scope = impact_plan.scope.clone();
    let discovery_microseconds = discovery_started.elapsed().as_micros();
    trace_scan_phase("discovery", discovery_microseconds);
    let dotnet_project_sources = discovery
        .files
        .iter()
        .filter(|file| {
            file.absolute
                .extension()
                .is_some_and(|extension| extension == "csproj")
        })
        .filter_map(|file| {
            fs::read_to_string(&file.absolute)
                .ok()
                .map(|source| (file.relative.clone(), source))
        })
        .collect::<Vec<_>>();
    let python_template_sources = discovery
        .files
        .iter()
        .filter(|file| {
            let normalized = file.relative.replace('\\', "/").to_ascii_lowercase();
            (normalized.starts_with("templates/") || normalized.contains("/templates/"))
                && normalized.ends_with(".html")
        })
        .filter_map(|file| {
            fs::read_to_string(&file.absolute)
                .ok()
                .map(|source| (file.relative.clone(), source))
        })
        .collect::<Vec<_>>();
    let node_pug_template_sources = discovery
        .files
        .iter()
        .filter(|file| {
            file.absolute
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("pug"))
        })
        .filter_map(|file| {
            fs::read_to_string(&file.absolute)
                .ok()
                .map(|source| (file.relative.clone(), source))
        })
        .collect::<Vec<_>>();
    let python_openapi_sources = discovery
        .files
        .iter()
        .filter(|file| {
            file.absolute
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| {
                    extension.eq_ignore_ascii_case("yaml") || extension.eq_ignore_ascii_case("yml")
                })
        })
        .filter(|file| {
            fs::metadata(&file.absolute)
                .is_ok_and(|metadata| metadata.len() <= MAX_SECRET_TEXT_BYTES)
        })
        .filter_map(|file| {
            let source = fs::read_to_string(&file.absolute).ok()?;
            (source
                .lines()
                .any(|line| line.trim_start().starts_with("openapi:"))
                && source.lines().any(|line| line.trim() == "paths:")
                && source
                    .lines()
                    .any(|line| line.trim_start().starts_with("operationId:")))
            .then_some((file.relative.clone(), source))
        })
        .collect::<Vec<_>>();
    let dotnet_project_context = DotnetProjectContext::from_project_files(
        dotnet_project_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str())),
    );
    let mut coverage = Coverage {
        ignored_subtrees: discovery.ignored_subtrees,
        ..Coverage::default()
    };
    let mut evidence = Vec::new();
    let mut security_paths = Vec::new();
    let mut diagnostics = discovery.diagnostics;
    let mut compiled = BTreeMap::new();
    let (secret_allowlist, allowlist_warnings) = if options.scan_secrets {
        load_allowlist(&discovery.root)
    } else {
        (crate::secrets::SecretAllowlist::default(), Vec::new())
    };
    diagnostics.extend(allowlist_warnings.into_iter().map(|message| Diagnostic {
        level: DiagnosticLevel::Warning,
        message,
        path: Some(".mehscan-secrets-allowlist".to_string()),
    }));

    let compilation_started = Instant::now();
    for language in all_languages() {
        compiled.insert(language, compile_for_language(rules, language)?);
    }
    let rule_compilation_microseconds = compilation_started.elapsed().as_micros();
    trace_scan_phase("rule_compilation", rule_compilation_microseconds);

    let source_started = Instant::now();
    let mut prepared = Vec::new();
    let mut specialized_files = 0usize;
    let single_file_scan = discovery.root.is_file();
    let explicitly_changed = options
        .impact_scope
        .as_ref()
        .map(|scope| {
            scope
                .changed_files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    for file in discovery.files {
        coverage.totals.discovered += 1;
        let analyze_file = !matches!(
            file.class,
            FileClass::Ignored | FileClass::UnsupportedSource
        ) && impact_plan.includes(&file.relative);
        match file.class {
            FileClass::Ignored => {
                coverage.totals.ignored += 1;
                if file.reason == Some("non-source file")
                    && !single_file_scan
                    && !explicitly_changed.contains(file.relative.as_str())
                {
                    coverage
                        .omitted_files_by_extension
                        .entry(omitted_extension(&file.relative))
                        .or_insert_with(OmittedExtensionCoverage::default)
                        .non_source += 1;
                } else {
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::Ignored,
                        reason: file.reason.map(str::to_string),
                    });
                }
            }
            FileClass::UnsupportedSource => {
                coverage.totals.unsupported += 1;
                if single_file_scan || explicitly_changed.contains(file.relative.as_str()) {
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::Unsupported,
                        reason: file.reason.map(str::to_string),
                    });
                } else {
                    coverage
                        .omitted_files_by_extension
                        .entry(omitted_extension(&file.relative))
                        .or_insert_with(OmittedExtensionCoverage::default)
                        .unsupported_source += 1;
                }
            }
            FileClass::SecretOnly if !analyze_file => {
                coverage.totals.ignored += 1;
                coverage.files.push(FileCoverage {
                    path: file.relative,
                    language: None,
                    status: FileStatus::Ignored,
                    reason: Some("outside impact scan scope".to_string()),
                });
            }
            FileClass::SecretOnly if !options.scan_secrets => {
                coverage.totals.ignored += 1;
                if file.reason.is_none()
                    && !single_file_scan
                    && !explicitly_changed.contains(file.relative.as_str())
                {
                    coverage
                        .omitted_files_by_extension
                        .entry(omitted_extension(&file.relative))
                        .or_insert_with(OmittedExtensionCoverage::default)
                        .secret_scan_disabled += 1;
                } else {
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::Ignored,
                        reason: Some("secret scanning disabled".to_string()),
                    });
                }
            }
            FileClass::SecretOnly => match read_secret_text(&file.absolute) {
                Ok(source) => {
                    let mut secret_scan = crate::secrets::scan_source(
                        &file.relative,
                        &source,
                        &CommentRanges::default(),
                        &secret_allowlist,
                    );
                    coverage.totals.secret_scanned += 1;
                    coverage.totals.secret_suppressed += secret_scan.suppressed;
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::SecretScanned,
                        reason: file.reason.map(str::to_string),
                    });
                    evidence.append(&mut secret_scan.evidence);
                }
                Err(reason) => {
                    coverage.totals.secret_skipped += 1;
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::SecretSkipped,
                        reason: Some(reason),
                    });
                }
            },
            FileClass::EmbeddedJavascriptTemplate => {
                let source = match fs::read_to_string(&file.absolute) {
                    Ok(source) => source,
                    Err(error) => {
                        coverage.totals.ignored += 1;
                        coverage.files.push(FileCoverage {
                            path: file.relative,
                            language: None,
                            status: FileStatus::Ignored,
                            reason: Some(format!(
                                "EJS template could not be read as UTF-8: {error}"
                            )),
                        });
                        continue;
                    }
                };
                let Some(source) = super::embedded_javascript::extract_ejs_scripts(&source) else {
                    coverage.totals.ignored += 1;
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::Ignored,
                        reason: Some(
                            "EJS template contains no executable inline JavaScript".to_string(),
                        ),
                    });
                    continue;
                };
                coverage
                    .languages
                    .entry(Language::Javascript)
                    .or_default()
                    .discovered += 1;
                prepared.push(PreparedFile {
                    relative: file.relative,
                    language: Language::Javascript,
                    source,
                    build_symbols: BTreeMap::new(),
                });
            }
            FileClass::Razor if !analyze_file => {
                coverage.totals.ignored += 1;
                coverage.files.push(FileCoverage {
                    path: file.relative,
                    language: None,
                    status: FileStatus::Ignored,
                    reason: Some("outside impact scan scope".to_string()),
                });
            }
            FileClass::Razor => match read_secret_text(&file.absolute) {
                Ok(source) => {
                    let mut razor_evidence =
                        crate::code::razor::scan_escape_hatches(&file.relative, &source);
                    crate::code::csharp_sinks::annotate_decision_critical_origins(
                        Language::Csharp,
                        &mut razor_evidence,
                    );
                    specialized_files += 1;
                    coverage.totals.scanned += 1;
                    if options.scan_secrets {
                        let mut secret_scan = crate::secrets::scan_source(
                            &file.relative,
                            &source,
                            &CommentRanges::default(),
                            &secret_allowlist,
                        );
                        coverage.totals.secret_scanned += 1;
                        coverage.totals.secret_suppressed += secret_scan.suppressed;
                        evidence.append(&mut secret_scan.evidence);
                    }
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::Scanned,
                        reason: Some(
                            "specialized Razor escape-hatch scan; no full Razor parser".to_string(),
                        ),
                    });
                    evidence.append(&mut razor_evidence);
                }
                Err(reason) => {
                    coverage.totals.secret_skipped += 1;
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::SecretSkipped,
                        reason: Some(reason),
                    });
                }
            },
            FileClass::WebForms if !analyze_file => {
                coverage.totals.ignored += 1;
                coverage.files.push(FileCoverage {
                    path: file.relative,
                    language: None,
                    status: FileStatus::Ignored,
                    reason: Some("outside impact scan scope".to_string()),
                });
            }
            FileClass::WebForms => match read_secret_text(&file.absolute) {
                Ok(source) => {
                    let (mut webforms_evidence, mut webforms_paths) =
                        crate::code::webforms::scan_inline_output(&file.relative, &source);
                    crate::code::csharp_sinks::annotate_decision_critical_origins(
                        Language::Csharp,
                        &mut webforms_evidence,
                    );
                    specialized_files += 1;
                    coverage.totals.scanned += 1;
                    if options.scan_secrets {
                        let mut secret_scan = crate::secrets::scan_source(
                            &file.relative,
                            &source,
                            &CommentRanges::default(),
                            &secret_allowlist,
                        );
                        coverage.totals.secret_scanned += 1;
                        coverage.totals.secret_suppressed += secret_scan.suppressed;
                        evidence.append(&mut secret_scan.evidence);
                    }
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::Scanned,
                        reason: Some(
                            "specialized WebForms inline-output scan; no full ASPX parser"
                                .to_string(),
                        ),
                    });
                    evidence.append(&mut webforms_evidence);
                    security_paths.append(&mut webforms_paths);
                }
                Err(reason) => {
                    coverage.totals.secret_skipped += 1;
                    coverage.files.push(FileCoverage {
                        path: file.relative,
                        language: None,
                        status: FileStatus::SecretSkipped,
                        reason: Some(reason),
                    });
                }
            },
            FileClass::Supported(language) => {
                let source = match fs::read_to_string(&file.absolute) {
                    Ok(source) => source,
                    Err(error) => {
                        record_parse_failure(
                            &mut coverage,
                            &mut diagnostics,
                            file.relative,
                            language,
                            format!("source could not be read as UTF-8: {error}"),
                        );
                        continue;
                    }
                };
                if !options.include_tests
                    && is_generated_javascript_source(Path::new(&file.relative), &source)
                {
                    let reason = "generated or bundled frontend source excluded from SAST; secret scan retained";
                    if options.scan_secrets {
                        match read_secret_text(&file.absolute) {
                            Ok(secret_source) => {
                                let mut secret_scan = crate::secrets::scan_source(
                                    &file.relative,
                                    &secret_source,
                                    &CommentRanges::default(),
                                    &secret_allowlist,
                                );
                                coverage.totals.secret_scanned += 1;
                                coverage.totals.secret_suppressed += secret_scan.suppressed;
                                coverage.files.push(FileCoverage {
                                    path: file.relative,
                                    language: None,
                                    status: FileStatus::SecretScanned,
                                    reason: Some(reason.to_string()),
                                });
                                evidence.append(&mut secret_scan.evidence);
                            }
                            Err(secret_reason) => {
                                coverage.totals.secret_skipped += 1;
                                coverage.files.push(FileCoverage {
                                    path: file.relative,
                                    language: None,
                                    status: FileStatus::SecretSkipped,
                                    reason: Some(format!("{reason}; {secret_reason}")),
                                });
                            }
                        }
                    } else {
                        coverage.totals.ignored += 1;
                        coverage.files.push(FileCoverage {
                            path: file.relative,
                            language: None,
                            status: FileStatus::Ignored,
                            reason: Some(format!("{reason}; secret scanning disabled")),
                        });
                    }
                    continue;
                }
                coverage.languages.entry(language).or_default().discovered += 1;
                prepared.push(PreparedFile {
                    relative: file.relative,
                    language,
                    source,
                    build_symbols: file.build_symbols,
                });
            }
        }
    }
    let source_loading_and_secret_scan_microseconds = source_started.elapsed().as_micros();
    trace_scan_phase(
        "source_loading_and_secret_scan",
        source_loading_and_secret_scan_microseconds,
    );

    let project_symbols_started = Instant::now();
    let project_symbols = ProjectSymbolEnvironment::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let project_symbols_microseconds = project_symbols_started.elapsed().as_micros();
    trace_scan_phase("project_symbols", project_symbols_microseconds);
    let node_context_started = Instant::now();
    let node_context = NodeProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    )
    .with_pug_templates(
        node_pug_template_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str())),
    );
    let node_project_context_microseconds = node_context_started.elapsed().as_micros();
    trace_scan_phase("node_project_context", node_project_context_microseconds);
    let object_context_started = Instant::now();
    let object_input_context = ObjectInputProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let object_input_context_microseconds = object_context_started.elapsed().as_micros();
    trace_scan_phase("object_input_context", object_input_context_microseconds);
    let csharp_model_context_started = Instant::now();
    let csharp_model_context = CsharpModelProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let csharp_model_context_microseconds = csharp_model_context_started.elapsed().as_micros();
    trace_scan_phase("csharp_model_context", csharp_model_context_microseconds);
    let csharp_rpc_context_started = Instant::now();
    let csharp_rpc_context = CsharpRpcProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let csharp_rpc_context_microseconds = csharp_rpc_context_started.elapsed().as_micros();
    trace_scan_phase("csharp_rpc_context", csharp_rpc_context_microseconds);
    let java_project_context_started = Instant::now();
    let java_project_context = JavaProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let java_project_context_microseconds = java_project_context_started.elapsed().as_micros();
    trace_scan_phase("java_project_context", java_project_context_microseconds);
    let go_project_context_started = Instant::now();
    let go_project_context = GoProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let go_project_context_microseconds = go_project_context_started.elapsed().as_micros();
    trace_scan_phase("go_project_context", go_project_context_microseconds);
    let drogon_project_context_started = Instant::now();
    let drogon_project_context = DrogonProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let drogon_project_context_microseconds = drogon_project_context_started.elapsed().as_micros();
    trace_scan_phase(
        "drogon_project_context",
        drogon_project_context_microseconds,
    );
    let native_invalidation_context_started = Instant::now();
    let native_invalidation_context = NativeInvalidationProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let native_invalidation_context_microseconds =
        native_invalidation_context_started.elapsed().as_micros();
    trace_scan_phase(
        "native_invalidation_context",
        native_invalidation_context_microseconds,
    );
    let python_project_context_started = Instant::now();
    let python_project_context = PythonProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    )
    .with_templates(
        python_template_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str())),
    )
    .with_openapi(
        python_openapi_sources
            .iter()
            .map(|(path, source)| (path.as_str(), source.as_str())),
    );
    let python_project_context_microseconds = python_project_context_started.elapsed().as_micros();
    trace_scan_phase(
        "python_project_context",
        python_project_context_microseconds,
    );
    let rust_project_context = RustProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let php_project_context = super::php::PhpProjectContext::from_sources(
        prepared
            .iter()
            .map(|file| (file.relative.as_str(), file.language, file.source.as_str())),
    );
    let mut analysis_prepared = Vec::new();
    for file in prepared {
        if impact_plan.includes(&file.relative) {
            analysis_prepared.push(file);
        } else {
            coverage.totals.ignored += 1;
            coverage.files.push(FileCoverage {
                path: file.relative,
                language: Some(file.language),
                status: FileStatus::Ignored,
                reason: Some(
                    "outside impact scan scope; loaded only for project context".to_string(),
                ),
            });
        }
    }
    let file_analysis_started = Instant::now();
    let mut file_analysis = FileAnalysisProfile {
        files: specialized_files,
        ..FileAnalysisProfile::default()
    };
    let worker_count = resolve_worker_count(options.jobs, analysis_prepared.len())?;
    let outcomes = analyze_prepared_files(
        &analysis_prepared,
        &compiled,
        &project_symbols,
        &secret_allowlist,
        relations,
        &node_context,
        &object_input_context,
        &csharp_model_context,
        csharp_model_context.handoff_context(),
        &csharp_rpc_context,
        &java_project_context,
        &go_project_context,
        &drogon_project_context,
        &native_invalidation_context,
        &python_project_context,
        &rust_project_context,
        &php_project_context,
        &dotnet_project_context,
        options.scan_secrets,
        options.include_tests,
        worker_count,
    )?;
    for (file, outcome) in analysis_prepared.into_iter().zip(outcomes) {
        match outcome {
            ParseOutcome::Failed {
                reason,
                evidence: mut secret_evidence,
                secret_suppressed,
                timing,
            } => {
                add_file_timing(&mut file_analysis, timing);
                coverage.totals.secret_suppressed += secret_suppressed;
                coverage
                    .languages
                    .entry(file.language)
                    .or_default()
                    .evidence += secret_evidence.len();
                evidence.append(&mut secret_evidence);
                record_parse_failure(
                    &mut coverage,
                    &mut diagnostics,
                    file.relative,
                    file.language,
                    reason,
                );
            }
            ParseOutcome::Recovered {
                reason,
                evidence: mut file_evidence,
                security_paths: mut file_security_paths,
                secret_suppressed,
                timing,
            } => {
                add_file_timing(&mut file_analysis, timing);
                coverage.totals.secret_suppressed += secret_suppressed;
                coverage
                    .languages
                    .entry(file.language)
                    .or_default()
                    .evidence += file_evidence.len();
                evidence.append(&mut file_evidence);
                security_paths.append(&mut file_security_paths);
                record_parse_failure(
                    &mut coverage,
                    &mut diagnostics,
                    file.relative,
                    file.language,
                    reason,
                );
            }
            ParseOutcome::Parsed {
                evidence: mut file_evidence,
                security_paths: mut file_security_paths,
                secret_suppressed,
                timing,
            } => {
                add_file_timing(&mut file_analysis, timing);
                coverage.totals.secret_suppressed += secret_suppressed;
                coverage.totals.scanned += 1;
                let language_coverage = coverage.languages.entry(file.language).or_default();
                language_coverage.scanned += 1;
                language_coverage.evidence += file_evidence.len();
                coverage.files.push(FileCoverage {
                    path: file.relative,
                    language: Some(file.language),
                    status: FileStatus::Scanned,
                    reason: None,
                });
                evidence.append(&mut file_evidence);
                security_paths.append(&mut file_security_paths);
            }
        }
    }
    file_analysis.total_microseconds = file_analysis_started.elapsed().as_micros();
    trace_scan_phase("file_analysis", file_analysis.total_microseconds);

    let finalization_started = Instant::now();
    security_paths.extend(super::native_allocation::link_native_allocation_paths(
        &mut evidence,
    ));
    security_paths.extend(super::native_lifetime::link_native_lifetime_paths(
        &mut evidence,
    ));
    security_paths.extend(super::native_state::link_native_state_paths(&mut evidence));
    security_paths.extend(super::native_ownership::link_native_ownership_paths(
        &mut evidence,
    ));
    evidence.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then_with(|| {
                left.location
                    .start
                    .byte_offset
                    .cmp(&right.location.start.byte_offset)
            })
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    security_paths.sort_by(|left, right| left.id.cmp(&right.id));
    coverage.security_surfaces = security_surface_counts(&evidence);
    (coverage.cwe, coverage.producers) =
        cwe_coverage(rules, &evidence, &coverage.files, options.scan_secrets);
    let root = display_path(&discovery.root);
    let result = ScanResult {
        schema_version: SCHEMA_VERSION.to_string(),
        root,
        evidence,
        security_paths,
        coverage,
        impact_scope,
        diagnostics,
    };
    let finalization_microseconds = finalization_started.elapsed().as_micros();
    trace_scan_phase("finalization", finalization_microseconds);
    let profile = ScanProfile {
        total_microseconds: total_started.elapsed().as_micros(),
        discovery_microseconds,
        rule_compilation_microseconds,
        source_loading_and_secret_scan_microseconds,
        project_symbols_microseconds,
        node_project_context_microseconds,
        object_input_context_microseconds,
        csharp_model_context_microseconds,
        csharp_rpc_context_microseconds,
        java_project_context_microseconds,
        go_project_context_microseconds,
        drogon_project_context_microseconds,
        native_invalidation_context_microseconds,
        python_project_context_microseconds,
        worker_count,
        file_analysis,
        finalization_microseconds,
        ..ScanProfile::default()
    };
    Ok((result, profile))
}

#[allow(clippy::too_many_arguments)]
fn analyze_prepared_files(
    prepared: &[PreparedFile],
    compiled: &BTreeMap<Language, Vec<CompiledRule>>,
    project_symbols: &ProjectSymbolEnvironment,
    secret_allowlist: &crate::secrets::SecretAllowlist,
    relations: &[RelationContract],
    node_context: &NodeProjectContext,
    object_input_context: &ObjectInputProjectContext,
    csharp_model_context: &CsharpModelProjectContext,
    csharp_handoff_context: &CsharpHandoffProjectContext,
    csharp_rpc_context: &CsharpRpcProjectContext,
    java_project_context: &JavaProjectContext,
    go_project_context: &GoProjectContext,
    drogon_project_context: &DrogonProjectContext,
    native_invalidation_context: &NativeInvalidationProjectContext,
    python_project_context: &PythonProjectContext,
    rust_project_context: &RustProjectContext,
    php_project_context: &super::php::PhpProjectContext,
    dotnet_project_context: &DotnetProjectContext,
    scan_secrets: bool,
    include_nonproduction: bool,
    worker_count: usize,
) -> Result<Vec<ParseOutcome>, EngineError> {
    if prepared.is_empty() {
        return Ok(Vec::new());
    }
    if worker_count == 1 {
        return Ok(prepared
            .iter()
            .map(|file| {
                scan_prepared_file(
                    file,
                    compiled,
                    project_symbols,
                    secret_allowlist,
                    relations,
                    node_context,
                    object_input_context,
                    csharp_model_context,
                    csharp_handoff_context,
                    csharp_rpc_context,
                    java_project_context,
                    go_project_context,
                    drogon_project_context,
                    native_invalidation_context,
                    python_project_context,
                    rust_project_context,
                    php_project_context,
                    dotnet_project_context,
                    scan_secrets,
                    include_nonproduction,
                )
            })
            .collect());
    }

    let next = AtomicUsize::new(0);
    let mut indexed =
        thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let next = &next;
                handles.push(scope.spawn(move || {
                    let mut outcomes = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(file) = prepared.get(index) else {
                            break;
                        };
                        outcomes.push((
                            index,
                            scan_prepared_file(
                                file,
                                compiled,
                                project_symbols,
                                secret_allowlist,
                                relations,
                                node_context,
                                object_input_context,
                                csharp_model_context,
                                csharp_handoff_context,
                                csharp_rpc_context,
                                java_project_context,
                                go_project_context,
                                drogon_project_context,
                                native_invalidation_context,
                                python_project_context,
                                rust_project_context,
                                php_project_context,
                                dotnet_project_context,
                                scan_secrets,
                                include_nonproduction,
                            ),
                        ));
                    }
                    outcomes
                }));
            }
            let mut outcomes = Vec::with_capacity(prepared.len());
            for handle in handles {
                outcomes.extend(handle.join().map_err(|_| {
                    EngineError("parallel file-analysis worker panicked".to_string())
                })?);
            }
            Ok::<_, EngineError>(outcomes)
        })?;
    indexed.sort_by_key(|(index, _)| *index);
    Ok(indexed.into_iter().map(|(_, outcome)| outcome).collect())
}

#[allow(clippy::too_many_arguments)]
fn scan_prepared_file(
    file: &PreparedFile,
    compiled: &BTreeMap<Language, Vec<CompiledRule>>,
    project_symbols: &ProjectSymbolEnvironment,
    secret_allowlist: &crate::secrets::SecretAllowlist,
    relations: &[RelationContract],
    node_context: &NodeProjectContext,
    object_input_context: &ObjectInputProjectContext,
    csharp_model_context: &CsharpModelProjectContext,
    csharp_handoff_context: &CsharpHandoffProjectContext,
    csharp_rpc_context: &CsharpRpcProjectContext,
    java_project_context: &JavaProjectContext,
    go_project_context: &GoProjectContext,
    drogon_project_context: &DrogonProjectContext,
    native_invalidation_context: &NativeInvalidationProjectContext,
    python_project_context: &PythonProjectContext,
    rust_project_context: &RustProjectContext,
    php_project_context: &super::php::PhpProjectContext,
    dotnet_project_context: &DotnetProjectContext,
    scan_secrets: bool,
    include_nonproduction: bool,
) -> ParseOutcome {
    scan_source(
        &file.relative,
        &file.source,
        parser_language(file.language),
        file.language,
        compiled
            .get(&file.language)
            .expect("all languages are compiled"),
        ScanDependencies {
            project_symbols,
            secret_allowlist,
            scan_secrets,
            include_nonproduction,
            relations,
            node_context,
            object_input_context,
            csharp_model_context,
            csharp_handoff_context,
            csharp_rpc_context,
            java_project_context,
            go_project_context,
            drogon_project_context,
            native_invalidation_context,
            python_project_context,
            rust_project_context,
            php_project_context,
            dotnet_project_context,
            build_symbols: &file.build_symbols,
        },
    )
}

fn resolve_worker_count(requested: Option<usize>, files: usize) -> Result<usize, EngineError> {
    if requested == Some(0) {
        return Err(EngineError(
            "scan worker count must be at least 1".to_string(),
        ));
    }
    let available = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(MAX_AUTOMATIC_WORKERS);
    Ok(requested.unwrap_or(available).min(files.max(1)))
}

fn add_file_timing(
    aggregate: &mut FileAnalysisProfile,
    timing: crate::code::matcher::FileScanTiming,
) {
    aggregate.files += 1;
    aggregate.parse_context_microseconds += timing.parse_context_microseconds;
    aggregate.declarative_rules_microseconds += timing.declarative_rules_microseconds;
    aggregate.symbol_rules_microseconds += timing.symbol_rules_microseconds;
    aggregate.summaries_microseconds += timing.summaries_microseconds;
    aggregate.security_paths_microseconds += timing.security_paths_microseconds;
    aggregate.declarative_patterns_considered += timing.declarative_patterns_considered;
    aggregate.declarative_patterns_skipped += timing.declarative_patterns_skipped;
    aggregate.declarative_patterns_executed = aggregate
        .declarative_patterns_considered
        .saturating_sub(aggregate.declarative_patterns_skipped);
}

struct PreparedFile {
    relative: String,
    language: Language,
    source: String,
    build_symbols: BTreeMap<String, bool>,
}

pub(crate) fn read_secret_text(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("metadata unavailable: {error}"))?;
    if metadata.len() > MAX_SECRET_TEXT_BYTES {
        return Err(format!(
            "secret scan size limit exceeded: {} bytes is greater than {MAX_SECRET_TEXT_BYTES}",
            metadata.len()
        ));
    }
    let bytes =
        fs::read(path).map_err(|error| format!("secret text could not be read: {error}"))?;
    if bytes.len() as u64 > MAX_SECRET_TEXT_BYTES {
        return Err(format!(
            "secret scan size limit exceeded after read: {} bytes is greater than {MAX_SECRET_TEXT_BYTES}",
            bytes.len()
        ));
    }
    if looks_binary(&bytes) {
        return Err("binary content detected".to_string());
    }
    String::from_utf8(bytes).map_err(|error| format!("secret text is not UTF-8: {error}"))
}

fn looks_binary(bytes: &[u8]) -> bool {
    if bytes.contains(&0) {
        return true;
    }
    let controls = bytes
        .iter()
        .filter(|byte| **byte < 0x20 && !matches!(**byte, b'\n' | b'\r' | b'\t'))
        .count();
    controls > 0 && controls * 100 > bytes.len().max(1)
}

fn record_parse_failure(
    coverage: &mut Coverage,
    diagnostics: &mut Vec<Diagnostic>,
    path: String,
    language: Language,
    reason: String,
) {
    coverage.totals.parse_failed += 1;
    coverage.languages.entry(language).or_default().parse_failed += 1;
    coverage.files.push(FileCoverage {
        path: path.clone(),
        language: Some(language),
        status: FileStatus::ParseFailed,
        reason: Some(reason.clone()),
    });
    diagnostics.push(Diagnostic {
        level: DiagnosticLevel::Warning,
        message: reason,
        path: Some(path),
    });
}

fn security_surface_counts(evidence: &[mehscan_core::Evidence]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for item in evidence {
        let name = capability_name(item.capability).to_string();
        *counts.entry(name).or_default() += 1;
    }
    counts
}

fn capability_name(capability: Capability) -> &'static str {
    match capability {
        Capability::ProcessExecution => "process_execution",
        Capability::ProcessArgumentSeparation => "process_argument_separation",
        Capability::LdapQuery => "ldap_query",
        Capability::XpathQuery => "xpath_query",
        Capability::LdapFilterEncoding => "ldap_filter_encoding",
        Capability::LdapDistinguishedNameEncoding => "ldap_distinguished_name_encoding",
        Capability::DynamicCodeExecution => "dynamic_code_execution",
        Capability::DynamicCodeRestriction => "dynamic_code_restriction",
        Capability::TemplateEvaluation => "template_evaluation",
        Capability::DatabaseQuery => "database_query",
        Capability::SqlParameterization => "sql_parameterization",
        Capability::FilesystemRead => "filesystem_read",
        Capability::FilesystemWrite => "filesystem_write",
        Capability::PathCanonicalization => "path_canonicalization",
        Capability::PathContainmentCheck => "path_containment_check",
        Capability::OutboundNetworkRequest => "outbound_network_request",
        Capability::UrlParsing => "url_parsing",
        Capability::UrlDestinationValidation => "url_destination_validation",
        Capability::Redirect => "redirect",
        Capability::RedirectDestinationValidation => "redirect_destination_validation",
        Capability::HtmlOutput => "html_output",
        Capability::HtmlEncoding => "html_encoding",
        Capability::HttpHeaderOutput => "http_header_output",
        Capability::Serialization => "serialization",
        Capability::Deserialization => "deserialization",
        Capability::DeserializationRestriction => "deserialization_restriction",
        Capability::XmlParsing => "xml_parsing",
        Capability::CryptographicHash => "cryptographic_hash",
        Capability::FixedFormatTransform => "fixed_format_transform",
        Capability::CryptographicEncryption => "cryptographic_encryption",
        Capability::RandomGeneration => "random_generation",
        Capability::Authentication => "authentication",
        Capability::Authorization => "authorization",
        Capability::ResourceAccess => "resource_access",
        Capability::Logging => "logging",
        Capability::TokenGeneration => "token_generation",
        Capability::CookieConfiguration => "cookie_configuration",
        Capability::CorsConfiguration => "cors_configuration",
        Capability::BufferWrite => "buffer_write",
        Capability::BufferCapacityValidation => "buffer_capacity_validation",
        Capability::StringTerminationValidation => "string_termination_validation",
        Capability::SignedSizeConversion => "signed_size_conversion",
        Capability::SignedSizeMemoryOperation => "signed_size_memory_operation",
        Capability::NonnegativeSizeValidation => "nonnegative_size_validation",
        Capability::LocalHeapAllocation => "local_heap_allocation",
        Capability::LocalHeapDeallocation => "local_heap_deallocation",
        Capability::EarlyExitDeallocation => "early_exit_deallocation",
        Capability::CppHeapAllocation => "cpp_heap_allocation",
        Capability::CppHeapDeallocation => "cpp_heap_deallocation",
        Capability::CppAllocationFamilyValidation => "cpp_allocation_family_validation",
        Capability::CppRaiiOwner => "cpp_raii_owner",
        Capability::CppOwnershipTransfer => "cpp_ownership_transfer",
        Capability::IntegerNarrowing => "integer_narrowing",
        Capability::ArithmeticDivision => "arithmetic_division",
        Capability::NonzeroValidation => "nonzero_validation",
        Capability::InputQuantity => "input_quantity",
        Capability::DomainLimitComputation => "domain_limit_computation",
        Capability::DomainLimitValidation => "domain_limit_validation",
        Capability::CountControlledMemoryOperation => "count_controlled_memory_operation",
        Capability::IntegerWidthConstraint => "integer_width_constraint",
        Capability::ArithmeticMultiplication => "arithmetic_multiplication",
        Capability::MultiplicationOverflowValidation => "multiplication_overflow_validation",
        Capability::ArchitectureSizeInput => "architecture_size_input",
        Capability::AllocationSizeComputation => "allocation_size_computation",
        Capability::ArchitectureSizeValidation => "architecture_size_validation",
        Capability::StackAddressEscape => "stack_address_escape",
        Capability::LifetimeCallbackHandoff => "lifetime_callback_handoff",
        Capability::PostReturnDereference => "post_return_dereference",
        Capability::StackLifetimeRestoration => "stack_lifetime_restoration",
        Capability::InvalidatingReturnContract => "invalidating_return_contract",
        Capability::PostInvalidationUse => "post_invalidation_use",
        Capability::InvalidationStatusValidation => "invalidation_status_validation",
        Capability::SerializedBlobLoad => "serialized_blob_load",
        Capability::SerializedBlobCopy => "serialized_blob_copy",
        Capability::SerializedBlobLengthValidation => "serialized_blob_length_validation",
        Capability::SerializedScalarLoad => "serialized_scalar_load",
        Capability::LoadedMemoryExtent => "loaded_memory_extent",
        Capability::MemoryExtentOverflowValidation => "memory_extent_overflow_validation",
        Capability::DecodedInputExtent => "decoded_input_extent",
        Capability::RemainingInputRead => "remaining_input_read",
        Capability::RemainingInputValidation => "remaining_input_validation",
        Capability::RequiredStateInitialization => "required_state_initialization",
        Capability::StatePointerHandoff => "state_pointer_handoff",
        Capability::StateDependentDereference => "state_dependent_dereference",
        Capability::FatalStateInvariantValidation => "fatal_state_invariant_validation",
        Capability::OwnedResourceAllocation => "owned_resource_allocation",
        Capability::OwnershipFlagRegistration => "ownership_flag_registration",
        Capability::OwnershipGatedRelease => "ownership_gated_release",
        Capability::FormatStringOutput => "format_string_output",
        Capability::MemorySafetyBoundary => "memory_safety_boundary",
        Capability::NativeInteropBoundary => "native_interop_boundary",
        Capability::TlsConfiguration => "tls_configuration",
        Capability::FileUpload => "file_upload",
        Capability::UploadedFileContent => "uploaded_file_content",
        Capability::UploadedFilePath => "uploaded_file_path",
        Capability::ArchiveEntryPath => "archive_entry_path",
        Capability::UploadedFilenameValidation => "uploaded_filename_validation",
        Capability::StoredUserContent => "stored_user_content",
        Capability::HttpRequestHandling => "http_request_handling",
        Capability::HttpRequestData => "http_request_data",
        Capability::RpcRequestData => "rpc_request_data",
        Capability::BrowserInput => "browser_input",
        Capability::BrowserNavigation => "browser_navigation",
        Capability::BrowserCredentialedRequest => "browser_credentialed_request",
        Capability::BrowserMessageSend => "browser_message_send",
        Capability::ExternalInput => "external_input",
        Capability::ModelToolInput => "model_tool_input",
        Capability::CredentialMaterial => "credential_material",
    }
}

fn cwe_coverage(
    rules: &[Rule],
    evidence: &[Evidence],
    files: &[FileCoverage],
    secret_scanning_enabled: bool,
) -> (Vec<CweCoverage>, ProducerCoverage) {
    let mut declarative: BTreeMap<String, BTreeSet<Language>> = BTreeMap::new();
    for rule in rules {
        for cwe in &rule.cwe {
            declarative
                .entry(cwe.clone())
                .or_default()
                .insert(rule.language);
        }
    }
    let declarative_rule_ids = rules
        .iter()
        .map(|rule| rule.id.as_str())
        .collect::<BTreeSet<_>>();
    let file_languages = files
        .iter()
        .filter_map(|file| file.language.map(|language| (file.path.as_str(), language)))
        .collect::<BTreeMap<_, _>>();
    let mut observed_procedural: BTreeMap<String, BTreeSet<Language>> = BTreeMap::new();
    let mut producer_coverage = ProducerCoverage {
        loaded_declarative_rules: rules.len(),
        ..ProducerCoverage::default()
    };
    for item in evidence {
        if declarative_rule_ids.contains(item.rule_id.as_str()) {
            continue;
        }
        producer_coverage.observed_procedural_evidence += 1;
        let language = file_languages
            .get(item.location.path.as_str())
            .copied()
            .or_else(|| language_from_path(&item.location.path));
        let Some(language) = language else {
            producer_coverage.unattributed_procedural_evidence += 1;
            continue;
        };
        for cwe in &item.cwe_candidates {
            observed_procedural
                .entry(cwe.clone())
                .or_default()
                .insert(language);
        }
    }

    let mut cwes = declarative
        .keys()
        .chain(observed_procedural.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    if secret_scanning_enabled {
        cwes.insert("CWE-798".to_string());
    }
    let coverage = cwes
        .into_iter()
        .map(|cwe| {
            let declarative_languages = declarative
                .remove(&cwe)
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            let observed_procedural_languages = observed_procedural
                .remove(&cwe)
                .unwrap_or_default()
                .into_iter()
                .collect::<Vec<_>>();
            let mut supported_languages = declarative_languages
                .iter()
                .chain(&observed_procedural_languages)
                .copied()
                .collect::<BTreeSet<_>>();
            let language_independent = cwe == "CWE-798" && secret_scanning_enabled;
            if language_independent {
                supported_languages.extend(all_languages());
            }
            CweCoverage {
                cwe,
                level: CweSupportLevel::Partial,
                declarative_languages,
                observed_procedural_languages,
                supported_languages: supported_languages.into_iter().collect(),
                language_independent,
            }
        })
        .collect();
    (coverage, producer_coverage)
}

fn language_from_path(path: &str) -> Option<Language> {
    let extension = Path::new(path).extension()?.to_str()?.to_ascii_lowercase();
    match extension.as_str() {
        "c" | "h" => Some(Language::C),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Some(Language::Cpp),
        "cs" | "cshtml" | "aspx" | "ascx" => Some(Language::Csharp),
        "java" => Some(Language::Java),
        "kt" | "kts" => Some(Language::Kotlin),
        "js" | "mjs" | "cjs" => Some(Language::Javascript),
        "ts" => Some(Language::Typescript),
        "tsx" => Some(Language::Tsx),
        "py" => Some(Language::Python),
        "php" => Some(Language::Php),
        "go" => Some(Language::Go),
        "rs" => Some(Language::Rust),
        _ => None,
    }
}

fn all_languages() -> [Language; 12] {
    [
        Language::C,
        Language::Cpp,
        Language::Csharp,
        Language::Java,
        Language::Kotlin,
        Language::Javascript,
        Language::Typescript,
        Language::Tsx,
        Language::Python,
        Language::Php,
        Language::Go,
        Language::Rust,
    ]
}

fn display_path(path: &Path) -> String {
    let value = path.to_string_lossy();
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(&value)
        .replace('\\', "/")
}
