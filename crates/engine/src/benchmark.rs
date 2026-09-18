//! Checked-in benchmark manifests for deterministic SAST coverage measurement.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use mehscan_core::{
    Capability, Language, ScanResult, SecurityPath, SecurityPathState, SecurityPathStepKind,
};
use serde::{Deserialize, Serialize};

use crate::{EngineError, scan_path};

const LANGUAGES: [Language; 7] = [
    Language::Csharp,
    Language::Java,
    Language::Javascript,
    Language::Typescript,
    Language::Tsx,
    Language::Python,
    Language::Go,
];

#[derive(Clone, Debug, Deserialize)]
pub struct BenchmarkManifest {
    pub version: u32,
    #[serde(default)]
    pub profiles: BTreeMap<String, LanguageExpectation>,
    pub cases: Vec<BenchmarkCase>,
    #[serde(default)]
    pub optional_corpora: Vec<OptionalCorpus>,
    #[serde(default)]
    pub known_unsupported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BenchmarkCase {
    pub id: String,
    pub fixture: String,
    pub source_capability: Capability,
    #[serde(default)]
    pub additional_source_capabilities: Vec<Capability>,
    pub sink_capabilities: Vec<Capability>,
    pub cwe_candidates: Vec<String>,
    #[serde(default = "default_maximum_propagation_depth")]
    pub maximum_propagation_depth: usize,
    pub expected: CaseExpectation,
    #[serde(default)]
    pub known_unsupported: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CaseExpectation {
    pub scanned: usize,
    pub parse_failed: usize,
    #[serde(default = "default_true")]
    pub deterministic: bool,
    pub languages: BTreeMap<Language, LanguageExpectation>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LanguageExpectation {
    pub positive_sources: usize,
    pub positive_sinks: usize,
    pub negative_sinks: usize,
    pub direct_paths: usize,
    pub propagated_paths: usize,
    pub protected_paths: usize,
    pub unknown_paths: usize,
    pub negative_paths: usize,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OptionalCorpus {
    pub id: String,
    pub root: String,
    pub expected: CorpusExpectation,
    #[serde(default)]
    pub known_unsupported: Vec<String>,
    #[serde(default)]
    pub truth_cases: Vec<CorpusTruthCase>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CorpusTruthCase {
    pub id: String,
    pub file: String,
    pub line: usize,
    pub cwe: String,
    pub capability: Capability,
    #[serde(default)]
    pub source_line: Option<usize>,
    #[serde(default)]
    pub source_column: Option<usize>,
    pub disposition: TruthDisposition,
    pub expected_paths: usize,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruthDisposition {
    Vulnerable,
    Safe,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CorpusExpectation {
    pub discovered: usize,
    pub scanned: usize,
    pub secret_scanned: usize,
    pub ignored: usize,
    pub unsupported: usize,
    pub parse_failed: usize,
    pub evidence: usize,
    pub security_paths: usize,
    #[serde(default)]
    pub capability_evidence: BTreeMap<Capability, usize>,
    #[serde(default)]
    pub path_cwes: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BenchmarkReport {
    pub manifest_version: u32,
    pub passed: bool,
    pub optional_corpora_included: bool,
    pub cases: Vec<CaseReport>,
    pub optional_corpora: Vec<CorpusReport>,
    pub known_unsupported: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseReport {
    pub id: String,
    pub fixture: String,
    pub passed: bool,
    pub elapsed_milliseconds: u128,
    pub actual: CaseActual,
    pub mismatches: Vec<String>,
    pub known_unsupported: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaseActual {
    pub scanned: usize,
    pub parse_failed: usize,
    pub deterministic: bool,
    pub languages: BTreeMap<Language, LanguageExpectation>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CorpusReport {
    pub id: String,
    pub root: String,
    pub passed: bool,
    pub elapsed_milliseconds: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<CorpusExpectation>,
    pub mismatches: Vec<String>,
    pub known_unsupported: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truth: Option<CorpusTruthReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorpusTruthReport {
    pub cases: usize,
    pub vulnerable_cases: usize,
    pub safe_cases: usize,
    pub true_positives: usize,
    pub false_negatives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub recall_basis_points: u32,
    pub precision_basis_points: u32,
    pub baseline_matched: bool,
    pub results: Vec<CorpusTruthResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CorpusTruthResult {
    pub id: String,
    pub file: String,
    pub line: usize,
    pub cwe: String,
    pub capability: Capability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_column: Option<usize>,
    pub disposition: TruthDisposition,
    pub expected_paths: usize,
    pub observed_paths: usize,
    pub classification: TruthClassification,
    pub baseline_matched: bool,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TruthClassification {
    TruePositive,
    FalseNegative,
    FalsePositive,
    TrueNegative,
}

pub fn run_manifest(
    workspace_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
    include_optional_corpora: bool,
) -> Result<BenchmarkReport, EngineError> {
    let workspace_root = fs::canonicalize(workspace_root.as_ref()).map_err(|error| {
        EngineError(format!(
            "benchmark workspace root could not be resolved: {error}"
        ))
    })?;
    let manifest_path = resolve_beneath(&workspace_root, manifest_path.as_ref())?;
    let source = fs::read_to_string(&manifest_path).map_err(|error| {
        EngineError(format!(
            "benchmark manifest {} could not be read: {error}",
            manifest_path.display()
        ))
    })?;
    let manifest: BenchmarkManifest = serde_yaml::from_str(&source).map_err(|error| {
        EngineError(format!(
            "benchmark manifest {} is invalid: {error}",
            manifest_path.display()
        ))
    })?;
    validate_manifest(&manifest)?;

    let mut cases = Vec::with_capacity(manifest.cases.len());
    for case in &manifest.cases {
        let fixture = resolve_beneath(&workspace_root, Path::new(&case.fixture))?;
        cases.push(run_case(case, &fixture)?);
    }

    let mut optional_corpora = Vec::new();
    if include_optional_corpora {
        for corpus in &manifest.optional_corpora {
            optional_corpora.push(run_optional_corpus(corpus, &workspace_root)?);
        }
    }

    let passed =
        cases.iter().all(|case| case.passed) && optional_corpora.iter().all(|corpus| corpus.passed);
    Ok(BenchmarkReport {
        manifest_version: manifest.version,
        passed,
        optional_corpora_included: include_optional_corpora,
        cases,
        optional_corpora,
        known_unsupported: manifest.known_unsupported,
    })
}

fn run_case(case: &BenchmarkCase, fixture: &Path) -> Result<CaseReport, EngineError> {
    let started = Instant::now();
    let result = scan_path(fixture)?;
    let elapsed_milliseconds = started.elapsed().as_millis();
    let repeated = scan_path(fixture)?;
    let deterministic = result.evidence == repeated.evidence
        && result.security_paths == repeated.security_paths
        && result.coverage == repeated.coverage;
    let actual = measure_case(case, &result, deterministic);
    let mut mismatches = compare_case(case, &actual);
    validate_selected_paths(case, &result, &mut mismatches);
    Ok(CaseReport {
        id: case.id.clone(),
        fixture: case.fixture.clone(),
        passed: mismatches.is_empty(),
        elapsed_milliseconds,
        actual,
        mismatches,
        known_unsupported: case.known_unsupported.clone(),
    })
}

fn measure_case(case: &BenchmarkCase, result: &ScanResult, deterministic: bool) -> CaseActual {
    let mut languages = LANGUAGES
        .into_iter()
        .map(|language| (language, LanguageExpectation::default()))
        .collect::<BTreeMap<_, _>>();

    for evidence in &result.evidence {
        let Some(language) = language_for_path(&evidence.location.path) else {
            continue;
        };
        let measurements = languages.get_mut(&language).expect("language initialized");
        if evidence.location.path.starts_with("positive/") {
            if accepts_source_capability(case, evidence.capability) {
                measurements.positive_sources += 1;
            }
            if case.sink_capabilities.contains(&evidence.capability) {
                measurements.positive_sinks += 1;
            }
        } else if evidence.location.path.starts_with("negative/")
            && case.sink_capabilities.contains(&evidence.capability)
        {
            measurements.negative_sinks += 1;
        }
    }

    for path in selected_paths(case, result) {
        let Some(sink_path) = path.steps.last().map(|step| step.location.path.as_str()) else {
            continue;
        };
        let Some(language) = language_for_path(sink_path) else {
            continue;
        };
        let measurements = languages.get_mut(&language).expect("language initialized");
        match path.state {
            SecurityPathState::Direct => measurements.direct_paths += 1,
            SecurityPathState::Propagated => measurements.propagated_paths += 1,
            SecurityPathState::Protected => measurements.protected_paths += 1,
            SecurityPathState::Unknown => measurements.unknown_paths += 1,
        }
        if path
            .steps
            .iter()
            .any(|step| step.location.path.starts_with("negative/"))
        {
            measurements.negative_paths += 1;
        }
    }

    CaseActual {
        scanned: result.coverage.totals.scanned,
        parse_failed: result.coverage.totals.parse_failed,
        deterministic,
        languages,
    }
}

fn compare_case(case: &BenchmarkCase, actual: &CaseActual) -> Vec<String> {
    let expected = &case.expected;
    let mut mismatches = Vec::new();
    if actual.scanned != expected.scanned {
        mismatches.push(format!(
            "scanned files: expected {}, observed {}",
            expected.scanned, actual.scanned
        ));
    }
    if actual.parse_failed != expected.parse_failed {
        mismatches.push(format!(
            "parse failures: expected {}, observed {}",
            expected.parse_failed, actual.parse_failed
        ));
    }
    if actual.deterministic != expected.deterministic {
        mismatches.push(format!(
            "deterministic rescan: expected {}, observed {}",
            expected.deterministic, actual.deterministic
        ));
    }
    for language in LANGUAGES {
        let expected_language = expected
            .languages
            .get(&language)
            .expect("manifest validation requires every language");
        let actual_language = actual
            .languages
            .get(&language)
            .expect("measurement initializes every language");
        if actual_language != expected_language {
            mismatches.push(format!(
                "{language:?}: expected {expected_language:?}, observed {actual_language:?}"
            ));
        }
    }
    mismatches
}

fn validate_selected_paths(
    case: &BenchmarkCase,
    result: &ScanResult,
    mismatches: &mut Vec<String>,
) {
    let evidence = result
        .evidence
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    for path in selected_paths(case, result) {
        let Some(source) = evidence.get(path.source_evidence_id.as_str()) else {
            mismatches.push(format!("{} references a missing source", path.id));
            continue;
        };
        let Some(sink) = evidence.get(path.sink_evidence_id.as_str()) else {
            mismatches.push(format!("{} references a missing sink", path.id));
            continue;
        };
        if !accepts_source_capability(case, source.capability) {
            mismatches.push(format!("{} has the wrong source capability", path.id));
        }
        if !case.sink_capabilities.contains(&sink.capability) {
            mismatches.push(format!("{} has the wrong sink capability", path.id));
        }
        if path.capability != sink.capability {
            mismatches.push(format!("{} does not match its sink capability", path.id));
        }
        if path.provenance.maximum_propagation_depth != case.maximum_propagation_depth {
            mismatches.push(format!("{} has an unexpected propagation bound", path.id));
        }
        let first = path.steps.first();
        let last = path.steps.last();
        if first.map(|step| step.kind) != Some(SecurityPathStepKind::Source)
            || last.map(|step| step.kind) != Some(SecurityPathStepKind::Sink)
        {
            mismatches.push(format!("{} has invalid terminal steps", path.id));
        }
        if first.is_some_and(|step| {
            step.evidence_id.as_deref() != Some(source.id.as_str())
                || step.location != source.location
        }) {
            mismatches.push(format!("{} has an inconsistent source step", path.id));
        }
        if last.is_some_and(|step| {
            step.evidence_id.as_deref() != Some(sink.id.as_str()) || step.location != sink.location
        }) {
            mismatches.push(format!("{} has an inconsistent sink step", path.id));
        }
        let protection_steps = path
            .steps
            .iter()
            .filter(|step| step.kind == SecurityPathStepKind::Protection)
            .filter_map(|step| step.evidence_id.as_deref())
            .collect::<Vec<_>>();
        let protection_ids = path
            .protection_evidence_ids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if protection_steps != protection_ids
            || protection_ids
                .iter()
                .any(|evidence_id| !evidence.contains_key(evidence_id))
        {
            mismatches.push(format!("{} has inconsistent protection links", path.id));
        }
    }
}

fn accepts_source_capability(case: &BenchmarkCase, capability: Capability) -> bool {
    capability == case.source_capability
        || case.additional_source_capabilities.contains(&capability)
}

fn selected_paths<'a>(
    case: &'a BenchmarkCase,
    result: &'a ScanResult,
) -> impl Iterator<Item = &'a SecurityPath> {
    result.security_paths.iter().filter(|path| {
        case.sink_capabilities.contains(&path.capability)
            && path.cwe_candidates == case.cwe_candidates
    })
}

fn run_optional_corpus(
    corpus: &OptionalCorpus,
    workspace_root: &Path,
) -> Result<CorpusReport, EngineError> {
    let relative = Path::new(&corpus.root);
    let resolved = match resolve_beneath(workspace_root, relative) {
        Ok(path) => path,
        Err(error) => {
            return Ok(CorpusReport {
                id: corpus.id.clone(),
                root: corpus.root.clone(),
                passed: false,
                elapsed_milliseconds: 0,
                actual: None,
                mismatches: vec![error.to_string()],
                known_unsupported: corpus.known_unsupported.clone(),
                truth: None,
            });
        }
    };
    let started = Instant::now();
    let result = scan_path(resolved)?;
    let elapsed_milliseconds = started.elapsed().as_millis();
    let actual = measure_corpus(&result, &corpus.expected);
    let truth = measure_corpus_truth(&result, &corpus.truth_cases);
    let mut mismatches = if actual == corpus.expected {
        Vec::new()
    } else {
        vec![format!(
            "corpus baseline differs: expected {:?}, observed {:?}",
            corpus.expected, actual
        )]
    };
    mismatches.extend(
        truth
            .results
            .iter()
            .filter(|result| !result.baseline_matched)
            .map(|result| {
                format!(
                    "truth case {}: expected {} paths, observed {}",
                    result.id, result.expected_paths, result.observed_paths
                )
            }),
    );
    Ok(CorpusReport {
        id: corpus.id.clone(),
        root: corpus.root.clone(),
        passed: mismatches.is_empty(),
        elapsed_milliseconds,
        actual: Some(actual),
        mismatches,
        known_unsupported: corpus.known_unsupported.clone(),
        truth: Some(truth),
    })
}

fn measure_corpus_truth(scan: &ScanResult, cases: &[CorpusTruthCase]) -> CorpusTruthReport {
    let results = cases
        .iter()
        .map(|case| {
            let file = normalize_relative(&case.file);
            let observed_paths = scan
                .security_paths
                .iter()
                .filter(|path| {
                    path.capability == case.capability
                        && path.cwe_candidates.iter().any(|cwe| cwe == &case.cwe)
                        && path.steps.first().is_some_and(|step| {
                            case.source_line
                                .is_none_or(|line| step.location.start.line == line)
                                && case
                                    .source_column
                                    .is_none_or(|column| step.location.start.column == column)
                        })
                        && path.steps.last().is_some_and(|step| {
                            normalize_relative(&step.location.path) == file
                                && step.location.start.line <= case.line
                                && step.location.end.line >= case.line
                        })
                })
                .count();
            let detected = observed_paths > 0;
            let classification = match (case.disposition, detected) {
                (TruthDisposition::Vulnerable, true) => TruthClassification::TruePositive,
                (TruthDisposition::Vulnerable, false) => TruthClassification::FalseNegative,
                (TruthDisposition::Safe, true) => TruthClassification::FalsePositive,
                (TruthDisposition::Safe, false) => TruthClassification::TrueNegative,
            };
            CorpusTruthResult {
                id: case.id.clone(),
                file,
                line: case.line,
                cwe: case.cwe.clone(),
                capability: case.capability,
                source_line: case.source_line,
                source_column: case.source_column,
                disposition: case.disposition,
                expected_paths: case.expected_paths,
                observed_paths,
                classification,
                baseline_matched: observed_paths == case.expected_paths,
                reason: case.reason.clone(),
            }
        })
        .collect::<Vec<_>>();
    let true_positives = count_truth_classification(&results, TruthClassification::TruePositive);
    let false_negatives = count_truth_classification(&results, TruthClassification::FalseNegative);
    let false_positives = count_truth_classification(&results, TruthClassification::FalsePositive);
    CorpusTruthReport {
        cases: results.len(),
        vulnerable_cases: results
            .iter()
            .filter(|result| result.disposition == TruthDisposition::Vulnerable)
            .count(),
        safe_cases: results
            .iter()
            .filter(|result| result.disposition == TruthDisposition::Safe)
            .count(),
        true_positives,
        false_negatives,
        false_positives,
        true_negatives: count_truth_classification(&results, TruthClassification::TrueNegative),
        recall_basis_points: ratio_basis_points(true_positives, true_positives + false_negatives),
        precision_basis_points: ratio_basis_points(
            true_positives,
            true_positives + false_positives,
        ),
        baseline_matched: results.iter().all(|result| result.baseline_matched),
        results,
    }
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }
    u32::try_from(numerator.saturating_mul(10_000) / denominator).unwrap_or(10_000)
}

fn count_truth_classification(
    results: &[CorpusTruthResult],
    classification: TruthClassification,
) -> usize {
    results
        .iter()
        .filter(|result| result.classification == classification)
        .count()
}

fn measure_corpus(result: &ScanResult, expected: &CorpusExpectation) -> CorpusExpectation {
    let capability_evidence = expected
        .capability_evidence
        .keys()
        .copied()
        .map(|capability| {
            let count = result
                .evidence
                .iter()
                .filter(|item| item.capability == capability)
                .count();
            (capability, count)
        })
        .collect();
    let mut path_cwes = BTreeMap::new();
    for path in &result.security_paths {
        for cwe in &path.cwe_candidates {
            *path_cwes.entry(cwe.clone()).or_insert(0) += 1;
        }
    }
    CorpusExpectation {
        discovered: result.coverage.totals.discovered,
        scanned: result.coverage.totals.scanned,
        secret_scanned: result.coverage.totals.secret_scanned,
        ignored: result.coverage.totals.ignored,
        unsupported: result.coverage.totals.unsupported,
        parse_failed: result.coverage.totals.parse_failed,
        evidence: result.evidence.len(),
        security_paths: result.security_paths.len(),
        capability_evidence,
        path_cwes,
    }
}

fn validate_manifest(manifest: &BenchmarkManifest) -> Result<(), EngineError> {
    if manifest.version != 1 {
        return Err(EngineError(format!(
            "unsupported benchmark manifest version {}",
            manifest.version
        )));
    }
    if manifest.cases.is_empty() {
        return Err(EngineError(
            "benchmark manifest must contain at least one case".to_string(),
        ));
    }
    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
        if case.id.trim().is_empty() || !ids.insert(case.id.as_str()) {
            return Err(EngineError(format!(
                "benchmark case ids must be non-empty and unique: {:?}",
                case.id
            )));
        }
        if case.sink_capabilities.is_empty() || case.cwe_candidates.is_empty() {
            return Err(EngineError(format!(
                "benchmark case {} must declare sinks and CWE candidates",
                case.id
            )));
        }
        let mut source_capabilities = BTreeSet::from([case.source_capability]);
        if case
            .additional_source_capabilities
            .iter()
            .any(|capability| !source_capabilities.insert(*capability))
        {
            return Err(EngineError(format!(
                "benchmark case {} contains duplicate source capabilities",
                case.id
            )));
        }
        for language in LANGUAGES {
            if !case.expected.languages.contains_key(&language) {
                return Err(EngineError(format!(
                    "benchmark case {} is missing {language:?} expectations",
                    case.id
                )));
            }
        }
        if case.expected.languages.len() != LANGUAGES.len() {
            return Err(EngineError(format!(
                "benchmark case {} contains an unsupported language expectation",
                case.id
            )));
        }
    }
    for corpus in &manifest.optional_corpora {
        if corpus.id.trim().is_empty() || !ids.insert(corpus.id.as_str()) {
            return Err(EngineError(format!(
                "benchmark ids must be non-empty and unique: {:?}",
                corpus.id
            )));
        }
        let mut truth_ids = BTreeSet::new();
        for truth in &corpus.truth_cases {
            if truth.id.trim().is_empty()
                || !truth_ids.insert(truth.id.as_str())
                || truth.file.trim().is_empty()
                || truth.line == 0
                || truth.cwe.trim().is_empty()
                || truth.reason.trim().is_empty()
                || truth.source_line == Some(0)
                || truth.source_column == Some(0)
            {
                return Err(EngineError(format!(
                    "optional corpus {} has an invalid truth case {:?}",
                    corpus.id, truth.id
                )));
            }
        }
    }
    Ok(())
}

fn resolve_beneath(workspace_root: &Path, relative: &Path) -> Result<PathBuf, EngineError> {
    let candidate = if relative.is_absolute() {
        relative.to_path_buf()
    } else {
        workspace_root.join(relative)
    };
    let resolved = fs::canonicalize(candidate).map_err(|error| {
        EngineError(format!(
            "benchmark path {} could not be resolved: {error}",
            relative.display()
        ))
    })?;
    if !resolved.starts_with(workspace_root) {
        return Err(EngineError(format!(
            "benchmark path escapes the workspace: {}",
            relative.display()
        )));
    }
    Ok(resolved)
}

fn language_for_path(path: &str) -> Option<Language> {
    let path = path.to_ascii_lowercase();
    if path.ends_with(".cs") {
        Some(Language::Csharp)
    } else if path.ends_with(".java") {
        Some(Language::Java)
    } else if path.ends_with(".kt") || path.ends_with(".kts") {
        Some(Language::Kotlin)
    } else if path.ends_with(".tsx") {
        Some(Language::Tsx)
    } else if path.ends_with(".ts") {
        Some(Language::Typescript)
    } else if path.ends_with(".js") {
        Some(Language::Javascript)
    } else if path.ends_with(".py") {
        Some(Language::Python)
    } else if path.ends_with(".go") {
        Some(Language::Go)
    } else {
        None
    }
}

fn normalize_relative(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

const fn default_maximum_propagation_depth() -> usize {
    4
}

const fn default_true() -> bool {
    true
}
