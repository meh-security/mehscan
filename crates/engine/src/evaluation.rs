//! Provider-neutral matched evaluation packs and offline response scoring.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use mehscan_core::{
    CandidateReport, ControlLayer, EVALUATION_PACK_SCHEMA_VERSION,
    EVALUATION_RESPONSE_SCHEMA_VERSION, EVALUATION_SCORE_SCHEMA_VERSION, EvaluationFinding,
    EvaluationMode, EvaluationModeMetrics, EvaluationPack, EvaluationResponseSet,
    EvaluationResponseStatus, EvaluationReviewContract, EvaluationScoreReport, EvaluationSource,
    EvaluationTrial, EvidenceKind, Language, PathReviewTaskPayload,
    REVIEW_VERDICT_EVALUATION_SCHEMA_VERSION, ReviewAction, ReviewConfidence, ReviewDecision,
    ReviewDisposition, ReviewVerdictCaseScore, ReviewVerdictEvaluationCase,
    ReviewVerdictEvaluationPack, ReviewVerdictEvaluationReport, ReviewVerdictEvaluationResponseSet,
    ReviewVerdictLanguageMetrics, ReviewVerdictReviewabilityMetrics, ReviewabilityClass,
    SCHEMA_VERSION, ScanResult,
};
use serde::Deserialize;

use crate::{EngineError, scan_path};

const MAX_EVALUATION_SOURCE_BYTES: usize = 256 * 1024;

fn review_contract() -> EvaluationReviewContract {
    EvaluationReviewContract {
        version: "1.0".to_string(),
        instructions: vec![
            "Report a finding only when the supplied source or context supports a concrete security concern; scanner evidence and candidates are review leads, not verdicts.".to_string(),
            "For controls whose effective behavior may be owned or changed by a framework, reverse proxy, API gateway, service mesh, platform, or client, absence in application source is not proof that the deployed control is absent.".to_string(),
            "Use confirmed only when the supplied evidence establishes the weakness. Use needs_verification with verify_effective_control when deployment evidence is required; identify the likely control layer and the exact artifact or runtime behavior to inspect.".to_string(),
            "For HTTP response policy, inspect the final externally visible response on the affected route and environment, including duplicate, overwritten, or stripped headers, plus relevant proxy, gateway, CDN, ingress, and framework configuration.".to_string(),
            "Recommend fix_application only when application code owns the defective behavior. Recommend fix_control_layer only when the authoritative external layer is established. Do not recommend duplicate controls without a stated defense-in-depth reason.".to_string(),
            "If the concern is disproved, emit no finding rather than a confirmed or needs_verification finding.".to_string(),
        ],
    }
}

#[derive(Clone, Debug, Deserialize)]
struct EvaluationManifest {
    version: u32,
    id: String,
    objective: String,
    modes: Vec<EvaluationMode>,
    #[serde(default)]
    cases: Vec<EvaluationCase>,
    #[serde(default)]
    families: Vec<EvaluationFamily>,
}

#[derive(Clone, Debug, Deserialize)]
struct EvaluationCase {
    id: String,
    root: String,
    file: String,
    language: Language,
    #[serde(default)]
    expected_findings: Vec<ExpectedFinding>,
    #[serde(default)]
    ignored_regions: Vec<IgnoredRegion>,
    #[serde(default)]
    safe_regions: Vec<SafeRegion>,
}

#[derive(Clone, Debug, Deserialize)]
struct EvaluationFamily {
    id: String,
    root: String,
    #[serde(default)]
    negative_root: Option<String>,
    cwe: String,
    protected_disposition: RegionDisposition,
    protected_reason: String,
    variants: BTreeMap<Language, EvaluationVariant>,
}

#[derive(Clone, Debug, Deserialize)]
struct EvaluationVariant {
    positive_file: String,
    negative_file: String,
    direct_line: usize,
    propagated_line: usize,
    #[serde(default)]
    protected_line: Option<usize>,
    #[serde(default)]
    additional_vulnerable_lines: Vec<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RegionDisposition {
    Vulnerable,
    Safe,
    Excluded,
}

#[derive(Clone, Debug, Deserialize)]
struct ExpectedFinding {
    id: String,
    cwe: String,
    start_line: usize,
    end_line: usize,
    #[serde(default = "confirmed_disposition")]
    disposition: ReviewDisposition,
}

const fn confirmed_disposition() -> ReviewDisposition {
    ReviewDisposition::Confirmed
}

#[derive(Clone, Debug, Deserialize)]
struct IgnoredRegion {
    start_line: usize,
    end_line: usize,
    reason: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SafeRegion {
    cwe: String,
    start_line: usize,
    end_line: usize,
    reason: String,
}

struct PreparedEvaluation {
    pack: EvaluationPack,
    oracles: BTreeMap<String, CaseOracle>,
}

struct CaseOracle {
    file: String,
    expected_findings: Vec<ExpectedFinding>,
    ignored_regions: Vec<IgnoredRegion>,
    safe_regions: Vec<SafeRegion>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReviewVerdictManifest {
    version: u32,
    id: String,
    goal: String,
    #[serde(default = "default_review_context_lines")]
    context_lines: usize,
    cases: Vec<ReviewVerdictManifestCase>,
}

#[derive(Clone, Debug, Deserialize)]
struct ReviewVerdictManifestCase {
    id: String,
    root: String,
    review_kind: ReviewVerdictKind,
    language: Language,
    path: String,
    line: usize,
    #[serde(default)]
    rule_id: Option<String>,
    reviewability: ReviewabilityClass,
    expected_decision: ReviewDecision,
    allowed_confidence: Vec<ReviewConfidence>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReviewVerdictKind {
    SecurityPath,
    Observation,
}

const fn default_review_context_lines() -> usize {
    10
}

pub fn prepare_evaluation(
    workspace_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<EvaluationPack, EngineError> {
    Ok(prepare(workspace_root.as_ref(), manifest_path.as_ref())?.pack)
}

pub fn score_evaluation(
    workspace_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
    responses: &EvaluationResponseSet,
) -> Result<EvaluationScoreReport, EngineError> {
    let prepared = prepare(workspace_root.as_ref(), manifest_path.as_ref())?;
    score(&prepared, responses)
}

pub fn prepare_review_verdict_evaluation(
    workspace_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<ReviewVerdictEvaluationPack, EngineError> {
    let workspace_root = canonical_workspace_root(workspace_root.as_ref())?;
    let manifest = load_review_verdict_manifest(&workspace_root, manifest_path.as_ref())?;
    prepare_review_verdict_pack(&workspace_root, &manifest)
}

pub fn score_review_verdict_evaluation(
    workspace_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
    responses: &ReviewVerdictEvaluationResponseSet,
) -> Result<ReviewVerdictEvaluationReport, EngineError> {
    let workspace_root = canonical_workspace_root(workspace_root.as_ref())?;
    let manifest = load_review_verdict_manifest(&workspace_root, manifest_path.as_ref())?;
    let pack = prepare_review_verdict_pack(&workspace_root, &manifest)?;
    if responses.schema_version != REVIEW_VERDICT_EVALUATION_SCHEMA_VERSION
        || responses.suite_id != pack.suite_id
        || responses.pack_id != pack.pack_id
    {
        return Err(EngineError(
            "review-verdict responses do not match the prepared suite and pack".to_string(),
        ));
    }
    let expected_by_id = manifest
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let prepared_by_id = pack
        .cases
        .iter()
        .map(|case| (case.case_id.as_str(), case))
        .collect::<BTreeMap<_, _>>();
    let mut response_by_id = BTreeMap::new();
    for result in &responses.results {
        if !expected_by_id.contains_key(result.case_id.as_str()) {
            return Err(EngineError(format!(
                "review-verdict response references unknown case {:?}",
                result.case_id
            )));
        }
        if response_by_id
            .insert(result.case_id.as_str(), result)
            .is_some()
        {
            return Err(EngineError(format!(
                "review-verdict responses contain duplicate case {:?}",
                result.case_id
            )));
        }
        crate::investigation::validate_compact_triage(
            &result.case_id,
            result.decision,
            &result.summary,
            &result.checks,
        )?;
        let expected_confidence =
            review_case_confidence(prepared_by_id[result.case_id.as_str()], result.decision);
        if result.confidence != expected_confidence {
            return Err(EngineError(format!(
                "confidence for review-verdict case {:?} must be {:?} for the selected {:?} decision",
                result.case_id, expected_confidence, result.decision
            )));
        }
        if result.decision == ReviewDecision::NeedsReview {
            let unresolved = review_case_unresolved(prepared_by_id[result.case_id.as_str()]);
            for check in &result.checks {
                if !unresolved.iter().any(|fact| fact.trim() == check.trim()) {
                    return Err(EngineError(format!(
                        "needs_review check for review-verdict case {:?} must copy an exact supplied decision_facts.unresolved entry",
                        result.case_id
                    )));
                }
            }
        }
    }
    let missing = expected_by_id
        .keys()
        .filter(|id| !response_by_id.contains_key(**id))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(EngineError(format!(
            "review-verdict responses are missing cases: {}",
            missing.join(", ")
        )));
    }

    let mut decision_matches = 0;
    let mut confidence_matches = 0;
    let mut issue_expected = 0;
    let mut not_issue_expected = 0;
    let mut needs_review_expected = 0;
    let mut false_positive_count = 0;
    let mut false_negative_count = 0;
    let mut unjustified_deferral_count = 0;
    let mut unsafe_certainty_count = 0;
    let mut by_language = BTreeMap::<Language, ReviewVerdictLanguageMetrics>::new();
    let mut by_reviewability = [
        ReviewabilityClass::Standard,
        ReviewabilityClass::Advanced,
        ReviewabilityClass::ExternalContext,
    ]
    .into_iter()
    .map(|reviewability| {
        (
            reviewability,
            ReviewVerdictReviewabilityMetrics {
                reviewability,
                cases: 0,
                decision_matches: 0,
                false_positive_count: 0,
                false_negative_count: 0,
                unjustified_deferral_count: 0,
                unsafe_certainty_count: 0,
            },
        )
    })
    .collect::<BTreeMap<_, _>>();
    let mut case_scores = Vec::with_capacity(manifest.cases.len());
    let mut ordered_results = Vec::with_capacity(manifest.cases.len());
    for case in &manifest.cases {
        let result = response_by_id[case.id.as_str()];
        let decision_match = result.decision == case.expected_decision;
        let confidence_match = case.allowed_confidence.contains(&result.confidence);
        let false_positive = case.expected_decision == ReviewDecision::NotIssue
            && result.decision == ReviewDecision::Issue;
        let false_negative = case.expected_decision == ReviewDecision::Issue
            && result.decision == ReviewDecision::NotIssue;
        let unjustified_deferral = case.expected_decision != ReviewDecision::NeedsReview
            && result.decision == ReviewDecision::NeedsReview;
        let unsafe_certainty = case.expected_decision == ReviewDecision::NeedsReview
            && result.decision != ReviewDecision::NeedsReview;
        decision_matches += usize::from(decision_match);
        confidence_matches += usize::from(confidence_match);
        false_positive_count += usize::from(false_positive);
        false_negative_count += usize::from(false_negative);
        unjustified_deferral_count += usize::from(unjustified_deferral);
        unsafe_certainty_count += usize::from(unsafe_certainty);
        match case.expected_decision {
            ReviewDecision::Issue => issue_expected += 1,
            ReviewDecision::NotIssue => not_issue_expected += 1,
            ReviewDecision::NeedsReview => needs_review_expected += 1,
        }
        let language = by_language
            .entry(case.language)
            .or_insert(ReviewVerdictLanguageMetrics {
                language: case.language,
                cases: 0,
                decision_matches: 0,
                confidence_matches: 0,
            });
        language.cases += 1;
        language.decision_matches += usize::from(decision_match);
        language.confidence_matches += usize::from(confidence_match);
        let reviewability = by_reviewability
            .get_mut(&case.reviewability)
            .expect("all reviewability classes are initialized");
        reviewability.cases += 1;
        reviewability.decision_matches += usize::from(decision_match);
        reviewability.false_positive_count += usize::from(false_positive);
        reviewability.false_negative_count += usize::from(false_negative);
        reviewability.unjustified_deferral_count += usize::from(unjustified_deferral);
        reviewability.unsafe_certainty_count += usize::from(unsafe_certainty);
        case_scores.push(ReviewVerdictCaseScore {
            case_id: case.id.clone(),
            language: case.language,
            reviewability: case.reviewability,
            expected_decision: case.expected_decision,
            actual_decision: result.decision,
            decision_match,
            allowed_confidence: case.allowed_confidence.clone(),
            actual_confidence: result.confidence,
            confidence_match,
        });
        ordered_results.push((*result).clone());
    }
    Ok(ReviewVerdictEvaluationReport {
        schema_version: REVIEW_VERDICT_EVALUATION_SCHEMA_VERSION.to_string(),
        suite_id: pack.suite_id,
        pack_id: pack.pack_id,
        provider: responses.provider.clone(),
        model: responses.model.clone(),
        cases: manifest.cases.len(),
        decision_matches,
        confidence_matches,
        issue_expected,
        not_issue_expected,
        needs_review_expected,
        false_positive_count,
        false_negative_count,
        unjustified_deferral_count,
        unsafe_certainty_count,
        by_language: by_language.into_values().collect(),
        by_reviewability: by_reviewability.into_values().collect(),
        case_scores,
        results: ordered_results,
    })
}

fn canonical_workspace_root(root: &Path) -> Result<PathBuf, EngineError> {
    fs::canonicalize(root).map_err(|error| {
        EngineError(format!(
            "evaluation workspace root could not be resolved: {error}"
        ))
    })
}

fn load_review_verdict_manifest(
    workspace_root: &Path,
    manifest_path: &Path,
) -> Result<ReviewVerdictManifest, EngineError> {
    let path = if manifest_path.is_absolute() {
        manifest_path.to_path_buf()
    } else {
        workspace_root.join(manifest_path)
    };
    let path = fs::canonicalize(&path).map_err(|error| {
        EngineError(format!(
            "review-verdict manifest {} could not be resolved: {error}",
            path.display()
        ))
    })?;
    if !path.starts_with(workspace_root) {
        return Err(EngineError(
            "review-verdict manifest must remain inside the workspace".to_string(),
        ));
    }
    let source = fs::read_to_string(&path).map_err(|error| {
        EngineError(format!(
            "review-verdict manifest {} could not be read: {error}",
            path.display()
        ))
    })?;
    let manifest: ReviewVerdictManifest = serde_yaml::from_str(&source).map_err(|error| {
        EngineError(format!(
            "review-verdict manifest {} is invalid: {error}",
            path.display()
        ))
    })?;
    if manifest.version != 1
        || manifest.id.trim().is_empty()
        || manifest.goal.trim().is_empty()
        || manifest.cases.is_empty()
        || !(1..=50).contains(&manifest.context_lines)
    {
        return Err(EngineError(
            "review-verdict manifest requires version 1, an id, a goal, 1-50 context lines, and at least one case"
                .to_string(),
        ));
    }
    let mut ids = BTreeSet::new();
    for case in &manifest.cases {
        if case.id.trim().is_empty()
            || !ids.insert(case.id.as_str())
            || case.root.trim().is_empty()
            || case.path.trim().is_empty()
            || case.line == 0
            || case.allowed_confidence.is_empty()
            || (case.reviewability == ReviewabilityClass::ExternalContext
                && case.expected_decision != ReviewDecision::NeedsReview)
        {
            return Err(EngineError(
                "review-verdict cases require unique ids, roots, paths, positive lines, allowed confidence values, and external_context cases must expect needs_review"
                    .to_string(),
            ));
        }
    }
    Ok(manifest)
}

fn prepare_review_verdict_pack(
    workspace_root: &Path,
    manifest: &ReviewVerdictManifest,
) -> Result<ReviewVerdictEvaluationPack, EngineError> {
    let mut jobs = BTreeMap::new();
    let mut cases = Vec::with_capacity(manifest.cases.len());
    let mut triage_contract = None;
    for selected in &manifest.cases {
        if !jobs.contains_key(&selected.root) {
            let root = fs::canonicalize(workspace_root.join(&selected.root)).map_err(|error| {
                EngineError(format!(
                    "review-verdict root {:?} could not be resolved: {error}",
                    selected.root
                ))
            })?;
            if !root.starts_with(workspace_root) {
                return Err(EngineError(format!(
                    "review-verdict root {:?} escapes the workspace",
                    selected.root
                )));
            }
            let job = crate::investigation::build_all_path_review_jobs(
                &root,
                Some(manifest.context_lines),
                false,
            )?;
            jobs.insert(selected.root.clone(), job);
        }
        let job = &jobs[&selected.root];
        if let Some(existing) = &triage_contract {
            if existing != &job.triage_contract {
                return Err(EngineError(
                    "review-verdict cases produced inconsistent triage contracts".to_string(),
                ));
            }
        } else {
            triage_contract = Some(job.triage_contract.clone());
        }
        let payload = match selected.review_kind {
            ReviewVerdictKind::SecurityPath => {
                let matches = job
                    .reviews
                    .iter()
                    .filter(|review| {
                        review.language == Some(selected.language)
                            && review.candidate.primary_location.path == selected.path
                            && review.candidate.primary_location.start.line == selected.line
                            && selected.rule_id.as_ref().is_none_or(|rule_id| {
                                review.candidate.source.rule_id == *rule_id
                                    || review.candidate.sink.rule_id == *rule_id
                                    || review
                                        .candidate
                                        .protections
                                        .iter()
                                        .any(|item| item.rule_id == *rule_id)
                            })
                    })
                    .collect::<Vec<_>>();
                if matches.len() != 1 {
                    return Err(EngineError(format!(
                        "review-verdict case {:?} selected {} security paths instead of one",
                        selected.id,
                        matches.len()
                    )));
                }
                PathReviewTaskPayload::SecurityPath {
                    review: matches[0].clone(),
                }
            }
            ReviewVerdictKind::Observation => {
                let matches = job
                    .observation_reviews
                    .iter()
                    .filter(|review| {
                        review.language == Some(selected.language)
                            && review.evidence.iter().any(|evidence| {
                                evidence.location.path == selected.path
                                    && evidence.location.start.line == selected.line
                                    && selected
                                        .rule_id
                                        .as_ref()
                                        .is_none_or(|rule_id| evidence.rule_id == *rule_id)
                            })
                    })
                    .collect::<Vec<_>>();
                if matches.len() != 1 {
                    return Err(EngineError(format!(
                        "review-verdict case {:?} selected {} observation reviews instead of one",
                        selected.id,
                        matches.len()
                    )));
                }
                PathReviewTaskPayload::Observation {
                    review: matches[0].clone(),
                }
            }
        };
        let review_id = match &payload {
            PathReviewTaskPayload::SecurityPath { review } => review.id.clone(),
            PathReviewTaskPayload::Observation { review } => review.id.clone(),
        };
        let case = ReviewVerdictEvaluationCase {
            case_id: selected.id.clone(),
            language: selected.language,
            review_id,
            payload,
        };
        let expected_confidence = review_case_confidence(&case, selected.expected_decision);
        if !selected.allowed_confidence.contains(&expected_confidence) {
            return Err(EngineError(format!(
                "review-verdict case {:?} allows {:?} confidence for its expected {:?} decision, but the emitted confidence policy requires {:?}",
                selected.id,
                selected.allowed_confidence,
                selected.expected_decision,
                expected_confidence
            )));
        }
        cases.push(case);
    }
    let mut triage_contract = triage_contract.expect("non-empty manifest has a triage contract");
    if let Some(identifier) = triage_contract.response_fields.first_mut() {
        *identifier = "case_id".to_string();
    }
    triage_contract.instructions.push(
        "Return exactly one result for every case_id in this evaluation pack; review_id identifies scanner evidence and is not the response key."
            .to_string(),
    );
    let identity = serde_json::to_string(&(
        REVIEW_VERDICT_EVALUATION_SCHEMA_VERSION,
        &manifest.id,
        &manifest.goal,
        &triage_contract,
        &cases,
    ))
    .expect("review-verdict pack identity must serialize");
    let pack_id = stable_evaluation_hash("review-evalpack", &identity);
    Ok(ReviewVerdictEvaluationPack {
        schema_version: REVIEW_VERDICT_EVALUATION_SCHEMA_VERSION.to_string(),
        suite_id: manifest.id.clone(),
        pack_id,
        goal: manifest.goal.clone(),
        triage_contract,
        case_count: cases.len(),
        cases,
    })
}

fn review_case_confidence(
    case: &ReviewVerdictEvaluationCase,
    decision: ReviewDecision,
) -> ReviewConfidence {
    let policy = match &case.payload {
        PathReviewTaskPayload::SecurityPath { review } => &review.confidence_policy,
        PathReviewTaskPayload::Observation { review } => &review.confidence_policy,
    };
    match decision {
        ReviewDecision::Issue => policy.issue,
        ReviewDecision::NotIssue => policy.not_issue,
        ReviewDecision::NeedsReview => policy.needs_review,
    }
}

fn review_case_unresolved(case: &ReviewVerdictEvaluationCase) -> &[String] {
    match &case.payload {
        PathReviewTaskPayload::SecurityPath { review } => &review.decision_facts.unresolved,
        PathReviewTaskPayload::Observation { review } => &review.decision_facts.unresolved,
    }
}

fn stable_evaluation_hash(prefix: &str, value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.bytes() {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

fn prepare(workspace_root: &Path, manifest_path: &Path) -> Result<PreparedEvaluation, EngineError> {
    let workspace_root = fs::canonicalize(workspace_root).map_err(|error| {
        EngineError(format!(
            "evaluation workspace root could not be resolved: {error}"
        ))
    })?;
    let manifest_path = resolve_beneath(&workspace_root, manifest_path)?;
    let manifest_source = fs::read_to_string(&manifest_path).map_err(|error| {
        EngineError(format!(
            "evaluation manifest {} could not be read: {error}",
            manifest_path.display()
        ))
    })?;
    let manifest: EvaluationManifest = serde_yaml::from_str(&manifest_source).map_err(|error| {
        EngineError(format!(
            "evaluation manifest {} is invalid: {error}",
            manifest_path.display()
        ))
    })?;
    validate_manifest(&manifest)?;
    let cases = expand_cases(&manifest)?;

    let mut scans = BTreeMap::<PathBuf, ScanResult>::new();
    let mut trials = Vec::with_capacity(cases.len() * manifest.modes.len());
    let mut oracles = BTreeMap::new();
    for case in &cases {
        let case_root = resolve_beneath(&workspace_root, Path::new(&case.root))?;
        let source_path = resolve_beneath(&case_root, Path::new(&case.file))?;
        let source_bytes = fs::read(&source_path).map_err(|error| {
            EngineError(format!(
                "evaluation source {} could not be read: {error}",
                source_path.display()
            ))
        })?;
        if source_bytes.len() > MAX_EVALUATION_SOURCE_BYTES {
            return Err(EngineError(format!(
                "evaluation source {} exceeds the {} byte limit",
                source_path.display(),
                MAX_EVALUATION_SOURCE_BYTES
            )));
        }
        let source_text = String::from_utf8(source_bytes).map_err(|error| {
            EngineError(format!(
                "evaluation source {} is not UTF-8: {error}",
                source_path.display()
            ))
        })?;
        let actual_language = language_for_path(&relative_path_string(&source_path));
        if actual_language != Some(case.language) {
            return Err(EngineError(format!(
                "evaluation case {} declares {:?}, but its file extension resolves to {:?}",
                case.id, case.language, actual_language
            )));
        }
        validate_case_lines(case, source_text.lines().count().max(1))?;
        if !scans.contains_key(&case_root) {
            scans.insert(case_root.clone(), scan_path(&case_root)?);
        }
        let scan = &scans[&case_root];
        let relative_file = normalize_relative(&case.file);
        let mut file_evidence = scan
            .evidence
            .iter()
            .filter(|item| item.location.path == relative_file)
            .cloned()
            .collect::<Vec<_>>();
        let secret_ranges = file_evidence
            .iter()
            .filter(|item| item.kind == EvidenceKind::Secret)
            .map(|item| {
                (
                    item.location.start.byte_offset,
                    item.location.end.byte_offset,
                )
            })
            .collect::<Vec<_>>();
        let masked_source = mask_secrets(source_text, &secret_ranges)?;
        redact_evidence_captures(&mut file_evidence, &secret_ranges);
        let candidate_report = CandidateReport::from_scan(scan).map_err(|error| {
            EngineError(format!(
                "evaluation case {} could not build candidates: {error}",
                case.id
            ))
        })?;
        let mut file_candidates = candidate_report
            .candidates
            .into_iter()
            .filter(|candidate| {
                candidate.primary_location.path == relative_file
                    || candidate.source.location.path == relative_file
            })
            .collect::<Vec<_>>();
        redact_candidate_literals(&mut file_candidates, &secret_ranges);

        for mode in &manifest.modes {
            trials.push(EvaluationTrial {
                id: format!("{}::{}", case.id, mode_id(*mode)),
                case_id: case.id.clone(),
                mode: *mode,
                objective: manifest.objective.clone(),
                review_contract: review_contract(),
                source: EvaluationSource {
                    path: relative_file.clone(),
                    language: case.language,
                    text: masked_source.clone(),
                },
                evidence: if *mode == EvaluationMode::EvidenceAssisted {
                    file_evidence.clone()
                } else {
                    Vec::new()
                },
                candidates: if *mode == EvaluationMode::CandidateAssisted {
                    file_candidates.clone()
                } else {
                    Vec::new()
                },
                configuration_reviews: if *mode == EvaluationMode::CandidateAssisted {
                    file_evidence
                        .iter()
                        .filter(|item| item.kind == EvidenceKind::SecurityConfiguration)
                        .cloned()
                        .collect()
                } else {
                    Vec::new()
                },
            });
        }
        oracles.insert(
            case.id.clone(),
            CaseOracle {
                file: relative_file,
                expected_findings: case.expected_findings.clone(),
                ignored_regions: case.ignored_regions.clone(),
                safe_regions: case.safe_regions.clone(),
            },
        );
    }
    let serialized_trials = serde_yaml::to_string(&trials)
        .map_err(|error| EngineError(format!("evaluation trials could not be encoded: {error}")))?;
    let pack_id = fnv_id(&format!(
        "{}\0{}\0{serialized_trials}",
        manifest.id, EVALUATION_PACK_SCHEMA_VERSION
    ));
    Ok(PreparedEvaluation {
        pack: EvaluationPack {
            schema_version: EVALUATION_PACK_SCHEMA_VERSION.to_string(),
            suite_id: manifest.id,
            pack_id,
            scan_schema_version: SCHEMA_VERSION.to_string(),
            trial_count: trials.len(),
            trials,
        },
        oracles,
    })
}

fn score(
    prepared: &PreparedEvaluation,
    responses: &EvaluationResponseSet,
) -> Result<EvaluationScoreReport, EngineError> {
    if responses.schema_version != EVALUATION_RESPONSE_SCHEMA_VERSION {
        return Err(EngineError(format!(
            "unsupported evaluation response schema {:?}",
            responses.schema_version
        )));
    }
    if responses.suite_id != prepared.pack.suite_id || responses.pack_id != prepared.pack.pack_id {
        return Err(EngineError(
            "evaluation responses do not match the prepared suite and pack".to_string(),
        ));
    }
    let trial_ids = prepared
        .pack
        .trials
        .iter()
        .map(|trial| trial.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut response_by_trial = BTreeMap::new();
    for response in &responses.responses {
        if !trial_ids.contains(response.trial_id.as_str()) {
            return Err(EngineError(format!(
                "evaluation response references unknown trial {:?}",
                response.trial_id
            )));
        }
        if response_by_trial
            .insert(response.trial_id.as_str(), response)
            .is_some()
        {
            return Err(EngineError(format!(
                "evaluation responses contain duplicate trial {:?}",
                response.trial_id
            )));
        }
    }

    let mut modes = BTreeMap::<EvaluationMode, EvaluationModeMetrics>::new();
    let mut diagnostics = Vec::new();
    for trial in &prepared.pack.trials {
        let oracle = &prepared.oracles[&trial.case_id];
        let metrics = modes.entry(trial.mode).or_default();
        metrics.trials += 1;
        metrics.expected_findings += oracle.expected_findings.len();
        metrics.adjudicated_safe_regions += oracle.safe_regions.len();
        let Some(response) = response_by_trial.get(trial.id.as_str()).copied() else {
            metrics.missing_responses += 1;
            metrics.false_negatives += oracle.expected_findings.len();
            diagnostics.push(format!("missing response for trial {}", trial.id));
            continue;
        };
        metrics.input_tokens += response.usage.input_tokens;
        metrics.output_tokens += response.usage.output_tokens;
        metrics.requests += response.usage.requests;
        metrics.latency_milliseconds = metrics
            .latency_milliseconds
            .saturating_add(response.usage.latency_milliseconds);
        if response.status == EvaluationResponseStatus::Error {
            metrics.error_responses += 1;
            metrics.false_negatives += oracle.expected_findings.len();
            diagnostics.push(format!("trial {} returned an error", trial.id));
            continue;
        }
        validate_findings(&response.findings, &trial.id)?;
        metrics.completed_responses += 1;
        let valid_ids = valid_citation_ids(trial);
        let mut matched = vec![false; oracle.expected_findings.len()];
        for finding in &response.findings {
            let valid_citation = count_citations(metrics, finding, &valid_ids);
            if ignored_prediction(finding, oracle) {
                metrics.ignored_predictions += 1;
                continue;
            }
            if safe_region_prediction(finding, oracle) {
                metrics.safe_region_false_positives += 1;
                metrics.false_positives += 1;
                continue;
            }
            let expected_index = oracle
                .expected_findings
                .iter()
                .enumerate()
                .find(|(index, expected)| {
                    !matched[*index]
                        && expected.cwe == finding.cwe
                        && expected.disposition == finding.disposition
                        && normalize_relative(&finding.location.path) == oracle.file
                        && finding.location.line >= expected.start_line
                        && finding.location.line <= expected.end_line
                })
                .map(|(index, _)| index);
            if let Some(index) = expected_index {
                matched[index] = true;
                metrics.true_positives += 1;
                if valid_citation {
                    metrics.true_positives_with_valid_citation += 1;
                }
            } else {
                metrics.false_positives += 1;
            }
        }
        metrics.false_negatives += matched.iter().filter(|matched| !**matched).count();
    }
    for metrics in modes.values_mut() {
        metrics.recall_basis_points = ratio_basis_points(
            metrics.true_positives,
            metrics.true_positives + metrics.false_negatives,
        );
        metrics.precision_basis_points = ratio_basis_points(
            metrics.true_positives,
            metrics.true_positives + metrics.false_positives,
        );
        metrics.citation_accuracy_basis_points =
            ratio_basis_points(metrics.valid_cited_ids, metrics.cited_ids);
        metrics.citation_coverage_basis_points = ratio_basis_points(
            metrics.true_positives_with_valid_citation,
            metrics.true_positives,
        );
    }
    Ok(EvaluationScoreReport {
        schema_version: EVALUATION_SCORE_SCHEMA_VERSION.to_string(),
        suite_id: prepared.pack.suite_id.clone(),
        pack_id: prepared.pack.pack_id.clone(),
        provider: responses.provider.clone(),
        model: responses.model.clone(),
        modes,
        diagnostics,
    })
}

fn validate_findings(findings: &[EvaluationFinding], trial_id: &str) -> Result<(), EngineError> {
    for finding in findings {
        let valid = match (finding.disposition, finding.recommended_action) {
            (ReviewDisposition::Confirmed, ReviewAction::FixApplication) => {
                finding.control_layer == ControlLayer::Application
            }
            (ReviewDisposition::Confirmed, ReviewAction::FixControlLayer) => {
                finding.control_layer != ControlLayer::Unknown
            }
            (ReviewDisposition::NeedsVerification, ReviewAction::VerifyEffectiveControl) => {
                !finding.verification.is_empty()
                    && finding
                        .verification
                        .iter()
                        .all(|step| !step.trim().is_empty())
            }
            _ => false,
        };
        if !valid {
            return Err(EngineError(format!(
                "trial {trial_id} contains an invalid review disposition/action/control-layer combination"
            )));
        }
    }
    Ok(())
}

fn count_citations(
    metrics: &mut EvaluationModeMetrics,
    finding: &EvaluationFinding,
    valid_ids: &BTreeSet<&str>,
) -> bool {
    let citations = finding
        .evidence_ids
        .iter()
        .chain(&finding.candidate_ids)
        .map(String::as_str)
        .collect::<Vec<_>>();
    metrics.cited_ids += citations.len();
    let valid = citations
        .iter()
        .filter(|id| valid_ids.contains(**id))
        .count();
    metrics.valid_cited_ids += valid;
    valid > 0
}

fn valid_citation_ids(trial: &EvaluationTrial) -> BTreeSet<&str> {
    let mut ids = trial
        .evidence
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    for candidate in &trial.candidates {
        ids.insert(candidate.id.as_str());
        ids.insert(candidate.source.id.as_str());
        ids.insert(candidate.sink.id.as_str());
        ids.extend(candidate.protections.iter().map(|item| item.id.as_str()));
    }
    ids.extend(
        trial
            .configuration_reviews
            .iter()
            .map(|item| item.id.as_str()),
    );
    ids
}

fn ignored_prediction(finding: &EvaluationFinding, oracle: &CaseOracle) -> bool {
    normalize_relative(&finding.location.path) == oracle.file
        && oracle.ignored_regions.iter().any(|region| {
            finding.location.line >= region.start_line && finding.location.line <= region.end_line
        })
}

fn safe_region_prediction(finding: &EvaluationFinding, oracle: &CaseOracle) -> bool {
    normalize_relative(&finding.location.path) == oracle.file
        && oracle.safe_regions.iter().any(|region| {
            finding.cwe == region.cwe
                && finding.location.line >= region.start_line
                && finding.location.line <= region.end_line
        })
}

fn ratio_basis_points(numerator: usize, denominator: usize) -> u32 {
    if denominator == 0 {
        return 0;
    }
    u32::try_from(numerator.saturating_mul(10_000) / denominator).unwrap_or(10_000)
}

fn validate_manifest(manifest: &EvaluationManifest) -> Result<(), EngineError> {
    if manifest.version != 1 {
        return Err(EngineError(format!(
            "unsupported evaluation manifest version {}",
            manifest.version
        )));
    }
    if manifest.id.trim().is_empty()
        || manifest.objective.trim().is_empty()
        || (manifest.cases.is_empty() && manifest.families.is_empty())
    {
        return Err(EngineError(
            "evaluation manifest requires an id, objective, and cases or families".to_string(),
        ));
    }
    let required_modes = [
        EvaluationMode::AiOnly,
        EvaluationMode::EvidenceAssisted,
        EvaluationMode::CandidateAssisted,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let modes = manifest.modes.iter().copied().collect::<BTreeSet<_>>();
    if modes != required_modes || manifest.modes.len() != required_modes.len() {
        return Err(EngineError(
            "evaluation manifest must contain each matched mode exactly once".to_string(),
        ));
    }
    Ok(())
}

fn expand_cases(manifest: &EvaluationManifest) -> Result<Vec<EvaluationCase>, EngineError> {
    let required_languages = [
        Language::Csharp,
        Language::Java,
        Language::Javascript,
        Language::Typescript,
        Language::Tsx,
        Language::Python,
        Language::Go,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut cases = manifest.cases.clone();
    let mut family_ids = BTreeSet::new();
    for family in &manifest.families {
        if family.id.trim().is_empty()
            || !family_ids.insert(family.id.as_str())
            || family.root.trim().is_empty()
            || family.cwe.trim().is_empty()
            || family.protected_reason.trim().is_empty()
        {
            return Err(EngineError(
                "evaluation family ids, roots, CWEs, and protection reasons must be non-empty and unique"
                    .to_string(),
            ));
        }
        let languages = family.variants.keys().copied().collect::<BTreeSet<_>>();
        if languages != required_languages {
            return Err(EngineError(format!(
                "evaluation family {} must define exactly all seven supported languages",
                family.id
            )));
        }
        for (language, variant) in &family.variants {
            if variant.positive_file.trim().is_empty()
                || variant.negative_file.trim().is_empty()
                || variant.direct_line == 0
                || variant.propagated_line == 0
                || variant.protected_line == Some(0)
                || variant.additional_vulnerable_lines.contains(&0)
            {
                return Err(EngineError(format!(
                    "evaluation family {} has an invalid {:?} variant",
                    family.id, language
                )));
            }
            let mut positive = EvaluationCase {
                id: format!("{}-positive-{}", family.id, language_id(*language)),
                root: family.root.clone(),
                file: variant.positive_file.clone(),
                language: *language,
                expected_findings: vec![
                    ExpectedFinding {
                        id: "direct".to_string(),
                        cwe: family.cwe.clone(),
                        start_line: variant.direct_line,
                        end_line: variant.direct_line,
                        disposition: ReviewDisposition::Confirmed,
                    },
                    ExpectedFinding {
                        id: "propagated".to_string(),
                        cwe: family.cwe.clone(),
                        start_line: variant.propagated_line,
                        end_line: variant.propagated_line,
                        disposition: ReviewDisposition::Confirmed,
                    },
                ],
                ignored_regions: Vec::new(),
                safe_regions: Vec::new(),
            };
            match (family.protected_disposition, variant.protected_line) {
                (RegionDisposition::Vulnerable, Some(protected_line)) => {
                    positive.expected_findings.push(ExpectedFinding {
                        id: "protected".to_string(),
                        cwe: family.cwe.clone(),
                        start_line: protected_line,
                        end_line: protected_line,
                        disposition: ReviewDisposition::Confirmed,
                    });
                }
                (RegionDisposition::Safe, Some(protected_line)) => {
                    positive.safe_regions.push(SafeRegion {
                        cwe: family.cwe.clone(),
                        start_line: protected_line,
                        end_line: protected_line,
                        reason: family.protected_reason.clone(),
                    })
                }
                (RegionDisposition::Excluded, Some(protected_line)) => {
                    positive.ignored_regions.push(IgnoredRegion {
                        start_line: protected_line,
                        end_line: protected_line,
                        reason: family.protected_reason.clone(),
                    })
                }
                (_, None) => {}
            }
            positive.expected_findings.extend(
                variant
                    .additional_vulnerable_lines
                    .iter()
                    .enumerate()
                    .map(|(index, line)| ExpectedFinding {
                        id: format!("additional-{}", index + 1),
                        cwe: family.cwe.clone(),
                        start_line: *line,
                        end_line: *line,
                        disposition: ReviewDisposition::Confirmed,
                    }),
            );
            cases.push(positive);
            cases.push(EvaluationCase {
                id: format!("{}-negative-{}", family.id, language_id(*language)),
                root: family
                    .negative_root
                    .clone()
                    .unwrap_or_else(|| family.root.clone()),
                file: variant.negative_file.clone(),
                language: *language,
                expected_findings: Vec::new(),
                ignored_regions: Vec::new(),
                safe_regions: Vec::new(),
            });
        }
    }
    validate_cases(&cases)?;
    Ok(cases)
}

fn validate_cases(cases: &[EvaluationCase]) -> Result<(), EngineError> {
    let mut case_ids = BTreeSet::new();
    let mut expectation_ids = BTreeSet::new();
    for case in cases {
        if case.id.trim().is_empty() || !case_ids.insert(case.id.as_str()) {
            return Err(EngineError(format!(
                "evaluation case ids must be non-empty and unique: {:?}",
                case.id
            )));
        }
        if case.root.trim().is_empty() || case.file.trim().is_empty() {
            return Err(EngineError(format!(
                "evaluation case {} requires a root and file",
                case.id
            )));
        }
        for expected in &case.expected_findings {
            if expected.id.trim().is_empty()
                || !expectation_ids.insert(format!("{}::{}", case.id, expected.id))
                || expected.cwe.trim().is_empty()
                || expected.start_line == 0
                || expected.start_line > expected.end_line
            {
                return Err(EngineError(format!(
                    "evaluation case {} has an invalid expected finding",
                    case.id
                )));
            }
        }
        for ignored in &case.ignored_regions {
            if ignored.start_line == 0
                || ignored.start_line > ignored.end_line
                || ignored.reason.trim().is_empty()
            {
                return Err(EngineError(format!(
                    "evaluation case {} has an invalid ignored region",
                    case.id
                )));
            }
        }
        for safe in &case.safe_regions {
            if safe.cwe.trim().is_empty()
                || safe.start_line == 0
                || safe.start_line > safe.end_line
                || safe.reason.trim().is_empty()
            {
                return Err(EngineError(format!(
                    "evaluation case {} has an invalid safe region",
                    case.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_case_lines(case: &EvaluationCase, line_count: usize) -> Result<(), EngineError> {
    if case
        .expected_findings
        .iter()
        .any(|expected| expected.end_line > line_count)
        || case
            .ignored_regions
            .iter()
            .any(|ignored| ignored.end_line > line_count)
        || case
            .safe_regions
            .iter()
            .any(|safe| safe.end_line > line_count)
    {
        return Err(EngineError(format!(
            "evaluation case {} contains a range beyond its {} source lines",
            case.id, line_count
        )));
    }
    if case.expected_findings.iter().any(|expected| {
        case.ignored_regions.iter().any(|ignored| {
            expected.start_line <= ignored.end_line && ignored.start_line <= expected.end_line
        })
    }) {
        return Err(EngineError(format!(
            "evaluation case {} overlaps scored and ignored regions",
            case.id
        )));
    }
    if case.expected_findings.iter().any(|expected| {
        case.safe_regions.iter().any(|safe| {
            expected.start_line <= safe.end_line && safe.start_line <= expected.end_line
        })
    }) {
        return Err(EngineError(format!(
            "evaluation case {} overlaps vulnerable and safe regions",
            case.id
        )));
    }
    Ok(())
}

fn mask_secrets(
    mut source: String,
    secret_ranges: &[(usize, usize)],
) -> Result<String, EngineError> {
    let mut bytes = source.into_bytes();
    for &(start, end) in secret_ranges {
        if start < end && end <= bytes.len() {
            bytes[start..end].fill(b'*');
        }
    }
    source = String::from_utf8(bytes)
        .map_err(|error| EngineError(format!("masked evaluation source is not UTF-8: {error}")))?;
    Ok(source)
}

fn redact_evidence_captures(
    evidence: &mut [mehscan_core::Evidence],
    secret_ranges: &[(usize, usize)],
) {
    for item in evidence {
        let mut redacted_captures = Vec::new();
        for (name, capture) in &mut item.captures {
            if overlaps(
                capture.location.start.byte_offset,
                capture.location.end.byte_offset,
                secret_ranges,
            ) {
                capture.text = "[REDACTED]".to_string();
                redacted_captures.push(name.clone());
            }
        }
        for name in redacted_captures {
            item.context.literals.remove(&name);
        }
    }
}

fn redact_candidate_literals(
    candidates: &mut [mehscan_core::Candidate],
    secret_ranges: &[(usize, usize)],
) {
    for candidate in candidates {
        for evidence in std::iter::once(&mut candidate.source)
            .chain(std::iter::once(&mut candidate.sink))
            .chain(candidate.protections.iter_mut())
        {
            if overlaps(
                evidence.location.start.byte_offset,
                evidence.location.end.byte_offset,
                secret_ranges,
            ) {
                evidence.context.literals.clear();
            }
        }
    }
}

fn overlaps(start: usize, end: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|&(range_start, range_end)| start < range_end && range_start < end)
}

fn resolve_beneath(root: &Path, relative: &Path) -> Result<PathBuf, EngineError> {
    let candidate = if relative.is_absolute() {
        relative.to_path_buf()
    } else {
        root.join(relative)
    };
    let resolved = fs::canonicalize(candidate).map_err(|error| {
        EngineError(format!(
            "evaluation path {} could not be resolved: {error}",
            relative.display()
        ))
    })?;
    if !resolved.starts_with(root) {
        return Err(EngineError(format!(
            "evaluation path escapes its root: {}",
            relative.display()
        )));
    }
    Ok(resolved)
}

fn normalize_relative(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches("./").to_string()
}

fn relative_path_string(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string()
}

fn language_for_path(path: &str) -> Option<Language> {
    let path = path.to_ascii_lowercase();
    if path.ends_with(".cs") {
        Some(Language::Csharp)
    } else if path.ends_with(".java") {
        Some(Language::Java)
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

const fn mode_id(mode: EvaluationMode) -> &'static str {
    match mode {
        EvaluationMode::AiOnly => "ai_only",
        EvaluationMode::EvidenceAssisted => "evidence_assisted",
        EvaluationMode::CandidateAssisted => "candidate_assisted",
    }
}

const fn language_id(language: Language) -> &'static str {
    match language {
        Language::Csharp => "cs",
        Language::Java => "java",
        Language::Javascript => "js",
        Language::Typescript => "ts",
        Language::Tsx => "tsx",
        Language::Python => "py",
        Language::Go => "go",
        Language::Rust => "rs",
    }
}

fn fnv_id(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("evalpack-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use mehscan_core::{
        ControlLayer, EvaluationFinding, EvaluationFindingLocation, ReviewAction, ReviewDisposition,
    };

    use super::{mask_secrets, ratio_basis_points, validate_findings};

    #[test]
    fn computes_integer_metrics_without_nan_or_rounding_drift() {
        assert_eq!(ratio_basis_points(2, 3), 6666);
        assert_eq!(ratio_basis_points(0, 0), 0);
    }

    #[test]
    fn masks_known_secret_bytes_before_building_a_provider_pack() {
        assert_eq!(
            mask_secrets("prefix-secret-suffix".to_string(), &[(7, 13)]).expect("mask"),
            "prefix-******-suffix"
        );
    }

    #[test]
    fn requires_review_only_findings_to_name_a_verification_step() {
        let mut finding = EvaluationFinding {
            cwe: "CWE-693".to_string(),
            location: EvaluationFindingLocation {
                path: "app.ts".to_string(),
                line: 1,
            },
            evidence_ids: Vec::new(),
            candidate_ids: Vec::new(),
            disposition: ReviewDisposition::NeedsVerification,
            recommended_action: ReviewAction::VerifyEffectiveControl,
            control_layer: ControlLayer::Unknown,
            verification: vec![
                "Inspect the externally visible response for the production route".to_string(),
            ],
            rationale: "the application source does not establish the effective header policy"
                .to_string(),
        };
        assert!(validate_findings(&[finding.clone()], "header-review").is_ok());

        finding.verification.clear();
        assert!(validate_findings(&[finding.clone()], "header-review").is_err());

        finding.disposition = ReviewDisposition::Confirmed;
        finding.recommended_action = ReviewAction::FixApplication;
        assert!(validate_findings(&[finding], "header-review").is_err());
    }
}
