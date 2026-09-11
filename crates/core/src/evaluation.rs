use serde::{Deserialize, Serialize};

use crate::{
    Candidate, Evidence, Language, PathReviewTaskPayload, ReviewConfidence, ReviewDecision,
    ReviewTriageContract,
};

pub const EVALUATION_PACK_SCHEMA_VERSION: &str = "1.1";
pub const EVALUATION_RESPONSE_SCHEMA_VERSION: &str = "1.1";
pub const EVALUATION_SCORE_SCHEMA_VERSION: &str = "1.1";
pub const REVIEW_VERDICT_EVALUATION_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationMode {
    AiOnly,
    EvidenceAssisted,
    CandidateAssisted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationSource {
    pub path: String,
    pub language: Language,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationTrial {
    pub id: String,
    pub case_id: String,
    pub mode: EvaluationMode,
    pub objective: String,
    pub review_contract: EvaluationReviewContract,
    pub source: EvaluationSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<Candidate>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub configuration_reviews: Vec<Evidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationReviewContract {
    pub version: String,
    pub instructions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationPack {
    pub schema_version: String,
    pub suite_id: String,
    pub pack_id: String,
    pub scan_schema_version: String,
    pub trial_count: usize,
    pub trials: Vec<EvaluationTrial>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationResponseStatus {
    Completed,
    Error,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationUsage {
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub requests: usize,
    pub latency_milliseconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationFindingLocation {
    pub path: String,
    pub line: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationFinding {
    pub cwe: String,
    pub location: EvaluationFindingLocation,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_ids: Vec<String>,
    pub disposition: ReviewDisposition,
    pub recommended_action: ReviewAction,
    pub control_layer: ControlLayer,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification: Vec<String>,
    pub rationale: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDisposition {
    Confirmed,
    NeedsVerification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAction {
    FixApplication,
    FixControlLayer,
    VerifyEffectiveControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlLayer {
    Application,
    Framework,
    ReverseProxy,
    ApiGateway,
    ServiceMesh,
    Platform,
    Client,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationResponse {
    pub trial_id: String,
    pub status: EvaluationResponseStatus,
    #[serde(default)]
    pub usage: EvaluationUsage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<EvaluationFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationResponseSet {
    pub schema_version: String,
    pub suite_id: String,
    pub pack_id: String,
    pub provider: String,
    pub model: String,
    pub responses: Vec<EvaluationResponse>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationModeMetrics {
    pub trials: usize,
    pub completed_responses: usize,
    pub error_responses: usize,
    pub missing_responses: usize,
    pub expected_findings: usize,
    pub adjudicated_safe_regions: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub safe_region_false_positives: usize,
    pub false_negatives: usize,
    pub ignored_predictions: usize,
    pub recall_basis_points: u32,
    pub precision_basis_points: u32,
    pub cited_ids: usize,
    pub valid_cited_ids: usize,
    pub citation_accuracy_basis_points: u32,
    pub true_positives_with_valid_citation: usize,
    pub citation_coverage_basis_points: u32,
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub requests: usize,
    pub latency_milliseconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvaluationScoreReport {
    pub schema_version: String,
    pub suite_id: String,
    pub pack_id: String,
    pub provider: String,
    pub model: String,
    pub modes: std::collections::BTreeMap<EvaluationMode, EvaluationModeMetrics>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewVerdictEvaluationCase {
    pub case_id: String,
    pub language: Language,
    pub review_id: String,
    #[serde(flatten)]
    pub payload: PathReviewTaskPayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewVerdictEvaluationPack {
    pub schema_version: String,
    pub suite_id: String,
    pub pack_id: String,
    pub goal: String,
    pub triage_contract: ReviewTriageContract,
    pub case_count: usize,
    pub cases: Vec<ReviewVerdictEvaluationCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewVerdictEvaluationResult {
    pub case_id: String,
    pub decision: ReviewDecision,
    pub confidence: ReviewConfidence,
    pub summary: String,
    pub checks: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewVerdictEvaluationResponseSet {
    pub schema_version: String,
    pub suite_id: String,
    pub pack_id: String,
    pub provider: String,
    pub model: String,
    pub results: Vec<ReviewVerdictEvaluationResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewVerdictLanguageMetrics {
    pub language: Language,
    pub cases: usize,
    pub decision_matches: usize,
    pub confidence_matches: usize,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewabilityClass {
    Standard,
    Advanced,
    ExternalContext,
}

/// Offline routing metrics. These distinguish a wrong definite verdict from
/// a justified or unjustified deferral; they do not alter production triage.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewVerdictReviewabilityMetrics {
    pub reviewability: ReviewabilityClass,
    pub cases: usize,
    pub decision_matches: usize,
    pub false_positive_count: usize,
    pub false_negative_count: usize,
    pub unjustified_deferral_count: usize,
    pub unsafe_certainty_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewVerdictCaseScore {
    pub case_id: String,
    pub language: Language,
    pub reviewability: ReviewabilityClass,
    pub expected_decision: ReviewDecision,
    pub actual_decision: ReviewDecision,
    pub decision_match: bool,
    pub allowed_confidence: Vec<ReviewConfidence>,
    pub actual_confidence: ReviewConfidence,
    pub confidence_match: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewVerdictEvaluationReport {
    pub schema_version: String,
    pub suite_id: String,
    pub pack_id: String,
    pub provider: String,
    pub model: String,
    pub cases: usize,
    pub decision_matches: usize,
    pub confidence_matches: usize,
    pub issue_expected: usize,
    pub not_issue_expected: usize,
    pub needs_review_expected: usize,
    pub false_positive_count: usize,
    pub false_negative_count: usize,
    pub unjustified_deferral_count: usize,
    pub unsafe_certainty_count: usize,
    pub by_language: Vec<ReviewVerdictLanguageMetrics>,
    pub by_reviewability: Vec<ReviewVerdictReviewabilityMetrics>,
    pub case_scores: Vec<ReviewVerdictCaseScore>,
    pub results: Vec<ReviewVerdictEvaluationResult>,
}
