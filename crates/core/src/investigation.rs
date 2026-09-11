use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    Candidate, Capability, Coverage, Diagnostic, Evidence, Language, Location, Resolution,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueryProvenance {
    pub resolution: Resolution,
    pub engine: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QueryResponse<T> {
    pub schema_version: String,
    pub root: String,
    pub operation: String,
    pub provenance: QueryProvenance,
    pub truncated: bool,
    pub results: T,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutlineSymbol {
    pub name: String,
    pub symbol_type: String,
    pub signature: String,
    pub ast_kind: String,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_import: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_exported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_public: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileOutline {
    pub path: String,
    pub language: Language,
    pub symbols: Vec<OutlineSymbol>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceSlice {
    pub location: Location,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnclosingSymbolResult {
    pub evidence_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<OutlineSymbol>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<crate::EvidenceKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<crate::Capability>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EvidenceResults {
    pub filter: EvidenceFilter,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationshipFunnelCapability {
    pub sink_observations: usize,
    pub sinks_with_compatible_source_in_symbol: usize,
    pub linked_sink_observations: usize,
    pub unlinked_sinks_with_compatible_source_in_symbol: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RelationshipFunnel {
    pub relation_source_observations: usize,
    pub remote_source_observations: usize,
    pub eligible_sink_observations: usize,
    pub sinks_with_compatible_source_in_symbol: usize,
    pub linked_sink_observations: usize,
    pub unlinked_sinks_with_compatible_source_in_symbol: usize,
    pub sinks_without_compatible_source_in_symbol: usize,
    pub security_paths: usize,
    pub by_capability: BTreeMap<Capability, RelationshipFunnelCapability>,
    pub interpretation: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TextReference {
    pub text: String,
    pub location: Location,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructuralMatch {
    pub text: String,
    pub location: Location,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationAnchor {
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<OutlineSymbol>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationUnitProvenance {
    pub grouping: QueryProvenance,
    pub source: QueryProvenance,
    pub imports: QueryProvenance,
    pub guidance: QueryProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationUnit {
    /// Stable identity derived from the source path and anchor byte range.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub anchor: InvestigationAnchor,
    /// Evidence matching the job filter that caused this unit to be selected.
    pub selected_evidence_ids: Vec<String>,
    /// All bounded observations related by the enclosing symbol or source window.
    pub evidence: Vec<Evidence>,
    pub source: SourceSlice,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<OutlineSymbol>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ai_guidance: Vec<String>,
    pub provenance: InvestigationUnitProvenance,
    pub context_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationLimits {
    pub max_units: usize,
    pub context_lines: usize,
    pub max_evidence_per_unit: usize,
    pub max_imports_per_unit: usize,
    pub max_source_lines: usize,
    pub max_source_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InvestigationJob {
    pub schema_version: String,
    pub root: String,
    pub operation: String,
    pub filter: EvidenceFilter,
    pub limits: InvestigationLimits,
    pub truncated: bool,
    pub units: Vec<InvestigationUnit>,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewNeighborhoodFact {
    pub role: String,
    pub symbol: String,
    pub location: Location,
    pub excerpt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    pub provenance: QueryProvenance,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewNeighborhoodVerification {
    pub persistence_call_observed: bool,
    pub runtime_persistence_verified: bool,
    pub retrieval_verified: bool,
    pub raw_output_observed: bool,
    pub encoding_verified: bool,
    pub authorization_verified: bool,
    pub runtime_dispatch_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewNeighborhood {
    /// Stable identity derived from the language, model/property key, and anchor.
    pub id: String,
    pub language: Language,
    pub candidate: String,
    pub cwe: String,
    /// Exact project identity used to collect the facts, for example
    /// `BlogEntry.Contents`.
    pub key: String,
    pub anchor_evidence_ids: Vec<String>,
    pub facts: Vec<ReviewNeighborhoodFact>,
    /// Detailed deterministic state retained for engine-side policy and tests;
    /// the model-facing JSON uses `open_questions` instead.
    #[serde(skip)]
    pub verification: ReviewNeighborhoodVerification,
    pub open_questions: Vec<String>,
    #[serde(skip)]
    pub uncertainties: Vec<String>,
    #[serde(skip)]
    pub ai_guidance: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewTriageContract {
    pub response_fields: Vec<String>,
    pub decisions: Vec<String>,
    pub confidence_levels: Vec<String>,
    pub instructions: Vec<String>,
}

pub const REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecision {
    Issue,
    NotIssue,
    NeedsReview,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewConfidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewTriageResult {
    pub neighborhood_id: String,
    pub decision: ReviewDecision,
    pub confidence: ReviewConfidence,
    pub summary: String,
    pub checks: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewTriageResponseSet {
    pub schema_version: String,
    pub job_fingerprint: String,
    pub results: Vec<ReviewTriageResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewTriageReport {
    pub schema_version: String,
    pub job_fingerprint: String,
    pub issue_count: usize,
    pub not_issue_count: usize,
    pub needs_review_count: usize,
    pub results: Vec<ReviewTriageResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewNeighborhoodJob {
    pub schema_version: String,
    pub root: String,
    pub operation: String,
    pub language: Language,
    /// Deterministic identity of the selected review input, excluding coverage
    /// and diagnostics.
    pub fingerprint: String,
    pub triage_contract: ReviewTriageContract,
    pub max_neighborhoods: usize,
    pub truncated: bool,
    pub neighborhoods: Vec<ReviewNeighborhood>,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

/// A self-contained, language-neutral review of one deterministic security
/// path. The nested candidate preserves the engine's exact bounded claim;
/// facts add only source and configuration context for the reviewer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReview {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub candidate: Candidate,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_basis: Option<PathReviewBasis>,
    /// Compact reviewer-facing separation between facts already supplied,
    /// linked controls, and only the questions that remain unresolved.
    #[serde(default)]
    pub decision_facts: ReviewDecisionFacts,
    /// Deterministic confidence calibration for each allowed decision. Models
    /// decide the verdict; the scanner owns confidence consistency.
    pub confidence_policy: ReviewConfidencePolicy,
    pub facts: Vec<ReviewNeighborhoodFact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_questions: Vec<String>,
    /// Legacy engine aggregate retained for internal callers. Model-facing
    /// payloads use `truncation`, which distinguishes decisive from auxiliary
    /// clipping.
    #[serde(default, skip_serializing)]
    pub context_truncated: bool,
    #[serde(default)]
    pub truncation: ReviewContextTruncation,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewDecisionFacts {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub established: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effective_controls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewConfidencePolicy {
    pub issue: ReviewConfidence,
    pub not_issue: ReviewConfidence,
    pub needs_review: ReviewConfidence,
    pub rationale: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewContextTruncation {
    pub occurred: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    pub decision_critical: bool,
}

/// Compact deterministic semantics supplied to an AI reviewer in addition to
/// source excerpts. This explains what each rule observed without asserting a
/// vulnerability verdict or adding unproved runtime behavior.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBasis {
    pub relationship: String,
    pub security_question: String,
    pub source: PathReviewEvidenceBasis,
    pub sink: PathReviewEvidenceBasis,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protections: Vec<PathReviewEvidenceBasis>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deterministic_facts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub investigate: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verify: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewEvidenceBasis {
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_title: Option<String>,
    pub kind: crate::EvidenceKind,
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub captures: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_note: Option<String>,
}

/// A bounded non-path neighborhood for observations that merit AI review but
/// do not satisfy a deterministic relation contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationReview {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub title: String,
    pub anchor_evidence_ids: Vec<String>,
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_basis: Option<ObservationReviewBasis>,
    #[serde(default)]
    pub decision_facts: ReviewDecisionFacts,
    pub confidence_policy: ReviewConfidencePolicy,
    pub facts: Vec<ReviewNeighborhoodFact>,
    pub open_questions: Vec<String>,
    #[serde(default, skip_serializing)]
    pub context_truncated: bool,
    #[serde(default)]
    pub truncation: ReviewContextTruncation,
}

/// Compact rule semantics for a non-path observation neighborhood. It states
/// exactly what was observed and preserves the rule's model guidance without
/// promoting the neighborhood into a deterministic relationship.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservationReviewBasis {
    pub relationship: String,
    pub security_question: String,
    pub observations: Vec<PathReviewEvidenceBasis>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deterministic_facts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub investigate: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verify: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewJob {
    pub schema_version: String,
    pub root: String,
    pub operation: String,
    /// Deterministic identity of reviews, facts, questions, and contract. It
    /// deliberately excludes coverage and diagnostics.
    pub fingerprint: String,
    pub triage_contract: ReviewTriageContract,
    pub context_lines: usize,
    pub max_reviews: usize,
    /// Zero-based position in the stable, path-first review sequence.
    #[serde(default)]
    pub offset: usize,
    /// Total review items available with the same admission policy.
    #[serde(default)]
    pub total_reviews: usize,
    /// Offset for the next page, when more review items remain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    /// Whether source payloads and teaching/code-fix material were admitted.
    #[serde(default)]
    pub include_review_material: bool,
    /// Review items omitted by the default non-deployed-material policy.
    #[serde(default)]
    pub review_material_excluded: usize,
    pub truncated: bool,
    pub reviews: Vec<PathReview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observation_reviews: Vec<ObservationReview>,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

pub const PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathReviewTriageResult {
    pub review_id: String,
    pub decision: ReviewDecision,
    pub confidence: ReviewConfidence,
    pub summary: String,
    pub checks: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathReviewTriageResponseSet {
    pub schema_version: String,
    pub job_fingerprint: String,
    pub results: Vec<PathReviewTriageResult>,
}

/// One model-sized task extracted from a review page. It repeats the page
/// identity and response contract so it can be transported independently.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewTask {
    pub schema_version: String,
    pub job_fingerprint: String,
    pub review_id: String,
    pub sequence: usize,
    pub page_size: usize,
    pub triage_contract: ReviewTriageContract,
    #[serde(flatten)]
    pub payload: PathReviewTaskPayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "review_kind", rename_all = "snake_case")]
pub enum PathReviewTaskPayload {
    SecurityPath { review: PathReview },
    Observation { review: ObservationReview },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewTaskPage {
    pub schema_version: String,
    pub root: String,
    pub operation: String,
    pub job_fingerprint: String,
    pub offset: usize,
    pub total_reviews: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
    pub tasks: Vec<PathReviewTask>,
}

pub const PATH_REVIEW_BUNDLE_SCHEMA_VERSION: &str = "1.0";

/// The semantic class shared by every review in one model request. Keeping a
/// bundle homogeneous makes both its filename and the review goal intelligible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBundleCategory {
    pub scope: String,
    pub review_kind: String,
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "review_kind", rename_all = "snake_case")]
pub enum PathReviewBundlePayload {
    SecurityPath { reviews: Vec<PathReview> },
    Observation { reviews: Vec<ObservationReview> },
}

/// One complete model request. A response is accepted or retried as a whole;
/// there is deliberately no per-item response state in this format.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBundle {
    pub schema_version: String,
    pub bundle_fingerprint: String,
    pub job_fingerprint: String,
    pub goal: String,
    pub category: PathReviewBundleCategory,
    pub part: usize,
    pub part_count: usize,
    pub triage_contract: ReviewTriageContract,
    pub review_ids: Vec<String>,
    #[serde(flatten)]
    pub payload: PathReviewBundlePayload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBundleManifestEntry {
    pub filename: String,
    pub bundle_fingerprint: String,
    pub category: PathReviewBundleCategory,
    pub part: usize,
    pub part_count: usize,
    pub review_count: usize,
    pub input_bytes: usize,
    /// UTF-8 bytes occupied by source-bearing fact excerpts and evidence
    /// captures before JSON escaping. This is a stable payload-composition
    /// metric, not a model-token estimate.
    #[serde(default)]
    pub context_text_bytes: usize,
    /// Context bytes after the first occurrence of each exact text within the
    /// bundle. Repetition can be intentional when the same text has distinct
    /// locations or semantic roles, so this is not an automatic savings claim.
    #[serde(default)]
    pub repeated_context_text_bytes: usize,
    pub review_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBundleManifest {
    pub schema_version: String,
    pub root: String,
    pub operation: String,
    pub job_fingerprint: String,
    pub max_input_bytes: usize,
    /// Effective transport ceiling for reviews in one request. Semantic and
    /// byte boundaries can split a bundle before this limit is reached.
    #[serde(default)]
    pub max_reviews_per_bundle: usize,
    pub review_count: usize,
    pub bundle_count: usize,
    pub bundles: Vec<PathReviewBundleManifestEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathReviewBundleSet {
    pub manifest: PathReviewBundleManifest,
    pub bundles: Vec<PathReviewBundle>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathReviewBundleResponseSet {
    pub schema_version: String,
    pub bundle_fingerprint: String,
    pub results: Vec<PathReviewTriageResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBundleTriageReport {
    pub schema_version: String,
    pub bundle_fingerprint: String,
    pub complete: bool,
    pub issue_count: usize,
    pub not_issue_count: usize,
    pub needs_review_count: usize,
    pub results: Vec<PathReviewTriageResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBundleIssueGroup {
    pub id: String,
    pub review_ids: Vec<String>,
    pub review_kinds: Vec<String>,
    /// Rule identity defining the security behavior consolidated by this group.
    pub invariant_id: String,
    pub confidence: ReviewConfidence,
    pub capability: Capability,
    pub location: Location,
    pub cwe_candidates: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewBundleRunReport {
    pub schema_version: String,
    pub job_fingerprint: String,
    pub bundle_count: usize,
    pub review_count: usize,
    pub issue_count: usize,
    pub not_issue_count: usize,
    pub needs_review_count: usize,
    pub issue_group_count: usize,
    pub issue_groups: Vec<PathReviewBundleIssueGroup>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quality_warnings: Vec<String>,
    pub results: Vec<PathReviewTriageResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewTriageProgress {
    pub schema_version: String,
    pub job_fingerprint: String,
    pub submitted_count: usize,
    pub remaining_count: usize,
    pub complete: bool,
    pub issue_count: usize,
    pub not_issue_count: usize,
    pub needs_review_count: usize,
    pub missing_review_ids: Vec<String>,
    pub results: Vec<PathReviewTriageResult>,
}

/// Conservative consolidation: issue decisions merge only when their
/// capability, exact sink range, and rule-defined security invariant are
/// identical. Constituent review results remain available separately.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewIssueGroup {
    pub id: String,
    pub review_ids: Vec<String>,
    /// Rule identity defining the security behavior consolidated by this group.
    pub invariant_id: String,
    pub confidence: ReviewConfidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub location: Location,
    pub capability: Capability,
    pub cwe_candidates: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathReviewTriageReport {
    pub schema_version: String,
    pub job_fingerprint: String,
    pub issue_count: usize,
    pub not_issue_count: usize,
    pub needs_review_count: usize,
    pub issue_group_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub issue_groups: Vec<PathReviewIssueGroup>,
    pub results: Vec<PathReviewTriageResult>,
}
