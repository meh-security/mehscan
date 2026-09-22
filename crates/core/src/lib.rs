//! Stable product types shared by scanner engines, clients, and the CLI.
//!
//! This crate deliberately has no parser or language-runtime dependencies.

pub mod candidate;
pub mod coverage;
pub mod evaluation;
pub mod evidence;
pub mod finding;
pub mod finding_sarif;
pub mod investigation;
pub mod location;
pub mod protocol;
pub mod relation;
pub mod report;
pub mod rule;
pub mod sarif;
pub mod security_path;

pub use candidate::{
    CANDIDATE_REPORT_SCHEMA_VERSION, Candidate, CandidateBuildError, CandidateClassification,
    CandidateEvidence, CandidateReport,
};
pub use coverage::{
    Coverage, CoverageTotals, CweCoverage, CweSupportLevel, FileCoverage, FileStatus,
    LanguageCoverage, ProducerCoverage,
};
pub use evaluation::{
    ControlLayer, EVALUATION_PACK_SCHEMA_VERSION, EVALUATION_RESPONSE_SCHEMA_VERSION,
    EVALUATION_SCORE_SCHEMA_VERSION, EvaluationFinding, EvaluationFindingLocation, EvaluationMode,
    EvaluationModeMetrics, EvaluationPack, EvaluationResponse, EvaluationResponseSet,
    EvaluationResponseStatus, EvaluationReviewContract, EvaluationScoreReport, EvaluationSource,
    EvaluationTrial, EvaluationUsage, REVIEW_VERDICT_EVALUATION_SCHEMA_VERSION, ReviewAction,
    ReviewDisposition, ReviewVerdictCaseScore, ReviewVerdictEvaluationCase,
    ReviewVerdictEvaluationPack, ReviewVerdictEvaluationReport, ReviewVerdictEvaluationResponseSet,
    ReviewVerdictEvaluationResult, ReviewVerdictLanguageMetrics, ReviewVerdictReviewabilityMetrics,
    ReviewabilityClass,
};
pub use evidence::{
    Availability, AvailabilityState, Capability, Confidence, Evidence, EvidenceContext,
    EvidenceKind, FixedOutputFormat, HttpRouteAccess, HttpRouteContext, LiteralEvaluation,
    LiteralState, LiteralValue, Provenance, Reachability, ReachabilityReason, ReachabilityState,
    Resolution, ResourcePolicyContext, ResourcePolicyState, RuntimeEnvironment, SecretDetector,
    SecretMetadata, SymbolConfidence, SymbolResolution, SymbolResolutionMethod, ValueTransform,
};
pub use finding::{Finding, Severity};
pub use finding_sarif::{
    FindingSarifAutomationDetails, FindingSarifConfiguration, FindingSarifDriver, FindingSarifLog,
    FindingSarifResult, FindingSarifResultProperties, FindingSarifRule, FindingSarifRuleProperties,
    FindingSarifRun, FindingSarifRunProperties, FindingSarifTool,
};
pub use investigation::{
    EnclosingSymbolResult, EvidenceFilter, EvidenceResults, FileOutline,
    INVESTIGATION_TRACE_RESPONSE_SCHEMA_VERSION, InvestigationAnchor, InvestigationJob,
    InvestigationLimits, InvestigationUnit, InvestigationUnitProvenance,
    LEGACY_PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, NativeCallArgument, NativeCallSite,
    NativeSyntaxAnchor, NativeSyntaxContext, NativeSyntaxResults, ObservationReview,
    ObservationReviewBasis, OutlineSymbol, PATH_REVIEW_BUNDLE_SCHEMA_VERSION,
    PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, PathReview, PathReviewBasis, PathReviewBundle,
    PathReviewBundleCategory, PathReviewBundleIssueGroup, PathReviewBundleManifest,
    PathReviewBundleManifestEntry, PathReviewBundlePayload, PathReviewBundleResponseSet,
    PathReviewBundleRunReport, PathReviewBundleSet, PathReviewBundleTriageReport,
    PathReviewEvidenceBasis, PathReviewIssueGroup, PathReviewJob, PathReviewTask,
    PathReviewTaskPage, PathReviewTaskPayload, PathReviewTriageProgress, PathReviewTriageReport,
    PathReviewTriageResponseSet, PathReviewTriageResult, QueryProvenance, QueryResponse,
    REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, RelationshipFunnel, RelationshipFunnelCapability,
    ReviewArtifactCitation, ReviewConfidence, ReviewConfidencePolicy, ReviewContextTruncation,
    ReviewDecision, ReviewDecisionFacts, ReviewInvestigationBudget, ReviewInvestigationPlan,
    ReviewInvestigationTrace, ReviewLookupAttempt, ReviewLookupOutcome, ReviewLookupRequest,
    ReviewNeighborhood, ReviewNeighborhoodFact, ReviewNeighborhoodJob,
    ReviewNeighborhoodVerification, ReviewPipelineCoverage, ReviewReadiness,
    ReviewRetrievedArtifact, ReviewTriageContract, ReviewTriageReport, ReviewTriageResponseSet,
    ReviewTriageResult, ReviewWorkSummary, ReviewerInference, SourceSlice, StructuralMatch,
    TextReference,
};
pub use location::{Capture, Location, Position};
pub use protocol::{
    ChangedFile, ChangedFileStatus, ChangedLineRange, Diagnostic, DiagnosticLevel, ImpactScanScope,
    ImpactScopeFile, ScanRequest, ScanResult,
};
pub use relation::{
    ProtectionApplication, RelationContract, RelationProtection, RelationSink, RelationSource,
    RelationStrategy,
};
pub use report::{
    DismissedReview, FINDING_REPORT_SCHEMA_VERSION, FindingFlow, FindingProvenance,
    FindingRelatedLocation, FindingRemediation, FindingReport, FindingReportScan,
    FindingReportSummary, FindingReportTool, FindingReportTriage, FindingStatus, ReportedFinding,
    ReportedSeverity, SeveritySource,
};
pub use rule::{AiGuidance, Language, MatchSpec, PatternSpec, Rule, RuleProvenance, SymbolSpec};
pub use sarif::{SARIF_SCHEMA_URI, SARIF_VERSION, SarifLog};
pub use security_path::{
    SecurityPath, SecurityPathProvenance, SecurityPathState, SecurityPathStep, SecurityPathStepKind,
};

pub const SCHEMA_VERSION: &str = "2.1";
