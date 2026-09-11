use serde::{Deserialize, Serialize};

use crate::{
    Capability, EvidenceContext, EvidenceKind, Language, Location, ReviewConfidence,
    ReviewDecision, SecurityPathStep, Severity,
};

pub const FINDING_REPORT_SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingReportTool {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingReportScan {
    pub root: String,
    pub job_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingReportTriage {
    pub response_schema_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingReportSummary {
    pub reviewed: usize,
    pub issue_decisions: usize,
    pub needs_review_decisions: usize,
    pub not_issue_decisions: usize,
    pub findings: usize,
    pub review_required: usize,
    pub dismissed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Issue,
    NeedsReview,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeveritySource {
    Unknown,
    RuleDefault,
    /// Conservative consumer default used until a rule has an adjudicated
    /// impact level. This is deliberately distinct from model confidence.
    FallbackDefault,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReportedSeverity {
    pub level: Severity,
    pub source: SeveritySource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingFlow {
    pub steps: Vec<SecurityPathStep>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingRelatedLocation {
    pub role: EvidenceKind,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingProvenance {
    pub review_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingRemediation {
    pub text: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReportedFinding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub status: FindingStatus,
    pub severity: ReportedSeverity,
    pub confidence: ReviewConfidence,
    pub category: Capability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<Language>,
    pub primary_location: Location,
    #[serde(default, skip_serializing_if = "EvidenceContext::is_empty")]
    pub context: EvidenceContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow: Option<FindingFlow>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<FindingRelatedLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<FindingRemediation>,
    pub provenance: FindingProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DismissedReview {
    pub review_id: String,
    pub confidence: ReviewConfidence,
    pub description: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingReport {
    pub schema_version: String,
    pub report_kind: String,
    pub tool: FindingReportTool,
    pub scan: FindingReportScan,
    pub triage: FindingReportTriage,
    pub summary: FindingReportSummary,
    pub findings: Vec<ReportedFinding>,
    pub review_required: Vec<ReportedFinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dismissed: Vec<DismissedReview>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quality_warnings: Vec<String>,
}

impl FindingStatus {
    pub fn from_decision(decision: ReviewDecision) -> Option<Self> {
        match decision {
            ReviewDecision::Issue => Some(Self::Issue),
            ReviewDecision::NeedsReview => Some(Self::NeedsReview),
            ReviewDecision::NotIssue => None,
        }
    }
}
