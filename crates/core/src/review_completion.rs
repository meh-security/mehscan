//! Explicit scoped work accounting; completion never establishes application safety.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewCompletionPolicy {
    Value,
    Comprehensive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewChangePassStatus {
    Unassessed,
    Reviewed,
    NeedsReview,
    Deferred,
    CoverageGap,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewChangeEvidenceSide {
    Current,
    Base,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangeSourceReference {
    pub side: ReviewChangeEvidenceSide,
    pub path: String,
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangePassDraftEntry {
    pub path: String,
    pub status: ReviewChangePassStatus,
    pub summary: String,
    pub questions: Vec<String>,
    pub native_review_ids: Vec<String>,
    pub evidence: Vec<ReviewChangeSourceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCompletionDraft {
    pub schema_version: String,
    pub policy: ReviewCompletionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<crate::ReviewRuntimeContract>,
    pub selected_review_ids: Vec<String>,
    pub deferred_review_ids: BTreeMap<String, String>,
    pub change_pass: Vec<ReviewChangePassDraftEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangeEvidence {
    pub artifact_id: String,
    pub source: ReviewChangeSourceReference,
    pub revision: Option<String>,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewChangePassEntry {
    pub path: String,
    pub status: ReviewChangePassStatus,
    pub summary: String,
    pub questions: Vec<String>,
    pub native_review_ids: Vec<String>,
    pub evidence: Vec<ReviewChangeEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCompletionPlan {
    pub schema_version: String,
    pub inventory_input_fingerprint: String,
    pub policy: ReviewCompletionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<crate::ReviewRuntimeContract>,
    pub selected_review_ids: Vec<String>,
    pub deferred_review_ids: BTreeMap<String, String>,
    pub change_pass: Vec<ReviewChangePassEntry>,
    pub native_coverage_limits: Vec<ReviewCompletionCoverageLimit>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCompletionCoverageLimit {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewCompletionPlanRecord {
    pub plan_id: String,
    pub parent_plan_id: Option<String>,
    pub generation: u64,
    pub plan: ReviewCompletionPlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_package_id: Option<String>,
}
