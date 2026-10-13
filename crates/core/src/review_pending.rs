//! Source-bound pending questions and evidence updates; updates are not verdicts.
use crate::{ReviewAssessmentContext, ReviewChangeEvidence, ReviewChangeSourceReference};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPendingKind {
    SourceAuthority,
    ControlCoverage,
    CallerReachability,
    Configuration,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewPendingOrigin {
    Decision { decision_id: String },
    ChangePass { plan_id: String, path: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPendingDraft {
    pub schema_version: String,
    pub origin: ReviewPendingOrigin,
    pub kind: ReviewPendingKind,
    pub question: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewPendingRecord {
    pub question_id: String,
    pub generation: u64,
    pub assessment_context: ReviewAssessmentContext,
    pub subject_key: Option<String>,
    pub origin: ReviewPendingOrigin,
    pub kind: ReviewPendingKind,
    pub question: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewFactDraft {
    pub schema_version: String,
    pub question_id: String,
    pub answer: String,
    pub evidence: Vec<ReviewChangeSourceReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewFactRecord {
    pub fact_id: String,
    pub question_id: String,
    pub generation: u64,
    pub inventory_input_fingerprint: String,
    pub answer: String,
    pub evidence: Vec<ReviewChangeEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewWorkPayload {
    pub schema_version: String,
    pub generation: u64,
    pub snapshot_id: String,
    pub plan_id: String,
    pub inventory_input_fingerprint: String,
    pub repository: crate::ReviewRepositoryIdentity,
    pub assessment_context: ReviewAssessmentContext,
    pub impact_scope: Option<crate::ImpactScanScope>,
    pub review_ids: Vec<String>,
    pub policy: crate::ReviewCompletionPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<crate::ReviewRuntimeContract>,
    pub planned_review_ids: Vec<String>,
    pub deferred_review_ids: std::collections::BTreeMap<String, String>,
    pub expected_parents: std::collections::BTreeMap<String, Vec<String>>,
    pub parent_decisions: Vec<crate::ReviewDecisionRecord>,
    pub pending_questions: Vec<ReviewPendingRecord>,
    pub evidence_updates: Vec<ReviewFactRecord>,
    pub change_pass: Vec<crate::ReviewChangePassEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewWorkPackage {
    pub package_id: String,
    pub payload: ReviewWorkPayload,
}
