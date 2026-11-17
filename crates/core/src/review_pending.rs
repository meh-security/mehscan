//! Source-bound pending questions and evidence updates; updates are not verdicts.
use crate::{ReviewAssessmentContext, ReviewChangeEvidence, ReviewChangeSourceReference};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKnowledgeOrigin {
    Assertion,
    SourceObservation,
    Inference,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewKnowledgeScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewKnowledgeRevision {
    pub item_id: String,
    pub revision_id: String,
    pub parent_revision: Option<String>,
    pub key: String,
    pub author: String,
    pub origin: ReviewKnowledgeOrigin,
    pub statement: String,
    pub scope: ReviewKnowledgeScope,
    pub source_sha256: BTreeMap<String, String>,
    pub evidence: Vec<String>,
    pub observed_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub withdrawn: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewSharingBinding {
    pub enrollment: String,
    pub database_id: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewKnowledgeContext {
    pub items: Vec<ReviewKnowledgeRevision>,
    pub by_review: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub omitted_source_links: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sharing: Option<ReviewSharingBinding>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

impl ReviewKnowledgeContext {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty() && self.by_review.is_empty() && self.sharing.is_none()
    }

    pub fn revisions(&self, review_id: &str) -> &[String] {
        self.by_review.get(review_id).map_or(&[], Vec::as_slice)
    }
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
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub excluded_review_ids: std::collections::BTreeMap<String, String>,
    pub expected_parents: std::collections::BTreeMap<String, Vec<String>>,
    pub parent_decisions: Vec<crate::ReviewDecisionRecord>,
    pub pending_questions: Vec<ReviewPendingRecord>,
    pub evidence_updates: Vec<ReviewFactRecord>,
    pub change_pass: Vec<crate::ReviewChangePassEntry>,
    #[serde(default, skip_serializing_if = "ReviewKnowledgeContext::is_empty")]
    pub knowledge: ReviewKnowledgeContext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewWorkPackage {
    pub package_id: String,
    pub payload: ReviewWorkPayload,
}
