//! Local durable review state. Ownership and lineage do not establish safety.
use crate::{
    ImpactScanScope, ReviewAssessmentContext, ReviewRepositoryIdentity, ReviewSubjectIdentity,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStateBinding {
    pub repository: ReviewRepositoryIdentity,
    pub assessment_context: ReviewAssessmentContext,
    pub source_fingerprint: String,
    pub inventory_input_fingerprint: String,
    pub impact_scope: Option<ImpactScanScope>,
    /// Opaque trusted-coordinator contract binding; does not authenticate it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordination_key: Option<String>,
    pub subjects: BTreeMap<String, ReviewSubjectIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewStateSupersession {
    pub decision_id: String,
    pub parents: Vec<String>,
    /// Describes validated re-evaluation; not an independent safety proof.
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAttemptStatus {
    Running,
    Finished,
    Cancelled,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSubjectState {
    Unassessed,
    Recorded,
    Conflict,
    AwaitingSupersession,
}
