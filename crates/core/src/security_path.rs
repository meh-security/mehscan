use serde::{Deserialize, Serialize};

use crate::{Capability, Location};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPathState {
    Direct,
    Propagated,
    Protected,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityPathStepKind {
    Source,
    Assignment,
    Alias,
    Protection,
    IneffectiveProtection,
    Sink,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityPathStep {
    pub kind: SecurityPathStepKind,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityPathProvenance {
    pub engine: String,
    pub maximum_propagation_depth: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecurityPath {
    /// Deterministic ID derived from the source, sink, state, and path steps.
    pub id: String,
    pub source_evidence_id: String,
    pub sink_evidence_id: String,
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
    pub state: SecurityPathState,
    pub steps: Vec<SecurityPathStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protection_evidence_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncertainty_reasons: Vec<String>,
    pub provenance: SecurityPathProvenance,
}
