//! Native question identity. Matching identity never authorizes verdict reuse.
use crate::{CandidateEvidence, PathReviewTriageResult, SecurityPathStep};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewRepositoryIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repository_key: Option<String>,
    /// Scan-root prefix within the assessed repository; never an absolute path.
    pub path_prefix: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityContinuity {
    Structural,
    Ambiguous,
    SnapshotBound,
    Unscoped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IdentityToken {
    pub kind: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationIdentity {
    pub path: String,
    pub language: Option<crate::Language>,
    pub enclosing_symbol: Option<String>,
    pub tokens: Vec<IdentityToken>,
    pub structural_context: Vec<String>,
    pub normalization: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OccurrenceIdentityTuple {
    pub version: String,
    pub repository_key: Option<String>,
    pub weakness_identity: String,
    pub operation: OperationIdentity,
    pub operation_role: String,
    /// Present only when structural continuity cannot distinguish sites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_discriminator: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReviewRelationshipScope {
    SourceToOperation {
        source: OperationIdentity,
        source_rule: String,
        source_role: String,
        /// Ambiguous producers cannot share a subject implicitly.
        source_snapshot: Option<String>,
    },
    OperationQuestion,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewLocationFingerprint {
    /// Exact scan-root-relative primary location in this source snapshot.
    pub location: crate::Location,
    pub primary_location_line_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewSubjectIdentity {
    /// Transport hint bound by the job/bundle, excluded from native keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_location_fingerprint: Option<ReviewLocationFingerprint>,
    pub anchor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_anchor_id: Option<String>,
    pub occurrence_key: String,
    pub subject_key: String,
    pub continuity: IdentityContinuity,
    pub occurrence: OccurrenceIdentityTuple,
    pub relationship_scope: ReviewRelationshipScope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewIdentitySummary {
    pub anchor_id: String,
    pub occurrence_key: String,
    pub subject_key: String,
    pub continuity: IdentityContinuity,
}
impl From<&ReviewSubjectIdentity> for ReviewIdentitySummary {
    fn from(identity: &ReviewSubjectIdentity) -> Self {
        Self {
            anchor_id: identity.anchor_id.clone(),
            occurrence_key: identity.occurrence_key.clone(),
            subject_key: identity.subject_key.clone(),
            continuity: identity.continuity,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewAssessmentContext {
    pub kind: String,
    pub source_boundary: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewIdentityCatalog {
    pub schema_version: String,
    pub repository: ReviewRepositoryIdentity,
    /// This slice supports source-only assessment, not deployment applicability.
    pub assessment_context: ReviewAssessmentContext,
    pub source_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inventory_input_fingerprint: Option<String>,
    pub subjects: BTreeMap<String, ReviewSubjectIdentity>,
}

/// Immutable output of joining a validated answer to a native-issued question.
/// It preserves all verdicts; a later state store must validate supersession.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReviewDecisionRecord {
    pub decision_id: String,
    pub identity: ReviewSubjectIdentity,
    pub repository: ReviewRepositoryIdentity,
    pub assessment_context: ReviewAssessmentContext,
    pub basis_fingerprint: String,
    pub source_fingerprint: String,
    pub inventory_input_fingerprint: Option<String>,
    pub job_fingerprint: String,
    pub bundle_fingerprint: String,
    pub response_fingerprint: String,
    pub native_evidence: Vec<CandidateEvidence>,
    pub native_flows: Vec<Vec<SecurityPathStep>>,
    pub response: PathReviewTriageResult,
}
