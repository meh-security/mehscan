use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    Capability, Confidence, Coverage, Diagnostic, Evidence, EvidenceContext, EvidenceKind,
    ImpactScanScope, Location, Provenance, ScanResult, SecurityPathProvenance, SecurityPathState,
    SecurityPathStep, SecurityPathStepKind, SymbolResolution,
};

pub const CANDIDATE_REPORT_SCHEMA_VERSION: &str = "1.0";

/// A reviewable deterministic relationship. A candidate is not a confirmed
/// vulnerability and deliberately has no severity or remediation verdict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub classification: CandidateClassification,
    pub title: String,
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
    pub state: SecurityPathState,
    pub primary_location: Location,
    pub source: CandidateEvidence,
    pub sink: CandidateEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protections: Vec<CandidateEvidence>,
    pub steps: Vec<SecurityPathStep>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncertainty_reasons: Vec<String>,
    pub provenance: SecurityPathProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateClassification {
    SecurityPath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CandidateEvidence {
    pub id: String,
    pub rule_id: String,
    pub kind: EvidenceKind,
    pub capability: Capability,
    pub location: Location,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclosing_symbol: Option<String>,
    pub confidence: Confidence,
    pub provenance: Provenance,
    #[serde(default, skip_serializing_if = "EvidenceContext::is_empty")]
    pub context: EvidenceContext,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_resolution: Option<SymbolResolution>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CandidateReport {
    pub schema_version: String,
    pub scan_schema_version: String,
    pub root: String,
    pub evidence_count: usize,
    pub security_path_count: usize,
    pub candidates: Vec<Candidate>,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_scope: Option<ImpactScanScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateBuildError(String);

impl CandidateBuildError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CandidateBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CandidateBuildError {}

impl CandidateReport {
    pub fn from_scan(result: &ScanResult) -> Result<Self, CandidateBuildError> {
        let mut evidence_by_id = BTreeMap::new();
        for evidence in &result.evidence {
            if evidence_by_id
                .insert(evidence.id.as_str(), evidence)
                .is_some()
            {
                return Err(CandidateBuildError::new(format!(
                    "duplicate evidence id {:?}",
                    evidence.id
                )));
            }
        }

        let candidates = result
            .security_paths
            .iter()
            .map(|path| {
                let source = evidence_by_id
                    .get(path.source_evidence_id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        CandidateBuildError::new(format!(
                            "security path {} references missing source evidence {}",
                            path.id, path.source_evidence_id
                        ))
                    })?;
                let sink = evidence_by_id
                    .get(path.sink_evidence_id.as_str())
                    .copied()
                    .ok_or_else(|| {
                        CandidateBuildError::new(format!(
                            "security path {} references missing sink evidence {}",
                            path.id, path.sink_evidence_id
                        ))
                    })?;
                validate_terminal_steps(path, source, sink)?;
                if path.capability != sink.capability {
                    return Err(CandidateBuildError::new(format!(
                        "security path {} capability does not match its sink evidence",
                        path.id
                    )));
                }
                let protections = path
                    .protection_evidence_ids
                    .iter()
                    .map(|id| {
                        evidence_by_id.get(id.as_str()).copied().ok_or_else(|| {
                            CandidateBuildError::new(format!(
                                "security path {} references missing protection evidence {}",
                                path.id, id
                            ))
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let step_protections = path
                    .steps
                    .iter()
                    .filter(|step| step.kind == SecurityPathStepKind::Protection)
                    .filter_map(|step| step.evidence_id.as_deref())
                    .collect::<Vec<_>>();
                if step_protections != path.protection_evidence_ids {
                    return Err(CandidateBuildError::new(format!(
                        "security path {} has inconsistent protection steps",
                        path.id
                    )));
                }
                if (path.state == SecurityPathState::Protected) == protections.is_empty() {
                    return Err(CandidateBuildError::new(format!(
                        "security path {} has an inconsistent protected state",
                        path.id
                    )));
                }

                Ok(Candidate {
                    id: path.id.clone(),
                    classification: CandidateClassification::SecurityPath,
                    title: candidate_title(&path.cwe_candidates, path.capability, &sink.rule_id),
                    capability: path.capability,
                    cwe_candidates: path.cwe_candidates.clone(),
                    state: path.state,
                    primary_location: sink.location.clone(),
                    source: candidate_evidence(source),
                    sink: candidate_evidence(sink),
                    protections: protections.into_iter().map(candidate_evidence).collect(),
                    steps: path.steps.clone(),
                    uncertainty_reasons: path.uncertainty_reasons.clone(),
                    provenance: path.provenance.clone(),
                })
            })
            .collect::<Result<Vec<_>, CandidateBuildError>>()?;

        Ok(Self {
            schema_version: CANDIDATE_REPORT_SCHEMA_VERSION.to_string(),
            scan_schema_version: result.schema_version.clone(),
            // Candidate reports are portable artifacts. Locations are already
            // relative to the scanned repository, so do not disclose the
            // machine-local absolute root used by the scanner process.
            root: ".".to_string(),
            evidence_count: result.evidence.len(),
            security_path_count: result.security_paths.len(),
            candidates,
            coverage: result.coverage.clone(),
            impact_scope: result.impact_scope.clone(),
            diagnostics: result.diagnostics.clone(),
        })
    }
}

fn validate_terminal_steps(
    path: &crate::SecurityPath,
    source: &Evidence,
    sink: &Evidence,
) -> Result<(), CandidateBuildError> {
    let first = path.steps.first().ok_or_else(|| {
        CandidateBuildError::new(format!("security path {} contains no steps", path.id))
    })?;
    let last = path.steps.last().expect("a first step implies a last step");
    if first.kind != SecurityPathStepKind::Source
        || first.evidence_id.as_deref() != Some(source.id.as_str())
        || first.location != source.location
    {
        return Err(CandidateBuildError::new(format!(
            "security path {} has an inconsistent source step",
            path.id
        )));
    }
    if last.kind != SecurityPathStepKind::Sink
        || last.evidence_id.as_deref() != Some(sink.id.as_str())
        || last.location != sink.location
    {
        return Err(CandidateBuildError::new(format!(
            "security path {} has an inconsistent sink step",
            path.id
        )));
    }
    Ok(())
}

fn candidate_evidence(evidence: &Evidence) -> CandidateEvidence {
    CandidateEvidence {
        id: evidence.id.clone(),
        rule_id: evidence.rule_id.clone(),
        kind: evidence.kind,
        capability: evidence.capability,
        location: evidence.location.clone(),
        enclosing_symbol: evidence.enclosing_symbol.clone(),
        confidence: evidence.confidence,
        provenance: evidence.provenance.clone(),
        context: evidence.context.clone(),
        symbol_resolution: evidence.symbol_resolution.clone(),
    }
}

fn candidate_title(_cwes: &[String], capability: Capability, sink_rule_id: &str) -> String {
    let behavior = match sink_rule_id {
        "c-family-signed-size-memory-operation" => {
            "signed length used as memory-operation size".to_string()
        }
        _ => semantic_rule_words(sink_rule_id)
            .unwrap_or_else(|| debug_words(&format!("{capability:?}"))),
    };
    sentence_case(&behavior)
}

fn sentence_case(value: &str) -> String {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    first.to_uppercase().chain(characters).collect()
}

fn semantic_rule_words(rule_id: &str) -> Option<String> {
    let without_language = [
        "javascript-",
        "typescript-",
        "csharp-",
        "python-",
        "java-",
        "rust-",
        "tsx-",
        "go-",
    ]
    .iter()
    .find_map(|prefix| rule_id.strip_prefix(prefix))
    .unwrap_or(rule_id);
    let without_review = without_language
        .strip_suffix("-review")
        .unwrap_or(without_language);
    let words = without_review
        .split(['-', '_'])
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    (words.split_whitespace().count() >= 2).then_some(words)
}

pub(crate) fn debug_words(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);
    for (index, character) in value.chars().enumerate() {
        if index > 0 && character.is_uppercase() {
            output.push(' ');
        }
        output.extend(character.to_lowercase());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_titles_prefer_sink_rule_semantics_to_broad_capabilities() {
        assert_eq!(
            candidate_title(
                &["CWE-312".to_string()],
                Capability::ResourceAccess,
                "typescript-plaintext-totp-storage",
            ),
            "Plaintext totp storage"
        );
        assert_eq!(
            candidate_title(
                &["CWE-352".to_string()],
                Capability::ResourceAccess,
                "go-cookie-authenticated-state-change-review",
            ),
            "Cookie authenticated state change"
        );
        assert_eq!(
            candidate_title(
                &["CWE-195".to_string(), "CWE-681".to_string()],
                Capability::SignedSizeMemoryOperation,
                "c-family-signed-size-memory-operation",
            ),
            "Signed length used as memory-operation size"
        );
        assert!(
            !candidate_title(
                &["CWE-195".to_string()],
                Capability::SignedSizeMemoryOperation,
                "c-family-signed-size-memory-operation",
            )
            .contains("CWE")
        );
    }
}
