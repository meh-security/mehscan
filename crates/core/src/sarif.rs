use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::candidate::debug_words;
use crate::{
    Candidate, CandidateBuildError, CandidateClassification, CandidateReport, Capability,
    Confidence, Coverage, Location, Provenance, ScanResult, SecurityPathProvenance,
    SecurityPathState, SecurityPathStepKind,
};

pub const SARIF_VERSION: &str = "2.1.0";
pub const SARIF_SCHEMA_URI: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRun {
    pub tool: SarifTool,
    pub column_kind: String,
    pub results: Vec<SarifResult>,
    pub properties: SarifRunProperties,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifDriver {
    pub name: String,
    pub semantic_version: String,
    pub rules: Vec<SarifRule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub full_description: SarifMessage,
    pub properties: SarifRuleProperties,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRuleProperties {
    pub classification: CandidateClassification,
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResult {
    pub rule_id: String,
    pub rule_index: usize,
    pub kind: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<SarifLocation>,
    pub partial_fingerprints: BTreeMap<String, String>,
    pub code_flows: Vec<SarifCodeFlow>,
    pub properties: SarifResultProperties,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifLocation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<usize>,
    pub physical_location: SarifPhysicalLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<SarifMessage>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifPhysicalLocation {
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRegion {
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub byte_offset: usize,
    pub byte_length: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifCodeFlow {
    pub message: SarifMessage,
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    pub execution_order: usize,
    pub importance: String,
    pub properties: SarifStepProperties,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifStepProperties {
    pub step_kind: SecurityPathStepKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifResultProperties {
    pub classification: CandidateClassification,
    pub candidate_id: String,
    pub security_path_state: SecurityPathState,
    pub capability: Capability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_candidates: Vec<String>,
    pub source_evidence_id: String,
    pub sink_evidence_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protection_evidence_ids: Vec<String>,
    pub source_rule_id: String,
    pub sink_rule_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protection_rule_ids: Vec<String>,
    pub source_capability: Capability,
    pub source_confidence: Confidence,
    pub sink_confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protection_capabilities: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protection_confidences: Vec<Confidence>,
    pub source_provenance: Provenance,
    pub sink_provenance: Provenance,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protection_provenance: Vec<Provenance>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncertainty_reasons: Vec<String>,
    pub path_provenance: SecurityPathProvenance,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SarifRunProperties {
    pub report_kind: String,
    pub candidate_report_schema_version: String,
    pub scan_schema_version: String,
    pub scan_root: String,
    pub evidence_count: usize,
    pub security_path_count: usize,
    pub candidate_count: usize,
    pub coverage: Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub impact_scope: Option<crate::ImpactScanScope>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CandidateRuleKey {
    capability: Capability,
    cwe_candidates: Vec<String>,
}

impl SarifLog {
    pub fn from_scan(result: &ScanResult) -> Result<Self, CandidateBuildError> {
        let report = CandidateReport::from_scan(result)?;
        Ok(Self::from_candidate_report(&report))
    }

    pub fn from_candidate_report(report: &CandidateReport) -> Self {
        let keys = report
            .candidates
            .iter()
            .map(candidate_rule_key)
            .collect::<BTreeSet<_>>();
        let mut rule_indexes = BTreeMap::new();
        let mut rules = Vec::with_capacity(keys.len());
        for key in keys {
            let index = rules.len();
            rules.push(sarif_rule(&key));
            rule_indexes.insert(key, index);
        }
        let results = report
            .candidates
            .iter()
            .map(|candidate| {
                let key = candidate_rule_key(candidate);
                let rule_index = rule_indexes[&key];
                sarif_result(candidate, rule_index, &rules[rule_index].id)
            })
            .collect();

        Self {
            schema: SARIF_SCHEMA_URI.to_string(),
            version: SARIF_VERSION.to_string(),
            runs: vec![SarifRun {
                tool: SarifTool {
                    driver: SarifDriver {
                        name: "Mehscan".to_string(),
                        semantic_version: env!("CARGO_PKG_VERSION").to_string(),
                        rules,
                    },
                },
                column_kind: "unicodeCodePoints".to_string(),
                results,
                properties: SarifRunProperties {
                    report_kind: "security_path_candidates".to_string(),
                    candidate_report_schema_version: report.schema_version.clone(),
                    scan_schema_version: report.scan_schema_version.clone(),
                    scan_root: report.root.clone(),
                    evidence_count: report.evidence_count,
                    security_path_count: report.security_path_count,
                    candidate_count: report.candidates.len(),
                    coverage: report.coverage.clone(),
                    impact_scope: report.impact_scope.clone(),
                },
            }],
        }
    }
}

fn candidate_rule_key(candidate: &Candidate) -> CandidateRuleKey {
    CandidateRuleKey {
        capability: candidate.capability,
        cwe_candidates: candidate.cwe_candidates.clone(),
    }
}

fn sarif_rule(key: &CandidateRuleKey) -> SarifRule {
    let capability = debug_words(&format!("{:?}", key.capability));
    let cwes = cwe_label(&key.cwe_candidates);
    let id = format!(
        "MEHSCAN.{}.{}",
        if key.cwe_candidates.is_empty() {
            "SECURITY".to_string()
        } else {
            key.cwe_candidates.join(".")
        },
        capability.replace(' ', "-")
    );
    let mut tags = vec!["security".to_string(), "candidate".to_string()];
    tags.extend(key.cwe_candidates.iter().cloned());
    SarifRule {
        id,
        name: format!("{cwes} {capability} candidate"),
        short_description: SarifMessage {
            text: format!("Review bounded {cwes} paths to {capability}"),
        },
        full_description: SarifMessage {
            text: format!(
                "Mehscan observed a deterministic bounded relationship to {capability}. Results from this rule are review candidates, not confirmed vulnerabilities."
            ),
        },
        properties: SarifRuleProperties {
            classification: CandidateClassification::SecurityPath,
            capability: key.capability,
            cwe_candidates: key.cwe_candidates.clone(),
            tags,
        },
    }
}

fn sarif_result(candidate: &Candidate, rule_index: usize, rule_id: &str) -> SarifResult {
    let mut related_locations = vec![sarif_location(
        &candidate.source.location,
        Some(1),
        Some(format!("Source evidence {}", candidate.source.id)),
    )];
    related_locations.extend(candidate.protections.iter().enumerate().map(
        |(index, protection)| {
            sarif_location(
                &protection.location,
                Some(index + 2),
                Some(format!("Contextual protection evidence {}", protection.id)),
            )
        },
    ));
    let locations = vec![sarif_location(
        &candidate.primary_location,
        None,
        Some(format!("Sink evidence {}", candidate.sink.id)),
    )];
    let thread_locations = candidate
        .steps
        .iter()
        .enumerate()
        .map(|(index, step)| SarifThreadFlowLocation {
            location: sarif_location(
                &step.location,
                None,
                Some(step_message(step.kind, step.symbol.as_deref())),
            ),
            execution_order: index,
            importance: match step.kind {
                SecurityPathStepKind::Source
                | SecurityPathStepKind::Protection
                | SecurityPathStepKind::IneffectiveProtection
                | SecurityPathStepKind::Sink => "essential",
                SecurityPathStepKind::Assignment | SecurityPathStepKind::Alias => "important",
            }
            .to_string(),
            properties: SarifStepProperties {
                step_kind: step.kind,
                evidence_id: step.evidence_id.clone(),
                symbol: step.symbol.clone(),
            },
        })
        .collect();
    let mut partial_fingerprints = BTreeMap::new();
    partial_fingerprints.insert("mehscanSecurityPath/v1".to_string(), candidate.id.clone());

    SarifResult {
        rule_id: rule_id.to_string(),
        rule_index,
        kind: "review".to_string(),
        level: match candidate.state {
            SecurityPathState::Direct | SecurityPathState::Propagated => "warning",
            SecurityPathState::Protected | SecurityPathState::Unknown => "note",
        }
        .to_string(),
        message: SarifMessage {
            text: candidate_message(candidate),
        },
        locations,
        related_locations,
        partial_fingerprints,
        code_flows: vec![SarifCodeFlow {
            message: SarifMessage {
                text: "Bounded source-to-sink path".to_string(),
            },
            thread_flows: vec![SarifThreadFlow {
                locations: thread_locations,
            }],
        }],
        properties: SarifResultProperties {
            classification: candidate.classification,
            candidate_id: candidate.id.clone(),
            security_path_state: candidate.state,
            capability: candidate.capability,
            cwe_candidates: candidate.cwe_candidates.clone(),
            source_evidence_id: candidate.source.id.clone(),
            sink_evidence_id: candidate.sink.id.clone(),
            protection_evidence_ids: candidate
                .protections
                .iter()
                .map(|item| item.id.clone())
                .collect(),
            source_rule_id: candidate.source.rule_id.clone(),
            sink_rule_id: candidate.sink.rule_id.clone(),
            protection_rule_ids: candidate
                .protections
                .iter()
                .map(|item| item.rule_id.clone())
                .collect(),
            source_capability: candidate.source.capability,
            source_confidence: candidate.source.confidence,
            sink_confidence: candidate.sink.confidence,
            protection_capabilities: candidate
                .protections
                .iter()
                .map(|item| item.capability)
                .collect(),
            protection_confidences: candidate
                .protections
                .iter()
                .map(|item| item.confidence)
                .collect(),
            source_provenance: candidate.source.provenance.clone(),
            sink_provenance: candidate.sink.provenance.clone(),
            protection_provenance: candidate
                .protections
                .iter()
                .map(|item| item.provenance.clone())
                .collect(),
            uncertainty_reasons: candidate.uncertainty_reasons.clone(),
            path_provenance: candidate.provenance.clone(),
        },
    }
}

fn candidate_message(candidate: &Candidate) -> String {
    let capability = debug_words(&format!("{:?}", candidate.capability));
    let cwes = cwe_label(&candidate.cwe_candidates);
    let state = match candidate.state {
        SecurityPathState::Direct => "directly",
        SecurityPathState::Propagated => "through bounded local propagation",
        SecurityPathState::Protected => "with contextual protection evidence",
        SecurityPathState::Unknown => "with an unknown path state",
    };
    let suffix = if candidate.state == SecurityPathState::Protected {
        " The protection is context for review and is not a safe verdict."
    } else {
        ""
    };
    format!(
        "Review candidate: source evidence reaches {capability} {state} ({cwes}). This is not a confirmed vulnerability.{suffix}"
    )
}

fn step_message(kind: SecurityPathStepKind, symbol: Option<&str>) -> String {
    let kind = debug_words(&format!("{kind:?}"));
    match symbol {
        Some(symbol) => format!("{kind}: {symbol}"),
        None => kind,
    }
}

fn cwe_label(cwes: &[String]) -> String {
    if cwes.is_empty() {
        "security".to_string()
    } else {
        cwes.join("/")
    }
}

fn sarif_location(
    location: &Location,
    id: Option<usize>,
    message: Option<String>,
) -> SarifLocation {
    SarifLocation {
        id,
        physical_location: SarifPhysicalLocation {
            artifact_location: SarifArtifactLocation {
                uri: uri_reference(&location.path),
            },
            region: SarifRegion {
                start_line: location.start.line,
                start_column: location.start.column,
                end_line: location.end.line,
                end_column: location.end.column,
                byte_offset: location.start.byte_offset,
                byte_length: location
                    .end
                    .byte_offset
                    .saturating_sub(location.start.byte_offset),
            },
        },
        message: message.map(|text| SarifMessage { text }),
    }
}

fn uri_reference(path: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut uri = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte == b'\\' {
            uri.push('/');
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::uri_reference;

    #[test]
    fn creates_portable_uri_references() {
        assert_eq!(
            uri_reference("source folder\\café.js"),
            "source%20folder/caf%C3%A9.js"
        );
    }
}
