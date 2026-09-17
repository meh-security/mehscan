use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::sarif::{
    SarifArtifactLocation, SarifCodeFlow, SarifLocation, SarifMessage, SarifPhysicalLocation,
    SarifRegion, SarifStepProperties, SarifThreadFlow, SarifThreadFlowLocation,
};
use crate::{
    FindingReport, FindingStatus, Location, ReportedFinding, ReviewConfidence, SARIF_SCHEMA_URI,
    SARIF_VERSION, SecurityPathStepKind, Severity,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSarifLog {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<FindingSarifRun>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSarifRun {
    pub tool: FindingSarifTool,
    pub automation_details: FindingSarifAutomationDetails,
    pub column_kind: String,
    pub results: Vec<FindingSarifResult>,
    pub properties: FindingSarifRunProperties,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSarifTool {
    pub driver: FindingSarifDriver,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSarifDriver {
    pub name: String,
    pub semantic_version: String,
    pub rules: Vec<FindingSarifRule>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSarifRule {
    pub id: String,
    pub name: String,
    pub short_description: SarifMessage,
    pub full_description: SarifMessage,
    pub default_configuration: FindingSarifConfiguration,
    pub help: SarifMessage,
    pub properties: FindingSarifRuleProperties,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSarifConfiguration {
    pub level: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSarifRuleProperties {
    pub tags: Vec<String>,
    pub cwes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSarifResult {
    pub rule_id: String,
    pub rule_index: usize,
    pub kind: String,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_locations: Vec<SarifLocation>,
    pub partial_fingerprints: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_flows: Vec<SarifCodeFlow>,
    pub properties: FindingSarifResultProperties,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSarifResultProperties {
    pub status: FindingStatus,
    pub confidence: ReviewConfidence,
    pub category: crate::Capability,
    pub cwes: Vec<String>,
    pub review_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingSarifAutomationDetails {
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingSarifRunProperties {
    pub report_kind: String,
    pub finding_report_schema_version: String,
    pub scan_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
    pub job_fingerprint: String,
    pub reviewed: usize,
    pub finding_count: usize,
    pub review_required_count: usize,
    pub dismissed_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quality_warnings: Vec<String>,
}

impl FindingSarifLog {
    pub fn from_finding_report(report: &FindingReport) -> Self {
        let rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<BTreeSet<_>>();
        let mut rule_indexes = BTreeMap::new();
        let mut rules = Vec::new();
        for rule_id in rule_ids {
            let index = rules.len();
            let finding = report
                .findings
                .iter()
                .find(|finding| finding.rule_id == rule_id)
                .expect("a collected rule ID has a finding");
            rules.push(finding_rule(finding));
            rule_indexes.insert(rule_id, index);
        }
        let results = report
            .findings
            .iter()
            .map(|finding| finding_result(finding, rule_indexes[&finding.rule_id.as_str()]))
            .collect();
        let automation_id = report
            .triage
            .reviewer
            .as_deref()
            .map(|reviewer| format!("mehscan/triaged/{reviewer}"))
            .unwrap_or_else(|| "mehscan/triaged".to_string());
        Self {
            schema: SARIF_SCHEMA_URI.to_string(),
            version: SARIF_VERSION.to_string(),
            runs: vec![FindingSarifRun {
                tool: FindingSarifTool {
                    driver: FindingSarifDriver {
                        name: report.tool.name.clone(),
                        semantic_version: report.tool.version.clone(),
                        rules,
                    },
                },
                automation_details: FindingSarifAutomationDetails { id: automation_id },
                column_kind: "unicodeCodePoints".to_string(),
                results,
                properties: FindingSarifRunProperties {
                    report_kind: report.report_kind.clone(),
                    finding_report_schema_version: report.schema_version.clone(),
                    scan_root: report.scan.root.clone(),
                    scope: report.scan.scope.clone(),
                    job_fingerprint: report.scan.job_fingerprint.clone(),
                    reviewed: report.summary.reviewed,
                    finding_count: report.summary.findings,
                    review_required_count: report.summary.review_required,
                    dismissed_count: report.summary.dismissed,
                    quality_warnings: report.quality_warnings.clone(),
                },
            }],
        }
    }
}

fn finding_rule(finding: &ReportedFinding) -> FindingSarifRule {
    let mut tags = vec!["security".to_string()];
    tags.extend(finding.cwes.iter().cloned());
    tags.sort();
    tags.dedup();
    FindingSarifRule {
        id: finding.rule_id.clone(),
        name: sarif_rule_name(&finding.rule_id),
        short_description: SarifMessage {
            text: finding.title.clone(),
        },
        full_description: SarifMessage {
            text: finding.title.clone(),
        },
        default_configuration: FindingSarifConfiguration {
            level: severity_level(finding.severity.level).to_string(),
        },
        help: SarifMessage {
            text: finding
                .remediation
                .as_ref()
                .map(|remediation| remediation.text.clone())
                .unwrap_or_else(|| finding.title.clone()),
        },
        properties: FindingSarifRuleProperties {
            tags,
            cwes: finding.cwes.clone(),
        },
    }
}

fn finding_result(finding: &ReportedFinding, rule_index: usize) -> FindingSarifResult {
    let related_locations = finding
        .related_locations
        .iter()
        .enumerate()
        .map(|(index, related)| {
            finding_location(
                &related.location,
                Some(index + 1),
                Some(format!("{:?} evidence", related.role).to_ascii_lowercase()),
            )
        })
        .collect();
    let code_flows = finding
        .flow
        .as_ref()
        .map(|flow| SarifCodeFlow {
            message: SarifMessage {
                text: "Deterministic bounded security path".to_string(),
            },
            thread_flows: vec![SarifThreadFlow {
                locations: flow
                    .steps
                    .iter()
                    .enumerate()
                    .map(|(index, step)| SarifThreadFlowLocation {
                        location: finding_location(
                            &step.location,
                            None,
                            Some(format!("{:?}", step.kind).to_ascii_lowercase()),
                        ),
                        execution_order: index,
                        importance: if matches!(
                            step.kind,
                            SecurityPathStepKind::Source
                                | SecurityPathStepKind::Sink
                                | SecurityPathStepKind::Protection
                                | SecurityPathStepKind::IneffectiveProtection
                        ) {
                            "essential"
                        } else {
                            "important"
                        }
                        .to_string(),
                        properties: SarifStepProperties {
                            step_kind: step.kind,
                            evidence_id: step.evidence_id.clone(),
                            symbol: step.symbol.clone(),
                        },
                    })
                    .collect(),
            }],
        })
        .into_iter()
        .collect();
    FindingSarifResult {
        rule_id: finding.rule_id.clone(),
        rule_index,
        kind: "fail".to_string(),
        level: severity_level(finding.severity.level).to_string(),
        message: SarifMessage {
            text: format!("{}: {}", finding.title, finding.description),
        },
        locations: vec![finding_location(&finding.primary_location, None, None)],
        related_locations,
        partial_fingerprints: BTreeMap::from([(
            "mehscanFinding/v1".to_string(),
            finding.id.clone(),
        )]),
        code_flows,
        properties: FindingSarifResultProperties {
            status: finding.status,
            confidence: finding.confidence,
            category: finding.category,
            cwes: finding.cwes.clone(),
            review_ids: finding.provenance.review_ids.clone(),
        },
    }
}

fn severity_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High | Severity::Medium | Severity::Unknown => "warning",
        Severity::Low | Severity::Note => "note",
    }
}

fn sarif_rule_name(rule_id: &str) -> String {
    let mut name = String::with_capacity(rule_id.len());
    for character in rule_id.chars() {
        if character.is_ascii_alphanumeric() {
            name.push(character);
        } else if !name.ends_with('_') {
            name.push('_');
        }
    }
    name.trim_matches('_').to_string()
}

fn finding_location(
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
    use super::*;

    #[test]
    fn unknown_severity_remains_a_warning_for_older_reports() {
        assert_eq!(severity_level(Severity::Unknown), "warning");
    }

    #[test]
    fn rule_names_are_portable_identifiers() {
        assert_eq!(
            sarif_rule_name("typescript-sql/raw.query"),
            "typescript_sql_raw_query"
        );
    }
}
