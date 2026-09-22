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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<crate::CoverageTotals>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FindingReportTriage {
    pub response_schema_version: String,
    #[serde(default)]
    pub response_fingerprint: String,
    #[serde(default)]
    pub work: crate::ReviewWorkSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repairs: Vec<crate::ReviewRepairTrace>,
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
    /// Policy references are not proof that the reported operation is gated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_feature_policies: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_location: Option<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
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

impl FindingReport {
    /// Renders the canonical finding report for human review. Machine consumers
    /// should continue to use the JSON representation or the SARIF projection.
    pub fn to_markdown(&self) -> String {
        let mut output = String::new();
        output.push_str("# Mehscan security report\n\n");
        output.push_str(&format!(
            "- Scanner: {} {}\n- Scan root: {}\n- Review fingerprint: {}\n",
            markdown_text(&self.tool.name),
            markdown_text(&self.tool.version),
            markdown_code_span(&self.scan.root),
            markdown_code_span(&self.scan.job_fingerprint)
        ));
        if let Some(reviewer) = &self.triage.reviewer {
            output.push_str(&format!("- Reviewer: {}\n", markdown_code_span(reviewer)));
        }

        output.push_str("\n## Summary\n\n");
        output.push_str("| Outcome | Count | Meaning |\n| --- | ---: | --- |\n");
        output.push_str(&format!(
            "| Confirmed finding instances | {} | Supported by the supplied evidence; not a unique-vulnerability total |\n",
            self.summary.findings
        ));
        output.push_str(&format!(
            "| Review required | {} | A named missing fact can change the verdict |\n",
            self.summary.review_required
        ));
        output.push_str(&format!(
            "| Not issues | {} | Supplied evidence did not establish the reviewed weakness |\n",
            self.summary.dismissed
        ));
        output.push_str(&format!(
            "| Decisions reviewed | {} | {} issue, {} needs review, {} not issue |\n",
            self.summary.reviewed,
            self.summary.issue_decisions,
            self.summary.needs_review_decisions,
            self.summary.not_issue_decisions
        ));
        if !self.triage.repairs.is_empty()
            || self.triage.work.scheduled_review_count > 0
            || !self.triage.work.missing_review_ids.is_empty()
            || !self.triage.work.invalid_review_ids.is_empty()
        {
            output.push_str(&format!(
                "| Review work | {}/{} scheduled completed; {} admitted | {} accepted investigation traces; {} repaired, {} deferred, {} blocked, {} truncated, {} missing, {} invalid |\n",
                self.triage.work.completed_review_count,
                self.triage.work.scheduled_review_count,
                self.triage.work.admitted_review_count,
                self.triage.work.accepted_investigation_count,
                self.triage.repairs.len(),
                self.triage.work.deferred_review_ids.len(),
                self.triage.work.blocked_review_ids.len(),
                self.triage.work.truncated_review_ids.len(),
                self.triage.work.missing_review_ids.len(),
                self.triage.work.invalid_review_ids.len()
            ));
        }

        output.push_str("\n## Scope and limitations\n\nStatic source conclusions do not establish deployed activation or external exploitation. Any isolated execution checks apply only to the controls identified in the scope label. Ignored and unsupported material is outside coverage. Severity defaults are not a validated impact ranking.\n\n");
        if let Some(coverage) = &self.scan.coverage {
            output.push_str(&format!("Files: {} discovered, {} scanned, {} ignored, {} parse-failed, {} unsupported. Parse-failed files may retain partial evidence outside invalid syntax.\n\n", coverage.discovered, coverage.scanned, coverage.ignored, coverage.parse_failed, coverage.unsupported));
        } else {
            output.push_str("Coverage totals were not recorded in this legacy review run.\n\n");
        }
        for scope in &self.scan.scope {
            output.push_str(&format!("- {}\n", markdown_text(scope)));
        }

        output.push_str("\n## Review next\n\n");
        if self.review_required.is_empty() {
            output.push_str("No findings require additional review.\n");
        } else {
            output.push_str(
                "Resolve these evidence gaps first. Each check names the fact needed to reach a decisive verdict.\n\n",
            );
            for (index, finding) in self.review_required.iter().enumerate() {
                render_finding(&mut output, index + 1, finding, true);
            }
        }

        output.push_str("\n## Confirmed issues\n\n");
        if self.findings.is_empty() {
            output.push_str("No confirmed issues were reported.\n");
        } else {
            for (index, group) in grouped_confirmed_findings(&self.findings)
                .into_iter()
                .enumerate()
            {
                if group.len() == 1 {
                    render_finding(&mut output, index + 1, group[0], false);
                } else {
                    render_finding_group(&mut output, index + 1, &group);
                }
            }
        }

        output.push_str("\n## Not issues\n\n");
        if self.summary.dismissed == 0 {
            output.push_str("No candidates were dismissed as not issues.\n");
        } else if self.dismissed.is_empty() {
            output.push_str(&format!(
                "{} candidates were dismissed. Re-run with `--include-dismissed true` to include their summaries.\n",
                self.summary.dismissed
            ));
        } else {
            for dismissed in &self.dismissed {
                let location = dismissed
                    .primary_location
                    .as_ref()
                    .map(|location| {
                        format!(
                            " at {}",
                            markdown_code_span(&format!(
                                "{}:{}:{}",
                                location.path, location.start.line, location.start.column
                            ))
                        )
                    })
                    .unwrap_or_default();
                output.push_str(&format!(
                    "- {}{} ({} confidence): {}\n",
                    markdown_code_span(&dismissed.review_id),
                    location,
                    enum_label(dismissed.confidence),
                    markdown_description(&dismissed.description)
                ));
            }
        }

        if !self.quality_warnings.is_empty() {
            output.push_str("\n## Quality warnings\n\n");
            for warning in &self.quality_warnings {
                let warning = if warning.starts_with("review_kind_correlation:") {
                    format!(
                        "{warning}; this correlation applies only to this report's reviewed selection and does not establish a model-wide error"
                    )
                } else {
                    warning.clone()
                };
                output.push_str(&format!("- {}\n", markdown_text(&warning)));
            }
        }

        output
    }
}

fn grouped_confirmed_findings(findings: &[ReportedFinding]) -> Vec<Vec<&ReportedFinding>> {
    let mut groups: Vec<Vec<&ReportedFinding>> = Vec::new();
    for finding in findings {
        let remediation = finding
            .remediation
            .as_ref()
            .map(|value| value.text.as_str());
        if let Some(group) = groups.iter_mut().find(|group| {
            let first = group[0];
            first.title == finding.title
                && first.category == finding.category
                && first.remediation.as_ref().map(|value| value.text.as_str()) == remediation
        }) {
            group.push(finding);
        } else {
            groups.push(vec![finding]);
        }
    }
    groups
}

fn render_finding_group(output: &mut String, index: usize, findings: &[&ReportedFinding]) {
    let first = findings[0];
    let mut cwes = findings
        .iter()
        .flat_map(|finding| finding.cwes.iter())
        .collect::<Vec<_>>();
    cwes.sort();
    cwes.dedup();
    output.push_str(&format!(
        "### {}. {} ({} instances)\n\n- Category: {}\n- CWE: {}\n",
        index,
        markdown_text(&first.title),
        findings.len(),
        enum_label(first.category),
        if cwes.is_empty() {
            "unspecified".to_string()
        } else {
            cwes.into_iter()
                .map(|cwe| markdown_text(cwe))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));
    if let Some(remediation) = &first.remediation {
        output.push_str(&format!(
            "\nRemediation: {}\n",
            markdown_text(&remediation.text)
        ));
    }
    for (instance, finding) in findings.iter().enumerate() {
        output.push_str(&format!(
            "\n#### Instance {}\n\n- Location: {}\n- Severity: {} ({})\n- Confidence: {}\n\n{}\n",
            instance + 1,
            markdown_code_span(&format!(
                "{}:{}:{}",
                finding.primary_location.path,
                finding.primary_location.start.line,
                finding.primary_location.start.column
            )),
            enum_label(finding.severity.level),
            enum_label(finding.severity.source),
            enum_label(finding.confidence),
            markdown_description(&finding.description)
        ));
        render_availability(output, finding);
        render_flow(output, finding);
        render_related_locations(output, finding);
        render_review_ids(output, finding);
    }
    output.push('\n');
}

fn render_finding(
    output: &mut String,
    index: usize,
    finding: &ReportedFinding,
    include_checks: bool,
) {
    output.push_str(&format!(
        "### {}. {}\n\n- Location: {}\n- Category: {}\n- CWE: {}\n- Severity: {} ({})\n- Confidence: {}\n\n{}\n",
        index,
        markdown_text(&finding.title),
        markdown_code_span(&format!(
            "{}:{}:{}",
            finding.primary_location.path,
            finding.primary_location.start.line,
            finding.primary_location.start.column
        )),
        enum_label(finding.category),
        if finding.cwes.is_empty() {
            "unspecified".to_string()
        } else {
            finding
                .cwes
                .iter()
                .map(|cwe| markdown_text(cwe))
                .collect::<Vec<_>>()
                .join(", ")
        },
        enum_label(finding.severity.level),
        enum_label(finding.severity.source),
        enum_label(finding.confidence),
        markdown_description(&finding.description)
    ));

    render_availability(output, finding);
    render_flow(output, finding);
    render_related_locations(output, finding);
    render_review_ids(output, finding);

    if include_checks {
        output.push_str("\nRequired checks:\n\n");
        for check in &finding.checks {
            output.push_str(&format!("- {}\n", markdown_text(check)));
        }
    } else if let Some(remediation) = &finding.remediation {
        output.push_str(&format!(
            "\nRemediation: {}\n",
            markdown_text(&remediation.text)
        ));
    }
    output.push('\n');
}

fn render_related_locations(output: &mut String, finding: &ReportedFinding) {
    if finding.related_locations.is_empty() {
        return;
    }
    output.push_str(if finding.flow.is_some() {
        "\nRelated evidence locations:\n\n"
    } else {
        "\nRelated evidence locations (inventory/context; no native flow asserted):\n\n"
    });
    for related in &finding.related_locations {
        output.push_str(&format!(
            "- {}: {}\n",
            enum_label(related.role),
            markdown_code_span(&format!(
                "{}:{}:{}",
                related.location.path, related.location.start.line, related.location.start.column
            ))
        ));
    }
}

fn render_review_ids(output: &mut String, finding: &ReportedFinding) {
    if !finding.provenance.review_ids.is_empty() {
        output.push_str(&format!(
            "\n- Review IDs: {}\n",
            finding
                .provenance
                .review_ids
                .iter()
                .map(|id| markdown_code_span(id))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_flow(output: &mut String, finding: &ReportedFinding) {
    let Some(flow) = &finding.flow else { return };
    let locations = flow
        .steps
        .iter()
        .filter(|step| {
            matches!(
                step.kind,
                crate::SecurityPathStepKind::Source | crate::SecurityPathStepKind::Sink
            )
        })
        .map(|step| {
            markdown_code_span(&format!(
                "{}:{}:{}",
                step.location.path, step.location.start.line, step.location.start.column
            ))
        })
        .collect::<Vec<_>>();
    if locations.len() > 1 {
        output.push_str(&format!("\nFlow: {}\n", locations.join(" → ")));
    }
}

fn enum_label(value: impl std::fmt::Debug) -> String {
    let debug = format!("{value:?}");
    let mut label = String::new();
    for (index, character) in debug.chars().enumerate() {
        if index > 0 && character.is_uppercase() {
            label.push(' ');
        }
        label.extend(character.to_lowercase());
    }
    label
}

fn render_availability(output: &mut String, finding: &ReportedFinding) {
    for policy in &finding.related_feature_policies {
        output.push_str(&format!("\n- Related feature policy: {} (association only; runtime gating is not established)\n", markdown_text(policy)));
    }
    if let Some(availability) = &finding.context.availability
        && availability.state != crate::AvailabilityState::Always
    {
        output.push_str(&format!(
            "\n- Source availability: {}",
            enum_label(availability.state)
        ));
        if let Some(condition) = &availability.condition {
            output.push_str(&format!(" — {}", markdown_text(condition)));
        }
        output.push('\n');
    }
}

fn markdown_text(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace(['\r', '\n'], " ")
        .replace('*', "\\*")
        .replace('_', "\\_")
        .replace('[', "\\[")
        .replace(']', "\\]")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn markdown_description(value: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    while let Some(relative) = value[cursor..].find('`') {
        let start = cursor + relative;
        let fence_len = value[start..].bytes().take_while(|b| *b == b'`').count();
        let content_start = start + fence_len;
        let mut search = content_start;
        let mut closing = None;
        while let Some(relative) = value[search..].find('`') {
            let candidate = search + relative;
            let run = value[candidate..]
                .bytes()
                .take_while(|b| *b == b'`')
                .count();
            if run == fence_len {
                closing = Some(candidate);
                break;
            }
            search = candidate + run;
        }
        let Some(end) = closing else { break };
        output.push_str(&markdown_text(&value[cursor..start]).replace('`', "\\`"));
        let content = value[content_start..end]
            .replace("\r\n", " ")
            .replace(['\r', '\n'], " ");
        let content = if content.starts_with(' ')
            && content.ends_with(' ')
            && content.chars().any(|c| c != ' ')
        {
            &content[1..content.len() - 1]
        } else {
            &content
        };
        output.push_str(&markdown_code_span(content));
        cursor = end + fence_len;
    }
    output.push_str(&markdown_text(&value[cursor..]).replace('`', "\\`"));
    output
}

fn markdown_code_span(value: &str) -> String {
    let value = value.replace("\r\n", " ").replace(['\r', '\n'], " ");
    let longest_run = value
        .split(|character| character != '`')
        .map(str::len)
        .max()
        .unwrap_or(0);
    let fence = "`".repeat(longest_run + 1);
    let padding = if value.starts_with('`')
        || value.ends_with('`')
        || value.starts_with(' ') && value.ends_with(' ') && value.chars().any(|c| c != ' ')
    {
        " "
    } else {
        ""
    };
    format!("{fence}{padding}{value}{padding}{fence}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptions_preserve_code_identifiers_while_escaping_prose() {
        assert_eq!(
            markdown_description("Use `fixture_people` and `<em>own</em>`; prose <b>_x_</b>."),
            "Use `fixture_people` and `<em>own</em>`; prose &lt;b&gt;\\_x\\_&lt;/b&gt;."
        );
        assert_eq!(
            markdown_description("Use `` `quoted` ``."),
            "Use `` `quoted` ``."
        );
        assert_eq!(markdown_description("Use `one\r\ntwo`."), "Use `one two`.");
        assert_eq!(
            markdown_description("Unclosed `fixture_people"),
            "Unclosed \\`fixture\\_people"
        );
        assert_eq!(markdown_code_span(" name "), "`  name  `");
    }
    use crate::Position;

    fn location(path: &str, line: usize) -> Location {
        Location {
            path: path.to_string(),
            start: Position {
                line,
                column: 3,
                byte_offset: 0,
            },
            end: Position {
                line,
                column: 9,
                byte_offset: 6,
            },
        }
    }

    fn finding(status: FindingStatus, checks: Vec<String>) -> ReportedFinding {
        ReportedFinding {
            id: "finding-1".to_string(),
            rule_id: "typescript-database-query".to_string(),
            title: "Unsafe query".to_string(),
            description: "Request input reaches the query sink.".to_string(),
            status,
            severity: ReportedSeverity {
                level: Severity::High,
                source: SeveritySource::RuleDefault,
            },
            confidence: ReviewConfidence::Medium,
            category: Capability::DatabaseQuery,
            cwes: vec!["CWE-89".to_string()],
            language: None,
            primary_location: location("routes/search.ts", 23),
            context: EvidenceContext::default(),
            related_feature_policies: Vec::new(),
            flow: None,
            related_locations: Vec::new(),
            checks,
            remediation: None,
            provenance: FindingProvenance {
                review_ids: vec!["review-1".to_string()],
                evidence_ids: vec!["evidence-1".to_string()],
            },
        }
    }

    #[test]
    fn markdown_keeps_observation_sources_without_inventing_a_native_flow() {
        let mut item = finding(FindingStatus::Issue, Vec::new());
        item.related_locations.push(FindingRelatedLocation {
            role: EvidenceKind::Source,
            location: location("routes/input.kt", 10),
            evidence_id: Some("query-input".into()),
            rule_id: Some("kotlin-ktor-query-source".into()),
        });
        let mut standalone = String::new();
        render_finding(&mut standalone, 1, &item, false);
        let mut grouped = String::new();
        render_finding_group(&mut grouped, 1, &[&item, &item]);
        for markdown in [&standalone, &grouped] {
            assert!(markdown.contains("source: `routes/input.kt:10:3`"));
            assert!(markdown.contains("no native flow asserted"));
            assert!(!markdown.contains("Flow:"));
        }
        assert_eq!(grouped.matches("source: `routes/input.kt:10:3`").count(), 2);
    }

    #[test]
    fn markdown_shows_source_and_sink_from_canonical_flow() {
        let mut item = finding(FindingStatus::Issue, Vec::new());
        item.flow = Some(FindingFlow {
            steps: vec![
                SecurityPathStep {
                    kind: crate::SecurityPathStepKind::Source,
                    location: location("routes/input.kt", 10),
                    evidence_id: None,
                    symbol: Some("name".into()),
                },
                SecurityPathStep {
                    kind: crate::SecurityPathStepKind::Sink,
                    location: location("routes/query.kt", 23),
                    evidence_id: None,
                    symbol: Some("query".into()),
                },
            ],
        });
        let mut markdown = String::new();
        render_finding(&mut markdown, 1, &item, false);
        assert!(
            markdown.contains("Flow: `routes/input.kt:10:3` → `routes/query.kt:23:3`"),
            "{markdown}"
        );
        assert_eq!(
            markdown
                .matches("Request input reaches the query sink.")
                .count(),
            1
        );
    }

    #[test]
    fn markdown_prioritizes_review_checks_and_summarizes_all_outcomes() {
        let report = FindingReport {
            schema_version: FINDING_REPORT_SCHEMA_VERSION.to_string(),
            report_kind: "triaged_findings".to_string(),
            tool: FindingReportTool {
                name: "Mehscan".to_string(),
                version: "test".to_string(),
            },
            scan: FindingReportScan {
                root: ".".to_string(),
                job_fingerprint: "job-1".to_string(),
                coverage: None,
                scope: Vec::new(),
            },
            triage: FindingReportTriage {
                response_schema_version: "1.0".to_string(),
                response_fingerprint: "review-run-response-test".to_string(),
                work: crate::ReviewWorkSummary::default(),
                repairs: Vec::new(),
                reviewer: Some("reviewer-1".to_string()),
            },
            summary: FindingReportSummary {
                reviewed: 3,
                issue_decisions: 1,
                needs_review_decisions: 1,
                not_issue_decisions: 1,
                findings: 1,
                review_required: 1,
                dismissed: 1,
            },
            findings: vec![finding(FindingStatus::Issue, Vec::new())],
            review_required: vec![finding(
                FindingStatus::NeedsReview,
                vec!["Confirm the effective query parameterization.".to_string()],
            )],
            dismissed: vec![DismissedReview {
                review_id: "review-safe".to_string(),
                confidence: ReviewConfidence::High,
                description: "The value is a fixed repository literal.".to_string(),
                primary_location: Some(finding(FindingStatus::Issue, Vec::new()).primary_location),
                rule_id: Some("safe-rule".to_string()),
            }],
            quality_warnings: Vec::new(),
        };

        let markdown = report.to_markdown();
        assert!(markdown.contains("| Confirmed finding instances | 1 |"));
        assert!(markdown.contains("| Review required | 1 |"));
        assert!(markdown.contains("| Not issues | 1 |"));
        assert!(markdown.contains("`review-safe` at `routes/search.ts:23:3`"));
        let legacy: DismissedReview = serde_json::from_value(serde_json::json!({
            "review_id": "old-review", "confidence": "medium", "description": "Fixed literal."
        }))
        .expect("legacy dismissed review remains readable");
        assert!(legacy.primary_location.is_none());
        assert!(legacy.rule_id.is_none());
        assert!(markdown.contains("Confirm the effective query parameterization."));
        assert!(markdown.contains("`review-safe` at `routes/search.ts:23:3` (high confidence)"));
        assert!(
            markdown.find("## Review next").expect("review section")
                < markdown
                    .find("## Confirmed issues")
                    .expect("confirmed section")
        );
    }

    #[test]
    fn markdown_groups_same_root_cause_but_keeps_each_location() {
        let mut first = finding(FindingStatus::Issue, Vec::new());
        first.title = "Decoded length can exceed the remaining parser input".to_string();
        first.remediation = Some(FindingRemediation {
            text: "Compare the decoded length with total_size - cursor before reading.".to_string(),
            references: Vec::new(),
        });
        let mut second = first.clone();
        second.id = "finding-2".to_string();
        second.rule_id = "cpp-other-rule-for-same-invariant".to_string();
        second.primary_location = location("src/reader.cpp", 71);
        second.description = "A second decoder performs the same unchecked read.".to_string();
        second.provenance.review_ids = vec!["review-2".to_string()];
        let report = FindingReport {
            schema_version: FINDING_REPORT_SCHEMA_VERSION.to_string(),
            report_kind: "triaged_findings".to_string(),
            tool: FindingReportTool {
                name: "Mehscan".to_string(),
                version: "test".to_string(),
            },
            scan: FindingReportScan {
                root: ".".to_string(),
                job_fingerprint: "job-1".to_string(),
                coverage: None,
                scope: Vec::new(),
            },
            triage: FindingReportTriage {
                response_schema_version: "1.0".to_string(),
                response_fingerprint: "review-run-response-test".to_string(),
                work: crate::ReviewWorkSummary::default(),
                repairs: Vec::new(),
                reviewer: None,
            },
            summary: FindingReportSummary {
                reviewed: 2,
                issue_decisions: 2,
                needs_review_decisions: 0,
                not_issue_decisions: 0,
                findings: 2,
                review_required: 0,
                dismissed: 0,
            },
            findings: vec![first, second],
            review_required: Vec::new(),
            dismissed: Vec::new(),
            quality_warnings: Vec::new(),
        };

        let markdown = report.to_markdown();
        assert!(markdown.contains("(2 instances)"));
        assert!(markdown.contains("`routes/search.ts:23:3`"));
        assert!(markdown.contains("`src/reader.cpp:71:3`"));
        assert!(markdown.contains("`review-1`"));
        assert!(markdown.contains("`review-2`"));
        assert_eq!(markdown.matches("- Review IDs:").count(), 2);
        assert_eq!(markdown.matches("Remediation:").count(), 1);
        assert_eq!(markdown.matches("### 1.").count(), 1);
    }
}
