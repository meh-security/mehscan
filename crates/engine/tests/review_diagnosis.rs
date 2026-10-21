use mehscan_core::*;
use mehscan_engine::investigation::*;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> (
    Fixture,
    Vec<(PathReviewBundle, PathReviewBundleResponseSet)>,
) {
    let root = Fixture(std::env::temp_dir().join(format!(
        "mehscan-diagnosis-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    )));
    fs::create_dir_all(&root.0).unwrap();
    fs::write(root.0.join("app.js"), "const cp=require('node:child_process');\nfunction command(req){return cp.exec(req.query.command);}\nfunction contact(req){return User.findOne({where:{id:req.query.id}});}\nfunction repository(id){return User.findOne({where:{id}});}\n").unwrap();
    let job = build_all_path_review_jobs(&root.0, Some(100), false).unwrap();
    let bundles = build_path_review_bundles(&job, None).unwrap();
    let rows = bundles.bundles.into_iter().map(|bundle| {
        let results = bundle.review_ids.iter().map(|id| {
            let anchor = bundle_selected_anchor_id(&bundle, id).unwrap().to_string();
            PathReviewTriageResult {
                review_id:id.clone(), selected_anchor_id:Some(anchor.clone()), decision:ReviewDecision::Issue,
                confidence:ReviewConfidence::High, summary:"The supplied effect is described by the reviewer, independently of detector classification.".into(),
                diagnosis:None, checks:vec![], investigation:Some(ReviewInvestigationTrace {
                    citations:vec![ReviewArtifactCitation{artifact_id:anchor,claim:"Selected operation for this controller test.".into()}], ..Default::default()
                })
            }
        }).collect();
        let response = PathReviewBundleResponseSet{schema_version:PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.into(),bundle_fingerprint:bundle.bundle_fingerprint.clone(),results};
        (bundle,response)
    }).collect();
    (root, rows)
}

#[test]
fn reports_reviewed_effect_and_impact_without_promoting_candidate_classification() {
    // Synthetic reviewer assessments exercise report plumbing, not AI accuracy.
    let (_root, mut rows) = fixture();
    assert!(
        rows.iter()
            .any(|(b, _)| matches!(b.payload, PathReviewBundlePayload::SecurityPath { .. }))
    );
    assert!(
        rows.iter()
            .any(|(b, _)| matches!(b.payload, PathReviewBundlePayload::Observation { .. }))
    );
    for (bundle, response) in &mut rows {
        for result in &mut response.results {
            let resource = bundle.category.capability == Capability::ResourceAccess;
            result.diagnosis = Some(ReviewFindingDiagnosis {
                remediation: if resource {
                    "Restrict disclosure to the permitted contact fields."
                } else {
                    "Pass data through a non-shell API with an explicit executable."
                }
                .into(),
                title: if resource {
                    "Private contact details are disclosed"
                } else {
                    "Request text is interpreted by a shell"
                }
                .into(),
                cwes: vec![if resource { "CWE-200" } else { "CWE-78" }.into()],
                severity: if resource {
                    Severity::Low
                } else {
                    Severity::High
                },
                impact: if resource {
                    "Another account's private contact data is returned to the caller."
                } else {
                    "The caller can execute shell commands with the service's authority."
                }
                .into(),
            });
        }
    }
    let report = build_finding_report(".", "test", None, &rows, false).unwrap();
    assert!(!report.findings.is_empty());
    for finding in &report.findings {
        assert_eq!(finding.severity.source, SeveritySource::ReviewerAssessment);
        if finding.category == Capability::ResourceAccess {
            assert_eq!(finding.title, "Private contact details are disclosed");
            assert_eq!(finding.cwes, vec!["CWE-200"]);
            assert_eq!(finding.provenance.candidate_cwes, vec!["CWE-639"]);
            assert_eq!(finding.severity.level, Severity::Low);
            assert_eq!(
                finding.remediation.as_ref().unwrap().text,
                "Restrict disclosure to the permitted contact fields."
            );
        } else {
            assert_eq!(finding.severity.level, Severity::High);
            assert_eq!(finding.cwes, vec!["CWE-78"]);
        }
        assert!(finding.description.contains("Impact assessment:"));
    }
    let markdown = report.to_markdown();
    assert!(!markdown.contains("Request-selected objects lack subject authorization"));
    let sarif = serde_json::to_value(FindingSarifLog::from_finding_report(&report)).unwrap();
    assert!(!sarif["runs"][0]["results"].to_string().contains("CWE-639"));
    for (_, response) in &mut rows {
        for result in &mut response.results {
            result.diagnosis = None;
        }
    }
    let unassessed = build_finding_report(".", "test", None, &rows, false).unwrap();
    assert!(unassessed.findings.iter().all(|f| f.cwes.is_empty()
        && f.severity.level == Severity::Unknown
        && f.severity.source == SeveritySource::Unknown));
}

#[test]
fn diagnosis_validation_rejects_nonissues_empty_impact_and_invalid_classes() {
    let (_root, rows) = fixture();
    let (bundle, response) = &rows[0];
    for (decision, impact, cwes) in [
        (ReviewDecision::NotIssue, "An effect", vec!["CWE-200"]),
        (ReviewDecision::Issue, "", vec!["CWE-200"]),
        (
            ReviewDecision::Issue,
            "An effect",
            vec!["CWE-200", "CWE-200"],
        ),
        (ReviewDecision::Issue, "An effect", vec!["resource_access"]),
    ] {
        let mut rejected = response.clone();
        rejected.results[0].decision = decision;
        rejected.results[0].diagnosis = Some(ReviewFindingDiagnosis {
            title: "Reviewed effect".into(),
            cwes: cwes.into_iter().map(str::to_string).collect(),
            severity: Severity::Low,
            impact: impact.into(),
            remediation: "Restrict the operation to its intended authority.".into(),
        });
        assert!(validate_path_review_bundle_response(bundle, &rejected).is_err());
    }
    let mut ordinary = response.clone();
    for result in &mut ordinary.results {
        result.decision = ReviewDecision::NotIssue;
        result.summary = "This is an intended public lookup with no protected effect.".into();
    }
    let report =
        build_finding_report(".", "test", None, &[(bundle.clone(), ordinary)], false).unwrap();
    assert!(report.findings.is_empty());
}
