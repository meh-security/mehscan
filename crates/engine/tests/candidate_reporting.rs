use std::path::PathBuf;

use mehscan_core::{
    CandidateClassification, CandidateReport, SARIF_SCHEMA_URI, SARIF_VERSION, SarifLog,
    SecurityPathState, SecurityPathStepKind,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-sql-flow")
}

#[test]
fn converts_only_security_paths_into_review_candidates() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("scan should succeed");
    let report = CandidateReport::from_scan(&result).expect("candidate report should build");

    assert_eq!(report.schema_version, "1.0");
    assert_eq!(report.scan_schema_version, result.schema_version);
    assert_eq!(report.evidence_count, result.evidence.len());
    assert_eq!(report.security_path_count, result.security_paths.len());
    assert_eq!(report.candidates.len(), result.security_paths.len());
    assert_eq!(report.candidates.len(), 15);
    assert!(report.candidates.iter().all(|candidate| {
        candidate.classification == CandidateClassification::SecurityPath
            && candidate.primary_location == candidate.sink.location
            && candidate
                .steps
                .first()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Source)
            && candidate
                .steps
                .last()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
    }));
    let protected = report
        .candidates
        .iter()
        .find(|candidate| candidate.state == SecurityPathState::Protected)
        .expect("fixture should contain a protected candidate");
    assert_eq!(protected.protections.len(), 1);
    assert!(!protected.title.contains("CWE-89"));
    assert!(protected.title.contains("Database query"));

    let mut malformed = result;
    malformed.evidence.clear();
    let error = CandidateReport::from_scan(&malformed)
        .expect_err("broken path references must fail closed");
    assert!(error.to_string().contains("missing source evidence"));
}

#[test]
fn emits_sarif_review_results_with_code_flows_and_stable_fingerprints() {
    let scan = mehscan_engine::scan_path(fixture_root()).expect("scan should succeed");
    let sarif = SarifLog::from_scan(&scan).expect("SARIF should build");

    assert_eq!(sarif.schema, SARIF_SCHEMA_URI);
    assert_eq!(sarif.version, SARIF_VERSION);
    assert_eq!(sarif.runs.len(), 1);
    let run = &sarif.runs[0];
    assert_eq!(run.column_kind, "unicodeCodePoints");
    assert_eq!(run.tool.driver.rules.len(), 1);
    assert_eq!(run.tool.driver.rules[0].id, "MEHSCAN.CWE-89.database-query");
    assert_eq!(run.results.len(), scan.security_paths.len());
    assert_eq!(run.properties.candidate_count, scan.security_paths.len());
    assert!(run.results.iter().all(|result| {
        result.kind == "review"
            && result.locations.len() == 1
            && !result.related_locations.is_empty()
            && result.code_flows.len() == 1
            && result.code_flows[0].thread_flows.len() == 1
            && result.partial_fingerprints.get("mehscanSecurityPath/v1")
                == Some(&result.properties.candidate_id)
            && result.locations[0]
                .physical_location
                .artifact_location
                .uri
                .chars()
                .all(|character| character != '\\')
    }));
    let protected = run
        .results
        .iter()
        .find(|result| result.properties.security_path_state == SecurityPathState::Protected)
        .expect("fixture should contain a protected result");
    assert_eq!(protected.level, "note");
    assert!(protected.message.text.contains("not a safe verdict"));
    assert_eq!(protected.properties.protection_evidence_ids.len(), 1);
}
