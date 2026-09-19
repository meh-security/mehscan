use std::path::PathBuf;

use mehscan_core::{CandidateReport, Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-repository-handoff")
}

#[test]
fn maps_one_service_pass_through_to_a_unique_repository_sink() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let forwarded = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-controller-service-parameter-source")
        .collect::<Vec<_>>();
    assert_eq!(forwarded.len(), 2, "{forwarded:#?}");
    let repository = forwarded
        .iter()
        .find(|item| item.location.path == "Repository.cs")
        .expect("repository parameter should receive the controller source summary");
    assert_eq!(repository.captures["parameter"].text, "email");
    assert_eq!(repository.captures["controller_source"].text, "email");
    assert_eq!(repository.captures["controller_call"].text, "Lookup");
    assert_eq!(repository.captures["service_call"].text, "FindByEmail");
    assert_eq!(
        repository.captures["service_call"].location.path,
        "Service.cs"
    );
    assert!(repository.tags.iter().any(|tag| tag == "two-hop"));
    let sink = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "csharp-sql-command-text")
        .expect("repository query sink should exist");
    assert!(
        sink.tags
            .iter()
            .any(|tag| tag == "dynamic-query-composition")
    );
    assert_eq!(sink.captures["dynamic_operand"].text, "email");

    let paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::DatabaseQuery)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1, "{paths:#?}");
    assert_eq!(paths[0].state, SecurityPathState::Propagated);
    assert_eq!(
        paths[0].steps.first().unwrap().location.path,
        "Controller.cs"
    );
    assert_eq!(
        paths[0].steps.last().unwrap().location.path,
        "Repository.cs"
    );
    assert!(
        paths[0]
            .steps
            .iter()
            .any(|step| step.location.path == "Service.cs")
    );
    assert!(
        paths[0]
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "two_formal_parameter_hops")
    );

    let report = CandidateReport::from_scan(&result).expect("candidate report should build");
    assert_eq!(report.candidates.len(), 1, "{report:#?}");
    assert_eq!(report.candidates[0].source.location.path, "Controller.cs");
    assert_eq!(
        report.candidates[0].source.enclosing_symbol.as_deref(),
        Some("Find")
    );
}
