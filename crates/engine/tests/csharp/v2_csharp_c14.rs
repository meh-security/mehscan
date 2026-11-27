use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c14")
}

#[test]
fn admits_only_unique_single_hop_controller_service_parameters() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let forwarded = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-controller-service-parameter-source")
        .collect::<Vec<_>>();
    assert_eq!(forwarded.len(), 4);
    assert!(forwarded.iter().all(|source| {
        source.kind == EvidenceKind::Source
            && source.capability == Capability::HttpRequestData
            && source.location.path == "positive/Repositories.cs"
            && source.captures.contains_key("controller_source")
            && source.captures.contains_key("controller_call")
            && source.related_evidence.len() == 1
            && source
                .captures
                .get("controller_source")
                .is_some_and(|capture| capture.location.path == "positive/Controller.cs")
    }));
    assert!(
        !forwarded
            .iter()
            .any(|source| source.location.path.starts_with("negative/"))
    );

    let evidence_by_id = result
        .evidence
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(result.security_paths.len(), 2);
    assert!(result.security_paths.iter().all(|path| {
        path.state == SecurityPathState::Propagated
            && path.steps.first().is_some_and(|step| {
                step.location.path == "positive/Controller.cs"
                    && step.kind == mehscan_core::SecurityPathStepKind::Source
            })
            && path.steps.last().is_some_and(|step| {
                step.location.path == "positive/Repositories.cs"
                    && step.kind == mehscan_core::SecurityPathStepKind::Sink
            })
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "controller_service_parameter_summary_is_syntactic")
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "runtime_dispatch_unverified")
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "single_formal_parameter_hop")
    }));
    let capabilities = result
        .security_paths
        .iter()
        .map(|path| path.capability)
        .collect::<Vec<_>>();
    assert!(capabilities.contains(&Capability::DatabaseQuery));
    assert!(capabilities.contains(&Capability::ResourceAccess));

    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "csharp-sql-parameterization"
            && item.location.path == "positive/Repositories.cs"
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "csharp-ef-owner-scoped-query-control"
            && item.location.path == "positive/Repositories.cs"
    }));
    assert!(!result.security_paths.iter().any(|path| {
        let sink = evidence_by_id[&path.sink_evidence_id.as_str()];
        sink.location.path.starts_with("negative/") || sink.location.start.line == 34
    }));
}
