use std::path::PathBuf;

use mehscan_core::{AvailabilityState, EvidenceKind, ReachabilityState};

#[test]
fn every_specialized_fixture_observation_has_explicit_execution_context() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures");
    let result = mehscan_engine::scan_path_with_options(
        root,
        mehscan_engine::ScanOptions {
            include_tests: true,
            ..mehscan_engine::ScanOptions::default()
        },
    )
    .expect("the complete fixture corpus should scan");

    let missing = result
        .evidence
        .iter()
        .filter(|item| item.kind != EvidenceKind::Secret)
        .filter(|item| item.context.reachability.is_none() || item.context.availability.is_none())
        .map(|item| format!("{}:{}", item.location.path, item.rule_id))
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty(),
        "code observations without explicit execution context: {missing:#?}"
    );

    let textual_templates = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .starts_with("mehscan razor-escape-hatch")
                || item.provenance.engine == "mehscan webforms-inline-output 1"
        })
        .collect::<Vec<_>>();
    assert!(!textual_templates.is_empty());
    assert!(textual_templates.iter().all(|item| {
        item.context.reachability.as_ref().map(|value| value.state)
            == Some(ReachabilityState::Unknown)
            && item.context.availability.as_ref().map(|value| value.state)
                == Some(AvailabilityState::Unknown)
            && !item.context.comment
    }));
}
