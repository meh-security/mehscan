use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-process-flow")
}

#[test]
fn inventories_argument_separation_and_builds_bounded_process_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 15);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let protections = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::ProcessArgumentSeparation)
        .collect::<Vec<_>>();
    assert_eq!(protections.len(), 7);
    assert!(protections.iter().all(|item| {
        item.kind == EvidenceKind::Sanitizer && item.location.path.starts_with("positive/")
    }));

    let process_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ProcessExecution)
        .collect::<Vec<_>>();
    let states = process_paths
        .iter()
        .fold(BTreeMap::new(), |mut counts, path| {
            *counts.entry(path.state).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(states[&SecurityPathState::Direct], 7);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 6);

    assert!(process_paths.iter().all(|path| {
        path.cwe_candidates == ["CWE-78"]
            && path
                .steps
                .first()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Source)
            && path
                .steps
                .last()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
            && (path.state == SecurityPathState::Unknown
                || path
                    .steps
                    .iter()
                    .all(|step| !step.location.path.starts_with("negative/")))
    }));
    // Bounded uncertainty may retain a conditional sink without claiming a
    // confirmed or protected flow. Do not pin the total to confirmed paths.
    assert!(
        process_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .all(|path| !path.uncertainty_reasons.is_empty()
                && path.protection_evidence_ids.is_empty())
    );
    assert!(
        process_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .all(|path| {
                path.protection_evidence_ids.len() == 1
                    && path
                        .steps
                        .iter()
                        .any(|step| step.kind == SecurityPathStepKind::Protection)
            })
    );

    assert!(result.evidence.iter().any(|item| {
        item.location.path == "negative/conservative.js"
            && item.capability == Capability::HttpRequestData
    }));
    assert!(result.evidence.iter().any(|item| {
        item.location.path == "negative/conservative.js"
            && item.capability == Capability::ProcessExecution
    }));
}
