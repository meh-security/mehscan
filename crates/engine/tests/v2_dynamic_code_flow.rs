use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-dynamic-code-flow")
}

#[test]
fn inventories_restrictions_and_builds_bounded_dynamic_code_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let sinks = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::DynamicCodeExecution)
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 21);
    assert!(sinks.iter().all(|item| {
        item.kind == EvidenceKind::Sink && item.location.path.starts_with("positive/")
    }));

    let restrictions = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::DynamicCodeRestriction)
        .collect::<Vec<_>>();
    assert_eq!(restrictions.len(), 7);
    assert!(restrictions.iter().all(|item| {
        item.kind == EvidenceKind::Validation && item.location.path.starts_with("positive/")
    }));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::DynamicCodeExecution && path.cwe_candidates == ["CWE-94"]
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 21);
    let states = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts.entry(path.state).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(states[&SecurityPathState::Direct], 7);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 7);

    assert!(paths.iter().all(|path| {
        path.steps
            .first()
            .is_some_and(|step| step.kind == SecurityPathStepKind::Source)
            && path
                .steps
                .last()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
            && path
                .steps
                .iter()
                .all(|step| !step.location.path.starts_with("negative/"))
    }));
    assert!(
        paths
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
}
