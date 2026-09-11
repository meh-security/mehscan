use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-sql-flow")
}

#[test]
fn builds_only_bounded_unambiguous_sql_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 8);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths.len(), 15);
    assert_eq!(result.security_paths, repeated.security_paths);

    let states = result
        .security_paths
        .iter()
        .fold(BTreeMap::new(), |mut counts, path| {
            *counts.entry(path.state).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(states[&SecurityPathState::Direct], 7);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 1);

    assert!(result.security_paths.iter().all(|path| {
        path.capability == Capability::DatabaseQuery
            && path.cwe_candidates == ["CWE-89"]
            && path.provenance.maximum_propagation_depth == 4
            && path
                .steps
                .first()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Source)
            && path
                .steps
                .last()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
    }));
    assert!(result.security_paths.iter().all(|path| {
        result
            .evidence
            .iter()
            .any(|item| item.id == path.source_evidence_id)
            && result
                .evidence
                .iter()
                .any(|item| item.id == path.sink_evidence_id)
    }));

    let protected = result
        .security_paths
        .iter()
        .find(|path| path.state == SecurityPathState::Protected)
        .expect("parameterized call should retain a protected path");
    assert_eq!(protected.protection_evidence_ids.len(), 1);
    assert!(
        protected
            .steps
            .iter()
            .any(|step| step.kind == SecurityPathStepKind::Protection)
    );

    assert!(result.security_paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| !step.location.path.starts_with("negative/"))
    }));
    assert!(result.evidence.iter().any(|item| {
        item.location.path.starts_with("negative/")
            && item.capability == Capability::HttpRequestData
    }));
    assert!(result.evidence.iter().any(|item| {
        item.location.path.starts_with("negative/") && item.capability == Capability::DatabaseQuery
    }));
}
