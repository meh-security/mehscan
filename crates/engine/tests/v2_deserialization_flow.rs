use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-deserialization-flow")
}

#[test]
fn inventories_restrictions_and_builds_bounded_deserialization_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let sinks = result
        .evidence
        .iter()
        .filter(|item| {
            item.capability == Capability::Deserialization && item.kind == EvidenceKind::Sink
        })
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 18);
    assert!(sinks.iter().all(|item| {
        item.kind == EvidenceKind::Sink && item.location.path.starts_with("positive/")
    }));

    let restrictions = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::DeserializationRestriction)
        .collect::<Vec<_>>();
    assert_eq!(restrictions.len(), 6);
    assert!(restrictions.iter().all(|item| {
        item.kind == EvidenceKind::Validation && item.location.path.starts_with("positive/")
    }));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::Deserialization && path.cwe_candidates == ["CWE-502"]
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 18);
    let states = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts.entry(path.state).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(states[&SecurityPathState::Direct], 7);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 4);
    assert!(
        !result
            .evidence
            .iter()
            .any(|item| item.capability == Capability::Deserialization
                && item.location.path.ends_with(".go")
                && item.enclosing_symbol.as_deref() == Some("restricted"))
    );

    let typed_json = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-system-text-json-typed-deserialization-context")
        .collect::<Vec<_>>();
    assert_eq!(typed_json.len(), 1);
    assert_eq!(typed_json[0].kind, EvidenceKind::Validation);
    assert!(typed_json[0].cwe_candidates.is_empty());

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
