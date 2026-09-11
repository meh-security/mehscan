use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-upload-flow")
}

#[test]
fn inventories_uploaded_paths_and_builds_bounded_storage_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let uploaded_paths = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::UploadedFilePath)
        .collect::<Vec<_>>();
    assert_eq!(uploaded_paths.len(), 21);
    assert!(uploaded_paths.iter().all(|item| {
        item.kind == EvidenceKind::Source && item.location.path.starts_with("positive/")
    }));

    let validations = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::UploadedFilenameValidation)
        .collect::<Vec<_>>();
    assert_eq!(validations.len(), 7);
    assert!(validations.iter().all(|item| {
        item.kind == EvidenceKind::Validation && item.location.path.starts_with("positive/")
    }));

    let storage_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::FilesystemWrite
                && path.cwe_candidates == ["CWE-434", "CWE-22"]
        })
        .collect::<Vec<_>>();
    assert_eq!(storage_paths.len(), 21);
    let states = storage_paths
        .iter()
        .fold(BTreeMap::new(), |mut counts, path| {
            *counts.entry(path.state).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(states[&SecurityPathState::Direct], 7);
    assert_eq!(states[&SecurityPathState::Propagated], 7);
    assert_eq!(states[&SecurityPathState::Protected], 7);

    assert!(storage_paths.iter().all(|path| {
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
        storage_paths
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
