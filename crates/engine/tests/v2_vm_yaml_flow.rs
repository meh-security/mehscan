use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-vm-yaml-flow")
}

#[test]
fn maps_only_allowlisted_constant_vm_yaml_wrappers_to_deserialization() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::Deserialization && path.cwe_candidates == ["CWE-502"]
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3);
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Propagated)
            .count(),
        2
    );
    assert_eq!(
        paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        1
    );
    assert!(paths.iter().all(|path| {
        path.steps
            .iter()
            .any(|step| step.symbol.as_deref() == Some("sandbox.data"))
            && path
                .steps
                .iter()
                .any(|step| step.symbol.as_deref() == Some("yaml.load(data)"))
            && path
                .steps
                .iter()
                .all(|step| step.location.path.starts_with("positive/"))
    }));
    assert!(paths.iter().all(|path| {
        result
            .evidence
            .iter()
            .find(|item| item.id == path.source_evidence_id)
            .is_some_and(|source| source.capability == Capability::UploadedFileContent)
            && result
                .evidence
                .iter()
                .find(|item| item.id == path.sink_evidence_id)
                .is_some_and(|sink| {
                    sink.provenance.engine.ends_with("constant-vm-wrapper")
                        && sink.related_evidence.len() == 1
                })
    }));
}
