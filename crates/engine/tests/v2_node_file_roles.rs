use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-file-roles")
}

#[test]
fn models_archive_and_file_serving_roles_without_accepting_safe_ordering() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.uncertainty_reasons
                .iter()
                .any(|reason| reason == "node_file_role_relationship_is_syntactic")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2, "{paths:#?}");
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Unknown
            && path.steps.iter().all(|step| {
                step.location.path.starts_with("positive/")
                    && !step.location.path.starts_with("negative/")
            })
    }));

    let capabilities = paths
        .iter()
        .map(|path| path.capability)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        capabilities,
        [Capability::FilesystemRead, Capability::FilesystemWrite]
            .into_iter()
            .collect()
    );
    let archive = paths
        .iter()
        .find(|path| path.capability == Capability::FilesystemWrite)
        .expect("archive write path");
    assert_eq!(archive.cwe_candidates, ["CWE-434", "CWE-22"]);
    assert!(archive.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::IneffectiveProtection
            && step
                .symbol
                .as_deref()
                .is_some_and(|symbol| symbol.contains("does not establish path containment"))
    }));

    let serving = paths
        .iter()
        .find(|path| path.capability == Capability::FilesystemRead)
        .expect("file serving path");
    assert_eq!(serving.cwe_candidates, ["CWE-22"]);
    assert!(serving.steps.iter().any(|step| {
        step.kind == SecurityPathStepKind::IneffectiveProtection
            && step
                .symbol
                .as_deref()
                .is_some_and(|symbol| symbol.contains("before subsequent path transformation"))
    }));
    assert!(serving.steps.iter().any(|step| {
        step.symbol
            .as_deref()
            .is_some_and(|symbol| symbol.contains("after allowlist decision"))
    }));

    assert!(!result.evidence.iter().any(|item| {
        item.provenance.engine.ends_with("bounded-node-file-roles")
            && item.location.path.starts_with("negative/")
    }));
}
