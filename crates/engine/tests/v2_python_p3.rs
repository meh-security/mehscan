use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState, SecurityPathStepKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p3")
}

#[test]
fn builds_bounded_python_critical_paths_and_preserves_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let critical_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::DatabaseQuery
                    | Capability::OutboundNetworkRequest
                    | Capability::FilesystemRead
            )
        })
        .collect::<Vec<_>>();
    let counts = critical_paths
        .iter()
        .fold(BTreeMap::new(), |mut counts, path| {
            *counts
                .entry((path.capability, path.state))
                .or_insert(0usize) += 1;
            counts
        });
    assert_eq!(
        counts[&(
            Capability::OutboundNetworkRequest,
            SecurityPathState::Propagated
        )],
        1
    );
    assert_eq!(
        counts[&(Capability::DatabaseQuery, SecurityPathState::Propagated)],
        1
    );
    assert!(!counts.contains_key(&(Capability::DatabaseQuery, SecurityPathState::Protected)));
    assert_eq!(
        counts[&(Capability::FilesystemRead, SecurityPathState::Propagated)],
        1
    );
    assert_eq!(
        counts[&(Capability::FilesystemRead, SecurityPathState::Protected)],
        1
    );

    assert!(critical_paths.iter().all(|path| {
        path.steps
            .first()
            .is_some_and(|step| step.kind == SecurityPathStepKind::Source)
            && path
                .steps
                .last()
                .is_some_and(|step| step.kind == SecurityPathStepKind::Sink)
    }));
    assert!(
        critical_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .all(|path| path
                .steps
                .iter()
                .any(|step| step.kind == SecurityPathStepKind::Protection))
    );
    assert!(result.evidence.iter().any(|item| {
        item.location.path == "safe.py"
            && item.capability == Capability::SqlParameterization
            && item.kind == EvidenceKind::Sanitizer
    }));

    let tls_disabled = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-http-tls-verification-disabled")
        .collect::<Vec<_>>();
    assert_eq!(tls_disabled.len(), 2);
    assert!(tls_disabled.iter().all(|item| {
        item.kind == EvidenceKind::SecurityConfiguration
            && item.capability == Capability::TlsConfiguration
            && item.cwe_candidates == ["CWE-295"]
            && item.captures["verification"].text == "False"
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.rule_id == "python-http-tls-verification-disabled" && item.location.path == "safe.py"
    }));
}
