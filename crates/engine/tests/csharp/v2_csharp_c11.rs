use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c11")
}

#[test]
fn models_ldap_contexts_and_process_start_info_argument_semantics() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let ldap = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::LdapQuery)
        .collect::<Vec<_>>();
    assert_eq!(ldap.len(), 12);
    assert!(ldap.iter().all(|item| item.kind == EvidenceKind::Sink));
    assert!(!ldap.iter().any(|item| {
        item.location.path.contains("Lookalike") || item.location.path.ends_with("Shadowed.cs")
    }));

    let controls = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Validation
                && matches!(
                    item.capability,
                    Capability::LdapFilterEncoding | Capability::LdapDistinguishedNameEncoding
                )
                && item.rule_id.contains("applied-to-ldap")
        })
        .collect::<Vec<_>>();
    assert_eq!(controls.len(), 3);
    assert!(controls[0].captures.contains_key("value"));

    let evidence_by_id = result
        .evidence
        .iter()
        .map(|item| (item.id.as_str(), item))
        .collect::<BTreeMap<_, _>>();
    let ldap_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::LdapQuery)
        .collect::<Vec<_>>();
    assert_eq!(ldap_paths.len(), 10);
    assert_eq!(
        ldap_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        3
    );
    assert_eq!(
        ldap_paths
            .iter()
            .filter(|path| path.state != SecurityPathState::Protected)
            .count(),
        7
    );
    assert!(ldap_paths.iter().any(|path| {
        evidence_by_id[&path.sink_evidence_id.as_str()].rule_id
            == "csharp-directory-searcher-filter"
            && evidence_by_id[&path.sink_evidence_id.as_str()]
                .location
                .path
                .starts_with("control/")
            && path.state != SecurityPathState::Protected
    }));

    let process_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::ProcessExecution
                && path
                    .steps
                    .last()
                    .is_some_and(|step| step.location.path.starts_with("positive/"))
        })
        .collect::<Vec<_>>();
    assert_eq!(process_paths.len(), 3);
    assert!(process_paths.iter().all(|path| {
        evidence_by_id[&path.sink_evidence_id.as_str()]
            .captures
            .contains_key("arguments")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.capability == Capability::ProcessExecution
            && path
                .steps
                .last()
                .is_some_and(|step| step.location.path.starts_with("control/"))
    }));
}
