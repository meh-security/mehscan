use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-policy")
}

#[test]
fn separates_deterministic_node_policy_paths_from_route_review_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.uncertainty_reasons
                .iter()
                .any(|reason| reason == "node_policy_relationship_is_syntactic")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 2, "{paths:#?}");
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .steps
                .iter()
                .all(|step| step.location.path.starts_with("positive/"))
    }));
    assert_eq!(
        paths
            .iter()
            .flat_map(|path| path.cwe_candidates.iter().map(String::as_str))
            .collect::<BTreeSet<_>>(),
        ["CWE-20", "CWE-312"].into_iter().collect()
    );
    assert!(paths.iter().any(|path| {
        result.evidence.iter().any(|item| {
            item.id == path.source_evidence_id && item.capability == Capability::ModelToolInput
        })
    }));

    let reviews = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::SecurityConfiguration
                && item.provenance.engine.ends_with("bounded-node-policy")
        })
        .collect::<Vec<_>>();
    assert_eq!(reviews.len(), 3, "{reviews:#?}");
    assert!(reviews.iter().all(|item| {
        item.location.path == "positive/routes.ts"
            && item.tags.iter().any(|tag| tag == "needs-verification")
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.provenance.engine.ends_with("bounded-node-policy")
            && item.location.path.starts_with("negative/")
    }));
}
