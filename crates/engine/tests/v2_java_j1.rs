use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j1")
}

#[test]
fn recognizes_exact_spring_mvc_boundaries_and_local_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, evidence| {
            *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(counts["java-spring-mvc-parameter-source"], 9);
    assert_eq!(counts["java-spring-multipart-content-source"], 1);
    assert!(!result.evidence.iter().any(|evidence| {
        evidence.location.path == "Lookalikes.java" && evidence.rule_id.starts_with("java-spring-")
    }));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::ProcessExecution | Capability::OutboundNetworkRequest
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Propagated && path.protection_evidence_ids.is_empty()
    }));
}
