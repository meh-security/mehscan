use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, ResourcePolicyState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j2")
}

#[test]
fn relates_unique_spring_service_handoffs_to_exact_repository_resources() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 8);
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
    assert_eq!(counts["java-spring-controller-service-parameter-source"], 3);
    assert_eq!(counts["java-spring-data-resource-access"], 2);
    assert_eq!(counts["java-spring-data-owner-scoped-resource-control"], 1);
    assert_eq!(counts["java-spring-security-route-policy"], 3);
    assert_eq!(counts["java-outbound-http"], 1);

    let resource_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ResourceAccess)
        .collect::<Vec<_>>();
    assert_eq!(resource_paths.len(), 2);
    assert!(
        resource_paths
            .iter()
            .all(|path| path.cwe_candidates == ["CWE-639"])
    );
    assert!(result.evidence.iter().any(|evidence| {
        evidence.rule_id == "java-spring-data-owner-scoped-resource-control"
            && evidence
                .context
                .resource_policy
                .as_ref()
                .is_some_and(|policy| policy.state == ResourcePolicyState::OwnerScoped)
    }));
    assert!(!result.evidence.iter().any(|evidence| {
        evidence.location.path == "Lookalikes.java"
            && evidence.provenance.engine == "mehscan java-spring-data-resource-summary 1"
    }));
}
