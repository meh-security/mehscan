use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::EvidenceKind;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c12")
}

#[test]
fn c12_limits_randomness_to_exact_security_lifecycle_roles() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);

    let observations = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan csharp-crypto-policy 2")
        .filter(|item| item.capability == mehscan_core::Capability::RandomGeneration)
        .collect::<Vec<_>>();
    let counts = observations
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });

    assert_eq!(counts["csharp-security-token-weak-randomness"], 4);
    assert_eq!(counts["csharp-security-token-guid-suitability-review"], 1);
    assert_eq!(counts["csharp-security-token-csprng-control"], 5);
    assert_eq!(observations.len(), 10);

    assert!(observations.iter().all(|item| {
        item.location.path.starts_with("positive/")
            || item.location.path.starts_with("control/LifecycleControls")
    }));
    assert!(observations.iter().all(|item| {
        item.tags
            .iter()
            .any(|tag| tag.starts_with("lifecycle-role:"))
    }));
    assert!(
        observations
            .iter()
            .filter(|item| item.kind == EvidenceKind::SecurityConfiguration)
            .all(|item| {
                item.tags.iter().any(|tag| {
                    tag == "recommendation:fix-application" || tag == "recommendation:review-policy"
                })
            })
    );

    let guid = observations
        .iter()
        .find(|item| item.rule_id == "csharp-security-token-guid-suitability-review")
        .expect("security-sensitive GUID should be a suitability review");
    assert_eq!(guid.cwe_candidates, ["CWE-330"]);
    assert!(
        guid.tags
            .iter()
            .any(|tag| tag == "not-a-predictability-claim")
    );
    assert!(!guid.tags.iter().any(|tag| tag == "predictable-randomness"));

    assert!(
        observations
            .iter()
            .filter(|item| item.kind == EvidenceKind::Validation)
            .all(|item| {
                item.location.path == "control/LifecycleControls.cs"
                    && item
                        .tags
                        .iter()
                        .any(|tag| tag == "recommendation:control-present")
            })
    );
    assert!(result.security_paths.is_empty());
}
