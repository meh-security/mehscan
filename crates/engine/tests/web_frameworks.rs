use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{
    AvailabilityState, Capability, Confidence, EvidenceKind, LiteralState, LiteralValue,
    ReachabilityState,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/web-frameworks")
}

#[test]
fn enumerates_framework_entrypoints_and_security_guards() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("web fixture should scan");

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.evidence.len(), 21);
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.location.path.starts_with("positive/"))
    );

    let capability_counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, evidence| {
            *counts.entry(evidence.capability).or_insert(0) += 1;
            counts
        });
    assert_eq!(capability_counts[&Capability::HttpRequestHandling], 7);
    assert_eq!(capability_counts[&Capability::Authentication], 7);
    assert_eq!(capability_counts[&Capability::Authorization], 7);

    for evidence in &result.evidence {
        assert_eq!(evidence.confidence, Confidence::High);
        assert_eq!(
            evidence
                .context
                .reachability
                .as_ref()
                .expect("reachability")
                .state,
            ReachabilityState::Reachable
        );
        assert_eq!(
            evidence
                .context
                .availability
                .as_ref()
                .expect("availability")
                .state,
            AvailabilityState::Always
        );
        match evidence.capability {
            Capability::HttpRequestHandling => {
                assert_eq!(evidence.kind, EvidenceKind::Entrypoint);
                assert_eq!(
                    evidence
                        .context
                        .literals
                        .get("route")
                        .expect("route literal")
                        .value,
                    Some(LiteralValue::String("/admin".to_string()))
                );
            }
            Capability::Authentication => {
                assert_eq!(evidence.kind, EvidenceKind::Guard);
                if let Some(strategy) = evidence.context.literals.get("strategy") {
                    assert_eq!(
                        strategy.value,
                        Some(LiteralValue::String("jwt".to_string()))
                    );
                }
            }
            Capability::Authorization => {
                assert_eq!(evidence.kind, EvidenceKind::Guard);
                assert!(evidence.context.literals.values().any(|literal| {
                    literal.state == LiteralState::Known
                        && matches!(literal.value.as_ref(), Some(LiteralValue::String(_)))
                }));
            }
            capability => panic!("unexpected capability: {capability:?}"),
        }
    }
}

#[test]
fn exposes_authentication_and_authorization_cwe_coverage() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("web fixture should scan");
    let coverage: BTreeMap<_, _> = result
        .coverage
        .cwe
        .iter()
        .map(|item| (item.cwe.as_str(), item))
        .collect();
    for cwe in ["CWE-306", "CWE-862"] {
        assert_eq!(coverage[cwe].supported_languages.len(), 7, "{cwe}");
    }
}
