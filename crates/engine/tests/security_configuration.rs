use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{
    AvailabilityState, Capability, Confidence, EvidenceKind, LiteralState, LiteralValue,
    ReachabilityState,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/security-config")
}

#[test]
fn enumerates_literal_sensitive_security_surfaces_without_verdicts() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("security fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.evidence.len(), 35);
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.location.path.starts_with("positive/"))
    );

    let counts = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.capability).or_insert(0) += 1;
            counts
        });
    assert_eq!(counts[&Capability::TlsConfiguration], 7);
    assert_eq!(counts[&Capability::CookieConfiguration], 14);
    assert_eq!(counts[&Capability::CryptographicHash], 7);
    assert_eq!(counts[&Capability::Deserialization], 7);

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
            Capability::TlsConfiguration | Capability::CookieConfiguration => {
                assert_eq!(evidence.kind, EvidenceKind::SecurityConfiguration);
                let literal = evidence
                    .context
                    .literals
                    .values()
                    .next()
                    .expect("configuration value");
                assert_eq!(literal.state, LiteralState::Known, "{}", evidence.rule_id);
                assert_eq!(literal.value, Some(LiteralValue::Boolean(false)));
            }
            Capability::CryptographicHash => {
                assert_eq!(evidence.kind, EvidenceKind::SecurityConfiguration);
                let literal = evidence
                    .context
                    .literals
                    .get("algorithm")
                    .expect("algorithm value");
                if evidence.location.path.ends_with(".go") {
                    assert_eq!(literal.state, LiteralState::Unknown);
                    assert_eq!(literal.references, ["md5.New"]);
                } else {
                    assert_eq!(literal.state, LiteralState::Known);
                    assert!(matches!(
                        literal.value.as_ref(),
                        Some(LiteralValue::String(value)) if value.eq_ignore_ascii_case("md5")
                    ));
                }
            }
            Capability::Deserialization => {
                assert_eq!(evidence.kind, EvidenceKind::Sink);
                assert_eq!(
                    evidence
                        .context
                        .literals
                        .get("payload")
                        .expect("payload value")
                        .state,
                    LiteralState::Unknown
                );
            }
            capability => panic!("unexpected capability: {capability:?}"),
        }
    }
}

#[test]
fn declares_each_new_cwe_for_every_priority_language() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("security fixture should scan");
    let coverage: BTreeMap<_, _> = result
        .coverage
        .cwe
        .iter()
        .map(|item| (item.cwe.as_str(), item))
        .collect();
    assert_eq!(coverage["CWE-295"].supported_languages.len(), 8);
    assert_eq!(coverage["CWE-327"].supported_languages.len(), 9);
    for cwe in ["CWE-614", "CWE-1004"] {
        assert_eq!(coverage[cwe].supported_languages.len(), 7, "{cwe}");
    }
    assert_eq!(coverage["CWE-502"].supported_languages.len(), 8);
}
