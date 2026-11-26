use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j6")
}

#[test]
fn models_exact_java_deserialization_and_xml_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 5);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let j6 = result
        .evidence
        .iter()
        .filter(|evidence| evidence.provenance.engine == "mehscan java-serialization-xml-policy 1")
        .collect::<Vec<_>>();
    let counts = j6.iter().fold(BTreeMap::new(), |mut counts, evidence| {
        *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });
    assert!(!j6.is_empty());
    assert!(
        !result
            .evidence
            .iter()
            .any(|evidence| evidence.location.path == "Lookalikes.java")
    );
    assert_eq!(counts["java-xml-parser-input"], 10);
    assert_eq!(counts["java-xml-external-access-policy-not-observed"], 5);
    assert_eq!(counts["java-xml-external-access-restriction-control"], 5);
    assert_eq!(counts["java-jackson-object-deserialization"], 2);
    assert_eq!(counts["java-jackson-fixed-target-control"], 1);
    assert_eq!(counts["java-jackson-polymorphic-type-allowlist-control"], 1);
    assert_eq!(counts["java-jackson-class-name-polymorphism"], 1);
    assert_eq!(counts["java-jackson-named-subtype-control"], 1);
    assert_eq!(counts["java-snakeyaml-load"], 2);
    assert_eq!(counts["java-snakeyaml-safe-constructor-control"], 1);
    assert_eq!(counts["java-xstream-object-deserialization"], 2);
    assert_eq!(counts["java-native-object-deserialization"], 2);
    assert_eq!(counts["java-xml-decoder-deserialization"], 1);
    assert_eq!(j6.len(), 42);
    assert!(
        j6.iter()
            .filter(|evidence| evidence.kind == EvidenceKind::Sink)
            .all(|evidence| {
                matches!(
                    evidence.capability,
                    Capability::Deserialization | Capability::XmlParsing
                )
            })
    );
}
