use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j10")
}

#[test]
fn models_exact_java_crypto_material_kdf_and_security_randomness() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");
    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);

    let j10 = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan java-jca-randomness-policy 1")
        .collect::<Vec<_>>();
    let counts = j10.iter().fold(BTreeMap::new(), |mut counts, item| {
        *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });
    for rule in [
        "java-message-digest-selection",
        "java-mac-algorithm-selection",
        "java-signature-algorithm-selection",
        "java-key-generator-selection",
        "java-password-kdf-algorithm-selection",
        "java-password-kdf-parameters",
    ] {
        assert_eq!(counts[rule], 2, "{rule}");
    }
    assert_eq!(counts["java-cipher-transformation"], 3);
    assert_eq!(counts["java-hardcoded-secret-key-material"], 1);
    assert_eq!(counts["java-fixed-iv-or-nonce-material"], 1);
    assert_eq!(counts["java-insecure-security-randomness"], 2);
    assert_eq!(counts["java-secure-security-randomness-control"], 1);
    assert_eq!(j10.len(), 20);
    assert!(
        j10.iter()
            .all(|item| item.kind == EvidenceKind::SecurityConfiguration)
    );
    assert!(
        j10.iter()
            .any(|item| item.capability == Capability::CredentialMaterial)
    );
    assert!(!j10.iter().any(|item| matches!(
        item.location.path.as_str(),
        "OrdinaryRandom.java" | "Lookalikes.java"
    )));
}
