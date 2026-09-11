use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-crypto")
}

#[test]
fn classifies_csharp_crypto_lifecycle_risks_and_exact_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let observations = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan csharp-crypto-policy 2")
        .collect::<Vec<_>>();
    let counts = observations
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });

    for expected in [
        "csharp-identity-password-hasher-weak-parameters",
        "csharp-password-kdf-weak-parameters",
        "csharp-argon2id-weak-parameters",
        "csharp-security-token-weak-randomness",
        "csharp-aes-ecb-mode",
        "csharp-aes-constant-iv",
        "csharp-aes-gcm-constant-nonce",
        "csharp-jwt-signing-with-hardcoded-key",
        "csharp-jwt-missing-expiry-review",
        "csharp-identity-password-hasher-parameter-control",
        "csharp-password-kdf-parameter-control",
        "csharp-argon2id-parameter-control",
        "csharp-security-token-csprng-control",
        "csharp-aes-gcm-random-nonce-control",
        "csharp-aes-random-iv-control",
        "csharp-jwt-expiry-control",
    ] {
        assert!(
            counts.contains_key(expected),
            "missing {expected}: {counts:?}"
        );
    }
    assert_eq!(counts["csharp-password-kdf-weak-parameters"], 2);
    assert_eq!(counts["csharp-password-kdf-parameter-control"], 2);

    assert!(
        observations
            .iter()
            .filter(|item| {
                item.location.path == "positive/CryptoRisks.cs"
                    && item.kind == EvidenceKind::SecurityConfiguration
            })
            .count()
            >= 9
    );
    assert!(
        observations
            .iter()
            .filter(|item| {
                item.location.path == "control/CryptoControls.cs"
                    && item.kind == EvidenceKind::Validation
            })
            .count()
            >= 7
    );

    let jwt_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::TokenGeneration && path.cwe_candidates == ["CWE-321"]
        })
        .collect::<Vec<_>>();
    assert_eq!(jwt_paths.len(), 1);
    assert_eq!(jwt_paths[0].state, SecurityPathState::Unknown);
    assert!(
        jwt_paths[0]
            .steps
            .iter()
            .all(|step| { step.location.path == "positive/CryptoRisks.cs" })
    );
    assert!(!result.security_paths.iter().any(|path| {
        path.steps
            .iter()
            .any(|step| step.location.path == "control/CryptoControls.cs")
    }));
}
