use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use mehscan_core::{Capability, Confidence, EvidenceFilter, EvidenceKind, SecretDetector};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/secrets")
}

fn scan_with_secrets() -> mehscan_core::ScanResult {
    mehscan_engine::scan_path_with_options(
        fixture_root(),
        mehscan_engine::ScanOptions {
            scan_secrets: true,
            ..Default::default()
        },
    )
    .expect("fixture should scan")
}

#[test]
fn detects_and_redacts_credentials_in_code_and_comments() {
    let result = scan_with_secrets();

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.scanned, 14);
    assert_eq!(result.evidence.len(), 7);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|evidence| evidence.context.comment)
            .count(),
        4
    );
    assert!(
        result
            .evidence
            .iter()
            .all(|evidence| evidence.location.path.starts_with("positive/"))
    );

    let mut detectors = BTreeMap::new();
    let mut fingerprints = BTreeSet::new();
    for evidence in &result.evidence {
        assert_eq!(evidence.kind, EvidenceKind::Secret);
        assert_eq!(evidence.capability, Capability::CredentialMaterial);
        assert_eq!(evidence.cwe_candidates, ["CWE-798"]);
        assert_eq!(
            evidence.provenance.resolution,
            mehscan_core::Resolution::Textual
        );
        assert_eq!(
            evidence
                .captures
                .get("secret")
                .expect("redacted capture")
                .text,
            "[REDACTED]"
        );
        let secret = evidence.context.secret.as_ref().expect("secret context");
        assert_eq!(secret.redacted, "[REDACTED]");
        assert!(secret.fingerprint.starts_with("sec-fnv1a64-"));
        assert!(secret.value_length >= 16);
        fingerprints.insert(secret.fingerprint.clone());
        *detectors.entry(secret.detector).or_insert(0) += 1;
    }
    assert_eq!(detectors[&SecretDetector::GithubPersonalAccessToken], 2);
    assert_eq!(detectors[&SecretDetector::GitlabPersonalAccessToken], 2);
    assert_eq!(detectors[&SecretDetector::SlackToken], 1);
    assert_eq!(detectors[&SecretDetector::GenericHighEntropyAssignment], 2);
    assert_eq!(fingerprints.len(), 4, "repeated values share a fingerprint");
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|evidence| evidence.confidence == Confidence::High)
            .count(),
        5
    );
    assert_eq!(
        result.coverage.security_surfaces.get("credential_material"),
        Some(&7)
    );
    assert!(
        result.coverage.cwe.iter().any(|coverage| {
            coverage.cwe == "CWE-798" && coverage.supported_languages.len() == 12
        })
    );
}

#[test]
fn default_investigation_does_not_emit_secret_units() {
    let job = mehscan_engine::investigation::build_investigation_job(
        &fixture_root(),
        EvidenceFilter {
            kind: Some(EvidenceKind::Secret),
            capability: Some(Capability::CredentialMaterial),
            language: None,
            path: None,
        },
        Some(1),
        Some(20),
    )
    .expect("disabled secret investigation should build");

    assert_eq!(job.schema_version, "2.1");
    assert!(job.units.is_empty());
}
