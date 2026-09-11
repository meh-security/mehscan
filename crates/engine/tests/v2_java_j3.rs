use std::collections::BTreeMap;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j3")
}

#[test]
fn recognizes_exact_java_jwt_and_otp_lifecycle_facts() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let identity = result
        .evidence
        .iter()
        .filter(|evidence| evidence.provenance.engine == "mehscan java-identity-policy 1")
        .collect::<Vec<_>>();
    let counts = identity
        .iter()
        .fold(BTreeMap::new(), |mut counts, evidence| {
            *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });

    for rule in [
        "java-jwt-expiring-signed-token-control",
        "java-jwt-header-jku-key-trust",
        "java-jwt-header-selects-verifier-family",
        "java-jwt-kid-selects-known-hmac-key",
        "java-jwt-signed-token-without-expiration",
        "java-nimbus-claims-without-verification",
        "java-nimbus-plain-jwt-accepted",
        "java-nimbus-signature-verification-control",
        "java-otp-active-status-validation-control",
        "java-otp-attempt-limit-control",
        "java-otp-counter-without-enforced-limit",
        "java-otp-record-without-expiry",
        "java-short-numeric-otp-generation",
        "java-api-key-debug-logging",
        "java-email-token-use-without-lifecycle-control",
        "java-password-reset-authenticated-subject-control",
        "java-short-email-token-generation",
        "java-spring-password-encoding-control",
        "java-stateful-email-token-without-expiry",
    ] {
        assert_eq!(counts[rule], 1, "unexpected count for {rule}");
    }
    assert_eq!(counts["java-otp-single-use-invalidation-control"], 2);
    assert_eq!(identity.len(), 21);
    let api_key_log = identity
        .iter()
        .find(|evidence| evidence.rule_id == "java-api-key-debug-logging")
        .expect("API key log observation");
    assert_eq!(api_key_log.location.start.line, 31);
    assert!(
        !identity
            .iter()
            .any(|evidence| evidence.location.path == "Lookalikes.java")
    );

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("J3 review jobs should build")
            .observation_reviews;
    for rule in [
        "java-jwt-header-jku-key-trust",
        "java-jwt-kid-selects-known-hmac-key",
        "java-jwt-header-selects-verifier-family",
        "java-nimbus-plain-jwt-accepted",
        "java-api-key-debug-logging",
        "java-jwt-signed-token-without-expiration",
    ] {
        let review = reviews
            .iter()
            .find(|review| {
                review.evidence.iter().any(|evidence| {
                    review.anchor_evidence_ids.contains(&evidence.id) && evidence.rule_id == rule
                })
            })
            .unwrap_or_else(|| panic!("decision-ready review for {rule}"));
        assert!(review.decision_facts.unresolved.is_empty(), "{rule}");
        assert!(
            review.decision_facts.effective_controls.is_empty(),
            "{rule}"
        );
        assert!(
            review
                .decision_facts
                .established
                .iter()
                .any(|fact| fact.contains("explicitly establishes")),
            "{rule}"
        );
    }
}
