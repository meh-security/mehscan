use std::collections::BTreeMap;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j7")
}

#[test]
fn models_exact_java_outbound_destination_and_transport_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let j7 = result
        .evidence
        .iter()
        .filter(|evidence| evidence.provenance.engine == "mehscan java-network-transport-policy 1")
        .collect::<Vec<_>>();
    let counts = j7.iter().fold(BTreeMap::new(), |mut counts, evidence| {
        *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });
    assert!(
        !result
            .evidence
            .iter()
            .any(|evidence| evidence.location.path == "Lookalikes.java")
    );
    assert_eq!(counts["java-spring-resttemplate-outbound-request"], 1);
    assert_eq!(counts["java-spring-requestentity-dispatch"], 1);
    assert_eq!(counts["java-spring-webclient-outbound-request"], 1);
    assert_eq!(counts["java-jdk-http-request-builder"], 1);
    assert_eq!(counts["java-jdk-http-client-dispatch"], 1);
    assert_eq!(counts["java-outbound-http"], 2);
    assert_eq!(counts["java-apache-http-request"], 2);
    assert_eq!(counts["java-apache-http-dispatch"], 2);
    assert_eq!(counts["java-uri-https-scheme-control"], 1);
    assert_eq!(counts["java-uri-host-policy-control"], 1);
    assert_eq!(counts["java-inet-private-address-check"], 2);
    assert_eq!(counts["java-apache-redirect-disabled-control"], 1);
    assert_eq!(counts["java-apache-trust-all-certificates"], 1);
    assert_eq!(counts["java-apache-hostname-verification-disabled"], 1);
    assert_eq!(counts["java-hostname-verifier-always-accepts"], 1);
    assert_eq!(counts["java-apache-trust-strategy-always-accepts"], 1);
    assert_eq!(counts["java-x509-trust-manager-empty-server-check"], 1);
    assert_eq!(counts["java-apache-default-hostname-verifier-control"], 1);
    assert_eq!(j7.len(), 22);

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("J7 review jobs should build")
            .observation_reviews;
    for rule in [
        "java-apache-trust-all-certificates",
        "java-apache-hostname-verification-disabled",
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
    }
}
