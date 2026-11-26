use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::EvidenceKind;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-go-g2")
}

#[test]
fn adds_bounded_go_identity_and_deployment_policy_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    for rule in [
        "go-cors-wildcard-origin-review",
        "go-credentialed-wildcard-cors",
        "go-debug-pprof-route-review",
        "go-unbounded-request-body-read-review",
        "go-request-body-size-limit-control",
        "go-http-server-timeout-control",
        "go-http-server-tls-control",
        "go-http-server-plaintext-fallback-review",
        "go-postgres-sslmode-disabled-review",
        "go-mongodb-plaintext-uri-review",
        "go-remote-token-verification-request",
        "go-remote-token-verification-status-control",
        "go-unverified-claims-remote-verification-gate",
        "go-verified-identity-database-lookup",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }

    let identity = result
        .evidence
        .iter()
        .filter(|item| {
            item.location.path == "identity.go"
                && matches!(
                    item.kind,
                    EvidenceKind::Guard | EvidenceKind::SensitiveOperation
                )
        })
        .collect::<Vec<_>>();
    assert!(identity.len() >= 5);
    assert!(
        identity
            .iter()
            .all(|item| !item.related_evidence.is_empty())
    );
    let related = identity
        .iter()
        .flat_map(|item| item.related_evidence.iter().cloned())
        .collect::<BTreeSet<_>>();
    assert!(related.len() >= 5);

    let bounded = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-request-body-size-limit-control")
        .expect("bounded body should be a control");
    assert!(bounded.cwe_candidates.is_empty());
    assert_eq!(bounded.enclosing_symbol.as_deref(), Some("Bounded"));

    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("Go policy reviews should build");
    let cors = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-credentialed-wildcard-cors")
        })
        .expect("credentialed wildcard CORS review");
    assert!(cors.decision_facts.unresolved.is_empty());
    assert_eq!(cors.decision_facts.effective_controls.len(), 1);
    assert!(
        cors.decision_facts
            .established
            .iter()
            .any(|fact| fact.contains("browsers reject wildcard credentialed CORS"))
    );
}
