use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j11")
}

#[test]
fn models_exact_java_spring_web_cookie_proxy_header_and_logging_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");
    assert_eq!(result.coverage.totals.scanned, 5);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let j11 = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan java-spring-web-policy 1")
        .collect::<Vec<_>>();
    let counts = j11.iter().fold(BTreeMap::new(), |mut counts, item| {
        *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });
    for rule in [
        "java-spring-csrf-disabled-review",
        "java-spring-csrf-configured-control",
        "java-spring-cors-defaults-review",
        "java-spring-session-creation-review",
        "java-spring-stateless-session-control",
        "java-spring-session-fixation-disabled",
        "java-spring-session-fixation-control",
        "java-spring-credentialed-wildcard-cors",
        "java-spring-credentialed-cors-review",
        "java-cookie-missing-secure",
        "java-cookie-missing-http-only",
        "java-cookie-secure-control",
        "java-cookie-http-only-control",
        "java-cookie-same-site-policy",
        "java-servlet-raw-response-header",
        "java-rendered-log-message",
        "java-sensitive-value-logging-review",
    ] {
        assert_eq!(counts[rule], 1, "{rule}");
    }
    assert_eq!(counts["java-forwarded-header-trust-review"], 2);
    assert_eq!(j11.len(), 19);
    assert!(
        !j11.iter()
            .any(|item| item.location.path == "Lookalikes.java")
    );
    assert_eq!(
        j11.iter()
            .filter(|item| item.kind == EvidenceKind::Sink
                && matches!(
                    item.capability,
                    Capability::HttpHeaderOutput | Capability::Logging
                ))
            .count(),
        2
    );
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| matches!(
                path.capability,
                Capability::HttpHeaderOutput | Capability::Logging
            ))
            .count(),
        2
    );
}
