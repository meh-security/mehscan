use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn models_go_web_identity_template_and_route_policy() {
    let result = mehscan_engine::scan_path(fixture("v2-go-g5b-web"))
        .expect("positive web fixture should scan");

    for rule in [
        "go-cookie-store-hardcoded-key",
        "go-cookie-store-default-options-review",
        "go-passwordless-session-establishment-review",
        "go-auth-redirect-without-return-review",
        "go-text-template-html-output",
        "go-route-security-middleware-coverage-review",
        "go-state-changing-get-route-review",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }
    let key = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-cookie-store-hardcoded-key")
        .expect("hardcoded key evidence");
    assert_eq!(
        key.captures["key_material"].text,
        "[hardcoded byte-string literal]"
    );
    assert!(!key.captures["key_material"].text.contains("012345"));

    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::HtmlOutput && path.state == SecurityPathState::Propagated
    }));

    let jobs = mehscan_engine::investigation::build_path_review_jobs(
        &fixture("v2-go-g5b-web"),
        Some(8),
        Some(100),
    )
    .expect("web review jobs should build");
    let cookie = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-cookie-store-hardcoded-key")
        })
        .expect("cookie review should be admitted");
    assert!(
        cookie
            .facts
            .iter()
            .all(|fact| { !fact.excerpt.contains("01234567890123456789012345678901") })
    );
    assert!(
        cookie
            .facts
            .iter()
            .any(|fact| fact.excerpt.contains("********"))
    );
    let route_policy = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-state-changing-get-route-review")
        })
        .expect("route-policy review should be admitted");
    assert!(route_policy.facts.iter().any(|fact| {
        fact.role == "helper_definition_context"
            && fact.symbol == "addFriend"
            && fact.excerpt.contains("func addFriend")
    }));
}

#[test]
fn honors_environment_key_password_return_html_encoding_and_wrapped_post() {
    let result = mehscan_engine::scan_path(fixture("v2-go-g5b-web-safe"))
        .expect("safe web fixture should scan");

    for rule in [
        "go-cookie-store-hardcoded-key",
        "go-cookie-store-default-options-review",
        "go-passwordless-session-establishment-review",
        "go-auth-redirect-without-return-review",
        "go-text-template-html-output",
        "go-route-security-middleware-coverage-review",
        "go-state-changing-get-route-review",
    ] {
        assert!(
            result.evidence.iter().all(|item| item.rule_id != rule),
            "safe fixture emitted {rule}"
        );
    }
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-html-template-contextual-encoding-control"
            && item.kind == EvidenceKind::Sanitizer
            && item.capability == Capability::HtmlEncoding
    }));
    assert!(
        result
            .security_paths
            .iter()
            .all(|path| path.capability != Capability::HtmlOutput)
    );
}
