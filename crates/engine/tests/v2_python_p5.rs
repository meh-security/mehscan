use std::path::PathBuf;

use mehscan_core::{EvidenceKind, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p5")
}

#[test]
fn distinguishes_python_identity_boundaries_and_effective_drf_policy() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for rule in [
        "python-jwt-unverified-decode",
        "python-jwt-external-verification-boundary-review",
        "python-jwt-signature-validation-control",
        "python-jwt-token-without-expiry-review",
        "python-jwt-hardcoded-signing-key",
        "python-django-debug-enabled",
        "python-django-wildcard-allowed-hosts-review",
        "python-django-cors-all-origins-review",
        "python-django-csrf-middleware-control",
        "python-drf-default-permission-control",
        "python-django-cookie-flag-disabled",
        "python-django-cookie-flag-control",
        "python-django-cookie-samesite-control",
        "python-django-https-redirect-review",
        "python-django-proxy-ssl-header-review",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }

    let verified = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "python-jwt-signature-validation-control")
        .unwrap();
    assert_eq!(verified.kind, EvidenceKind::Validation);

    let handlers = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-django-handler-entrypoint")
        .collect::<Vec<_>>();
    assert!(handlers.iter().any(|item| {
        item.context.http_routes.iter().any(|route| {
            route.path == "/protected" && route.access == HttpRouteAccess::Authenticated
        })
    }));
    assert!(handlers.iter().any(|item| {
        item.context.http_routes.iter().any(|route| {
            route.path == "/public" && route.access == HttpRouteAccess::ExplicitlyPublic
        })
    }));
}
