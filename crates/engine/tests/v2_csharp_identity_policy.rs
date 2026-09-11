use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::EvidenceKind;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-identity-policy")
}

#[test]
fn separates_csharp_identity_reviews_from_explicit_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert!(result.security_paths.is_empty());

    let policy = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan csharp-identity-policy 1")
        .collect::<Vec<_>>();
    let counts = policy.iter().fold(BTreeMap::new(), |mut counts, item| {
        *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });

    for rule in [
        "csharp-jwt-validation-review",
        "csharp-cookie-authentication-review",
        "csharp-antiforgery-exemption-review",
        "csharp-minimal-antiforgery-exemption-review",
        "csharp-credentialed-cors-review",
        "csharp-forwarded-headers-trust-review",
        "csharp-null-fallback-authorization-review",
        "csharp-anonymous-state-change-review",
        "csharp-minimal-anonymous-state-change-review",
        "csharp-auth-middleware-order-review",
        "csharp-forwarded-headers-order-review",
        "csharp-jwt-validation-control",
        "csharp-cookie-authentication-control",
        "csharp-antiforgery-control",
        "csharp-minimal-antiforgery-control",
        "csharp-credentialed-cors-control",
        "csharp-forwarded-headers-trust-control",
        "csharp-fallback-authorization-control",
        "csharp-default-authorization-control",
        "csharp-authorize-attribute-control",
        "csharp-auth-middleware-order-control",
    ] {
        assert_eq!(counts[rule], 1, "unexpected count for {rule}");
    }

    let reviews = policy
        .iter()
        .filter(|item| item.kind == EvidenceKind::SecurityConfiguration)
        .collect::<Vec<_>>();
    assert_eq!(reviews.len(), 11);
    assert!(reviews.iter().all(|item| {
        item.location.path == "review/WeakPolicy.cs"
            && item.tags.iter().any(|tag| tag == "needs-verification")
            && item.tags.iter().any(|tag| tag.starts_with("verify-"))
    }));

    let controls = policy
        .iter()
        .filter(|item| matches!(item.kind, EvidenceKind::Guard | EvidenceKind::Validation))
        .collect::<Vec<_>>();
    assert_eq!(controls.len(), 10);
    assert!(controls.iter().all(|item| {
        item.location.path == "control/ExplicitPolicy.cs"
            && !item.tags.iter().any(|tag| tag == "needs-verification")
    }));
}
