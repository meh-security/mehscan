use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-go-g3")
}

#[test]
fn adds_bounded_go_vulnerability_and_control_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    for rule in [
        "go-request-fmt-to-trusted-html",
        "go-conditional-html-encoding-control",
        "go-sql-resource-filter-summary",
        "go-verified-session-value-control",
        "go-session-owned-resource-id-control",
        "go-unkeyed-md5-resource-signature-review",
        "go-md5-password-hash",
        "go-hardcoded-md5-otp-review",
        "go-cookie-store-signing-only-review",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }

    let password_path = result
        .security_paths
        .iter()
        .find(|path| path.cwe_candidates == ["CWE-916"])
        .expect("password material should have a bounded MD5 path");
    assert_eq!(password_path.capability, Capability::CryptographicHash);

    assert!(result.security_paths.iter().any(|path| {
        path.cwe_candidates == ["CWE-639"] && path.capability == Capability::ResourceAccess
    }));

    let session_control = result
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-session-owned-resource-id-control")
        .expect("session-owned ID override should remain visible");
    assert_eq!(session_control.kind, EvidenceKind::Guard);
    assert!(session_control.cwe_candidates.is_empty());

    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("Go authentication reviews should build");
    let otp = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-hardcoded-md5-otp-review")
        })
        .expect("hardcoded OTP review");
    assert!(otp.decision_facts.unresolved.is_empty());
    assert!(otp.decision_facts.effective_controls.is_empty());
    assert!(
        otp.decision_facts
            .established
            .iter()
            .any(|fact| fact.contains("fixed weak verifier"))
    );
}
