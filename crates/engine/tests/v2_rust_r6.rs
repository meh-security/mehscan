use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-rust-r6")
}

#[test]
fn inventories_production_safety_boundaries_and_build_time_execution() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths.len(), 0);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "rust-unsafe-boundary")
            .count(),
        4
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "rust-native-interop-boundary")
            .count(),
        1
    );
    assert!(
        result
            .evidence
            .iter()
            .filter(|item| {
                matches!(
                    item.capability,
                    Capability::MemorySafetyBoundary | Capability::NativeInteropBoundary
                )
            })
            .all(|item| item.kind == EvidenceKind::SensitiveOperation)
    );
    let build = result
        .evidence
        .iter()
        .find(|item| item.capability == Capability::ProcessExecution)
        .expect("build process observation");
    assert!(build.tags.iter().any(|tag| tag == "build-script"));
    assert!(build.tags.iter().any(|tag| tag == "build-time-execution"));
    assert!(!result.evidence.iter().any(|item| {
        item.location.path.ends_with("negative/lookalikes.rs")
            && matches!(
                item.capability,
                Capability::MemorySafetyBoundary | Capability::NativeInteropBoundary
            )
    }));
}

#[test]
fn include_tests_admits_inline_cfg_test_safety_boundaries() {
    let result = mehscan_engine::scan_path_with_options(
        fixture_root(),
        mehscan_engine::ScanOptions {
            include_tests: true,
            ..mehscan_engine::ScanOptions::default()
        },
    )
    .expect("fixture should scan with tests");
    let test_boundaries = result
        .evidence
        .iter()
        .filter(|item| {
            item.rule_id == "rust-unsafe-boundary"
                && item.location.path.ends_with("negative/lookalikes.rs")
        })
        .count();
    assert_eq!(test_boundaries, 2);
}

#[test]
fn safety_review_payload_preserves_decision_guidance() {
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&fixture_root(), Some(12), Some(100))
            .expect("review job should build");
    let review = job
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "rust-unsafe-boundary")
        })
        .expect("unsafe review");
    let basis = review.review_basis.as_ref().expect("rule-derived basis");
    assert_eq!(basis.relationship, "bounded_non_path_observation");
    assert!(
        basis
            .deterministic_facts
            .iter()
            .any(|fact| fact.contains("does not establish a violated invariant"))
    );
    assert!(
        basis
            .verify
            .iter()
            .any(|check| check.contains("safe wrapper and callers"))
    );
    assert!(
        basis
            .exclude
            .iter()
            .any(|exclusion| exclusion == "do not classify unsafe syntax alone as a vulnerability")
    );
}
