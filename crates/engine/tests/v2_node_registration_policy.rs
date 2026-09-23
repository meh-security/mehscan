use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::EvidenceKind;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-registration-policy")
}

#[test]
fn admits_only_bounded_registration_and_recovery_policy_reviews() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);

    let policy = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::SecurityConfiguration
                && [
                    "password-storage-policy-review",
                    "registration-rejection-fallthrough-review",
                    "password-confirmation-not-enforced-review",
                    "knowledge-based-password-recovery-review",
                ]
                .iter()
                .any(|suffix| item.rule_id.ends_with(suffix))
        })
        .collect::<Vec<_>>();
    assert_eq!(policy.len(), 4, "{policy:#?}");
    assert!(
        policy
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );

    let suffixes = policy
        .iter()
        .filter_map(|item| item.rule_id.strip_prefix("typescript-"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        suffixes,
        [
            "knowledge-based-password-recovery-review",
            "password-confirmation-not-enforced-review",
            "password-storage-policy-review",
            "registration-rejection-fallthrough-review",
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn keeps_non_enforcing_registration_checks_in_the_fail_open_contract() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("review job should build");
    let reviews = job
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|item| {
                item.tags.iter().any(|tag| {
                    matches!(
                        tag.as_str(),
                        "rejection-response-falls-through" | "mismatch-not-rejected"
                    )
                })
            })
        })
        .collect::<Vec<_>>();

    assert_eq!(reviews.len(), 2, "{reviews:#?}");
    assert!(reviews.iter().all(|review| {
        review.title == "Review non-enforcing security decision"
            && review
                .review_basis
                .as_ref()
                .is_some_and(|basis| basis.relationship == "bounded_fail_open_policy_review")
            && review.decision_facts.unresolved.is_empty()
    }));
}
