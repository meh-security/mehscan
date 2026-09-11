use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-security-randomness")
}

#[test]
fn gates_node_randomness_to_exact_security_lifecycle_roles() {
    let first = mehscan_engine::scan_path(fixture_root()).expect("randomness fixture should scan");
    let second = mehscan_engine::scan_path(fixture_root()).expect("repeat scan should succeed");
    assert_eq!(first.evidence, second.evidence);
    assert_eq!(first.coverage.totals.parse_failed, 0);

    let weak = first
        .evidence
        .iter()
        .filter(|item| item.rule_id == "typescript-insecure-security-randomness")
        .collect::<Vec<_>>();
    assert_eq!(weak.len(), 2);
    assert!(weak.iter().all(|item| {
        item.kind == EvidenceKind::SecurityConfiguration
            && item.capability == Capability::RandomGeneration
            && item.cwe_candidates == ["CWE-330"]
            && item.location.path == "weak.ts"
    }));
    assert!(weak.iter().any(|item| {
        item.captures["lifecycle_role"].text == "token"
            && item.tags.iter().any(|tag| tag == "lifecycle-role:token")
    }));
    assert!(weak.iter().any(|item| {
        item.captures["lifecycle_role"].text == "resetToken"
            && item
                .tags
                .iter()
                .any(|tag| tag == "lifecycle-role:resettoken")
    }));

    let controls = first
        .evidence
        .iter()
        .filter(|item| item.rule_id == "typescript-secure-security-randomness-control")
        .collect::<Vec<_>>();
    assert_eq!(controls.len(), 2);
    assert!(controls.iter().all(|item| {
        item.kind == EvidenceKind::Validation
            && item.capability == Capability::RandomGeneration
            && item.cwe_candidates.is_empty()
            && item.location.path == "safe.ts"
    }));

    assert!(!first.evidence.iter().any(|item| {
        item.capability == Capability::RandomGeneration
            && (item.location.path == "lookalikes.js"
                || item.captures["generator"].text.contains("price"))
    }));

    let reviews =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(6), false)
            .expect("randomness reviews should build");
    let randomness_reviews = reviews
        .observation_reviews
        .iter()
        .filter(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "typescript-insecure-security-randomness")
        })
        .collect::<Vec<_>>();
    assert_eq!(randomness_reviews.len(), 2);
    assert!(randomness_reviews.iter().all(|review| {
        review
            .open_questions
            .iter()
            .any(|question| question.contains("`Math.random()`"))
            && review
                .open_questions
                .iter()
                .all(|question| !question.contains("HttpOnly"))
    }));
}
