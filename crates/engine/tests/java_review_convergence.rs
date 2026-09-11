use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/java-review-convergence")
}

#[test]
fn supplies_possession_and_authenticated_owner_control_for_java_resource_path() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("Java convergence fixture should build");
    let review = job
        .reviews
        .iter()
        .find(|review| {
            review.candidate.capability == Capability::ResourceAccess
                && review
                    .review_basis
                    .as_ref()
                    .and_then(|basis| basis.sink.captures.get("filter"))
                    .is_some_and(|selector| selector == "vehicleForm.getVin()")
        })
        .expect("request VIN should reach the repository lookup");

    assert!(review.decision_facts.unresolved.is_empty());
    assert!(
        review
            .decision_facts
            .effective_controls
            .iter()
            .any(|control| {
                control.contains("stored PIN") && control.contains("authenticated request token")
            })
    );

    let oracle = job
        .reviews
        .iter()
        .find(|review| {
            review
                .review_basis
                .as_ref()
                .and_then(|basis| basis.sink.captures.get("filter"))
                .is_some_and(|selector| selector == "videoId")
        })
        .expect("request video ID should reach the repository lookup");
    assert!(oracle.decision_facts.effective_controls.is_empty());
    assert!(
        oracle.decision_facts.established.iter().any(|fact| {
            fact.contains("object-existence oracle") && fact.contains("status 403")
        })
    );
}
