use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/rust-review-convergence")
}

#[test]
fn resolves_only_compile_time_rust_resource_inputs() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("Rust convergence fixture should build");

    let static_reviews = job
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|evidence| {
                matches!(
                    evidence.enclosing_symbol.as_deref(),
                    Some("static_page" | "static_page_with_literal_placeholders" | "migration")
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(static_reviews.len(), 3);
    for review in static_reviews {
        assert!(review.decision_facts.unresolved.is_empty());
        assert!(!review.decision_facts.effective_controls.is_empty());
    }

    let dynamic = job
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|evidence| evidence.enclosing_symbol.as_deref() == Some("dynamic_page"))
        })
        .expect("dynamic replacement should remain reviewable");
    assert!(!dynamic.decision_facts.unresolved.is_empty());
    assert!(dynamic.decision_facts.effective_controls.is_empty());
}
