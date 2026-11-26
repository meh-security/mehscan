use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/csharp-redirect-helper-role")
}

#[test]
fn reviews_only_the_helper_argument_that_can_control_redirect_authority() {
    let scan = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let redirect_paths = scan
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::Redirect)
        .collect::<Vec<_>>();
    assert_eq!(redirect_paths.len(), 2, "raw evidence paths stay visible");

    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("review jobs should build");
    let redirect_reviews = job
        .reviews
        .iter()
        .filter(|review| review.candidate.capability == Capability::Redirect)
        .collect::<Vec<_>>();
    assert_eq!(redirect_reviews.len(), 1);
    assert_eq!(
        redirect_reviews[0]
            .review_basis
            .as_ref()
            .and_then(|basis| basis.source.captures.get("parameter"))
            .map(String::as_str),
        Some("carrier")
    );
    assert!(redirect_reviews[0].facts.iter().any(|fact| {
        fact.role == "helper_definition_context"
            && fact.symbol == "GetUrl"
            && fact.excerpt.contains("https://{0}/lookup")
    }));
    assert!(
        redirect_reviews[0]
            .decision_facts
            .established
            .iter()
            .any(|fact| fact.contains("request-selected helper argument")
                && fact.contains("authority of an absolute redirect URL")
                && fact.contains("fixed-host sibling branches"))
    );
}
