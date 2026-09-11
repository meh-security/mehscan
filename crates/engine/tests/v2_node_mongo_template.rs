use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-node-mongo-template")
}

#[test]
fn links_only_rendered_mongo_callback_results_and_supplies_exact_template_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let stored_sources = result
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.rule_id == "javascript-mongo-callback-stored-source"
                && evidence.capability == Capability::StoredUserContent
        })
        .collect::<Vec<_>>();
    assert_eq!(stored_sources.len(), 3);
    assert!(stored_sources.iter().all(|source| {
        source
            .provenance
            .engine
            .ends_with("bounded-mongo-callback-result-summary")
    }));

    let html_paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-79"])
        .collect::<Vec<_>>();
    assert_eq!(html_paths.len(), 3);

    let reviews =
        mehscan_engine::investigation::build_path_review_jobs(&fixture_root(), None, Some(100))
            .expect("review jobs should build");
    let html_reviews = reviews
        .reviews
        .iter()
        .filter(|review| review.candidate.cwe_candidates == ["CWE-79"])
        .collect::<Vec<_>>();
    assert_eq!(html_reviews.len(), 3);

    let profile = html_reviews
        .iter()
        .find(|review| review.candidate.sink.location.start.line == 9)
        .expect("profile review");
    assert!(profile.facts.iter().any(|fact| {
        fact.role == "server_template_binding_context"
            && fact.location.path == "app/views/profile.html"
            && fact.excerpt.contains("href=\"{{website}}\"")
    }));
    assert!(profile.facts.iter().any(|fact| {
        fact.role == "template_configuration_context"
            && fact.symbol == "autoescape"
            && fact.excerpt.contains("autoescape: false")
    }));

    let memo = html_reviews
        .iter()
        .find(|review| review.candidate.sink.location.start.line == 16)
        .expect("memo review");
    assert!(memo.facts.iter().any(|fact| {
        fact.role == "server_template_binding_context" && fact.excerpt.contains("marked(memo.body)")
    }));
    assert!(memo.facts.iter().any(|fact| {
        fact.role == "template_configuration_context"
            && fact.symbol == "sanitize"
            && fact.excerpt.contains("sanitize: true")
    }));

    let dashboard = html_reviews
        .iter()
        .find(|review| review.candidate.sink.location.start.line == 23)
        .expect("dashboard review");
    assert!(
        !dashboard
            .facts
            .iter()
            .any(|fact| fact.role == "server_template_binding_context")
    );
}
