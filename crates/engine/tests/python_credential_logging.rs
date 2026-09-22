use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-credential-logging")
}

#[test]
fn identifies_bounded_request_credentials_logged_in_python() {
    let scan = mehscan_engine::scan_path(fixture()).expect("Python logging fixture should scan");
    let findings = scan
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-request-credential-logging")
        .collect::<Vec<_>>();
    assert_eq!(findings.len(), 2);
    assert!(findings.iter().any(|item| {
        item.captures["credential_origin"]
            .text
            .contains("HTTP_AUTHORIZATION")
    }));
    assert!(findings.iter().any(|item| {
        item.captures["credential_origin"]
            .text
            .contains("openai_api_key")
    }));

    let jobs = mehscan_engine::investigation::build_path_review_jobs(&fixture(), None, Some(100))
        .expect("Python logging reviews should build");
    let reviews = jobs
        .observation_reviews
        .iter()
        .filter(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "python-request-credential-logging")
        })
        .collect::<Vec<_>>();
    assert_eq!(reviews.len(), 2);
    assert!(
        reviews
            .iter()
            .all(|review| review.decision_facts.unresolved.is_empty())
    );
}
