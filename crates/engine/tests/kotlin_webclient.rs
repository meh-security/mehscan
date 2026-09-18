#[test]
fn webclient_reviews_keep_overload_subscription_replacement_and_exchange_context() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-webclient");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-webclient-uri")
            .count(),
        10
    );
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    assert!(
        scan.security_paths.is_empty(),
        "URI-spec setters remain lazy source-review boundaries"
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.observation_reviews.len(), 10);
    assert!(jobs.reviews.is_empty());
    for review in jobs.observation_reviews {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "webclient_containing_function_context")
            .unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        assert!(
            fact.excerpt
                .contains(anchor.enclosing_symbol.as_deref().unwrap())
        );
        if anchor.enclosing_symbol.as_deref() == Some("nonNetworkFactory") {
            let helper = review
                .facts
                .iter()
                .find(|f| f.role == "webclient_local_helper_candidate_context")
                .unwrap();
            assert_eq!(helper.evidence_id.as_deref(), Some(anchor.id.as_str()));
            assert!(helper.excerpt.contains("fun clientExchange()"));
            assert!(helper.excerpt.contains("body(request.url().toString())"));
        }
        if anchor.enclosing_symbol.as_deref() == Some("replaced") {
            assert!(fact.excerpt.contains("spec.uri(target)"));
            assert!(fact.excerpt.contains("spec.uri(fixed)"));
        }
    }
}
