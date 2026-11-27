#[test]
fn functional_sources_preserve_reactive_context_without_native_unwrap_claims() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-webflux");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for (rule, count) in [
        ("kotlin-webflux-query-source", 2),
        ("kotlin-webflux-path-source", 1),
        ("kotlin-webflux-text-body-source", 2),
    ] {
        assert_eq!(
            scan.evidence.iter().filter(|e| e.rule_id == rule).count(),
            count
        );
    }
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    assert!(
        scan.security_paths.is_empty(),
        "Optional/Mono unwrap is source-review context"
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.reviews.len() + jobs.observation_reviews.len(), 5);
    for review in jobs.observation_reviews {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "webflux_containing_function_context")
            .unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        assert!(
            fact.excerpt
                .contains(anchor.enclosing_symbol.as_deref().unwrap())
        );
        assert!(
            fact.excerpt
                .contains("co-occurrence does not establish flow")
        );
        assert!(fact.excerpt.contains("not a native cross-lambda path"));
    }
}
