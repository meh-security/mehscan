#[test]
fn exposed_sql_owns_transaction_aliases_and_keeps_bound_values_in_context() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-exposed");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-exposed-sql-exec")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 6);
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    let reviews = jobs
        .observation_reviews
        .iter()
        .filter(|r| {
            r.evidence.iter().any(|e| {
                e.rule_id == "kotlin-exposed-sql-exec" && r.anchor_evidence_ids.contains(&e.id)
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(reviews.len(), 5);
    assert_eq!(jobs.reviews.len(), 1);
    assert_eq!(
        jobs.reviews[0].candidate.sink.enclosing_symbol.as_deref(),
        Some("typedExec")
    );
    assert_eq!(
        scan.security_paths.len(),
        1,
        "transaction lambdas must remain source review, while the declared receiver admits a local scalar path"
    );
    for review in reviews {
        let anchor = sinks
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "exposed_containing_function_context")
            .unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        assert!(
            fact.excerpt
                .contains(anchor.enclosing_symbol.as_deref().unwrap())
        );
        assert!(fact.excerpt.contains("not a native cross-lambda path"));
        if anchor.enclosing_symbol.as_deref() == Some("boundTransaction") {
            assert!(
                fact.excerpt
                    .contains("args = listOf(VarCharColumnType(64) to name)")
            );
        }
    }
}
