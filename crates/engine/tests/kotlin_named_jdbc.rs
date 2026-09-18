#[test]
fn named_parameter_templates_capture_sql_separately_from_bound_values() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-named-jdbc");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-jdbc-template-query")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 6);
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    for owner in ["boundMap", "boundSource"] {
        let sink = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(owner))
            .unwrap();
        assert!(sink.captures["query"].text.contains(":name"));
        assert!(!sink.captures["query"].text.contains("mapOf"));
        assert!(
            !sink.captures["query"]
                .text
                .contains("MapSqlParameterSource")
        );
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.reviews.len() + jobs.observation_reviews.len(), 6);
}
