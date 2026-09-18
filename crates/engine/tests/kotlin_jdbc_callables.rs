#[test]
fn callable_overloads_keep_execution_and_binding_with_the_same_preparation() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-jdbc-callables");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-jdbc-prepare-query")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 4);
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.reviews.len() + jobs.observation_reviews.len(), 4);
    for sink in sinks {
        let owner = sink.enclosing_symbol.as_deref().unwrap();
        let facts = jobs
            .reviews
            .iter()
            .filter(|r| r.candidate.sink.id == sink.id)
            .flat_map(|r| &r.facts)
            .chain(
                jobs.observation_reviews
                    .iter()
                    .filter(|r| r.anchor_evidence_ids.contains(&sink.id))
                    .flat_map(|r| &r.facts),
            )
            .collect::<Vec<_>>();
        assert_eq!(
            facts
                .iter()
                .any(|f| f.role == "prepared_statement_execution_context"),
            owner != "lazyCall4"
        );
        if owner == "boundCall3" {
            assert!(
                facts
                    .iter()
                    .any(|f| f.role == "prepared_statement_binding_context"
                        && f.excerpt.contains("prepared.setString(1, name)"))
            );
        }
        assert!(
            facts
                .iter()
                .any(|f| f.role == "prepared_statement_lifecycle_context"
                    && f.excerpt.contains("prepared.close()"))
        );
    }
}
