use std::collections::BTreeSet;

#[test]
fn pooled_xa_and_template_factories_keep_preparation_and_execution_distinct() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-jdbc-policy-factories");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("kotlin-jdbc-"))
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 8);
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    let owners = sinks
        .iter()
        .map(|e| e.enclosing_symbol.clone().unwrap())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        owners,
        [
            "rawTemplate",
            "boundTemplate",
            "rawPooled",
            "rawXa",
            "rawPrepared3",
            "rawPrepared4",
            "boundPrepared",
            "lazyPrepared"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.reviews.len() + jobs.observation_reviews.len(), 8);
    for review in &jobs.observation_reviews {
        let anchor = scan
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        if anchor.enclosing_symbol.as_deref() == Some("lazyPrepared") {
            assert!(
                !review
                    .facts
                    .iter()
                    .any(|f| f.role == "prepared_statement_execution_context")
            );
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.role == "prepared_statement_lifecycle_context"
                        && f.excerpt.contains("prepared.close()"))
            );
        }
    }
    for owner in [
        "rawPrepared3",
        "rawPrepared4",
        "boundPrepared",
        "lazyPrepared",
    ] {
        let sink = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(owner))
            .unwrap();
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
        if owner == "lazyPrepared" {
            assert!(
                !facts
                    .iter()
                    .any(|f| f.role == "prepared_statement_execution_context")
            );
            assert!(
                facts
                    .iter()
                    .any(|f| f.role == "prepared_statement_lifecycle_context"
                        && f.excerpt.contains("prepared.close()"))
            );
            continue;
        }
        assert!(
            facts
                .iter()
                .any(|f| f.role == "prepared_statement_execution_context"
                    && f.evidence_id.as_deref() == Some(sink.id.as_str())
                    && f.excerpt.contains("prepared.executeQuery()"))
        );
    }
}
