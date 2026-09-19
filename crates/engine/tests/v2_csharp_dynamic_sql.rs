use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-dynamic-sql")
}

#[test]
fn promotes_dynamic_sql_composition_across_csharp_database_apis() {
    let root = fixture_root();
    let result = mehscan_engine::scan_path(&root).expect("fixture should scan");
    let dynamic = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == Capability::DatabaseQuery
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "dynamic-query-composition")
        })
        .collect::<Vec<_>>();

    assert_eq!(dynamic.len(), 8, "{dynamic:#?}");
    assert!(dynamic.iter().all(|item| {
        item.captures.contains_key("query_composition")
            && item.captures.contains_key("dynamic_operand")
            && item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
            && item
                .tags
                .iter()
                .any(|tag| tag == "dynamic-origin:method-parameter")
    }));
    assert!(
        dynamic
            .iter()
            .any(|item| item.rule_id == "csharp-dapper-database-query")
    );
    assert!(
        dynamic
            .iter()
            .any(|item| item.rule_id == "csharp-ef-database-sql-query")
    );
    assert!(
        dynamic
            .iter()
            .any(|item| item.rule_id == "csharp-ef-legacy-execute-sql-command")
    );

    let reviews = mehscan_engine::investigation::build_path_review_jobs(&root, Some(8), Some(100))
        .expect("review jobs should build");
    let dynamic_reviews = reviews
        .observation_reviews
        .iter()
        .filter(|review| {
            review
                .review_basis
                .as_ref()
                .is_some_and(|basis| basis.relationship == "bounded_dynamic_query_composition")
        })
        .collect::<Vec<_>>();
    assert_eq!(dynamic_reviews.len(), 8, "{dynamic_reviews:#?}");
    assert!(
        dynamic_reviews
            .iter()
            .all(|review| review.title == "Review dynamically composed C# SQL for CWE-89")
    );
    assert_eq!(
        dynamic_reviews
            .iter()
            .filter(|review| review.decision_facts.unresolved.len() == 1
                && review.decision_facts.unresolved[0].contains("production call site"))
            .count(),
        7
    );
    let numeric = dynamic_reviews
        .iter()
        .find(|review| {
            review.evidence.iter().any(|item| {
                item.tags
                    .iter()
                    .any(|tag| tag == "dynamic-origin:constrained-scalar")
            })
        })
        .expect("numeric composition should be characterized separately");
    assert!(numeric.decision_facts.unresolved.is_empty());
    assert!(
        numeric
            .decision_facts
            .established
            .iter()
            .any(|fact| fact.contains("affirmatively disproving SQL-syntax injection"))
    );
}
