use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-go-gorm")
}

#[test]
fn separates_gorm_condition_objects_from_raw_query_grammar() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let gorm = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "go-gorm-query")
        .collect::<Vec<_>>();
    assert_eq!(gorm.len(), 10, "{gorm:#?}");

    for symbol in [
        "structuredValue",
        "structuredPointer",
        "structuredMap",
        "structuredParameter",
        "structuredMapParameter",
    ] {
        let item = gorm
            .iter()
            .find(|item| item.enclosing_symbol.as_deref() == Some(symbol))
            .expect("structured GORM condition");
        assert!(item.captures.contains_key("structured_filter"));
        assert!(
            item.tags
                .iter()
                .any(|tag| tag == "query-role:structured-filter")
        );
        assert!(!item.tags.iter().any(|tag| tag == "dynamic-query-operand"));
        assert!(
            !item
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
        );
    }

    let unknown = gorm
        .iter()
        .find(|item| item.enclosing_symbol.as_deref() == Some("unknownCondition"))
        .expect("unknown condition");
    assert!(
        unknown
            .tags
            .iter()
            .any(|tag| tag == "dynamic-query-operand")
    );
    let string = gorm
        .iter()
        .find(|item| item.enclosing_symbol.as_deref() == Some("stringCondition"))
        .expect("string condition");
    assert!(string.tags.iter().any(|tag| tag == "dynamic-query-operand"));
    let raw_expression = gorm
        .iter()
        .find(|item| item.enclosing_symbol.as_deref() == Some("rawExpression"))
        .expect("raw clause expression");
    assert!(
        !raw_expression
            .tags
            .iter()
            .any(|tag| tag == "query-role:structured-filter")
    );

    let composed = gorm
        .iter()
        .find(|item| item.enclosing_symbol.as_deref() == Some("composedCondition"))
        .expect("composed condition");
    assert!(
        composed
            .tags
            .iter()
            .any(|tag| tag == "dynamic-query-composition")
    );

    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("review jobs should build");
    let mut database_review_symbols = jobs
        .reviews
        .iter()
        .filter(|review| review.candidate.capability == Capability::DatabaseQuery)
        .filter_map(|review| review.candidate.sink.enclosing_symbol.as_deref())
        .collect::<Vec<_>>();
    database_review_symbols.extend(
        jobs.observation_reviews
            .iter()
            .filter(|review| {
                review
                    .evidence
                    .iter()
                    .any(|item| item.capability == Capability::DatabaseQuery)
            })
            .filter_map(|review| {
                review
                    .evidence
                    .iter()
                    .find_map(|item| item.enclosing_symbol.as_deref())
            }),
    );
    assert!(database_review_symbols.contains(&"unknownCondition"));
    assert!(database_review_symbols.contains(&"stringCondition"));
    assert!(database_review_symbols.contains(&"rawExpression"));
    assert!(database_review_symbols.contains(&"composedCondition"));
    assert!(
        [
            "structuredValue",
            "structuredPointer",
            "structuredMap",
            "structuredParameter",
            "structuredMapParameter",
        ]
        .iter()
        .all(|symbol| !database_review_symbols.contains(symbol)),
        "{database_review_symbols:#?}"
    );
}
