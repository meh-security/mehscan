#[test]
fn named_file_charset_arguments_keep_path_and_content_separate() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-file-overloads");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| matches!(e.rule_id.as_str(), "kotlin-file-read" | "kotlin-file-write"))
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 6);
    assert!(
        !sinks
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("lookalike"))
    );
    let write = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("rawWrite"))
        .unwrap();
    assert!(write.captures["path"].text.contains("File(root, name)"));
    assert_eq!(write.captures["content"].text, "content");
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.reviews.len() + jobs.observation_reviews.len(), 6);
}
