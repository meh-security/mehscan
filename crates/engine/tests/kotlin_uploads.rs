#[test]
fn owned_multipart_and_script_boundaries_exclude_foreign_methods() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-uploads");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let boundaries = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("kotlin-upload-") || e.rule_id == "kotlin-script-eval")
        .collect::<Vec<_>>();
    assert_eq!(
        boundaries
            .iter()
            .filter(|e| e.rule_id == "kotlin-upload-part")
            .count(),
        2
    );
    assert_eq!(
        boundaries
            .iter()
            .filter(|e| e.rule_id == "kotlin-upload-filename")
            .count(),
        2
    );
    assert_eq!(
        boundaries
            .iter()
            .filter(|e| e.rule_id == "kotlin-upload-content")
            .count(),
        2
    );
    assert_eq!(
        boundaries
            .iter()
            .filter(|e| e.rule_id == "kotlin-script-eval")
            .count(),
        4
    );
    assert!(
        !boundaries
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("unrelated"))
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    let writes = jobs
        .observation_reviews
        .iter()
        .filter(|r| r.evidence.iter().any(|e| e.rule_id == "kotlin-file-write"))
        .collect::<Vec<_>>();
    assert_eq!(writes.len(), 2);
    assert!(writes.iter().all(|r| {
        r.facts.iter().any(|f| {
            f.role == "owned_boundary_containing_function_context" && f.excerpt.contains("getPart")
        })
    }));
}
