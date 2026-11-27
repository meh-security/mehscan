#[test]
fn spring_authorization_annotations_are_owned_context_only() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-authorization");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let guards = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-method-authorization")
        .collect::<Vec<_>>();
    assert_eq!(guards.len(), 4);
    assert!(
        guards
            .iter()
            .all(|e| e.kind == mehscan_core::EvidenceKind::Guard)
    );
    assert!(
        !guards
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("unrelated"))
    );
    assert!(guards.iter().all(|e| e.captures.contains_key("policy")));
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.reviews.len(), 1);
    assert_eq!(
        jobs.reviews[0].candidate.sink.rule_id,
        "kotlin-jdbc-template-query"
    );
    assert!(
        jobs.reviews[0]
            .facts
            .iter()
            .any(|f| f.excerpt.contains("isAuthenticated()"))
    );
    assert!(!jobs.observation_reviews.iter().any(|r| {
        r.anchor_evidence_ids
            .iter()
            .any(|id| guards.iter().any(|g| &g.id == id))
    }));
}
