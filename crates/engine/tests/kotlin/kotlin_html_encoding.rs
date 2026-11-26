#[test]
fn html_encoder_inventory_is_canonical_and_contextual() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-html-encoding");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let encoders = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "kotlin-html-encoding")
        .collect::<Vec<_>>();
    assert_eq!(encoders.len(), 4);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-ktor-html-output")
            .count(),
        4
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.reviews.len() + jobs.observation_reviews.len(), 4);
    assert!(jobs.observation_reviews.iter().all(|r| {
        r.facts.iter().any(|f| {
            f.role == "html_encoder_sdk_operation"
                && f.symbol == "org.owasp.encoder.Encode.forHtmlContent"
        })
    }));
    assert!(jobs.observation_reviews.iter().all(|r| {
        r.facts.iter().any(|f| {
            f.role == "html_output_operation_context" && f.excerpt.starts_with("call.respondText")
        })
    }));
    assert!(encoders.iter().all(
        |e| e.kind == mehscan_core::EvidenceKind::Sanitizer && e.captures.contains_key("value")
    ));
    assert!(
        !encoders
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("foreign"))
    );
}
