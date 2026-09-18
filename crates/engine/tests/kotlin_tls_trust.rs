#[test]
fn trust_configuration_context_preserves_consumption_order_and_validation() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-tls-trust");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-tls-trust-context")
            .count(),
        10
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    let reviews: Vec<_> = jobs
        .observation_reviews
        .iter()
        .filter(|r| {
            r.evidence
                .iter()
                .any(|e| e.rule_id == "kotlin-tls-trust-context")
        })
        .collect();
    assert_eq!(reviews.len(), 10);
    for review in reviews {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "tls_trust_containing_function_context")
            .unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        let owner = anchor.enclosing_symbol.as_deref().unwrap();
        assert!(fact.excerpt.contains(owner));
        assert!(fact.excerpt.contains("connection.sslSocketFactory"));
        match owner {
            "wrongContext" => assert!(fact.excerpt.contains("consumed.socketFactory")),
            "resetContext" => assert!(
                fact.excerpt.find("arrayOf(permissive)").unwrap()
                    < fact.excerpt.find("context.init(null, null, null)").unwrap()
            ),
            "firstPermissive" => assert!(fact.excerpt.contains("arrayOf(permissive, validating)")),
            "firstValidating" => assert!(fact.excerpt.contains("arrayOf(validating, permissive)")),
            "swallowedValidation" => assert!(
                fact.excerpt
                    .contains("catch (ignored: CertificateException) {}")
            ),
            _ => {}
        }
    }
}
