#[test]
fn global_hostname_context_preserves_construction_restoration_and_instance_policy() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-tls-defaults");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-tls-default-policy")
            .count(),
        9
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert!(jobs.reviews.is_empty());
    assert_eq!(jobs.observation_reviews.len(), 13);
    for review in jobs.observation_reviews {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        if anchor.rule_id != "kotlin-tls-default-policy" {
            assert!(
                !review
                    .facts
                    .iter()
                    .any(|f| f.role == "tls_default_containing_function_context")
            );
            continue;
        }
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "tls_default_containing_function_context")
            .unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        let matched = review
            .facts
            .iter()
            .find(|f| f.role == "tls_default_matched_policy_context")
            .unwrap();
        assert_eq!(matched.location, anchor.location);
        assert_eq!(matched.evidence_id.as_deref(), Some(anchor.id.as_str()));
        if [14, 25, 36, 47].contains(&anchor.location.start.line) {
            assert_eq!(matched.symbol, "saved");
            assert!(!matched.excerpt.contains("-> true"));
        }
        assert!(fact.excerpt.contains("finally"));
        assert!(fact.excerpt.contains("connection.inputStream"));
        match anchor.enclosing_symbol.as_deref().unwrap() {
            "existingConnection" => assert!(
                fact.excerpt.find("connection.hostnameVerifier =").unwrap()
                    < fact
                        .excerpt
                        .find("setDefaultHostnameVerifier { _, _ -> true }")
                        .unwrap()
            ),
            "instanceOverride" => assert!(
                fact.excerpt.find("connection.hostnameVerifier =").unwrap()
                    < fact.excerpt.find("connection.inputStream").unwrap()
            ),
            "restoredBeforeOpen" => assert!(
                fact.excerpt
                    .find("setDefaultHostnameVerifier { _, _ -> false }")
                    .unwrap()
                    < fact.excerpt.find(".openConnection()").unwrap()
            ),
            _ => {}
        }
    }
}
