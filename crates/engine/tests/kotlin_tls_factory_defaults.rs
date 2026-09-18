#[test]
fn factory_defaults_keep_the_consumed_policy_distinct_from_existing_factories() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-tls-factory-defaults");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for (rule, count) in [
        ("kotlin-tls-trust-context", 4),
        ("kotlin-tls-default-policy", 8),
        ("kotlin-url-connection", 4),
    ] {
        assert_eq!(
            scan.evidence.iter().filter(|e| e.rule_id == rule).count(),
            count
        );
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert!(jobs.reviews.is_empty());
    assert_eq!(jobs.observation_reviews.len(), 16);
    for review in jobs.observation_reviews {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let role = match anchor.rule_id.as_str() {
            "kotlin-tls-trust-context" => "tls_trust_containing_function_context",
            "kotlin-tls-default-policy" => "tls_default_containing_function_context",
            _ => continue,
        };
        let fact = review.facts.iter().find(|f| f.role == role).unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        match anchor.enclosing_symbol.as_deref().unwrap() {
            "existingFactory" => assert!(
                fact.excerpt
                    .find("connection.sslSocketFactory = saved")
                    .unwrap()
                    < fact
                        .excerpt
                        .find("setDefaultSSLSocketFactory(context.socketFactory)")
                        .unwrap()
            ),
            "capturedFactory" => assert!(
                fact.excerpt
                    .contains("connection.sslSocketFactory = captured")
            ),
            "defaultContextConsumed" => {
                assert!(fact.excerpt.contains(
                    "connection.sslSocketFactory = SSLContext.getDefault().socketFactory"
                ))
            }
            _ => {}
        }
        if role == "tls_default_containing_function_context" {
            let exact = review
                .facts
                .iter()
                .find(|f| f.role == "tls_default_matched_policy_context")
                .unwrap();
            assert_eq!(exact.location, anchor.location);
            if exact.symbol == "saved" {
                assert!(!exact.excerpt.contains("arrayOf(permissive)"));
            }
        }
    }
}
