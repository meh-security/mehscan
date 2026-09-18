#[test]
fn servlet_cookie_setters_and_properties_keep_exact_policy_context() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-cookies");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for rule in ["kotlin-cookie-secure-flag", "kotlin-cookie-httponly-flag"] {
        assert_eq!(
            scan.evidence.iter().filter(|e| e.rule_id == rule).count(),
            8
        );
    }
    assert!(
        !scan
            .evidence
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("foreign"))
    );
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert_eq!(jobs.observation_reviews.len(), 16);
    for review in jobs.observation_reviews {
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "cookie_containing_function_context")
            .unwrap();
        assert!(
            fact.evidence_id
                .as_ref()
                .is_some_and(|id| review.anchor_evidence_ids.contains(id))
        );
        if fact.symbol == "resetSession" {
            assert!(fact.excerpt.contains("cookie.secure = true"));
            assert!(fact.excerpt.contains("response.addCookie(cookie)"));
        }
    }
}
