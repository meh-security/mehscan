#[test]
fn jwt_policy_context_keeps_decoding_and_verification_distinct() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-jwt");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for rule in ["kotlin-auth0-jwt-decode", "kotlin-auth0-jwt-verify"] {
        assert_eq!(
            scan.evidence.iter().filter(|e| e.rule_id == rule).count(),
            4
        );
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert!(jobs.reviews.is_empty());
    assert_eq!(jobs.observation_reviews.len(), 8);
    for review in jobs.observation_reviews {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "jwt_containing_function_context")
            .unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        match anchor.enclosing_symbol.as_deref().unwrap() {
            "ignoredFailure" => assert!(
                fact.excerpt
                    .contains("catch (ignored: JWTVerificationException) {}")
            ),
            "unsignedAdmin" => assert!(fact.excerpt.contains("Algorithm.none()")),
            "verifiedBeforeDecode" => {
                let source =
                    &fact.excerpt[fact.excerpt.find("fun verifiedBeforeDecode").unwrap()..];
                assert!(
                    source.find(".verify(token)").unwrap()
                        < source.find("JWT().decodeJwt(token)").unwrap()
                );
            }
            _ => {}
        }
    }
}
