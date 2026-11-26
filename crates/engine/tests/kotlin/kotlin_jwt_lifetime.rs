#[test]
fn issuance_context_preserves_effective_builder_claims_and_separate_verification() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-jwt-lifetime");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for rule in [
        "kotlin-auth0-jwt-token-generation",
        "kotlin-auth0-jwt-verify",
    ] {
        assert_eq!(
            scan.evidence.iter().filter(|e| e.rule_id == rule).count(),
            7
        );
    }
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert!(jobs.reviews.is_empty());
    assert_eq!(jobs.observation_reviews.len(), 14);
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
            "clearedExpiry" => assert!(fact.excerpt.contains("null as Instant?")),
            "payloadOverride" => {
                assert!(fact.excerpt.contains("withPayload(mapOf(\"exp\" to null))"))
            }
            "restoredExpiry" => assert!(
                fact.excerpt.rfind("withPayload").unwrap()
                    < fact.excerpt.rfind("withExpiresAt").unwrap()
            ),
            "wrongBuilder" => assert!(
                fact.excerpt
                    .contains("val other = JWT.create().withExpiresAt")
            ),
            _ => {}
        }
    }
}
