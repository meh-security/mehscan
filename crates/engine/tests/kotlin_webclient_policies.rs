#[test]
fn policy_context_preserves_order_forwarded_request_and_factory_entry_points() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/kotlin-webclient-policies");
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    assert_eq!(
        scan.evidence
            .iter()
            .filter(|e| e.rule_id == "kotlin-webclient-uri")
            .count(),
        9
    );
    assert!(scan.security_paths.is_empty());
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    assert!(jobs.reviews.is_empty());
    assert_eq!(jobs.observation_reviews.len(), 9);
    for review in jobs.observation_reviews {
        let anchor = review
            .evidence
            .iter()
            .find(|e| review.anchor_evidence_ids.contains(&e.id))
            .unwrap();
        let fact = review
            .facts
            .iter()
            .find(|f| f.role == "webclient_containing_function_context")
            .unwrap();
        assert_eq!(fact.evidence_id.as_deref(), Some(anchor.id.as_str()));
        let owner = anchor.enclosing_symbol.as_deref().unwrap();
        let contract = review
            .facts
            .iter()
            .find(|f| f.role == "webclient_uri_overload_context")
            .unwrap();
        assert_eq!(contract.evidence_id.as_deref(), Some(anchor.id.as_str()));
        assert_eq!(contract.location, anchor.location);
        if owner == "absoluteUriBypass" {
            assert!(contract.excerpt.contains("URI-valued overload"));
        } else {
            assert!(
                contract
                    .excerpt
                    .contains("expand overloads are not invoked")
            );
        }
        assert!(fact.excerpt.contains(owner));
        match owner {
            "defaultBeforeUri" => assert!(
                fact.excerpt.find("defaultRequest").unwrap()
                    < fact.excerpt.rfind("uri(target)").unwrap()
            ),
            "wrongFilterRequest" => {
                assert!(
                    !review
                        .facts
                        .iter()
                        .any(|f| f.role == "webclient_direct_exchange_argument_context")
                );
                assert!(
                    fact.excerpt
                        .contains("val ignored = ClientRequest.from(request)")
                );
                assert!(fact.excerpt.contains("next.exchange(request)"));
            }
            "rewriteAfterApproval" => {
                let argument = review
                    .facts
                    .iter()
                    .find(|f| f.role == "webclient_direct_exchange_argument_context")
                    .unwrap();
                assert!(argument.excerpt.contains(
                    "next.exchange(ClientRequest.from(request).url(URI.create(target)).build())"
                ));
                let mutation = review
                    .facts
                    .iter()
                    .find(|f| {
                        f.role == "webclient_request_mutation_context"
                            && f.symbol == "URI.create(target)"
                    })
                    .unwrap();
                assert!(mutation.location.start.line < anchor.location.start.line);
                assert_eq!(mutation.evidence_id.as_deref(), Some(anchor.id.as_str()));
                assert!(
                    fact.excerpt.find("require(request.url()").unwrap()
                        < fact.excerpt.find("url(URI.create(target))").unwrap()
                );
            }
            "removedFilter" => assert!(fact.excerpt.contains("filters.clear()")),
            "pinnedStringFactory" | "absoluteUriBypass" => {
                assert!(fact.excerpt.contains("override fun uriString"))
            }
            "wrongExpandOverride" => {
                assert!(fact.excerpt.contains("override fun expand"));
                assert!(!fact.excerpt.contains("override fun uriString"));
            }
            _ => {}
        }
    }
}
