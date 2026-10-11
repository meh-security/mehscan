use std::path::PathBuf;

#[test]
fn clipped_state_writer_samples_remain_explicit() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/react-state-review");
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    let review = job
        .observation_reviews
        .iter()
        .find(|r| r.evidence.iter().any(|e| e.location.path == "Limited.tsx"))
        .unwrap();
    assert!(review.context_truncated);
    assert_eq!(
        review
            .facts
            .iter()
            .filter(|f| f.role == "frontend_state_writer_context")
            .count(),
        3
    );
}

#[test]
fn owned_state_writers_and_list_receivers_are_bounded_navigation() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/react-state-review");
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    let list = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.location.path == "Rows.tsx" && e.location.start.line == 5)
        })
        .unwrap();
    assert!(
        list.context_truncated,
        "spread is still an unresolved field binding"
    );
    assert!(
        list.facts
            .iter()
            .any(|f| f.role == "frontend_collection_producer_context" && f.excerpt == "rows")
    );
    assert!(
        list.facts
            .iter()
            .any(|f| f.role == "frontend_state_declaration_context"
                && f.excerpt.contains("[rows, setRows]"))
    );
    assert!(
        list.facts
            .iter()
            .any(|f| f.role == "frontend_state_writer_context"
                && f.excerpt.contains("response.items")
                && f.excerpt.contains("fetchRows('/api/items')"))
    );
    assert!(
        list.facts
            .iter()
            .any(|f| f.role == "frontend_imported_helper_context"
                && f.excerpt.contains("fetch(url)"))
    );
    let direct = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.location.path == "Rows.tsx" && e.location.start.line == 27)
        })
        .unwrap();
    assert!(
        direct
            .facts
            .iter()
            .any(|f| f.role == "frontend_state_declaration_context"
                && f.excerpt.contains("React.useState"))
    );
    assert!(
        direct
            .facts
            .iter()
            .any(|f| f.role == "frontend_state_writer_context"
                && f.excerpt.contains("useEffect")
                && f.excerpt.contains("clean(payload)"))
    );
    assert!(
        direct
            .facts
            .iter()
            .any(|f| f.role == "frontend_state_writer_context"
                && f.excerpt.contains("previous => previous + payload"))
    );
    assert!(
        direct
            .facts
            .iter()
            .any(|f| f.role == "frontend_imported_helper_context"
                && f.excerpt.contains("DOMPurify.sanitize"))
    );
    for review in [list, direct] {
        assert!(
            !review
                .facts
                .iter()
                .any(|f| f.role == "frontend_state_writer_context"
                    && f.excerpt.contains("unrelated")),
            "shadowed setters are not writers"
        );
    }
    for review in &job.observation_reviews {
        if review
            .evidence
            .iter()
            .any(|e| e.location.path == "Unrelated.tsx")
        {
            assert!(
                !review
                    .facts
                    .iter()
                    .any(|f| f.role.starts_with("frontend_state_")),
                "only owned React hooks"
            );
        }
        for fact in review
            .facts
            .iter()
            .filter(|f| f.role.starts_with("frontend_"))
        {
            let source = std::fs::read_to_string(root.join(&fact.location.path)).unwrap();
            assert_eq!(
                &source[fact.location.start.byte_offset..fact.location.end.byte_offset],
                fact.excerpt
            );
        }
    }
    assert!(
        !job.observation_reviews.iter().any(|r| r
            .evidence
            .iter()
            .any(|e| e.location.path == "Rows.tsx"
                && e.enclosing_symbol.as_deref() == Some("Escaped"))),
        "ordinary interpolation must not gain HTML reviews"
    );
}
