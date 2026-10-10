use mehscan_core::ObservationReview;
use std::path::PathBuf;

fn jobs() -> Vec<ObservationReview> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/react-producer-review");
    mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100))
        .unwrap()
        .observation_reviews
}

#[test]
fn react_transformed_props_types_callers_and_decoding_inputs_are_located() {
    let jobs = jobs();
    for path in ["Raw.tsx", "Clean.tsx"] {
        let review = jobs
            .iter()
            .find(|r| r.evidence.iter().any(|e| e.location.path == path))
            .unwrap();
        for role in [
            "frontend_output_producer_context",
            "frontend_component_prop_context",
            "frontend_component_prop_type_context",
            "frontend_prop_caller_context",
            "frontend_prop_producer_context",
        ] {
            assert!(
                review.facts.iter().any(|f| f.role == role),
                "{path}: missing {role}"
            );
        }
        assert!(review.facts.iter().any(|f| f.location.path == "Page.tsx" && f.excerpt.contains("new URLSearchParams")));
        assert!(
            !review
                .facts
                .iter()
                .any(|f| f.role == "frontend_prop_caller_context"
                    && f.excerpt.contains("not the imported"))
        );
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/react-producer-review");
    for fact in jobs
        .iter()
        .flat_map(|r| &r.facts)
        .filter(|f| f.role.starts_with("frontend_"))
    {
        let source = std::fs::read_to_string(root.join(&fact.location.path)).unwrap();
        assert_eq!(
            &source[fact.location.start.byte_offset..fact.location.end.byte_offset],
            fact.excerpt
        );
    }
}

#[test]
fn react_imported_wrappers_are_navigation_and_shadows_are_not_prop_contracts() {
    let jobs = jobs();
    let wrapped: Vec<_> = jobs
        .iter()
        .filter(|r| r.evidence.iter().any(|e| e.location.path == "Wrapped.tsx"))
        .collect();
    assert_eq!(wrapped.len(), 2);
    for review in wrapped {
        assert!(
            review
                .facts
                .iter()
                .any(|f| f.role == "frontend_component_wrapper_context")
        );
        assert!(
            review
                .facts
                .iter()
                .any(|f| f.role == "frontend_prop_caller_context")
        );
        assert!(
            review
                .facts
                .iter()
                .any(|f| f.role == "frontend_import_binding_context"
                    && f.excerpt.contains("from 'react'"))
        );
    }
    for (symbol, line) in [("Fake", 5), ("ShadowInput", 15)] {
        let review = jobs
            .iter()
            .find(|r| {
                r.evidence
                    .iter()
                    .any(|e| e.location.path == "Controls.tsx" && e.location.start.line == line)
            })
            .unwrap_or_else(|| {
                panic!(
                    "{symbol}: {:?}",
                    jobs.iter()
                        .flat_map(|r| &r.evidence)
                        .map(|e| (&e.location.path, e.location.start.line, &e.enclosing_symbol))
                        .collect::<Vec<_>>()
                )
            });
        assert!(
            !review
                .facts
                .iter()
                .any(|f| f.role == "frontend_component_prop_context"),
            "{symbol}"
        );
    }
    let local = jobs
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.location.path == "Controls.tsx"
                    && e.enclosing_symbol
                        .as_deref()
                        .is_some_and(|s| s.contains("Local"))
            })
        })
        .unwrap();
    assert!(
        local
            .facts
            .iter()
            .any(|f| f.role == "frontend_output_producer_context"
                && f.excerpt.contains("DOMPurify.sanitize"))
    );
    assert!(local.facts.iter().any(|f| f.role == "frontend_import_binding_context" && f.excerpt.contains("dompurify")));
    let destructured = jobs
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some("Destructured"))
        })
        .unwrap();
    assert!(
        !destructured
            .facts
            .iter()
            .any(|f| f.role == "frontend_output_producer_context"
                && f.excerpt.contains("unrelated outer value"))
    );
    let shadow = jobs
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.enclosing_symbol.as_deref() == Some("ShadowLocal"))
        })
        .unwrap();
    assert!(
        !shadow
            .facts
            .iter()
            .any(|f| f.role == "frontend_component_prop_context")
    );
}
