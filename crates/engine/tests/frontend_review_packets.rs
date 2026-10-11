use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/frontend-review-packets")
}

#[test]
fn multiple_props_bind_exact_arguments_without_duplicate_caller_windows() {
    let root = fixture();
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    for (line, component, callers) in [
        (2, "MultiProps", 2),
        (6, "MultiObject", 1),
        (10, "MultiAlias", 1),
    ] {
        let review = job
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence
                    .iter()
                    .any(|e| e.location.path == "MultiProps.tsx" && e.location.start.line == line)
            })
            .unwrap();
        let caller_facts: Vec<_> = review
            .facts
            .iter()
            .filter(|f| f.role == "frontend_prop_caller_context")
            .collect();
        assert_eq!(caller_facts.len(), callers);
        assert!(
            caller_facts
                .iter()
                .all(|f| f.location.path == "MultiCallers.tsx")
        );
        for prop in ["html", "enabled"] {
            assert_eq!(
                review
                    .facts
                    .iter()
                    .filter(|f| f.role == "frontend_prop_value_context"
                        && f.symbol == format!("{component}.{prop}"))
                    .count(),
                callers
            );
        }
        assert!(
            !review
                .facts
                .iter()
                .any(|f| f.role == "frontend_prop_caller_context"
                    && f.excerpt.contains("enabled={true}")),
            "do not map shadowed/unrelated components"
        );
        if component == "MultiProps" {
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.role == "frontend_imported_helper_context"
                        && f.location.path == "MultiControl.ts"
                        && f.excerpt.contains("DOMPurify.sanitize"))
            );
        }
        if component == "MultiObject" {
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.role == "frontend_prop_value_context"
                        && f.symbol == "MultiObject.enabled"
                        && f.excerpt == "enabled")
            );
        }
        for f in review
            .facts
            .iter()
            .filter(|f| f.role.starts_with("frontend_"))
        {
            let source = std::fs::read_to_string(root.join(&f.location.path)).unwrap();
            assert_eq!(
                &source[f.location.start.byte_offset..f.location.end.byte_offset],
                f.excerpt
            );
        }
    }
}

#[test]
fn multi_prop_gaps_remain_explicit_and_mutated_arguments_are_not_mapped() {
    let root = fixture();
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    for (line, component, bound) in [
        (14, "PartialMulti", vec!["html"]),
        (18, "DuplicateMulti", vec!["enabled"]),
        (22, "ManyProps", vec!["a", "b", "c"]),
    ] {
        let review = job
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence
                    .iter()
                    .any(|e| e.location.path == "MultiProps.tsx" && e.location.start.line == line)
            })
            .unwrap();
        assert!(
            review.context_truncated,
            "{component} gap must remain explicit"
        );
        let values: Vec<_> = review
            .facts
            .iter()
            .filter(|f| f.role == "frontend_prop_value_context")
            .collect();
        assert_eq!(values.len(), bound.len(), "{component}: {values:#?}");
        for prop in bound {
            assert!(
                values
                    .iter()
                    .any(|f| f.symbol == format!("{component}.{prop}"))
            );
        }
    }
    let mutated = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.location.path == "MultiProps.tsx" && e.location.start.line == 27)
        })
        .unwrap();
    assert!(!mutated.facts.iter().any(|f| matches!(
        f.role.as_str(),
        "frontend_component_prop_context"
            | "frontend_prop_caller_context"
            | "frontend_prop_value_context"
    )));
}

#[test]
fn nested_renderers_capture_outer_props_without_crossing_shadow_or_class_boundaries() {
    let root = fixture();
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    let reviews: Vec<_> = job
        .observation_reviews
        .iter()
        .filter(|r| {
            r.evidence.iter().any(|e| {
                e.location.path == "Nested.tsx"
                    && e.rule_id.ends_with("react-dangerous-html-output")
            })
        })
        .collect();
    assert_eq!(
        reviews.len(),
        6,
        "all six raw HTML operations remain reviewable"
    );
    for review in reviews {
        let line = review
            .evidence
            .iter()
            .find(|e| {
                e.location.path == "Nested.tsx"
                    && e.rule_id.ends_with("react-dangerous-html-output")
            })
            .unwrap()
            .location
            .start
            .line;
        let expected = matches!(line, 4 | 11);
        assert_eq!(
            review
                .facts
                .iter()
                .any(|f| f.role == "frontend_component_prop_context"),
            expected,
            "prop binding at line {line}: {:#?}",
            review.facts
        );
        assert_eq!(
            review
                .facts
                .iter()
                .any(|f| f.role == "frontend_prop_caller_context"
                    && f.location.path == "NestedCallers.tsx"),
            expected,
            "caller at line {line}"
        );
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
}

#[test]
fn jsx_packets_locate_owned_callers_producers_and_actual_controls() {
    let root = fixture();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    let review = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.location.path == "Rich.tsx" && e.rule_id == "tsx-react-dangerous-html-output"
            })
        })
        .expect("raw component should remain reviewable");
    let callers: Vec<_> = review
        .facts
        .iter()
        .filter(|f| f.role == "frontend_prop_caller_context")
        .collect();
    assert_eq!(callers.len(), 2, "{:#?}", review.facts);
    assert!(callers.iter().all(|f| f.location.path == "Callers.tsx"));
    assert!(callers.iter().any(|f| f.excerpt.contains("html={markup}")));
    assert!(
        callers
            .iter()
            .any(|f| f.excerpt.contains("html={untrusted}"))
    );
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_prop_producer_context"
                && f.excerpt.contains("clean(untrusted)"))
    );
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "helper_definition_context"
                && f.location.path == "Callers.tsx"
                && f.excerpt.contains("DOMPurify.sanitize"))
    );
    assert!(review.facts.iter().any(|f| f.role == "frontend_import_binding_context" && f.excerpt.contains("dompurify")));
    assert!(
        !review
            .facts
            .iter()
            .any(|f| f.role.starts_with("frontend_") && f.location.path == "Unrelated.tsx")
    );
    assert!(
        review
            .decision_facts
            .established
            .iter()
            .any(|s| s.contains("not proof of attacker control"))
    );
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
    assert!(
        scan.evidence.iter().any(
            |e| e.location.path == "Rich.tsx" && e.rule_id == "tsx-react-dangerous-html-output"
        )
    );
}

#[test]
fn jsx_packets_keep_spreads_and_more_callers_open_and_do_not_map_mutated_props() {
    let job = mehscan_engine::investigation::build_path_review_jobs(&fixture(), Some(3), Some(100))
        .unwrap();
    let solid = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.location.path == "Solid.tsx" && e.rule_id == "tsx-solid-inner-html-output"
            })
        })
        .unwrap();
    assert!(
        solid
            .facts
            .iter()
            .any(|f| f.role == "frontend_prop_caller_context" && f.excerpt.contains("...options"))
    );
    assert!(
        solid.context_truncated,
        "spread/reaching value must remain open"
    );
    assert!(solid.facts.iter().any(|f| f.role == "frontend_prop_caller_context" && f.excerpt.contains("fixed markup")));
    let mutated = job
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.location.path == "Mutated.tsx" && e.rule_id == "tsx-react-dangerous-html-output"
            })
        })
        .unwrap();
    assert!(
        !mutated.facts.iter().any(|f| matches!(
            f.role.as_str(),
            "frontend_component_prop_context" | "frontend_prop_caller_context"
        )),
        "do not map reassigned operands to initial props: {:#?}",
        mutated.facts
    );
}

#[test]
fn computed_props_explicit_exports_and_javascript_default_imports_are_navigable() {
    let job = mehscan_engine::investigation::build_path_review_jobs(&fixture(), Some(3), Some(100))
        .unwrap();
    for (path, caller) in [
        ("Memo.tsx", "MemoCallers.tsx"),
        ("Default.jsx", "DefaultCaller.jsx"),
    ] {
        let review = job
            .observation_reviews
            .iter()
            .find(|r| {
                r.evidence.iter().any(|e| {
                    e.location.path == path && e.rule_id.ends_with("react-dangerous-html-output")
                })
            })
            .unwrap();
        assert!(
            review
                .facts
                .iter()
                .any(|f| f.role == "frontend_prop_caller_context" && f.location.path == caller),
            "{path}: {:#?}",
            review.facts
        );
        if path == "Memo.tsx" {
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.role == "frontend_prop_caller_context"
                        && f.location.path == "PartialCaller.tsx"),
                "valid callers outside parser error regions remain available"
            );
            assert!(review.context_truncated, "parser gaps must remain explicit");
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.role == "frontend_output_producer_context"
                        && f.excerpt.contains("React.useMemo"))
            );
            assert!(
                review
                    .facts
                    .iter()
                    .any(|f| f.role == "frontend_import_binding_context"
                        && f.excerpt.contains("dompurify"))
            );
        }
    }
}
