use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/vue-prop-review")
}

#[test]
fn nested_vue_dependencies_keep_prop_reads_without_repeating_covered_source() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/vue-dependency-review");
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    let review = &jobs.observation_reviews[0];
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_output_producer_context"
                && f.excerpt.contains("const piece"))
    );
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_component_prop_context")
    );
    assert!(!review.facts.iter().any(
        |f| f.role == "frontend_output_dependency_context" && f.excerpt.starts_with("piece =")
    ));
}

#[test]
fn vue_packets_locate_setup_producers_props_and_exact_imported_callers() {
    let root = fixture();
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(3), Some(100)).unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| r.evidence.iter().any(|e| e.location.path == "Rich.vue"))
        .unwrap();
    for role in [
        "frontend_output_producer_context",
        "frontend_component_prop_context",
        "frontend_prop_caller_context",
        "frontend_prop_producer_context",
        "frontend_import_binding_context",
    ] {
        assert!(
            review.facts.iter().any(|f| f.role == role),
            "missing {role}: {:#?}",
            review.facts
        );
    }
    let callers: Vec<_> = review
        .facts
        .iter()
        .filter(|f| f.role == "frontend_prop_caller_context")
        .collect();
    assert_eq!(callers.len(), 2);
    assert!(callers.iter().all(|f| f.location.path == "Parent.vue"));
    assert!(
        callers
            .iter()
            .any(|f| f.excerpt.contains(":html=\"cleaned\""))
    );
    assert!(
        callers
            .iter()
            .any(|f| f.excerpt.contains("v-bind:html=\"input\""))
    );
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_prop_producer_context"
                && f.excerpt.contains("DOMPurify.sanitize"))
    );
    assert!(
        review.context_truncated,
        "additional static/spread caller samples must remain open"
    );
    assert!(
        !review
            .facts
            .iter()
            .any(|f| f.role.starts_with("frontend_") && f.location.path == "Decoy.vue")
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
    let shadow = jobs
        .observation_reviews
        .iter()
        .find(|r| r.evidence.iter().any(|e| e.location.path == "Shadow.vue"))
        .unwrap();
    assert!(
        !shadow
            .facts
            .iter()
            .any(|f| f.role == "frontend_component_prop_context"),
        "callback parameter is not the setup props binding"
    );
}

#[test]
fn vue_dom_packets_locate_nested_markup_construction_and_props_type() {
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&fixture(), Some(3), Some(100))
            .unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence.iter().any(|e| {
                e.location.path == "Input.vue" && e.tags.iter().any(|t| t == "vue-dom-ref")
            })
        })
        .unwrap();
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_output_dependency_context"
                && f.excerpt.contains("data-preview"))
    );
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_component_prop_type_context"
                && f.excerpt.contains("Record<string, string>"))
    );
}

#[test]
fn vue_static_attributes_and_loop_locals_do_not_claim_setup_producers() {
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&fixture(), Some(3), Some(100))
            .unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.location.path == "StaticSink.vue")
        })
        .unwrap();
    assert_eq!(
        review
            .facts
            .iter()
            .filter(|f| f.role == "frontend_prop_caller_context")
            .count(),
        2
    );
    assert!(
        !review
            .facts
            .iter()
            .any(|f| f.role == "frontend_prop_producer_context")
    );
    assert!(
        review.context_truncated,
        "template loop binding remains unlinked"
    );
}

#[test]
fn vue_implicit_declared_props_and_shorthand_callers_are_navigable() {
    let jobs =
        mehscan_engine::investigation::build_path_review_jobs(&fixture(), Some(3), Some(100))
            .unwrap();
    let review = jobs
        .observation_reviews
        .iter()
        .find(|r| r.evidence.iter().any(|e| e.location.path == "Implicit.vue"))
        .unwrap();
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_component_prop_type_context"
                && f.excerpt.contains("member:"))
    );
    assert!(
        review.facts.iter().any(
            |f| f.role == "frontend_prop_caller_context" && f.excerpt.contains("<Card :member")
        )
    );
    assert!(
        review
            .facts
            .iter()
            .any(|f| f.role == "frontend_template_scope_context"
                && f.excerpt.contains("member in members"))
    );
    assert!(
        !review
            .facts
            .iter()
            .any(|f| f.role == "frontend_prop_producer_context")
    );
    let unassigned = jobs
        .observation_reviews
        .iter()
        .find(|r| {
            r.evidence
                .iter()
                .any(|e| e.location.path == "Unassigned.vue")
        })
        .unwrap();
    assert!(
        unassigned
            .facts
            .iter()
            .any(|f| f.role == "frontend_component_prop_context"
                && f.excerpt.contains("defineProps<{ body:"))
    );
}
