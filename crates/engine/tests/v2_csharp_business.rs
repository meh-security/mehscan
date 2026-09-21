use std::path::PathBuf;

use mehscan_core::ReviewReadiness;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-business")
}

#[test]
fn packages_csharp_state_transitions_with_exact_policy_helpers() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let transitions = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-client-controlled-state-transition-review")
        .collect::<Vec<_>>();
    assert_eq!(transitions.len(), 2, "{transitions:#?}");
    assert!(transitions.iter().any(|item| {
        item.enclosing_symbol.as_deref() == Some("UnsafeTransitionAsync")
            && item.captures["request_field"].text == "TargetStatus"
            && item.captures["state_field"].text == "order.Status"
            && item.captures["persistence_effect"]
                .text
                .contains("SaveChangesAsync")
            && !item.captures.contains_key("transition_helper")
    }));
    assert!(transitions.iter().any(|item| {
        item.enclosing_symbol.as_deref() == Some("GuardedTransitionAsync")
            && item.captures["transition_helper"].text == "AdvanceAsync"
            && item.captures["next_state"].text == "request.TargetStatus"
    }));

    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("review jobs should build");
    let reviews = jobs
        .observation_reviews
        .iter()
        .filter(|review| {
            review.review_basis.as_ref().is_some_and(|basis| {
                basis.relationship == "bounded_state_transition_enforcement_review"
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(reviews.len(), 2, "{reviews:#?}");
    let direct = reviews
        .iter()
        .find(|review| {
            review.evidence[0].enclosing_symbol.as_deref() == Some("UnsafeTransitionAsync")
        })
        .expect("direct transition review");
    assert_eq!(direct.investigation.readiness, ReviewReadiness::Assessment);
    assert!(direct.decision_facts.unresolved.is_empty());
    let guarded = reviews
        .iter()
        .find(|review| {
            review.evidence[0].enclosing_symbol.as_deref() == Some("GuardedTransitionAsync")
        })
        .expect("helper transition review");
    assert_eq!(
        guarded.investigation.readiness,
        ReviewReadiness::Investigation
    );
    assert_eq!(guarded.decision_facts.unresolved.len(), 1);
    assert!(guarded.investigation.lookup_requests.iter().any(|lookup| {
        lookup.operation == "references"
            && lookup.arguments.get("symbol") == Some(&"AdvanceAsync".to_string())
    }));
    assert!(guarded.facts.iter().any(|fact| {
        fact.role == "helper_definition_context"
            && fact.symbol == "AdvanceAsync"
            && fact.excerpt.contains("order.AdvanceTo(target)")
    }));
}
