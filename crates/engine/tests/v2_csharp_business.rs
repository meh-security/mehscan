use std::path::PathBuf;

use mehscan_core::{
    Location, PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, PathReviewBundlePayload,
    PathReviewBundleResponseSet, PathReviewTriageResult, Position, ReviewArtifactCitation,
    ReviewConfidence, ReviewDecision, ReviewInvestigationTrace, ReviewReadiness,
    ReviewRetrievedArtifact, ReviewerInference,
};

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
            && lookup.purpose.starts_with("If the preceding source lookup")
    }));
    assert!(guarded.investigation.lookup_requests.iter().any(|lookup| {
        lookup.operation == "source"
            && lookup.arguments.get("path") == Some(&"OrderService.cs".to_string())
    }));
    assert!(guarded.facts.iter().any(|fact| {
        fact.role == "helper_definition_context"
            && fact.symbol == "AdvanceAsync"
            && fact.location.path == "OrderService.cs"
            && fact.excerpt.contains("order.AdvanceTo(target)")
    }));
    assert!(guarded.facts.iter().all(|fact| fact.evidence_id.is_some()));
}

#[test]
fn decisive_policy_evidence_changes_the_same_incomplete_review_outcome() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("review jobs");
    let bundles =
        mehscan_engine::investigation::build_path_review_bundles_with_limits(&job, None, Some(1))
            .expect("single-review bundles");
    let bundle = bundles
        .bundles
        .iter()
        .find(|bundle| match &bundle.payload {
            PathReviewBundlePayload::Observation { reviews } => reviews.iter().any(|review| {
                review
                    .evidence
                    .iter()
                    .any(|item| item.enclosing_symbol.as_deref() == Some("GuardedTransitionAsync"))
            }),
            PathReviewBundlePayload::SecurityPath { .. } => false,
        })
        .expect("guarded transition bundle");
    let review = match &bundle.payload {
        PathReviewBundlePayload::Observation { reviews } => &reviews[0],
        PathReviewBundlePayload::SecurityPath { .. } => unreachable!(),
    };
    let anchor = review.anchor_evidence_ids[0].clone();
    let question = review.decision_facts.unresolved[0].clone();
    let path = review
        .investigation
        .lookup_requests
        .iter()
        .find(|request| request.operation == "source")
        .and_then(|request| request.arguments.get("path"))
        .expect("source lookup path")
        .clone();
    let cases = [
        (
            ReviewDecision::Issue,
            Some(
                "public Task AdvanceAsync(Order order, OrderStatus target) { order.Status = target; return Save(order); }",
            ),
        ),
        (
            ReviewDecision::NotIssue,
            Some(
                "public Task AdvanceAsync(Order order, OrderStatus target) { if (!Allowed[order.Status].Contains(target)) throw new InvalidOperationException(); order.Status = target; return Save(order); }",
            ),
        ),
        (ReviewDecision::NeedsReview, None),
    ];
    let mut fingerprints = Vec::new();
    for (decision, excerpt) in cases {
        let mut trace = ReviewInvestigationTrace::default();
        if let Some(excerpt) = excerpt {
            let artifact_id = "transition-policy".to_string();
            trace.decisive_artifacts.push(ReviewRetrievedArtifact {
                artifact_id: artifact_id.clone(),
                location: Location {
                    path: path.clone(),
                    start: Position {
                        line: 1,
                        column: 1,
                        byte_offset: 0,
                    },
                    end: Position {
                        line: 1,
                        column: excerpt.len() + 1,
                        byte_offset: excerpt.len(),
                    },
                },
                excerpt: excerpt.to_string(),
            });
            trace.citations.push(ReviewArtifactCitation {
                artifact_id: artifact_id.clone(),
                claim: "The helper body determines whether the transition is rejected.".to_string(),
            });
            trace.citations.push(ReviewArtifactCitation {
                artifact_id: anchor.clone(),
                claim: "The selected operation invokes this transition.".to_string(),
            });
            trace.reviewer_inferences.push(ReviewerInference {
                claim: "The helper's rejection behavior decides the selected transition."
                    .to_string(),
                artifact_ids: vec![artifact_id],
            });
        }
        let response = PathReviewBundleResponseSet {
            schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
            bundle_fingerprint: bundle.bundle_fingerprint.clone(),
            results: vec![PathReviewTriageResult {
                review_id: review.id.clone(),
                selected_anchor_id: Some(anchor.clone()),
                decision,
                confidence: ReviewConfidence::Medium,
                summary: match decision {
                    ReviewDecision::Issue => {
                        "The helper permits an unchecked requested transition."
                    }
                    ReviewDecision::NotIssue => {
                        "The helper rejects invalid current-to-next transitions."
                    }
                    ReviewDecision::NeedsReview => "The decisive transition policy is unavailable.",
                }
                .to_string(),
                checks: if decision == ReviewDecision::NeedsReview {
                    vec![question.clone()]
                } else {
                    Vec::new()
                },
                investigation: Some(trace),
            }],
        };
        let report =
            mehscan_engine::investigation::validate_path_review_bundle_response(bundle, &response)
                .expect("each evidence-supported outcome validates");
        fingerprints.push(report.response_fingerprint);
    }
    fingerprints.sort();
    fingerprints.dedup();
    assert_eq!(fingerprints.len(), 3);
}
