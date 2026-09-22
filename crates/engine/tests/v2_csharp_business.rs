use std::path::PathBuf;

use mehscan_core::{
    Location, PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, PathReviewBundlePayload,
    PathReviewBundleResponseSet, PathReviewTriageResult, Position, ReviewArtifactCitation,
    ReviewDecision, ReviewInvestigationTrace, ReviewLookupAttempt, ReviewLookupOutcome,
    ReviewReadiness, ReviewRetrievedArtifact, ReviewerInference,
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
}

#[test]
fn retrieved_policy_evidence_changes_the_same_incomplete_review_outcome() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(8), false)
            .expect("review jobs should build");
    let bundle_set =
        mehscan_engine::investigation::build_path_review_bundles_with_limits(&job, None, Some(1))
            .expect("single-review bundles should build");
    let bundle = bundle_set
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
        .expect("guarded transition should have an isolated bundle");
    let review = match &bundle.payload {
        PathReviewBundlePayload::Observation { reviews } => &reviews[0],
        PathReviewBundlePayload::SecurityPath { .. } => unreachable!(),
    };
    let question = review
        .decision_facts
        .unresolved
        .first()
        .expect("guarded transition should retain its policy question")
        .clone();
    let source_request = review
        .investigation
        .lookup_requests
        .iter()
        .position(|request| request.operation == "source")
        .expect("review should supply an exact source lookup");
    let lookup_path = review.investigation.lookup_requests[source_request]
        .arguments
        .get("path")
        .expect("source lookup should name a path")
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
    for (decision, retrieved) in cases {
        let confidence = match decision {
            ReviewDecision::Issue => review.confidence_policy.issue,
            ReviewDecision::NotIssue => review.confidence_policy.not_issue,
            ReviewDecision::NeedsReview => review.confidence_policy.needs_review,
        };
        let (attempt, citations, reviewer_inferences) = if let Some(excerpt) = retrieved {
            let artifact_id = "retrieved-transition-policy".to_string();
            (
                ReviewLookupAttempt {
                    request_index: Some(source_request),
                    escalation: None,
                    outcome: ReviewLookupOutcome::Answered,
                    artifacts: vec![ReviewRetrievedArtifact {
                        artifact_id: artifact_id.clone(),
                        location: Location {
                            path: lookup_path.clone(),
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
                    }],
                    detail: "Retrieved the exact transition helper body.".to_string(),
                },
                vec![ReviewArtifactCitation {
                    artifact_id: artifact_id.clone(),
                    claim: "The helper body supplies the transition policy used by this endpoint."
                        .to_string(),
                }],
                vec![ReviewerInference {
                    claim: match decision {
                        ReviewDecision::Issue => {
                            "The retrieved helper writes the requested state without rejecting an invalid current-to-next transition."
                        }
                        ReviewDecision::NotIssue => {
                            "The retrieved helper checks the current-to-next transition and terminates before the write when it is invalid."
                        }
                        ReviewDecision::NeedsReview => unreachable!(),
                    }
                    .to_string(),
                    artifact_ids: vec![artifact_id],
                }],
            )
        } else {
            (
                ReviewLookupAttempt {
                    request_index: Some(source_request),
                    escalation: None,
                    outcome: ReviewLookupOutcome::NoRelevantResult,
                    artifacts: Vec::new(),
                    detail: "The bounded source lookup did not return the transition policy."
                        .to_string(),
                },
                Vec::new(),
                Vec::new(),
            )
        };
        let response = PathReviewBundleResponseSet {
            schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
            bundle_fingerprint: bundle.bundle_fingerprint.clone(),
            results: vec![PathReviewTriageResult {
                review_id: review.id.clone(),
                decision,
                confidence,
                summary: match decision {
                    ReviewDecision::Issue => {
                        "The retrieved helper permits an unchecked requested transition."
                    }
                    ReviewDecision::NotIssue => {
                        "The retrieved helper rejects disallowed current-to-next transitions."
                    }
                    ReviewDecision::NeedsReview => {
                        "The decisive transition policy remains unavailable after the supplied lookup."
                    }
                }
                .to_string(),
                checks: if decision == ReviewDecision::NeedsReview {
                    vec![question.clone()]
                } else {
                    Vec::new()
                },
                investigation: Some(ReviewInvestigationTrace {
                    lookup_attempts: vec![attempt],
                    citations,
                    reviewer_inferences,
                    reviewer_origin_leads: Vec::new(),
                    blockers: Vec::new(),
                }),
            }],
            repair: None,
        };
        let report =
            mehscan_engine::investigation::validate_path_review_bundle_response(bundle, &response)
                .expect("each evidence-supported outcome should validate");
        assert_eq!(report.results[0].decision, decision);
        fingerprints.push(report.response_fingerprint);
        if decision == ReviewDecision::NotIssue {
            let valid_repair = mehscan_engine::investigation::repair_path_review_bundle_response(
                bundle,
                &response,
                &review.id,
                response.results[0].clone(),
            )
            .expect_err("a valid security decision must not enter the repair path");
            assert!(valid_repair.to_string().contains("must not be repaired"));
            let mut failed = response.clone();
            failed.results[0].confidence = match failed.results[0].confidence {
                mehscan_core::ReviewConfidence::High => mehscan_core::ReviewConfidence::Low,
                _ => mehscan_core::ReviewConfidence::High,
            };
            let repaired = mehscan_engine::investigation::repair_path_review_bundle_response(
                bundle,
                &failed,
                &review.id,
                response.results[0].clone(),
            )
            .expect("one invalid result should accept one exact validated replacement");
            let repair = repaired.repair.as_ref().expect("repair history");
            assert_eq!(repair.review_id, review.id);
            assert!(repair.validation_error.contains("confidence"));
            mehscan_engine::investigation::validate_path_review_bundle_response(bundle, &repaired)
                .expect("the complete repaired response should validate");
            let run = mehscan_engine::investigation::summarize_path_review_bundle_run(&[(
                (*bundle).clone(),
                repaired.clone(),
            )])
            .expect("the canonical run summary should preserve repair history");
            assert_eq!(run.repairs, vec![repair.clone()]);
            assert_eq!(run.family_measurements.len(), 1);
            assert_eq!(run.family_measurements[0].completed_review_count, 1);
            assert_eq!(run.family_measurements[0].resolved_review_count, 1);
            assert_eq!(run.family_measurements[0].lookup_attempt_count, 1);
            assert!(run.family_measurements[0].returned_artifact_bytes > 0);
            let second_repair = mehscan_engine::investigation::repair_path_review_bundle_response(
                bundle,
                &repaired,
                &review.id,
                response.results[0].clone(),
            )
            .expect_err("repair history must prevent a second repair attempt");
            assert!(second_repair.to_string().contains("only once"));
        }
    }
    fingerprints.sort();
    fingerprints.dedup();
    assert_eq!(
        fingerprints.len(),
        3,
        "each investigated outcome needs a distinct identity"
    );
}
