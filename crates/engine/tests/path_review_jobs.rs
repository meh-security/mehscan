use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{
    EvidenceKind, PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, PathReviewBundlePayload,
    PathReviewBundleResponseSet, PathReviewTriageResponseSet, PathReviewTriageResult,
    ReviewAdmissionDisposition, ReviewConfidence, ReviewDecision,
};

fn process_fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-process-flow")
}

fn crapi_root() -> PathBuf {
    std::env::var_os("MEHSCAN_CRAPI_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("apps/crAPI")
        })
}

fn review_admission_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-admission")
}

fn review_csrf_admission_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-csrf-admission")
}

fn review_html_admission_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-html-admission")
}

fn review_resource_admission_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-resource-admission")
}

fn review_python_origin_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-python-origin")
}

fn review_python_control_scope_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-python-control-scope")
}

fn review_guidance_contract_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-guidance-contract")
}

fn review_helper_admission_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-helper-admission")
}

fn review_issue_grouping_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-issue-grouping")
}

fn native_secondary_tooling_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/native-secondary-tooling")
}

fn juice_shop_root() -> PathBuf {
    std::env::var_os("MEHSCAN_JUICE_SHOP_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("juice-shop")
        })
}

fn govwa_root() -> PathBuf {
    std::env::var_os("MEHSCAN_GOVWA_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join("apps/govwa")
        })
}

#[test]
fn builds_language_neutral_self_contained_path_reviews() {
    let job = mehscan_engine::investigation::build_path_review_jobs(
        &process_fixture_root(),
        Some(3),
        Some(100),
    )
    .expect("path reviews should build");
    let repeated = mehscan_engine::investigation::build_path_review_jobs(
        &process_fixture_root(),
        Some(3),
        Some(100),
    )
    .expect("path reviews should repeat");

    assert_eq!(job, repeated);
    assert!(job.fingerprint.starts_with("path-reviewpack-"));
    assert_eq!(job.context_lines, 3);
    assert_eq!(job.reviews.len(), 20);
    assert_eq!(
        job.review_coverage.returned_review_count,
        job.reviews.len() + job.observation_reviews.len()
    );
    assert_eq!(
        job.review_coverage.admitted_review_count,
        job.review_coverage.returned_review_count
    );
    assert!(
        job.review_coverage.recognized_boundary_count >= job.review_coverage.admitted_review_count
    );
    assert_eq!(
        job.review_coverage.assessment_review_count
            + job.review_coverage.investigation_ready_review_count
            + job.review_coverage.blocked_review_count,
        job.review_coverage.returned_review_count
    );
    assert!(!job.truncated);
    assert_eq!(job.triage_contract.response_fields[0], "review_id");
    assert!(job.triage_contract.instructions.iter().any(|instruction| {
        instruction.contains("Answer open questions from the supplied facts")
            && instruction.contains("do not ask to trace a flow")
    }));
    assert!(job.triage_contract.instructions.iter().any(|instruction| {
        instruction.contains("requested artifact is absent from facts")
            && instruction.contains("instead of asking to inspect it again")
    }));
    assert!(job.triage_contract.instructions.iter().any(|instruction| {
        instruction.contains("Evaluate each review independently")
            && instruction.contains("review_basis semantics")
            && instruction.contains("do not reuse category-wide boilerplate")
    }));
    assert!(job.reviews.iter().all(|review| {
        review.id.starts_with("review-")
            && review.review_basis.as_ref().is_some_and(|basis| {
                basis.relationship == "deterministic_bounded_path"
                    && basis.source.rule_id == review.candidate.source.rule_id
                    && basis.sink.rule_id == review.candidate.sink.rule_id
                    && !basis.deterministic_facts.is_empty()
            })
            && review
                .facts
                .iter()
                .any(|fact| fact.role == "source_context" && !fact.excerpt.is_empty())
            && review
                .facts
                .iter()
                .any(|fact| fact.role == "sink_context" && !fact.excerpt.is_empty())
    }));
    let languages = job
        .reviews
        .iter()
        .filter_map(|review| review.language)
        .collect::<BTreeSet<_>>();
    assert_eq!(languages.len(), 7);
    assert!(
        job.reviews
            .iter()
            .flat_map(|review| &review.open_questions)
            .all(|question| {
                !question.contains("scanner uncertainty")
                    && !question.contains("source_observation_not_high_confidence")
                    && !question.contains("_is_syntactic")
                    && !question.contains("bounded source value reach")
                    && !question
                        .contains("effective context-appropriate protection applied outside")
            })
    );
    assert!(
        job.reviews
            .iter()
            .filter(|review| review.candidate.protections.is_empty())
            .all(|review| review.open_questions.iter().any(|question| {
                question.contains("avoid a command shell")
                    && question.contains("structured process arguments")
            }))
    );
}

#[test]
fn preserves_decisive_observation_guidance_across_every_language() {
    let job = mehscan_engine::investigation::build_all_path_review_jobs(
        &review_guidance_contract_root(),
        Some(6),
        false,
    )
    .expect("cross-language guidance fixture should build");

    // Assert the reviewer-visible contract directly. A literal fingerprint
    // would make unrelated, valid context improvements break this test.
    let languages = job
        .observation_reviews
        .iter()
        .filter_map(|review| review.language)
        .collect::<BTreeSet<_>>();
    assert_eq!(languages.len(), 8);
    assert!(job.reviews.is_empty());
    assert_eq!(job.observation_reviews.len(), 8);
    for review in &job.observation_reviews {
        let basis = review.review_basis.as_ref().expect("rule-derived basis");
        assert_eq!(basis.relationship, "bounded_non_path_observation");
        assert!(!basis.investigate.is_empty(), "{} investigate", review.id);
        assert!(!basis.verify.is_empty(), "{} verify", review.id);
        assert!(!basis.exclude.is_empty(), "{} exclude", review.id);
        assert!(
            basis
                .deterministic_facts
                .iter()
                .any(|fact| { fact.contains("not a deterministic source-to-sink relationship") })
        );
    }
}

#[test]
#[ignore = "requires the optional crAPI corpus"]
fn observation_primary_context_covers_every_anchor_location() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&crapi_root(), Some(2), false)
            .expect("observation reviews should build");
    assert!(!job.observation_reviews.is_empty());

    for review in &job.observation_reviews {
        let primary = review
            .facts
            .iter()
            .filter(|fact| fact.role == "source_context")
            .collect::<Vec<_>>();
        for anchor_id in &review.anchor_evidence_ids {
            let anchor = review
                .evidence
                .iter()
                .find(|item| item.id == *anchor_id)
                .expect("anchor evidence should be retained in its review");
            assert!(
                primary.iter().any(|fact| {
                    fact.location.path == anchor.location.path
                        && fact.location.start.byte_offset <= anchor.location.start.byte_offset
                        && fact.location.end.byte_offset >= anchor.location.end.byte_offset
                }),
                "{} primary context does not cover anchor {}",
                review.id,
                anchor.id
            );
        }
    }
}

#[test]
#[ignore = "requires the optional GoVWA corpus"]
fn prefers_same_file_helper_definition_for_ambiguous_go_name() {
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&govwa_root(), Some(8), Some(100))
            .expect("GoVWA review job should build");
    let otp = job
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "go-hardcoded-md5-otp-review")
        })
        .expect("OTP review should be present");
    let helpers = otp
        .facts
        .iter()
        .filter(|fact| fact.role == "helper_definition_context" && fact.symbol == "Md5Sum")
        .collect::<Vec<_>>();
    assert_eq!(helpers.len(), 1);
    assert_eq!(helpers[0].location.path, "vulnerability/csa/csa.go");
}

#[test]
#[ignore = "requires the optional crAPI corpus"]
fn includes_non_secret_repository_configuration_facts() {
    let job =
        mehscan_engine::investigation::build_path_review_jobs(&crapi_root(), Some(6), Some(100))
            .expect("crAPI path review should build");

    assert!(!job.reviews.is_empty());
    assert_eq!(job.coverage.totals.secret_scanned, 0);
    assert!(
        job.reviews
            .iter()
            .flat_map(|review| &review.facts)
            .filter(|fact| fact.role == "configuration_context")
            .any(|fact| {
                fact.excerpt.contains("ENABLE_SHELL_INJECTION=false")
                    && !fact.excerpt.to_ascii_lowercase().contains("password")
            })
    );
}

#[test]
fn validates_one_compact_result_per_path_review() {
    let job = mehscan_engine::investigation::build_path_review_jobs(
        &process_fixture_root(),
        Some(2),
        Some(2),
    )
    .expect("path reviews should build");
    let responses = PathReviewTriageResponseSet {
        schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        job_fingerprint: job.fingerprint.clone(),
        results: job
            .reviews
            .iter()
            .map(|review| PathReviewTriageResult {
                review_id: review.id.clone(),
                decision: ReviewDecision::Issue,
                confidence: review.confidence_policy.issue,
                summary: "The supplied bounded path supports this issue decision.".to_string(),
                checks: Vec::new(),
                investigation: Some(Default::default()),
            })
            .collect(),
    };
    let report = mehscan_engine::investigation::validate_path_review_triage(&job, &responses)
        .expect("responses should validate");
    assert_eq!(report.needs_review_count, 0);
    assert_eq!(report.issue_count, 2);
    assert_eq!(report.not_issue_count, 0);
}

#[test]
fn paginates_one_stable_path_first_review_sequence() {
    let first = mehscan_engine::investigation::build_path_review_jobs_page(
        &process_fixture_root(),
        Some(2),
        Some(3),
        0,
        false,
    )
    .expect("first review page should build");
    let next_offset = first.next_offset.expect("fixture should have another page");
    let second = mehscan_engine::investigation::build_path_review_jobs_page(
        &process_fixture_root(),
        Some(2),
        Some(3),
        next_offset,
        false,
    )
    .expect("second review page should build");

    assert_eq!(first.offset, 0);
    assert_eq!(next_offset, 3);
    assert_eq!(second.offset, 3);
    assert_eq!(first.total_reviews, second.total_reviews);
    assert_ne!(first.fingerprint, second.fingerprint);
    let first_ids = first
        .reviews
        .iter()
        .map(|review| review.id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(
        second
            .reviews
            .iter()
            .all(|review| !first_ids.contains(review.id.as_str()))
    );
}

#[test]
fn rejects_review_pages_larger_than_one_hundred_items() {
    let error = mehscan_engine::investigation::build_path_review_jobs_page(
        &process_fixture_root(),
        Some(2),
        Some(101),
        0,
        false,
    )
    .expect_err("oversized review pages must fail closed");

    assert!(error.to_string().contains("between 1 and 100"));
}

#[test]
fn emits_independent_tasks_and_validates_resumable_progress() {
    let job = mehscan_engine::investigation::build_path_review_jobs_page(
        &process_fixture_root(),
        Some(2),
        Some(3),
        0,
        false,
    )
    .expect("review page should build");
    let tasks = mehscan_engine::investigation::path_review_tasks(&job);

    assert_eq!(tasks.tasks.len(), 3);
    assert_eq!(tasks.job_fingerprint, job.fingerprint);
    assert!(tasks.tasks.iter().enumerate().all(|(index, task)| {
        task.sequence == index
            && task.page_size == 3
            && task.job_fingerprint == job.fingerprint
            && task.triage_contract == job.triage_contract
    }));

    let responses = PathReviewTriageResponseSet {
        schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        job_fingerprint: job.fingerprint.clone(),
        results: vec![PathReviewTriageResult {
            review_id: tasks.tasks[0].review_id.clone(),
            decision: ReviewDecision::Issue,
            confidence: job.reviews[0].confidence_policy.issue,
            summary: "The first independently transported task supports this issue decision."
                .to_string(),
            checks: Vec::new(),
            investigation: Some(Default::default()),
        }],
    };
    let progress = mehscan_engine::investigation::validate_path_review_progress(&job, &responses)
        .expect("partial progress should validate");

    assert_eq!(progress.submitted_count, 1);
    assert_eq!(progress.remaining_count, 2);
    assert!(!progress.complete);
    assert_eq!(progress.missing_review_ids.len(), 2);
}

#[test]
fn emits_semantic_bundles_and_retries_incomplete_bundle_responses() {
    let job = mehscan_engine::investigation::build_all_path_review_jobs(
        &process_fixture_root(),
        Some(2),
        false,
    )
    .expect("complete review job should build");
    let bundle_set =
        mehscan_engine::investigation::build_path_review_bundles(&job, Some(64 * 1024))
            .expect("semantic bundles should build");

    assert_eq!(bundle_set.manifest.review_count, job.total_reviews);
    assert_eq!(bundle_set.manifest.bundle_count, bundle_set.bundles.len());
    assert_eq!(bundle_set.manifest.max_reviews_per_bundle, 20);
    assert!(bundle_set.manifest.bundles.iter().all(|entry| {
        entry.filename.starts_with("full--")
            && !entry.filename.starts_with("bundle-")
            && entry.filename.contains("--p0")
            && entry.input_bytes <= 64 * 1024
            && entry.context_text_bytes <= entry.input_bytes
            && entry.repeated_context_text_bytes <= entry.context_text_bytes
    }));
    assert!(
        bundle_set
            .manifest
            .bundles
            .iter()
            .any(|entry| entry.context_text_bytes > 0),
        "manifest should expose source-context payload cost"
    );
    assert!(
        bundle_set
            .manifest
            .bundles
            .iter()
            .any(|entry| entry.repeated_context_text_bytes > 0),
        "fixture should exercise exact context repetition accounting"
    );
    assert!(bundle_set.manifest.bundles.iter().any(|entry| {
        entry.filename.contains("--cwe-") || entry.filename.contains("--review-only--")
    }));
    let item_bounded = mehscan_engine::investigation::build_path_review_bundles_with_limits(
        &job,
        Some(64 * 1024),
        Some(1),
    )
    .expect("item-bounded semantic bundles should build");
    assert_eq!(item_bounded.manifest.max_reviews_per_bundle, 1);
    assert_eq!(item_bounded.manifest.review_count, job.total_reviews);
    assert!(
        item_bounded
            .manifest
            .bundles
            .iter()
            .all(|entry| entry.review_count == 1 && entry.input_bytes <= 64 * 1024)
    );
    let baseline_ids = bundle_set
        .manifest
        .bundles
        .iter()
        .flat_map(|entry| entry.review_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    let item_bounded_ids = item_bounded
        .manifest
        .bundles
        .iter()
        .flat_map(|entry| entry.review_ids.iter().cloned())
        .collect::<BTreeSet<_>>();
    assert_eq!(item_bounded_ids, baseline_ids);

    let bundle = bundle_set
        .bundles
        .iter()
        .find(|bundle| bundle.review_ids.len() > 1)
        .expect("fixture should produce a multi-review semantic bundle");
    let results = bundle
        .review_ids
        .iter()
        .map(|review_id| {
            let confidence = match &bundle.payload {
                PathReviewBundlePayload::SecurityPath { reviews } => {
                    reviews
                        .iter()
                        .find(|review| review.id == *review_id)
                        .expect("review should exist")
                        .confidence_policy
                        .issue
                }
                PathReviewBundlePayload::Observation { reviews } => {
                    reviews
                        .iter()
                        .find(|review| review.id == *review_id)
                        .expect("review should exist")
                        .confidence_policy
                        .issue
                }
            };
            PathReviewTriageResult {
                review_id: review_id.clone(),
                decision: ReviewDecision::Issue,
                confidence,
                summary: "The supplied evidence supports one complete compact decision."
                    .to_string(),
                checks: Vec::new(),
                investigation: Some(Default::default()),
            }
        })
        .collect::<Vec<_>>();
    let response = PathReviewBundleResponseSet {
        schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        bundle_fingerprint: bundle.bundle_fingerprint.clone(),
        results: results.clone(),
        repair: None,
    };
    let report =
        mehscan_engine::investigation::validate_path_review_bundle_response(bundle, &response)
            .expect("complete bundle response should validate");
    assert!(report.complete);
    assert_eq!(
        report.needs_review_count + report.issue_count,
        bundle.review_ids.len()
    );
    match &bundle.payload {
        PathReviewBundlePayload::SecurityPath { reviews } => {
            assert!(reviews.iter().all(|review| {
                !review.decision_facts.established.is_empty()
                    && review.truncation.occurred == review.context_truncated
            }))
        }
        PathReviewBundlePayload::Observation { reviews } => assert!(reviews.iter().all(|review| {
            !review.decision_facts.established.is_empty()
                && review.truncation.occurred == review.context_truncated
        })),
    }

    let mut invented_check = response.clone();
    invented_check.results[0].decision = ReviewDecision::NeedsReview;
    invented_check.results[0].checks =
        vec!["Inspect the whole repository for some additional security context.".to_string()];
    let error = mehscan_engine::investigation::validate_path_review_bundle_response(
        bundle,
        &invented_check,
    )
    .expect_err("needs_review must use a supplied unresolved fact");
    assert!(error.to_string().contains("needs_review"));

    let mut wrong_confidence = response.clone();
    wrong_confidence.results[0].confidence =
        if wrong_confidence.results[0].confidence == ReviewConfidence::High {
            ReviewConfidence::Medium
        } else {
            ReviewConfidence::High
        };
    let error = mehscan_engine::investigation::validate_path_review_bundle_response(
        bundle,
        &wrong_confidence,
    )
    .expect_err("confidence must match the selected decision's deterministic policy");
    assert!(error.to_string().contains("confidence"));

    let incomplete = PathReviewBundleResponseSet {
        results: results.into_iter().take(1).collect(),
        ..response
    };
    let error =
        mehscan_engine::investigation::validate_path_review_bundle_response(bundle, &incomplete)
            .expect_err("incomplete bundle response must be retried as a whole");
    assert!(error.to_string().contains("retry the whole bundle"));
}

#[test]
fn run_budget_reserves_every_capability_and_preserves_deferred_reviews() {
    let job = mehscan_engine::investigation::build_all_path_review_jobs(
        &review_admission_root(),
        Some(2),
        false,
    )
    .expect("complete review job should build");
    let full = mehscan_engine::investigation::build_path_review_bundles(&job, None)
        .expect("complete bundle set should build");
    let capabilities = full
        .manifest
        .bundles
        .iter()
        .map(|entry| entry.category.capability)
        .collect::<BTreeSet<_>>();
    assert!(
        full.manifest.review_count > capabilities.len(),
        "fixture needs one noisy family to exercise fair scheduling"
    );

    let limited = mehscan_engine::investigation::build_path_review_bundles_with_run_limit(
        &job,
        None,
        None,
        Some(capabilities.len()),
    )
    .expect("one reserved review per capability should fit");
    let scheduled_capabilities = limited
        .manifest
        .bundles
        .iter()
        .map(|entry| entry.category.capability)
        .collect::<BTreeSet<_>>();
    assert_eq!(scheduled_capabilities, capabilities);
    assert_eq!(limited.manifest.review_count, capabilities.len());
    assert_eq!(
        limited.manifest.admitted_review_count,
        full.manifest.review_count
    );
    assert_eq!(
        limited.manifest.deferred_review_ids.len(),
        full.manifest.review_count - capabilities.len()
    );
    let scheduled_ids = limited
        .manifest
        .bundles
        .iter()
        .flat_map(|entry| entry.review_ids.iter())
        .collect::<BTreeSet<_>>();
    assert!(
        limited
            .manifest
            .deferred_review_ids
            .iter()
            .all(|review_id| !scheduled_ids.contains(review_id))
    );

    let error = mehscan_engine::investigation::build_path_review_bundles_with_run_limit(
        &job,
        None,
        None,
        Some(capabilities.len() - 1),
    )
    .expect_err("a run too small to reserve every capability must fail clearly");
    assert!(error.to_string().contains("cannot reserve one review"));
}

#[test]
fn admits_only_actionable_observations_and_deduplicates_a_complete_bundle_run() {
    let scan = mehscan_engine::scan_path(review_admission_root())
        .expect("review-admission fixture should scan");
    let html_evidence = scan
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/production.ts"
                && evidence.capability == mehscan_core::Capability::HtmlOutput
        })
        .collect::<Vec<_>>();
    assert!(
        html_evidence.iter().any(|evidence| {
            evidence
                .captures
                .get("content")
                .is_some_and(|capture| capture.text == "'A fixed response message'")
        }),
        "literal HTML output must remain in deterministic evidence"
    );

    let job = mehscan_engine::investigation::build_all_path_review_jobs(
        &review_admission_root(),
        Some(2),
        false,
    )
    .expect("complete review job should build");
    let audit = &job.review_coverage.admission_audit;
    assert_eq!(
        audit.classified_boundary_count,
        audit.counts.iter().map(|entry| entry.count).sum::<usize>()
    );
    assert!(
        job.review_coverage.recognized_boundary_count >= job.review_coverage.admitted_review_count
    );
    for disposition in [
        ReviewAdmissionDisposition::PathOwned,
        ReviewAdmissionDisposition::ObservationAdmitted,
        ReviewAdmissionDisposition::SafelySuppressed,
        ReviewAdmissionDisposition::ExcludedReviewMaterial,
    ] {
        assert!(
            audit
                .counts
                .iter()
                .any(|entry| entry.disposition == disposition && entry.count > 0),
            "fixture must exercise {disposition:?} admission accounting"
        );
    }
    assert!(
        audit
            .counts
            .iter()
            .all(|entry| entry.disposition != ReviewAdmissionDisposition::Unclassified),
        "known fixture boundaries must not disappear behind an unexplained exclusion"
    );
    assert!(audit.excluded_examples.len() <= 64);
    assert!(audit.excluded_examples.iter().all(|example| {
        !example.evidence_id.is_empty()
            && !example.rule_id.is_empty()
            && !example.location.path.is_empty()
            && !matches!(
                example.disposition,
                ReviewAdmissionDisposition::PathOwned
                    | ReviewAdmissionDisposition::ObservationAdmitted
            )
    }));
    assert!(audit.excluded_examples.iter().any(|example| {
        example.disposition == ReviewAdmissionDisposition::SafelySuppressed
            && example.rule_id == "typescript-html-output"
            && example.location.path == "routes/production.ts"
    }));
    assert!(audit.excluded_examples.iter().any(|example| {
        example.disposition == ReviewAdmissionDisposition::ExcludedReviewMaterial
            && example.location.path == "data/static/codefixes/teaching.ts"
    }));
    assert!(
        job.observation_reviews
            .iter()
            .all(|review| review.anchor_evidence_ids.len() == 1)
    );
    assert!(job.observation_reviews.iter().all(|review| {
        review.evidence.iter().any(|evidence| {
            review.anchor_evidence_ids.contains(&evidence.id)
                && matches!(
                    evidence.kind,
                    EvidenceKind::Sink
                        | EvidenceKind::SensitiveOperation
                        | EvidenceKind::SecurityConfiguration
                )
        })
    }));
    assert!(job.observation_reviews.iter().all(|review| {
        review
            .evidence
            .iter()
            .all(|evidence| evidence.location.path != "playground/example/soln.py")
    }));
    let anchored = job
        .observation_reviews
        .iter()
        .flat_map(|review| {
            review
                .evidence
                .iter()
                .filter(|evidence| review.anchor_evidence_ids.contains(&evidence.id))
        })
        .collect::<Vec<_>>();
    let html_anchors = anchored
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/production.ts"
                && evidence.capability == mehscan_core::Capability::HtmlOutput
        })
        .collect::<Vec<_>>();
    assert!(
        html_anchors.iter().all(|evidence| {
            evidence
                .captures
                .get("content")
                .is_none_or(|capture| capture.text != "'A fixed response message'")
        }),
        "literal HTML output must not become a standalone AI verdict anchor"
    );
    assert!(
        html_anchors.iter().any(|evidence| {
            evidence
                .captures
                .get("content")
                .is_some_and(|capture| capture.text == "content")
        }),
        "unresolved HTML content must remain reviewable"
    );
    let json_response_evidence = scan
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/responses.ts"
                && evidence.capability == mehscan_core::Capability::HtmlOutput
        })
        .collect::<Vec<_>>();
    assert_eq!(
        json_response_evidence.len(),
        4,
        "JSON-shaped Express responses must remain deterministic evidence"
    );
    let json_response_anchors = anchored
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/responses.ts"
                && evidence.capability == mehscan_core::Capability::HtmlOutput
        })
        .collect::<Vec<_>>();
    for omitted in ["directJsonResponse", "helperJsonResponse"] {
        assert!(
            json_response_anchors
                .iter()
                .all(|evidence| evidence.enclosing_symbol.as_deref() != Some(omitted)),
            "{omitted} is an exact JSON response and must not become a CWE-79 review anchor",
        );
    }
    for retained in ["dynamicResponse", "shadowedHelperResponse"] {
        assert!(
            json_response_anchors
                .iter()
                .any(|evidence| evidence.enclosing_symbol.as_deref() == Some(retained)),
            "{retained} has unresolved response provenance and must remain reviewable",
        );
    }
    assert!(
        scan.evidence.iter().any(|evidence| {
            evidence.location.path == "routes/browser.ts"
                && evidence.enclosing_symbol.as_deref() == Some("fixedNavigation")
                && evidence.capability == mehscan_core::Capability::BrowserNavigation
        }),
        "fixed imported navigation must remain deterministic evidence",
    );
    let navigation_anchors = anchored
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/browser.ts"
                && evidence.capability == mehscan_core::Capability::BrowserNavigation
        })
        .collect::<Vec<_>>();
    assert!(
        navigation_anchors
            .iter()
            .all(|evidence| evidence.enclosing_symbol.as_deref() != Some("fixedNavigation"))
    );
    for symbol in [
        "dynamicNavigation",
        "dynamicSuffix",
        "shadowedNavigation",
        "locallyShadowedNavigation",
    ] {
        assert!(
            navigation_anchors
                .iter()
                .any(|evidence| evidence.enclosing_symbol.as_deref() == Some(symbol)),
            "{symbol} must remain reviewable",
        );
    }
    assert!(
        scan.evidence.iter().any(|evidence| {
            evidence.location.path == "routes/browser.ts"
                && evidence.enclosing_symbol.as_deref() == Some("fixedServiceNavigation")
                && evidence.capability == mehscan_core::Capability::BrowserNavigation
        }),
        "fixed service navigation must remain deterministic evidence",
    );
    assert!(
        navigation_anchors
            .iter()
            .all(|evidence| evidence.enclosing_symbol.as_deref() != Some("fixedServiceNavigation"))
    );
    assert!(
        navigation_anchors.iter().any(|evidence| {
            evidence.enclosing_symbol.as_deref() == Some("dynamicServiceNavigation")
        }),
        "a dynamic service authority must remain reviewable"
    );
    assert!(
        scan.evidence.iter().any(|evidence| {
            evidence.location.path == "routes/browser-request.ts"
                && evidence.enclosing_symbol.as_deref() == Some("fixedBrowserRequest")
                && evidence.capability == mehscan_core::Capability::OutboundNetworkRequest
        }),
        "fixed same-origin browser transport must remain deterministic evidence",
    );
    for endpoint in ["generatorUrl", "multilineUrl", "suffixUrl"] {
        assert!(scan.evidence.iter().any(|evidence| {
            evidence.location.path == "routes/browser-request.ts"
                && evidence
                    .captures
                    .get("endpoint")
                    .is_some_and(|capture| capture.text == endpoint)
        }));
    }
    let browser_request_anchors = anchored
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/browser-request.ts"
                && evidence.capability == mehscan_core::Capability::OutboundNetworkRequest
        })
        .collect::<Vec<_>>();
    assert!(
        browser_request_anchors.iter().all(|evidence| {
            evidence.enclosing_symbol.as_deref() != Some("fixedBrowserRequest")
                && evidence.captures.get("endpoint").is_none_or(|capture| {
                    capture.text != "generatorUrl"
                        && capture.text != "multilineUrl"
                        && capture.text != "suffixUrl"
                })
        }),
        "fixed imported same-origin transport must not require AI review",
    );
    assert!(
        browser_request_anchors.iter().any(|evidence| {
            evidence.enclosing_symbol.as_deref() == Some("dynamicBrowserRequest")
        })
    );
    for endpoint in [
        "externalUrl",
        "replaceableUrl.replace('<host>', destination)",
    ] {
        assert!(browser_request_anchors.iter().any(|evidence| {
            evidence
                .captures
                .get("endpoint")
                .is_some_and(|capture| capture.text == endpoint)
        }));
    }
    let setup_evidence = scan
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.location.path == "data/setup.ts"
                && evidence.capability == mehscan_core::Capability::ResourceAccess
        })
        .collect::<Vec<_>>();
    assert_eq!(
        setup_evidence.len(),
        2,
        "both seed cleanup and externally callable selectors remain deterministic evidence"
    );
    let setup_anchors = anchored
        .iter()
        .filter(|evidence| {
            evidence.location.path == "data/setup.ts"
                && evidence.capability == mehscan_core::Capability::ResourceAccess
        })
        .collect::<Vec<_>>();
    assert!(
        setup_anchors
            .iter()
            .all(|evidence| { evidence.enclosing_symbol.as_deref() != Some("deleteCreatedUser") })
    );
    assert!(
        setup_anchors.iter().any(|evidence| {
            evidence.enclosing_symbol.as_deref() == Some("deleteRequestedUser")
        })
    );
    let directory_evidence = scan
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/directory.ts"
                && evidence.capability == mehscan_core::Capability::FilesystemRead
        })
        .collect::<Vec<_>>();
    assert_eq!(
        directory_evidence.len(),
        2,
        "enumerated and dynamic filesystem reads must remain deterministic evidence"
    );
    let directory_anchors = anchored
        .iter()
        .filter(|evidence| {
            evidence.location.path == "routes/directory.ts"
                && evidence.capability == mehscan_core::Capability::FilesystemRead
        })
        .collect::<Vec<_>>();
    assert!(
        directory_anchors
            .iter()
            .all(|evidence| { evidence.enclosing_symbol.as_deref() != Some("checksumDirectory") })
    );
    assert!(
        directory_anchors
            .iter()
            .any(|evidence| { evidence.enclosing_symbol.as_deref() == Some("dynamicDirectory") })
    );
    assert!(anchored.iter().all(|evidence| {
        evidence.location.path != "fixed_sinks.py"
            || (evidence
                .context
                .literals
                .values()
                .all(|literal| literal.state != mehscan_core::LiteralState::Known)
                && evidence
                    .captures
                    .get("path")
                    .is_none_or(|capture| capture.text != "fixed_path"))
    }));
    assert!(
        anchored
            .iter()
            .filter(|evidence| evidence.location.path == "fixed_sinks.py")
            .count()
            >= 3,
        "dynamic filesystem and outbound endpoints remain reviewable",
    );
    let redirect_anchors = anchored
        .iter()
        .filter(|evidence| {
            evidence.location.path == "fixed_sinks.py"
                && evidence.capability == mehscan_core::Capability::Redirect
        })
        .collect::<Vec<_>>();
    assert_eq!(redirect_anchors.len(), 1);
    assert_eq!(
        redirect_anchors[0]
            .captures
            .get("location")
            .map(|capture| capture.text.as_str()),
        Some("destination")
    );
    assert_eq!(
        job.observation_reviews
            .iter()
            .flat_map(|review| review.evidence.iter())
            .filter(|evidence| {
                evidence.location.path == "fixed_sinks.py"
                    && evidence.capability == mehscan_core::Capability::Redirect
            })
            .count(),
        1,
        "fixed redirect evidence remains in scan output but not in AI review payloads"
    );
    let bundle_set = mehscan_engine::investigation::build_path_review_bundles(&job, None)
        .expect("semantic bundles should build");
    for bundle in &bundle_set.bundles {
        if let PathReviewBundlePayload::Observation { reviews } = &bundle.payload {
            assert!(reviews.iter().all(|review| {
                review
                    .evidence
                    .iter()
                    .filter(|evidence| review.anchor_evidence_ids.contains(&evidence.id))
                    .find(|evidence| evidence.kind == EvidenceKind::Sink)
                    .or_else(|| {
                        review.evidence.iter().find(|evidence| {
                            review.anchor_evidence_ids.contains(&evidence.id)
                                && matches!(
                                    evidence.kind,
                                    EvidenceKind::SensitiveOperation
                                        | EvidenceKind::SecurityConfiguration
                                )
                        })
                    })
                    .is_some_and(|anchor| anchor.capability == bundle.category.capability)
            }));
        }
    }
    let bundle_responses = bundle_set
        .bundles
        .into_iter()
        .map(|bundle| {
            let path_bundle = matches!(
                &bundle.payload,
                PathReviewBundlePayload::SecurityPath { .. }
            );
            let results = bundle
                .review_ids
                .iter()
                .map(|review_id| PathReviewTriageResult {
                    review_id: review_id.clone(),
                    decision: if path_bundle {
                        ReviewDecision::Issue
                    } else {
                        ReviewDecision::NotIssue
                    },
                    confidence: ReviewConfidence::Medium,
                    summary: "The supplied bounded evidence supports this compact decision."
                        .to_string(),
                    checks: Vec::new(),
                    investigation: Some(Default::default()),
                })
                .collect();
            let responses = PathReviewBundleResponseSet {
                schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
                bundle_fingerprint: bundle.bundle_fingerprint.clone(),
                results,
                repair: None,
            };
            (bundle, responses)
        })
        .collect::<Vec<_>>();
    let report = mehscan_engine::investigation::summarize_path_review_bundle_run(&bundle_responses)
        .expect("complete semantic run should summarize");

    assert_eq!(report.issue_count, 2);
    assert_eq!(
        report.issue_group_count, 2,
        "two response calls in one function are two exact sinks"
    );
    assert!(
        report
            .issue_groups
            .iter()
            .all(|group| group.review_ids.len() == 1 && group.review_kinds == ["path"])
    );
    assert!(
        report
            .quality_warnings
            .iter()
            .any(|warning| warning.contains("uniform_confidence"))
    );
}

#[test]
fn keeps_csrf_scan_context_but_reviews_only_handlers_with_possible_security_effects() {
    let root = review_csrf_admission_root();
    let scan = mehscan_engine::scan_path(&root).expect("CSRF fixture should scan");
    let csrf_scan_evidence = scan
        .evidence
        .iter()
        .filter(|evidence| evidence.rule_id == "python-django-csrf-exempt-handler")
        .collect::<Vec<_>>();
    assert_eq!(csrf_scan_evidence.len(), 8);
    assert!(csrf_scan_evidence.iter().all(|evidence| {
        matches!(
            evidence.enclosing_symbol.as_deref(),
            Some(
                "profile"
                    | "transfer"
                    | "delegated"
                    | "session_change"
                    | "source_writer"
                    | "evaluator"
                    | "image_writer"
                    | "ui"
            )
        )
    }));

    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), false)
        .expect("CSRF review admission should build");
    let reviewed_symbols = jobs
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|evidence| {
                review.anchor_evidence_ids.contains(&evidence.id)
                    && evidence.rule_id == "python-django-csrf-exempt-handler"
            })
        })
        .filter_map(|review| {
            review
                .evidence
                .iter()
                .find(|evidence| evidence.rule_id == "python-django-csrf-exempt-handler")
                .and_then(|evidence| evidence.enclosing_symbol.as_deref())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        reviewed_symbols,
        BTreeSet::from(["session_change", "transfer"])
    );
    for review in jobs.observation_reviews.iter().filter(|review| {
        review.evidence.iter().any(|evidence| {
            review.anchor_evidence_ids.contains(&evidence.id)
                && evidence.rule_id == "python-django-csrf-exempt-handler"
        })
    }) {
        assert!(
            review
                .decision_facts
                .unresolved
                .iter()
                .all(|check| check.chars().count() <= 300),
            "every exact unresolved check must fit the response validator"
        );
        let fact = review
            .facts
            .iter()
            .find(|fact| fact.role == "python_csrf_handler_context")
            .expect("admitted CSRF reviews should name their direct local context");
        assert!(fact.excerpt.contains("direct_effects:"));
        if fact.symbol == "session_change" {
            assert!(fact.excerpt.contains("request_methods: POST"));
            assert!(fact.excerpt.contains("authenticated_user"));
            assert!(fact.excerpt.contains("session_or_cookie_mutation"));
        }
    }
}

#[test]
fn omits_autoescaped_django_responses_and_supplies_exact_fetch_handler_context() {
    let root = review_html_admission_root();
    let scan = mehscan_engine::scan_path(&root).expect("HTML admission fixture should scan");
    let python_html = scan
        .evidence
        .iter()
        .filter(|evidence| evidence.rule_id == "python-html-output")
        .collect::<Vec<_>>();
    assert_eq!(python_html.len(), 3);

    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), false)
        .expect("HTML review admission should build");
    let reviewed_python_symbols = jobs
        .observation_reviews
        .iter()
        .flat_map(|review| {
            review.evidence.iter().filter_map(|evidence| {
                (review.anchor_evidence_ids.contains(&evidence.id)
                    && evidence.rule_id == "python-html-output")
                    .then(|| evidence.enclosing_symbol.clone())
                    .flatten()
            })
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        reviewed_python_symbols,
        BTreeSet::from([
            "delegated_response".to_string(),
            "unsafe_response".to_string()
        ])
    );

    let browser_review = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review.evidence.iter().any(|evidence| {
                review.anchor_evidence_ids.contains(&evidence.id)
                    && evidence.rule_id == "javascript-browser-dom-html-output"
            })
        })
        .expect("browser HTML output should remain reviewable");
    assert!(browser_review.facts.iter().any(|fact| {
        fact.role == "endpoint_registration_context" && fact.excerpt.contains("views.logs")
    }));
    assert!(browser_review.facts.iter().any(|fact| {
        fact.role == "endpoint_handler_context"
            && fact.symbol == "logs"
            && fact.excerpt.contains("JsonResponse")
    }));
    assert!(browser_review.open_questions.iter().any(|question| {
        question.contains("registered `logs` endpoint")
            && question.contains("`logs` response field")
    }));
}

#[test]
fn keeps_fixed_resource_selectors_in_scan_evidence_but_out_of_review_anchors() {
    let root = review_resource_admission_root();
    let scan = mehscan_engine::scan_path(&root).expect("resource fixture should scan");
    let resource_evidence = scan
        .evidence
        .iter()
        .filter(|evidence| evidence.rule_id == "python-django-orm-resource-access")
        .collect::<Vec<_>>();
    assert_eq!(resource_evidence.len(), 3);
    let scan_selectors = resource_evidence
        .iter()
        .filter_map(|evidence| evidence.captures.get("filter"))
        .map(|capture| capture.text.as_str())
        .collect::<BTreeSet<_>>();
    assert!(scan_selectors.contains("1"));
    assert!(scan_selectors.contains("\"system\""));
    assert!(
        scan_selectors
            .iter()
            .any(|selector| selector.contains("request.POST"))
    );
    assert!(scan.evidence.iter().any(|evidence| {
        evidence.rule_id == "typescript-sequelize-resource-access"
            && evidence
                .captures
                .get("filter")
                .is_some_and(|capture| capture.text == "{ id: 1, tenant: 'system' }")
    }));
    assert!(scan.evidence.iter().any(|evidence| {
        evidence.rule_id == "java-spring-data-resource-access"
            && evidence
                .captures
                .get("filter")
                .is_some_and(|capture| capture.text == "1L")
    }));
    assert!(scan.evidence.iter().any(|evidence| {
        evidence.rule_id == "csharp-ef-unscoped-resource-query"
            && evidence
                .captures
                .get("filter")
                .is_some_and(|capture| capture.text == "record => record.Id == 1")
    }));

    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), false)
        .expect("resource review admission should build");
    let reviewed_selectors = jobs
        .observation_reviews
        .iter()
        .flat_map(|review| {
            review.evidence.iter().filter_map(|evidence| {
                (review.anchor_evidence_ids.contains(&evidence.id)
                    && evidence.capability == mehscan_core::Capability::ResourceAccess)
                    .then(|| {
                        evidence
                            .captures
                            .get("filter")
                            .map(|capture| capture.text.clone())
                    })
                    .flatten()
            })
        })
        .collect::<BTreeSet<_>>();
    assert!(
        jobs.reviews
            .iter()
            .any(|review| { review.candidate.sink.rule_id == "python-django-orm-resource-access" })
    );
    assert!(!reviewed_selectors.contains("1"));
    assert!(!reviewed_selectors.contains("\"system\""));
    assert!(!reviewed_selectors.contains("{ id: 1, tenant: 'system' }"));
    assert!(!reviewed_selectors.contains("1L"));
    assert!(!reviewed_selectors.contains("record => record.Id == 1"));
    assert!(reviewed_selectors.contains("{ id: 1, tenant: req.user.tenant }"));
    assert!(reviewed_selectors.contains("id"));
    assert!(reviewed_selectors.contains("record => record.Id == id"));
}

#[test]
fn supplies_python_caller_loader_jwt_and_fixed_payload_origin_context() {
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(
        &review_python_origin_root(),
        Some(8),
        false,
    )
    .expect("Python origin review jobs should build");

    let review_for_rule = |rule_id: &str| {
        jobs.observation_reviews.iter().find(|review| {
            review.evidence.iter().any(|evidence| {
                review.anchor_evidence_ids.contains(&evidence.id) && evidence.rule_id == rule_id
            })
        })
    };
    let jwt = review_for_rule("python-jwt-hardcoded-signing-key")
        .expect("hardcoded JWT key should remain reviewable");
    assert!(
        jwt.facts
            .iter()
            .any(|fact| fact.role == "jwt_verification_context" && fact.symbol == "verify")
    );
    assert!(
        jwt.open_questions
            .iter()
            .all(|question| { !question.contains("effective runtime or deployed control value") })
    );
    assert!(jwt.decision_facts.unresolved.is_empty());
    assert!(jwt.decision_facts.established.iter().any(|fact| {
        fact.contains("accepted with the same source-visible literal signing key")
    }));

    let yaml = review_for_rule("python-unspecified-yaml-loader")
        .expect("fixed-file unsafe YAML should retain provenance review");
    assert!(yaml.facts.iter().any(|fact| {
        fact.role == "source_context" && fact.excerpt.contains("/opt/application/trusted.yaml")
    }));
    assert!(
        yaml.decision_facts
            .unresolved
            .iter()
            .any(|question| question.contains("modify payload `stream`"))
    );

    let read = review_for_rule("python-filesystem-read")
        .expect("cross-file read helper should remain reviewable");
    assert!(read.facts.iter().any(|fact| {
        fact.role == "exact_caller_context"
            && fact.symbol == "read_route"
            && fact.excerpt.contains("request.GET")
    }));
    assert!(read.facts.iter().any(|fact| {
        fact.role == "caller_helper_definition_context" && fact.symbol == "normalize"
    }));

    let write = review_for_rule("python-source-file-content-write")
        .expect("cross-file source writer should remain reviewable");
    assert!(write.facts.iter().any(|fact| {
        fact.role == "exact_caller_context"
            && fact.symbol == "write_route"
            && fact.excerpt.contains("request.POST")
    }));
    assert!(
        write
            .facts
            .iter()
            .any(|fact| fact.role == "python_source_file_consumer_context")
    );
}

#[test]
fn scopes_python_owner_control_to_resource_access_in_mixed_observations() {
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(
        &review_python_control_scope_root(),
        Some(8),
        false,
    )
    .expect("Python control-scope review jobs should build");

    let process = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "python-process-execution")
        })
        .expect("mixed process observation should remain reviewable");
    assert!(process.decision_facts.effective_controls.is_empty());
    assert!(
        process.decision_facts.unresolved.iter().any(|question| {
            question.contains("executable") && question.contains("command.split")
        })
    );
    assert!(!process.open_questions.is_empty());
    assert_eq!(
        process.confidence_policy.not_issue,
        ReviewConfidence::Medium
    );
    assert!(process.decision_facts.established.iter().all(|fact| {
        !fact.contains("owner constraint applies to this exact resource selector")
    }));

    let resource = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review.evidence.iter().any(|item| {
                item.rule_id == "python-django-orm-resource-access"
                    && item.kind == EvidenceKind::Sink
            })
        })
        .expect("resource observation should remain reviewable");
    assert_eq!(resource.decision_facts.effective_controls.len(), 1);
    assert!(resource.decision_facts.unresolved.is_empty());
}

#[test]
fn observed_conditional_encoding_and_quoting_are_not_proven_controls() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/review-control-observation");
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), true)
        .expect("conditional control observations should build");
    for sink_rule in [
        "php-command-execution",
        "php-html-output",
        "python-html-output",
    ] {
        let review = jobs
            .observation_reviews
            .iter()
            .find(|review| review.evidence.iter().any(|item| item.rule_id == sink_rule))
            .unwrap_or_else(|| panic!("missing conditional sink observation {sink_rule}"));
        assert!(
            review.evidence.iter().any(|item| {
                matches!(
                    item.kind,
                    EvidenceKind::Sanitizer | EvidenceKind::Validation
                )
            }),
            "the possible control must remain available to the reviewer: {sink_rule}"
        );
        assert!(
            review.decision_facts.effective_controls.is_empty(),
            "conditional control syntax must not certify protection: {sink_rule}"
        );
        assert_eq!(
            review.confidence_policy.not_issue,
            ReviewConfidence::Medium,
            "unproved protection must not raise dismissal confidence: {sink_rule}"
        );
        assert!(
            review
                .facts
                .iter()
                .any(|fact| { fact.excerpt.contains("else") || fact.excerpt.contains("?") }),
            "the raw branch must remain visible: {sink_rule}"
        );
    }
}

#[test]
fn php_request_origin_context_stays_with_unique_unconditional_owner_binding() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/php-review-origin");
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), true)
        .expect("PHP origin sibling fixture should build");
    for file in [
        "positive.php",
        "reassigned.php",
        "conditional.php",
        "shadowed.php",
        "short-circuit.php",
    ] {
        let review = jobs
            .observation_reviews
            .iter()
            .find(|review| {
                review.evidence.iter().any(|item| {
                    item.rule_id == "php-command-execution" && item.location.path == file
                })
            })
            .unwrap_or_else(|| panic!("missing sink for {file}"));
        let origins = review
            .facts
            .iter()
            .filter(|fact| fact.role == "request_binding_context")
            .collect::<Vec<_>>();
        if file == "positive.php" {
            assert_eq!(origins.len(), 1);
            assert_eq!(origins[0].symbol, "$message");
            assert!(origins[0].excerpt.contains("$_POST['message']"));
            assert!(origins[0].provenance.engine.contains("not a flow"));
            assert!(
                !review
                    .facts
                    .iter()
                    .filter(|fact| fact.role == "source_context")
                    .any(|fact| fact.excerpt.contains("$_POST"))
            );
        } else {
            assert!(
                origins.is_empty(),
                "unproved origin must not be selected for {file}"
            );
        }
    }
}

#[test]
fn php_server_name_output_requires_authoritative_host_configuration() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/php-review-origin/server-name.php");
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), true)
        .expect("server metadata fixture should build");
    let review = jobs
        .observation_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id == "php-html-output")
        })
        .expect("raw server-name output");
    assert_eq!(review.decision_facts.unresolved.len(), 1);
    let check = &review.decision_facts.unresolved[0];
    assert!(check.contains("server-name.php:2"));
    assert!(check.contains("UseCanonicalName and ServerName"));
    assert!(check.contains("configured host or a client-supplied host"));
    assert!(review.decision_facts.effective_controls.is_empty());
}

#[test]
fn supplemental_php_origin_redacts_sensitive_fallback_literals() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/php-review-origin/credential.php");
    let jobs = mehscan_engine::investigation::build_all_path_review_jobs(&root, Some(8), true)
        .expect("credential fixture should build");
    let origin = jobs
        .observation_reviews
        .iter()
        .flat_map(|review| &review.facts)
        .find(|fact| fact.role == "request_binding_context")
        .expect("credential origin context");
    assert!(!origin.excerpt.contains("sensitive-fallback-sentinel"));
    assert!(origin.excerpt.contains("$_POST"));
    assert!(origin.excerpt.contains("redacted"));
}

#[test]
fn does_not_repeat_a_python_helper_sink_already_covered_by_a_path() {
    let job = mehscan_engine::investigation::build_all_path_review_jobs(
        &review_helper_admission_root(),
        Some(6),
        false,
    )
    .expect("helper review admission should build");
    assert!(job.reviews.iter().any(|review| {
        review.candidate.capability == mehscan_core::Capability::ProcessExecution
            && review.candidate.sink.rule_id == "python-file-local-parameter-sink-summary"
    }));
    assert!(job.observation_reviews.iter().all(|review| {
        review.evidence.iter().all(|evidence| {
            evidence.capability != mehscan_core::Capability::ProcessExecution
                || evidence.enclosing_symbol.as_deref() != Some("execute")
        })
    }));
}

#[test]
fn keeps_distinct_sink_instances_in_one_symbol_without_hiding_results() {
    let job = mehscan_engine::investigation::build_path_review_jobs_page(
        &review_admission_root(),
        Some(2),
        Some(2),
        0,
        false,
    )
    .expect("review page should build");
    assert_eq!(job.reviews.len(), 2);
    assert!(job.observation_reviews.is_empty());
    let responses = PathReviewTriageResponseSet {
        schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        job_fingerprint: job.fingerprint.clone(),
        results: job
            .reviews
            .iter()
            .map(|review| PathReviewTriageResult {
                review_id: review.id.clone(),
                decision: ReviewDecision::Issue,
                confidence: review.confidence_policy.issue,
                summary: "Attacker-controlled HTML reaches an unencoded response sink.".to_string(),
                checks: Vec::new(),
                investigation: Some(Default::default()),
            })
            .collect(),
    };
    let report = mehscan_engine::investigation::validate_path_review_triage(&job, &responses)
        .expect("complete triage should validate");

    assert_eq!(report.issue_count, 2);
    assert_eq!(report.results.len(), 2);
    assert_eq!(report.issue_group_count, 2);
    assert!(
        report
            .issue_groups
            .iter()
            .all(|group| group.review_ids.len() == 1)
    );
}

#[test]
fn consolidates_multiple_sources_at_one_exact_sink_and_invariant() {
    let job = mehscan_engine::investigation::build_all_path_review_jobs(
        &review_issue_grouping_root(),
        Some(3),
        false,
    )
    .expect("issue-grouping fixture should build");
    assert_eq!(
        job.reviews.len(),
        2,
        "each request field should retain its path"
    );
    assert!(job.observation_reviews.is_empty());
    let exact_sink = &job.reviews[0].candidate.sink.location;
    assert!(
        job.reviews
            .iter()
            .all(|review| review.candidate.sink.location == *exact_sink),
        "both paths must terminate at the same exact sink"
    );
    assert_eq!(
        job.reviews
            .iter()
            .map(|review| review.candidate.sink.rule_id.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        1,
        "both paths must represent the same rule-defined invariant"
    );

    let bundle_set = mehscan_engine::investigation::build_path_review_bundles(&job, None)
        .expect("issue-grouping bundles should build");
    let bundle_responses = bundle_set
        .bundles
        .into_iter()
        .map(|bundle| {
            let reviews = match &bundle.payload {
                PathReviewBundlePayload::SecurityPath { reviews } => reviews,
                PathReviewBundlePayload::Observation { .. } => {
                    panic!("the grouping fixture should contain only paths")
                }
            };
            let results = reviews
                .iter()
                .map(|review| PathReviewTriageResult {
                    review_id: review.id.clone(),
                    decision: ReviewDecision::Issue,
                    confidence: review.confidence_policy.issue,
                    summary: format!(
                        "Source {} reaches the same unencoded HTML response.",
                        review.id
                    ),
                    checks: Vec::new(),
                    investigation: Some(Default::default()),
                })
                .collect();
            let response = PathReviewBundleResponseSet {
                schema_version: PATH_REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
                bundle_fingerprint: bundle.bundle_fingerprint.clone(),
                results,
                repair: None,
            };
            (bundle, response)
        })
        .collect::<Vec<_>>();
    let report = mehscan_engine::investigation::summarize_path_review_bundle_run(&bundle_responses)
        .expect("same-sink issue paths should summarize");
    assert_eq!(report.issue_count, 2);
    assert_eq!(report.issue_group_count, 1);
    assert_eq!(report.issue_groups[0].review_ids.len(), 2);

    let finding_report = mehscan_engine::investigation::build_finding_report(
        review_issue_grouping_root().display().to_string(),
        "test",
        Some("test-reviewer".to_string()),
        &bundle_responses,
        false,
    )
    .expect("same-sink issues should produce a finding report");
    assert_eq!(finding_report.summary.issue_decisions, 2);
    assert_eq!(finding_report.summary.findings, 1);
    assert_eq!(finding_report.findings.len(), 1);
    assert_eq!(
        finding_report.findings[0].status,
        mehscan_core::FindingStatus::Issue
    );
    assert_eq!(
        finding_report.findings[0].severity.level,
        mehscan_core::Severity::Medium
    );
    assert_eq!(
        finding_report.findings[0].severity.source,
        mehscan_core::SeveritySource::FallbackDefault
    );
    assert!(finding_report.findings[0].flow.is_some());
    assert_eq!(finding_report.findings[0].provenance.review_ids.len(), 2);
    for (_, response) in &bundle_responses {
        for result in &response.results {
            assert!(
                finding_report.findings[0]
                    .description
                    .contains(&result.summary)
            );
        }
    }
    assert!(finding_report.to_markdown().contains("Source review-"));
}

#[test]
fn excludes_teaching_source_payloads_from_ai_review_by_default() {
    let production = mehscan_engine::investigation::build_path_review_jobs_page(
        &review_admission_root(),
        Some(2),
        Some(100),
        0,
        false,
    )
    .expect("production review pack should build");
    let complete = mehscan_engine::investigation::build_path_review_jobs_page(
        &review_admission_root(),
        Some(2),
        Some(100),
        0,
        true,
    )
    .expect("complete review pack should build");

    assert!(production.review_material_excluded > 0);
    assert!(
        production.reviews.iter().all(|review| !review
            .candidate
            .primary_location
            .path
            .contains("codefixes"))
    );
    assert!(
        production
            .observation_reviews
            .iter()
            .all(|review| !review.evidence[0].location.path.contains("codefixes"))
    );
    assert!(complete.include_review_material);
    assert!(complete.total_reviews > production.total_reviews);
    assert!(
        complete
            .reviews
            .iter()
            .any(|review| { review.candidate.primary_location.path.contains("codefixes") })
    );
}

#[test]
fn native_repository_secondary_tooling_is_opt_in_review_material() {
    let production = mehscan_engine::investigation::build_path_review_jobs_page(
        &native_secondary_tooling_root(),
        Some(2),
        Some(100),
        0,
        false,
    )
    .expect("production review pack should build");
    let complete = mehscan_engine::investigation::build_path_review_jobs_page(
        &native_secondary_tooling_root(),
        Some(2),
        Some(100),
        0,
        true,
    )
    .expect("complete review pack should build");

    assert_eq!(production.total_reviews, 0);
    assert!(production.review_material_excluded > 0);
    assert!(complete.observation_reviews.iter().any(|review| {
        review
            .evidence
            .iter()
            .any(|item| item.location.path == "scripts/release.py")
    }));
}

#[test]
#[ignore = "requires the optional local Juice Shop corpus"]
fn juice_shop_first_page_keeps_all_paths_and_excludes_teaching_material() {
    let job = mehscan_engine::investigation::build_path_review_jobs_page(
        &juice_shop_root(),
        Some(8),
        Some(100),
        0,
        false,
    )
    .expect("Juice Shop review pack should build");

    assert_eq!(job.reviews.len(), 48);
    assert_eq!(job.observation_reviews.len(), 52);
    // The 2026-09-04 FP-11/FP-18/FP-20 audit removed thirty-seven non-actionable verdict
    // jobs while retaining their raw evidence: seven fixed filesystem reads,
    // two fixed filesystem writes, one fixed SQL metadata query, and one
    // literal HTML response, plus four repository-owned browser navigation
    // bases and two injected repository service bases with fixed internal paths,
    // plus two Express object responses with exact repository JSON wrappers and
    // two private seed-cleanup selectors receiving IDs of just-created records.
    // One build checksum read consumes a direct child enumerated from the same
    // fixed directory. The generic ZIP filesystem-write observation is also
    // covered by the richer overlapping CWE-22/CWE-434 archive path. Four
    // additional standalone jobs are omitted for exact safe purposes: a fixed
    // local Swagger YAML load, a package-only MD5 checksum, and two fixed VM
    // programs whose XML/YAML operations retain separate security evidence.
    // Ten more exact purpose guards cover schema-validation tooling, repository
    // snippet indexing, generated authenticated upload destinations,
    // configuration-backed promotion assets and output, CAPTCHA verification,
    // and fixed/configured startup dependency health checks.
    // Dynamic navigation, dynamic HTML, template rendering, and the real
    // interpolated search query remain represented.
    // Five same-symbol aggregate observations are represented as twenty
    // independent actionable anchors so one verdict cannot hide sibling
    // operations with different security consequences.
    assert_eq!(job.total_reviews, 104);
    assert_eq!(job.next_offset, Some(100));
    assert!(job.truncated);
    assert!(job.review_material_excluded >= 9);
    assert!(job.observation_reviews.iter().all(|review| {
        !review.evidence[0].location.path.contains("codefixes")
            && !review.evidence[0]
                .location
                .path
                .contains("hacking-instructor")
    }));
    assert!(
        job.observation_reviews
            .iter()
            .all(|review| review.anchor_evidence_ids.len() == 1)
    );
    assert!(!job.observation_reviews.iter().any(|review| {
        review.anchor_evidence_ids.iter().any(|anchor| {
            review.evidence.iter().any(|evidence| {
                &evidence.id == anchor
                    && evidence.rule_id == "typescript-filesystem-write"
                    && evidence.location.path == "routes/fileUpload.ts"
                    && evidence.location.start.line == 34
            })
        })
    }));

    let track_xss = job
        .reviews
        .iter()
        .find(|review| review.id == "review-6821f10442521e88")
        .expect("tracking XSS review should remain stable");
    assert!(track_xss.facts.iter().any(|fact| {
        fact.role == "template_binding_context"
            && fact.symbol == "orderNo"
            && fact.location.path.ends_with("track-result.component.html")
    }));
    assert!(track_xss.facts.iter().any(|fact| {
        fact.role == "endpoint_registration_context"
            && fact.location.path == "server.ts"
            && fact.excerpt.contains("trackOrder")
    }));
    assert!(track_xss.facts.iter().any(|fact| {
        fact.role == "request_response_origin_context"
            && fact.symbol == "trackOrder"
            && fact.excerpt.contains("result.data[0] = { orderId: id }")
    }));

    let layout = job
        .reviews
        .iter()
        .find(|review| review.id == "review-c12de20c3eb34fa7")
        .expect("request-controlled Pug layout review");
    assert!(
        layout
            .review_basis
            .as_ref()
            .expect("path basis")
            .security_question
            .contains("req.body spread into render layout options")
    );

    for id in ["review-703ab07bdf4b02c0", "review-af3783ae27ab90ab"] {
        let review = job
            .reviews
            .iter()
            .find(|review| review.id == id)
            .expect("ineffective-control path review");
        assert!(
            review
                .decision_facts
                .established
                .iter()
                .any(|fact| fact.contains("identifies") && fact.contains("as ineffective"))
        );
    }

    for id in [
        "review-00d8a1f448c235ce",
        "review-773e7dce99e984c4",
        "review-9fc3ecb19d6effb1",
        "review-a7f80f8fd6fdef52",
    ] {
        let review = job
            .reviews
            .iter()
            .find(|review| review.id == id)
            .expect("explicit authentication-cookie omission path");
        assert!(review.decision_facts.unresolved.is_empty());
        assert!(
            review
                .decision_facts
                .established
                .iter()
                .any(|fact| fact.contains("remediation ownership"))
        );
    }
    let same_site = job
        .observation_reviews
        .iter()
        .find(|review| review.id == "observation-review-e2ef0db344e11b5d")
        .expect("SameSite omission observation");
    assert!(same_site.decision_facts.unresolved.is_empty());

    let captcha = job
        .observation_reviews
        .iter()
        .find(|review| review.id == "observation-review-6a16a515ca7e011b")
        .expect("fixed arithmetic CAPTCHA evaluator observation");
    assert!(captcha.decision_facts.unresolved.is_empty());
    assert!(
        captcha
            .decision_facts
            .effective_controls
            .iter()
            .any(|control| { control.contains("fixed server-generated arithmetic grammar") })
    );

    for id in [
        "observation-review-3939039a3c539ed4",
        "observation-review-aba5e47490236de1",
        "observation-review-ce88867a569fe605",
        "observation-review-d4f7e78a8ded7387",
    ] {
        let review = job
            .observation_reviews
            .iter()
            .find(|review| review.id == id)
            .expect("shared catalog resource review");
        assert!(review.decision_facts.unresolved.is_empty());
        assert!(review.decision_facts.established.iter().any(|fact| {
            fact.contains("affirmatively disproving an object-ownership violation")
        }));
        assert_eq!(review.confidence_policy.not_issue, ReviewConfidence::High);
    }

    let chat_order = job
        .reviews
        .iter()
        .find(|review| review.id == "review-909b7dea7345a330")
        .expect("chat order lookup review should remain stable");
    assert!(chat_order.facts.iter().any(|fact| {
        fact.role == "reference_use_context"
            && fact.symbol == "getUserId"
            && fact.excerpt.contains("getOrderById")
            && fact
                .excerpt
                .contains("ordersCollection.findOne({ orderId })")
    }));

    let stored_username = job
        .reviews
        .iter()
        .find(|review| review.id == "review-1aec18855799bf69")
        .expect("stored username evaluator review should remain stable");
    assert!(stored_username.facts.iter().any(|fact| {
        fact.role == "stored_write_origin_context"
            && fact.symbol == "username"
            && fact
                .excerpt
                .contains("user.update({ username: req.body.username })")
    }));

    let gated_rce = job
        .reviews
        .iter()
        .find(|review| review.id == "review-b05da55b88329c92")
        .expect("B2B evaluator review should remain stable");
    assert!(gated_rce.facts.iter().any(|fact| {
        fact.role == "feature_gate_policy_context" && fact.symbol == "getChallengeEnablementStatus"
    }));
    assert!(
        gated_rce
            .facts
            .iter()
            .any(|fact| fact.role == "feature_gate_context" && fact.symbol == "rceChallenge")
    );

    let stored_subtitles = job
        .reviews
        .iter()
        .find(|review| review.id == "review-3dac0ddb94de0f62")
        .expect("promotion subtitle review should remain stable");
    assert!(stored_subtitles.facts.iter().any(|fact| {
        fact.role == "configuration_binding_context"
            && fact.symbol == "application.promotion.subtitles"
            && fact.location.path == "config/default.yml"
    }));
    assert!(stored_subtitles.facts.iter().any(|fact| {
        fact.role == "configuration_lifecycle_context"
            && fact.symbol == "application.promotion.subtitles"
            && fact.excerpt.contains("application.promotion.subtitles")
    }));
    assert!(stored_subtitles.facts.iter().any(|fact| {
        fact.role == "configuration_lifecycle_context"
            && fact.symbol == "retrieveCustomFile"
            && fact.excerpt.contains("downloadToFile")
    }));
    assert!(stored_subtitles.facts.iter().any(|fact| {
        fact.role == "registration_context"
            && fact.symbol == "promotionVideo"
            && fact.location.path == "server.ts"
    }));
    assert!(stored_subtitles.decision_facts.unresolved.is_empty());
    assert!(
        stored_subtitles
            .decision_facts
            .established
            .iter()
            .any(|fact| fact.contains("operator-configured local asset path"))
    );

    let poison_null = job
        .reviews
        .iter()
        .find(|review| review.id == "review-703ab07bdf4b02c0")
        .expect("poison-null ordering review should remain stable");
    assert!(poison_null.facts.iter().any(|fact| {
        fact.role == "ineffective_protection_context"
            && fact
                .symbol
                .contains("before subsequent path transformation")
    }));

    let redirect = job
        .reviews
        .iter()
        .find(|review| review.id == "review-af3783ae27ab90ab")
        .expect("substring redirect review should remain stable");
    assert!(redirect.facts.iter().any(|fact| {
        fact.role == "ineffective_protection_context"
            && fact.symbol == "substring URL allowlist"
            && fact.excerpt.contains("includes(allowedUrl)")
    }));
}
