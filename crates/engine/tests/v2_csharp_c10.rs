use std::collections::BTreeSet;
use std::path::PathBuf;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c10")
}

fn webgoat_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/WebGoat.NET")
}

#[test]
fn builds_exact_non_path_csharp_review_neighborhoods() {
    let scan = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let before_paths = scan.security_paths.clone();
    let before_evidence = scan.evidence.clone();

    let job =
        mehscan_engine::investigation::build_csharp_review_neighborhoods(&fixture_root(), Some(10))
            .expect("review neighborhoods should build");
    let repeated =
        mehscan_engine::investigation::build_csharp_review_neighborhoods(&fixture_root(), Some(10))
            .expect("review neighborhoods should repeat");

    assert_eq!(job, repeated);
    assert!(!job.truncated);
    assert_eq!(job.neighborhoods.len(), 2);
    assert_eq!(
        job.neighborhoods
            .iter()
            .map(|item| item.key.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["StoredComment.Contents", "StoredPost.Contents"])
    );
    for neighborhood in &job.neighborhoods {
        assert_eq!(
            neighborhood.uncertainties,
            [
                "persistence_unproven",
                "runtime_flow_unproven",
                "symbol_binding_syntactic"
            ]
        );
        let roles = neighborhood
            .facts
            .iter()
            .map(|fact| fact.role.as_str())
            .collect::<BTreeSet<_>>();
        assert!(roles.contains("bound_remote_input"));
        assert!(roles.contains("property_assignment"));
        assert!(roles.contains("controller_repository_call"));
        assert!(roles.contains("persistence_call_observed"));
        assert!(roles.contains("model_property"));
        assert!(roles.contains("raw_output_sink"));
        assert_eq!(
            neighborhood.candidate,
            "Potential stored XSS through raw Razor output"
        );
        assert_eq!(neighborhood.cwe, "CWE-79");
        assert_eq!(neighborhood.open_questions.len(), 3);
        assert!(neighborhood.verification.persistence_call_observed);
        assert!(!neighborhood.verification.runtime_persistence_verified);
        assert!(!neighborhood.verification.retrieval_verified);
    }
    assert_eq!(
        job.triage_contract.response_fields,
        [
            "neighborhood_id",
            "decision",
            "confidence",
            "summary",
            "checks"
        ]
    );
    assert_eq!(
        job.triage_contract.decisions,
        ["issue", "not_issue", "needs_review"]
    );
    assert!(!job.neighborhoods.iter().any(|item| {
        matches!(
            item.key.as_str(),
            "DisplayModel.Contents" | "Article.Contents"
        )
    }));

    let limited =
        mehscan_engine::investigation::build_csharp_review_neighborhoods(&fixture_root(), Some(1))
            .expect("bounded review job should build");
    assert!(limited.truncated);
    assert_eq!(limited.neighborhoods.len(), 1);
    assert!(
        mehscan_engine::investigation::build_csharp_review_neighborhoods(&fixture_root(), Some(0))
            .is_err()
    );

    let after = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");
    assert_eq!(after.evidence, before_evidence);
    assert_eq!(after.security_paths, before_paths);
}

#[test]
fn validates_compact_final_triage_against_the_exact_job() {
    use mehscan_core::{
        REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION, ReviewConfidence, ReviewDecision,
        ReviewTriageResponseSet, ReviewTriageResult,
    };

    let job =
        mehscan_engine::investigation::build_csharp_review_neighborhoods(&fixture_root(), Some(10))
            .expect("review neighborhoods should build");
    let results = job
        .neighborhoods
        .iter()
        .enumerate()
        .map(|(index, neighborhood)| ReviewTriageResult {
            neighborhood_id: neighborhood.id.clone(),
            decision: if index == 0 {
                ReviewDecision::Issue
            } else {
                ReviewDecision::NeedsReview
            },
            confidence: ReviewConfidence::Medium,
            summary: "The supplied facts support this concise decision.".to_string(),
            checks: if index == 0 {
                Vec::new()
            } else {
                vec!["Confirm the runtime retrieval into the raw sink.".to_string()]
            },
        })
        .collect::<Vec<_>>();
    let responses = ReviewTriageResponseSet {
        schema_version: REVIEW_TRIAGE_RESPONSE_SCHEMA_VERSION.to_string(),
        job_fingerprint: job.fingerprint.clone(),
        results,
    };

    let report = mehscan_engine::investigation::validate_review_triage(&job, &responses)
        .expect("well-formed triage should validate");
    assert_eq!(report.issue_count, 1);
    assert_eq!(report.not_issue_count, 0);
    assert_eq!(report.needs_review_count, 1);

    let mut stale = responses.clone();
    stale.job_fingerprint = "csharp-reviewpack-stale".to_string();
    assert!(
        mehscan_engine::investigation::validate_review_triage(&job, &stale)
            .expect_err("stale triage must fail")
            .to_string()
            .contains("fingerprint")
    );

    let mut missing = responses.clone();
    missing.results.pop();
    assert!(
        mehscan_engine::investigation::validate_review_triage(&job, &missing)
            .expect_err("partial triage must fail")
            .to_string()
            .contains("missing neighborhoods")
    );

    let mut unresolved_without_check = responses.clone();
    unresolved_without_check.results[1].checks.clear();
    assert!(
        mehscan_engine::investigation::validate_review_triage(&job, &unresolved_without_check)
            .expect_err("needs_review must name a check")
            .to_string()
            .contains("requires at least one decisive check")
    );

    let mut final_with_check = responses;
    final_with_check.results[0]
        .checks
        .push("This check contradicts a final decision.".to_string());
    assert!(
        mehscan_engine::investigation::validate_review_triage(&job, &final_with_check)
            .expect_err("final decisions cannot retain checks")
            .to_string()
            .contains("cannot retain checks")
    );
}

#[test]
fn optional_webgoat_neighborhood_baseline_matches_when_requested() {
    if std::env::var_os("MEHSCAN_RUN_WEBGOAT_DOTNET").is_none() {
        return;
    }
    let job =
        mehscan_engine::investigation::build_csharp_review_neighborhoods(&webgoat_root(), Some(10))
            .expect("WebGoat review neighborhoods should build");
    let scan = mehscan_engine::scan_path(webgoat_root()).expect("WebGoat should scan");
    assert_eq!(job.coverage.totals.scanned, 90);
    assert_eq!(job.coverage.totals.parse_failed, 0);
    assert_eq!(scan.evidence.len(), 54);
    assert_eq!(scan.security_paths.len(), 1);
    assert_eq!(job.neighborhoods.len(), 2);
    assert_eq!(
        job.neighborhoods
            .iter()
            .map(|item| item.key.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["BlogEntry.Contents", "BlogResponse.Contents"])
    );
}
