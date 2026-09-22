use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{
    EvidenceKind, PathReviewBundlePayload, PathReviewBundleResponseSet, PathReviewTriageResult,
    ReviewDecision, SecurityPathState,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-identity-boundary")
}

fn is_identity_path(path: &&mehscan_core::SecurityPath) -> bool {
    path.uncertainty_reasons
        .iter()
        .any(|reason| reason == "node_identity_boundary_relationship_is_syntactic")
}

#[test]
fn reports_bounded_identity_and_request_boundary_candidates_with_safe_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 15);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let custom = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-node-identity-boundary")
        })
        .collect::<Vec<_>>();
    let sinks = custom
        .iter()
        .filter(|item| item.kind == EvidenceKind::Sink)
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 11, "{sinks:#?}");
    assert!(
        sinks
            .iter()
            .all(|item| item.location.path.starts_with("positive/"))
    );

    let expected_cwes = [
        "CWE-307", "CWE-321", "CWE-345", "CWE-347", "CWE-352", "CWE-613", "CWE-614", "CWE-640",
        "CWE-942", "CWE-1004",
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let actual_cwes = sinks
        .iter()
        .flat_map(|item| item.cwe_candidates.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    assert_eq!(actual_cwes, expected_cwes);

    let paths = result
        .security_paths
        .iter()
        .filter(is_identity_path)
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 11, "{paths:#?}");
    assert!(
        paths
            .iter()
            .all(|path| path.state == SecurityPathState::Unknown)
    );
    assert!(paths.iter().all(|path| {
        path.steps
            .last()
            .is_some_and(|step| step.location.path.starts_with("positive/"))
    }));

    let guards = custom
        .iter()
        .filter(|item| item.kind == EvidenceKind::Guard)
        .collect::<Vec<_>>();
    assert!(guards.len() >= 7);
    assert!(
        guards
            .iter()
            .all(|item| item.location.path.starts_with("negative/"))
    );
}

#[test]
fn keeps_distinct_cookie_invariants_at_one_sink_as_separate_issue_groups() {
    let job =
        mehscan_engine::investigation::build_all_path_review_jobs(&fixture_root(), Some(4), false)
            .expect("identity-boundary review jobs should build");
    let bundle_set = mehscan_engine::investigation::build_path_review_bundles(&job, None)
        .expect("identity-boundary review bundles should build");
    let responses = bundle_set
        .bundles
        .into_iter()
        .map(|bundle| {
            let results = match &bundle.payload {
                PathReviewBundlePayload::SecurityPath { reviews } => reviews
                    .iter()
                    .map(|review| PathReviewTriageResult {
                        review_id: review.id.clone(),
                        decision: ReviewDecision::Issue,
                        confidence: review.confidence_policy.issue,
                        summary: "The supplied evidence establishes this exact cookie weakness."
                            .to_string(),
                        checks: Vec::new(),
                        investigation: Default::default(),
                    })
                    .collect(),
                PathReviewBundlePayload::Observation { reviews } => reviews
                    .iter()
                    .map(|review| PathReviewTriageResult {
                        review_id: review.id.clone(),
                        decision: ReviewDecision::Issue,
                        confidence: review.confidence_policy.issue,
                        summary: "The supplied evidence establishes this exact observed weakness."
                            .to_string(),
                        checks: Vec::new(),
                        investigation: Default::default(),
                    })
                    .collect(),
            };
            let response = PathReviewBundleResponseSet {
                schema_version: "1.0".to_string(),
                bundle_fingerprint: bundle.bundle_fingerprint.clone(),
                results,
                repair: None,
            };
            (bundle, response)
        })
        .collect::<Vec<_>>();
    let report = mehscan_engine::investigation::summarize_path_review_bundle_run(&responses)
        .expect("complete identity-boundary responses should summarize");

    let cookie_groups = report
        .issue_groups
        .iter()
        .filter(|group| {
            group.location.path == "positive/cookie.ts"
                && group.location.start.line == 2
                && group.review_kinds == ["path"]
        })
        .collect::<Vec<_>>();
    assert_eq!(
        cookie_groups.len(),
        2,
        "missing Secure and missing HttpOnly are different security invariants at one call"
    );
    let cookie_cwes = cookie_groups
        .iter()
        .flat_map(|group| group.cwe_candidates.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    assert_eq!(cookie_cwes, BTreeSet::from(["CWE-614", "CWE-1004"]));
    let cookie_invariants = cookie_groups
        .iter()
        .map(|group| group.invariant_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        cookie_invariants,
        BTreeSet::from([
            "typescript-auth-cookie-missing-http-only",
            "typescript-auth-cookie-missing-secure",
        ])
    );
    assert!(
        cookie_groups
            .iter()
            .all(|group| group.review_ids.len() == 1)
    );
}

#[test]
#[ignore = "requires the optional local Juice Shop corpus"]
fn juice_shop_identity_boundary_targets_are_exact() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("juice-shop");
    let result = mehscan_engine::scan_path(root).expect("Juice Shop should scan");
    let paths = result
        .security_paths
        .iter()
        .filter(is_identity_path)
        .collect::<Vec<_>>();

    let expected = [
        ("lib/insecurity.ts", 54, "CWE-321"),
        ("routes/chat.ts", 45, "CWE-345"),
        ("lib/insecurity.ts", 78, "CWE-613"),
        ("lib/insecurity.ts", 189, "CWE-347"),
        ("lib/insecurity.ts", 192, "CWE-614"),
        ("lib/insecurity.ts", 192, "CWE-1004"),
        ("routes/dataErasure.ts", 83, "CWE-352"),
        ("routes/profileImageUrlUpload.ts", 32, "CWE-352"),
        ("routes/profileImageUrlUpload.ts", 36, "CWE-352"),
        ("routes/updateUserProfile.ts", 38, "CWE-352"),
        ("routes/updateUserProfile.ts", 42, "CWE-614"),
        ("routes/updateUserProfile.ts", 42, "CWE-1004"),
        ("routes/verify.ts", 120, "CWE-347"),
        ("server.ts", 346, "CWE-307"),
    ];
    assert_eq!(paths.len(), expected.len(), "{paths:#?}");
    for (path, line, cwe) in expected {
        assert!(
            paths.iter().any(|candidate| {
                candidate.cwe_candidates == [cwe]
                    && candidate.steps.last().is_some_and(|step| {
                        step.location.path == path && step.location.start.line == line
                    })
            }),
            "missing {cwe} at {path}:{line}"
        );
    }

    assert!(!paths.iter().any(|candidate| {
        candidate.cwe_candidates == ["CWE-942"]
            && candidate
                .steps
                .last()
                .is_some_and(|step| step.location.path == "server.ts")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.kind == EvidenceKind::Guard
            && item.location.path == "lib/insecurity.ts"
            && item.location.start.line == 54
            && item.tags.iter().any(|tag| tag == "expiry-configured")
    }));
}
