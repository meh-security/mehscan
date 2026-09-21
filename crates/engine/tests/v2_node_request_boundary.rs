use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::EvidenceKind;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn models_node_session_cookie_csrf_rotation_and_password_policy_without_comment_defaults() {
    let risk = mehscan_engine::scan_path(fixture("v2-node-request-boundary-risk"))
        .expect("risk fixture should scan");
    let safe = mehscan_engine::scan_path(fixture("v2-node-request-boundary-safe"))
        .expect("safe fixture should scan");
    let explicit_risk =
        mehscan_engine::scan_path(fixture("v2-node-request-boundary-explicit-risk"))
            .expect("explicit-risk fixture should scan");

    let risk_rules = risk
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-node-request-boundary")
        })
        .map(|item| item.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        risk_rules,
        [
            "javascript-cookie-session-csrf-review",
            "javascript-login-session-fixation-risk",
            "javascript-session-cookie-policy-review",
            "javascript-weak-password-policy",
        ]
        .into_iter()
        .collect()
    );
    assert!(risk.evidence.iter().any(|item| {
        item.rule_id == "javascript-cookie-session-csrf-review"
            && item.captures["state_changing_routes"].text == "POST /profile"
    }));
    assert!(risk.evidence.iter().any(|item| {
        item.rule_id == "javascript-session-cookie-policy-review"
            && item.tags.iter().any(|tag| tag == "http-only:default")
            && item.tags.iter().any(|tag| tag == "secure:default")
            && item.tags.iter().any(|tag| tag == "same-site:default")
    }));
    assert!(risk.evidence.iter().all(|item| {
        !item
            .provenance
            .engine
            .ends_with("bounded-node-request-boundary")
            || item.kind == EvidenceKind::SecurityConfiguration
    }));

    let controls = safe
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-node-request-boundary")
        })
        .collect::<Vec<_>>();
    assert_eq!(controls.len(), 4, "{controls:#?}");
    assert!(controls.iter().all(|item| item.kind == EvidenceKind::Guard));
    assert_eq!(
        controls
            .iter()
            .map(|item| item.rule_id.as_str())
            .collect::<BTreeSet<_>>(),
        [
            "typescript-login-session-regeneration-control",
            "typescript-project-csrf-middleware-control",
            "typescript-session-cookie-policy-control",
            "typescript-strong-password-policy-control",
        ]
        .into_iter()
        .collect()
    );
    assert!(!safe.evidence.iter().any(|item| {
        item.rule_id.contains("fixation-risk")
            || item.rule_id.contains("csrf-review")
            || item.rule_id.contains("policy-review")
    }));

    let cookie_risk = explicit_risk
        .evidence
        .iter()
        .find(|item| item.rule_id == "javascript-session-cookie-policy-risk")
        .expect("explicitly weak cookie policy");
    assert_eq!(
        cookie_risk
            .cwe_candidates
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["CWE-1004", "CWE-1275", "CWE-614"].into_iter().collect()
    );
    assert!(
        cookie_risk
            .tags
            .iter()
            .any(|tag| tag == "recommendation:fix-application")
    );

    let jobs = mehscan_engine::investigation::build_path_review_jobs(
        &fixture("v2-node-request-boundary-risk"),
        None,
        Some(100),
    )
    .expect("request-boundary review jobs should build");
    let boundary_reviews = jobs
        .observation_reviews
        .iter()
        .filter(|review| {
            review.evidence.iter().any(|item| {
                item.provenance
                    .engine
                    .ends_with("bounded-node-request-boundary")
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(boundary_reviews.len(), 4, "{boundary_reviews:#?}");
    assert!(boundary_reviews.iter().any(|review| {
        review
            .open_questions
            .iter()
            .any(|question| question.contains("old session identifier"))
    }));
    assert!(boundary_reviews.iter().any(|review| {
        review
            .open_questions
            .iter()
            .any(|question| question.contains("trivially short passwords"))
    }));
    let csrf_review = boundary_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id.ends_with("cookie-session-csrf-review"))
        })
        .expect("independent CSRF review");
    assert_eq!(
        csrf_review
            .evidence
            .iter()
            .filter(|item| {
                item.provenance
                    .engine
                    .ends_with("bounded-node-request-boundary")
            })
            .count(),
        1
    );
    assert_eq!(csrf_review.open_questions.len(), 1);
    assert!(
        csrf_review
            .review_basis
            .as_ref()
            .is_some_and(|basis| { basis.relationship == "bounded_request_integrity_review" })
    );
    let cookie_review = boundary_reviews
        .iter()
        .find(|review| {
            review
                .evidence
                .iter()
                .any(|item| item.rule_id.ends_with("session-cookie-policy-review"))
        })
        .expect("independent cookie-policy review");
    assert_eq!(cookie_review.open_questions.len(), 1);
}
