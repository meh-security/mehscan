use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::EvidenceKind;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn models_node_closure_risks_and_executable_controls() {
    let risk = mehscan_engine::scan_path(fixture("v2-node-closure-risk"))
        .expect("risk fixture should scan");
    let safe = mehscan_engine::scan_path(fixture("v2-node-closure-safe"))
        .expect("safe fixture should scan");

    let risk_rules = risk
        .evidence
        .iter()
        .filter(|item| item.provenance.engine.ends_with("bounded-node-policy"))
        .map(|item| item.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "javascript-request-log-source",
        "javascript-unencoded-log-message",
        "javascript-credential-response-enumeration-risk",
        "javascript-sensitive-record-persistence-risk",
        "javascript-http-listener-deployment-review",
    ] {
        assert!(
            risk_rules.contains(expected),
            "missing {expected}: {risk_rules:#?}"
        );
    }
    assert_eq!(
        risk.security_paths
            .iter()
            .filter(|path| path.cwe_candidates == ["CWE-117"])
            .count(),
        1
    );
    let storage = risk
        .evidence
        .iter()
        .find(|item| item.rule_id == "javascript-sensitive-record-persistence-risk")
        .expect("sensitive record risk");
    assert_eq!(storage.captures["fields"].text, "dateofbirth, ssn");
    let listener = risk
        .evidence
        .iter()
        .find(|item| item.rule_id == "javascript-http-listener-deployment-review")
        .expect("HTTP listener review");
    assert_eq!(listener.kind, EvidenceKind::SecurityConfiguration);
    assert!(
        listener
            .tags
            .iter()
            .any(|tag| tag == "recommendation:review-deployment")
    );

    let safe_rules = safe
        .evidence
        .iter()
        .filter(|item| item.provenance.engine.ends_with("bounded-node-policy"))
        .map(|item| item.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "typescript-uniform-credential-response-control",
        "typescript-sensitive-record-protection-control",
        "typescript-https-listener-control",
    ] {
        assert!(
            safe_rules.contains(expected),
            "missing {expected}: {safe_rules:#?}"
        );
    }
    assert!(
        safe.evidence
            .iter()
            .filter(|item| { item.provenance.engine.ends_with("bounded-node-policy") })
            .all(|item| item.kind == EvidenceKind::Guard)
    );
    assert!(
        !safe
            .security_paths
            .iter()
            .any(|path| path.cwe_candidates == ["CWE-117"])
    );
}

#[test]
fn emits_precise_review_questions_for_node_closure_evidence() {
    let jobs = mehscan_engine::investigation::build_path_review_jobs(
        &fixture("v2-node-closure-risk"),
        None,
        Some(100),
    )
    .expect("closure review jobs should build");
    let questions = jobs
        .reviews
        .iter()
        .flat_map(|review| review.open_questions.iter())
        .chain(
            jobs.observation_reviews
                .iter()
                .flat_map(|review| review.open_questions.iter()),
        )
        .cloned()
        .collect::<Vec<_>>();
    for phrase in [
        "CR, LF",
        "paired executable login branches",
        "listed sensitive fields",
        "authoritative proxy, gateway",
    ] {
        assert!(
            questions.iter().any(|question| question.contains(phrase)),
            "missing question containing {phrase:?}: {questions:#?}"
        );
    }
}
