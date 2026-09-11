use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript/serverless-goat")
}

#[test]
#[ignore = "requires the optional pinned OWASP ServerlessGoat corpus"]
fn locks_the_js6_serverless_goat_baseline() {
    let result = mehscan_engine::scan_path(corpus()).expect("ServerlessGoat should scan");

    assert_eq!(result.coverage.totals.discovered, 71);
    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(
        (result.evidence.len(), result.security_paths.len()),
        (17, 1)
    );

    let path = &result.security_paths[0];
    assert_eq!(path.capability, Capability::ProcessExecution);
    assert_eq!(path.cwe_candidates, ["CWE-78"]);
    assert!(path.steps.last().is_some_and(|step| {
        step.location.path == "src/api/convert/index.js" && step.location.start.line == 29
    }));

    for rule in [
        "javascript-aws-dynamodb-operation",
        "javascript-aws-s3-object-operation",
        "javascript-aws-s3-public-object-acl",
        "javascript-lambda-redirect-response",
        "javascript-lambda-stack-trace-response",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "javascript-aws-dynamodb-operation"
            && item.kind == EvidenceKind::SensitiveOperation
            && item.related_evidence.len() == 1
    }));
}
