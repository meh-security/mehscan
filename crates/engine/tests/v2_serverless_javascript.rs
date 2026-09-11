use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, RuntimeEnvironment};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-serverless-javascript")
}

#[test]
fn resolves_commonjs_lambda_ingress_helpers_aws_operations_and_responses() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let serverless = result
        .evidence
        .iter()
        .filter(|item| {
            item.provenance
                .engine
                .ends_with("bounded-serverless-boundary")
        })
        .collect::<Vec<_>>();
    assert!(!serverless.is_empty());
    assert!(serverless.iter().all(|item| {
        !item.location.path.starts_with("negative/")
            && item.context.runtime_environment == Some(RuntimeEnvironment::Server)
    }));
    assert_eq!(
        serverless
            .iter()
            .filter(|item| item.kind == EvidenceKind::Entrypoint)
            .count(),
        3
    );
    assert!(serverless.iter().any(|item| {
        item.rule_id == "javascript-aws-dynamodb-operation" && !item.related_evidence.is_empty()
    }));
    assert!(serverless.iter().any(|item| {
        item.rule_id == "javascript-aws-s3-object-operation"
            && item.location.path.starts_with("safe/")
    }));
    assert_eq!(
        serverless
            .iter()
            .filter(|item| item.rule_id == "javascript-aws-s3-public-object-acl")
            .count(),
        1,
        "private ACL is an operation fact but not a public-access fact"
    );
    assert!(
        serverless
            .iter()
            .any(|item| item.rule_id == "javascript-lambda-stack-trace-response")
    );
    assert!(
        serverless
            .iter()
            .any(|item| item.rule_id == "javascript-lambda-redirect-response")
    );

    let command_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::ProcessExecution)
        .collect::<Vec<_>>();
    assert_eq!(command_paths.len(), 1, "{command_paths:#?}");
    assert!(
        command_paths[0]
            .steps
            .iter()
            .all(|step| step.location.path.starts_with("positive/"))
    );
    assert!(!result.security_paths.iter().any(|path| {
        path.steps.iter().any(|step| {
            step.location.path.starts_with("safe/") || step.location.path.starts_with("negative/")
        })
    }));
}
