use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-node-js4-typescript")
}

#[test]
fn typescript_express_relationships_preserve_exact_imports_and_safe_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("JS4 fixture should scan");

    let positive_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.steps
                .iter()
                .all(|step| step.location.path.starts_with("positive/"))
        })
        .collect::<Vec<_>>();
    for cwe in [
        "CWE-22", "CWE-321", "CWE-639", "CWE-918", "CWE-915", "CWE-1321", "CWE-942",
    ] {
        assert!(
            positive_paths
                .iter()
                .any(|path| path.cwe_candidates == [cwe]),
            "missing positive {cwe}: {positive_paths:#?}"
        );
    }
    let unexpected_safe_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.steps
                .iter()
                .any(|step| step.location.path.starts_with("safe/"))
                && matches!(
                    path.cwe_candidates.as_slice(),
                    [cwe] if matches!(cwe.as_str(), "CWE-321" | "CWE-639" | "CWE-918" | "CWE-915" | "CWE-1321" | "CWE-942")
                )
        })
        .collect::<Vec<_>>();
    assert!(
        unexpected_safe_paths.is_empty(),
        "{unexpected_safe_paths:#?}"
    );

    let safe_yaml = result.evidence.iter().find(|item| {
        item.location.path == "safe/server.ts"
            && item.capability == Capability::DeserializationRestriction
    });
    assert!(
        safe_yaml.is_some(),
        "safeLoad should be retained as restriction evidence"
    );
    assert!(result.evidence.iter().any(|item| {
        item.location.path == "positive/server.ts"
            && item.kind == EvidenceKind::Sink
            && item.cwe_candidates == ["CWE-1321"]
            && item
                .tags
                .iter()
                .any(|tag| tag == "dependency-version-sensitive")
    }));
    for rule in [
        "typescript-administrative-route-authorization-review",
        "typescript-environment-response-disclosure",
        "typescript-stack-trace-response-disclosure",
    ] {
        assert!(
            result
                .evidence
                .iter()
                .any(|item| { item.location.path == "positive/server.ts" && item.rule_id == rule })
        );
        assert!(
            !result
                .evidence
                .iter()
                .any(|item| { item.location.path == "safe/server.ts" && item.rule_id == rule })
        );
    }
    let safe_resource = result.evidence.iter().find(|item| {
        item.location.path == "safe/server.ts"
            && item.rule_id == "typescript-in-memory-resource-access"
    });
    assert!(safe_resource.is_some_and(|item| {
        item.context
            .resource_policy
            .as_ref()
            .is_some_and(|policy| policy.state == mehscan_core::ResourcePolicyState::OwnerScoped)
    }));
}
