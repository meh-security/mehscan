use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-rpc-ingress")
}

#[test]
fn inventories_grpc_and_signalr_parameters_without_calling_them_http_data() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let sources = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::RpcRequestData)
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 9);
    assert!(sources.iter().all(|source| {
        source.kind == EvidenceKind::Source
            && source.location.path == "positive/RpcIngress.cs"
            && !source.tags.iter().any(|tag| tag == "http")
    }));

    let by_rule = sources.iter().fold(BTreeMap::new(), |mut counts, source| {
        *counts.entry(source.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(by_rule["csharp-grpc-request-parameter-source"], 3);
    assert_eq!(by_rule["csharp-signalr-hub-parameter-source"], 6);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.uncertainty_reasons.iter().any(|reason| {
                matches!(
                    reason.as_str(),
                    "grpc_parameter_binding_is_syntactic"
                        | "signalr_parameter_binding_is_syntactic"
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 8);
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Propagated
            && path
                .steps
                .iter()
                .all(|step| step.location.path == "positive/RpcIngress.cs")
    }));

    let by_capability = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts.entry(path.capability).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(by_capability[&Capability::ProcessExecution], 5);
    assert_eq!(by_capability[&Capability::Redirect], 2);
    assert_eq!(by_capability[&Capability::OutboundNetworkRequest], 1);
}
