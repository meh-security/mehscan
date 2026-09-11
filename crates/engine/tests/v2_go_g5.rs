use std::path::PathBuf;

use mehscan_core::{Capability, FileStatus, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-go-g5-grpc")
}

#[test]
fn excludes_generated_protobuf_and_models_grpc_sql_and_transport() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.discovered, 2);
    assert_eq!(result.coverage.totals.scanned, 1);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let generated = result
        .coverage
        .files
        .iter()
        .find(|file| file.path == "generated/messages.pb.go")
        .expect("generated protobuf source should remain visible in coverage");
    assert_eq!(generated.status, FileStatus::Ignored);

    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-grpc-request-accessor-source"
            && item.enclosing_symbol.as_deref() == Some("Unsafe")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-grpc-insecure-transport"
            && item.capability == Capability::TlsConfiguration
    }));
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "go-grpc-server-plaintext-transport-review")
    );
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "go-grpc-server-transport-credentials-control"
            && item.cwe_candidates.is_empty()
    }));

    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::DatabaseQuery
            && path.state == SecurityPathState::Propagated
            && path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason == "grpc_parameter_binding_is_syntactic")
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::DatabaseQuery && path.state == SecurityPathState::Protected
    }));
}
