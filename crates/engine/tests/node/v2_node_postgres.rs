use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-node-postgres")
}

#[test]
fn distinguishes_node_postgres_query_text_from_bound_values() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    let sql_paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-89"])
        .collect::<Vec<_>>();
    assert_eq!(sql_paths.len(), 1, "{sql_paths:#?}");
    assert_eq!(
        sql_paths[0].steps.last().expect("sink").location.path,
        "positive/app.js"
    );
    assert!(result.evidence.iter().any(|item| {
        item.location.path == "negative/app.js"
            && item.kind == EvidenceKind::Sanitizer
            && item.capability == Capability::SqlParameterization
            && item.rule_id == "javascript-postgres-parameterization-control"
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.cwe_candidates == ["CWE-89"]
            && path
                .steps
                .last()
                .is_some_and(|step| step.location.path == "negative/app.js")
    }));
}
