use std::path::PathBuf;

use mehscan_core::{EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p8")
}

#[test]
fn connects_only_exact_openapi_operations_and_declared_parameters() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 1);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let handlers = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-connexion-openapi-handler-entrypoint")
        .collect::<Vec<_>>();
    assert_eq!(handlers.len(), 2);
    assert!(handlers.iter().any(|item| {
        item.enclosing_symbol.as_deref() == Some("unsafe")
            && item
                .context
                .http_routes
                .iter()
                .any(|route| route.method == "POST" && route.path == "/api/unsafe")
    }));
    assert!(
        handlers
            .iter()
            .all(|item| { item.enclosing_symbol.as_deref() != Some("not_an_operation") })
    );

    let parameters = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-openapi-operation-parameter")
        .collect::<Vec<_>>();
    assert_eq!(parameters.len(), 2);
    assert!(parameters.iter().all(|item| {
        item.kind == EvidenceKind::Source
            && item.captures["name"].text == "payload"
            && item.provenance.resolution == mehscan_core::Resolution::External
    }));

    let sql_paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates.iter().any(|cwe| cwe == "CWE-89"))
        .collect::<Vec<_>>();
    assert!(sql_paths.iter().any(|path| {
        path.steps
            .last()
            .is_some_and(|step| step.location.path == "api.py" && step.location.start.line == 9)
            && path.state != SecurityPathState::Protected
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "python-proved-dbapi-parameterization" && item.location.start.line == 18
    }));
    assert!(sql_paths.iter().all(|path| {
        path.steps
            .last()
            .is_none_or(|step| step.location.path != "api.py" || step.location.start.line != 18)
            || path.state == SecurityPathState::Protected
    }));
}
