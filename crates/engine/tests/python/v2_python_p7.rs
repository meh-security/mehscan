use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p7")
}

#[test]
fn models_bounded_flask_dbapi_output_redirect_and_file_context() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 1);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "python-proved-dbapi-cursor-query"
            && item.captures["query"].text.contains("SELECT name")
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "python-proved-dbapi-parameterization"
            && item.kind == EvidenceKind::Sanitizer
    }));
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.rule_id == "python-flask-raw-dynamic-response")
    );
    assert!(result.evidence.iter().any(|item| {
        item.capability == Capability::FilesystemRead && item.captures["path"].text == "path"
    }));
    assert!(result.evidence.iter().any(|item| {
        item.capability == Capability::Redirect
            && item.captures["location"].text.contains("request.args.get")
    }));

    assert!(result.security_paths.iter().any(|path| {
        path.cwe_candidates.iter().any(|cwe| cwe == "CWE-89")
            && path.state != SecurityPathState::Protected
    }));
    assert!(result.security_paths.iter().any(|path| {
        path.cwe_candidates.iter().any(|cwe| cwe == "CWE-79")
            && path.state != SecurityPathState::Protected
    }));
}
