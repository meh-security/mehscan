use std::path::PathBuf;

use mehscan_core::Language;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn emits_one_cookie_authenticated_state_change_and_honors_project_csrf_control() {
    let vulnerable = mehscan_engine::scan_path(fixture("v2-go-g4-csrf"))
        .expect("vulnerable fixture should scan");
    let safe = mehscan_engine::scan_path(fixture("v2-go-g4-csrf-safe"))
        .expect("controlled fixture should scan");

    assert_eq!(vulnerable.coverage.totals.parse_failed, 0);
    assert_eq!(safe.coverage.totals.parse_failed, 0);

    let csrf_paths = vulnerable
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-352"])
        .collect::<Vec<_>>();
    assert_eq!(csrf_paths.len(), 1);
    assert!(vulnerable.coverage.cwe.iter().any(|coverage| {
        coverage.cwe == "CWE-352" && coverage.supported_languages.contains(&Language::Go)
    }));

    let source = vulnerable
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-cookie-authenticated-request-source")
        .expect("state-change request source should be explicit");
    let sink = vulnerable
        .evidence
        .iter()
        .find(|item| item.rule_id == "go-cookie-authenticated-state-change-review")
        .expect("state-change sink should be explicit");
    assert_eq!(source.related_evidence.as_slice(), [sink.id.as_str()]);
    assert_eq!(sink.related_evidence.as_slice(), [source.id.as_str()]);

    assert!(
        !safe
            .evidence
            .iter()
            .any(|item| item.rule_id == "go-cookie-authenticated-state-change-review")
    );
    assert!(
        !safe
            .security_paths
            .iter()
            .any(|path| path.cwe_candidates == ["CWE-352"])
    );
    assert!(
        safe.evidence
            .iter()
            .any(|item| item.rule_id == "go-project-csrf-middleware-control")
    );
}
