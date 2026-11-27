use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
#[ignore = "requires the optional local crAPI workshop corpus"]
fn optional_python_p5_crapi_workshop_baseline_matches_when_requested() {
    let corpus = workspace_root().join("apps/crAPI/services/workshop");
    assert!(
        corpus.is_dir(),
        "optional corpus is missing: {}",
        corpus.display()
    );

    let result = mehscan_engine::scan_path(corpus).expect("workshop corpus should scan");
    assert_eq!(result.coverage.totals.discovered, 64);
    assert_eq!(result.coverage.totals.scanned, 41);
    assert_eq!(result.coverage.totals.ignored, 23);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence.len(), 153);
    assert_eq!(result.security_paths.len(), 16);
    assert!(result.security_paths.iter().any(|path| {
        path.cwe_candidates == ["CWE-639"]
            && path.steps.last().is_some_and(|step| {
                step.location.path == "utils/mock_methods.py" && step.location.start.line == 115
            })
    }));

    let surfaces = &result.coverage.security_surfaces;
    assert_eq!(surfaces.get("http_request_handling"), Some(&50));
    assert_eq!(surfaces.get("http_request_data"), Some(&38));
    assert_eq!(surfaces.get("database_query"), Some(&5));
    assert_eq!(surfaces.get("outbound_network_request"), Some(&4));
    assert_eq!(surfaces.get("filesystem_read"), Some(&3));
    assert_eq!(surfaces.get("filesystem_write"), Some(&1));
    assert_eq!(surfaces.get("path_canonicalization"), Some(&2));
    assert_eq!(surfaces.get("tls_configuration"), Some(&4));
    assert_eq!(surfaces.get("resource_access"), Some(&27));
    assert_eq!(surfaces.get("authentication"), Some(&17));
    assert_eq!(surfaces.get("authorization"), Some(&2));
}
