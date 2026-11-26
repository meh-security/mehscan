use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
#[ignore = "requires the optional local Vulpy corpus"]
fn optional_python_p6_vulpy_pair_preserves_security_differences() {
    let root = workspace_root().join("apps/python/vulpy");
    assert!(
        root.is_dir(),
        "optional corpus is missing: {}",
        root.display()
    );

    let bad = mehscan_engine::scan_path(root.join("bad")).expect("bad side should scan");
    assert_eq!(bad.coverage.totals.discovered, 41);
    assert_eq!(bad.coverage.totals.scanned, 21);
    assert_eq!(bad.coverage.totals.ignored, 20);
    assert_eq!(bad.coverage.totals.parse_failed, 0);
    assert_eq!(bad.evidence.len(), 86);
    assert_eq!(bad.security_paths.len(), 5);
    assert_eq!(
        bad.evidence
            .iter()
            .filter(|item| item.rule_id == "python-flask-handler-entrypoint")
            .count(),
        15
    );
    assert_eq!(
        bad.evidence
            .iter()
            .filter(|item| item.rule_id == "python-flask-unsigned-client-session")
            .count(),
        1
    );
    assert_eq!(
        bad.evidence
            .iter()
            .filter(|item| item.rule_id == "python-module-qualified-sql-helper-summary")
            .count(),
        8
    );
    assert_eq!(
        bad.evidence
            .iter()
            .filter(|item| item.rule_id == "python-proved-dbapi-cursor-query")
            .count(),
        17
    );
    assert_eq!(
        bad.evidence
            .iter()
            .filter(|item| item.rule_id == "python-proved-dbapi-parameterization")
            .count(),
        7
    );
    assert!(
        bad.security_paths
            .iter()
            .all(|path| path.cwe_candidates.iter().any(|cwe| cwe == "CWE-89"))
    );

    let good = mehscan_engine::scan_path(root.join("good")).expect("good side should scan");
    assert_eq!(good.coverage.totals.discovered, 43);
    assert_eq!(good.coverage.totals.scanned, 20);
    assert_eq!(good.coverage.totals.ignored, 23);
    assert_eq!(good.coverage.totals.parse_failed, 0);
    assert_eq!(good.evidence.len(), 89);
    assert_eq!(good.security_paths.len(), 0);
    assert_eq!(
        good.evidence
            .iter()
            .filter(|item| item.rule_id == "python-flask-handler-entrypoint")
            .count(),
        18
    );
    assert_eq!(
        good.evidence
            .iter()
            .filter(|item| item.rule_id == "python-flask-authenticated-session-control")
            .count(),
        1
    );
    assert_eq!(
        good.evidence
            .iter()
            .filter(|item| item.rule_id == "python-proved-dbapi-cursor-query")
            .count(),
        13
    );
    assert_eq!(
        good.evidence
            .iter()
            .filter(|item| item.rule_id == "python-proved-dbapi-parameterization")
            .count(),
        9
    );
    assert!(
        !good
            .evidence
            .iter()
            .any(|item| item.rule_id == "python-module-qualified-sql-helper-summary")
    );
}
