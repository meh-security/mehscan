use std::path::PathBuf;

use mehscan_core::SecurityPathState;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/rust/rust-vulnerable-apps")
}

#[test]
#[ignore = "requires the optional local rust-vulnerable-apps corpus"]
fn optional_rust_r2_sql_truth_preserves_bad_good_and_disputed_cases() {
    let root = corpus_root();
    assert!(
        root.is_dir(),
        "optional corpus is missing: {}",
        root.display()
    );
    let result = mehscan_engine::scan_path(root).expect("Rust vulnerability corpus should scan");

    assert_eq!(result.coverage.totals.scanned, 31);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "rust-database-query")
            .count(),
        10
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "rust-sql-parameterization")
            .count(),
        2
    );

    let sql_paths = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates.iter().any(|cwe| cwe == "CWE-89"))
        .collect::<Vec<_>>();
    assert_eq!(sql_paths.len(), 10, "{sql_paths:#?}");
    assert_eq!(
        sql_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Protected)
            .count(),
        2
    );
    assert_eq!(
        sql_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Propagated)
            .count(),
        6
    );
    assert_eq!(
        sql_paths
            .iter()
            .filter(|path| path.state == SecurityPathState::Unknown)
            .count(),
        2
    );

    let state_for = |fragment: &str| {
        sql_paths
            .iter()
            .find(|path| {
                path.steps
                    .last()
                    .is_some_and(|step| step.location.path.contains(fragment))
            })
            .map(|path| path.state)
    };
    assert_eq!(
        state_for("sqli_good_001_sqlx"),
        Some(SecurityPathState::Protected)
    );
    assert_eq!(
        state_for("sqli_good_003_diesel"),
        Some(SecurityPathState::Protected)
    );
    assert_eq!(
        state_for("sqli_good_002_sqlx"),
        Some(SecurityPathState::Propagated),
        "a bind without a SQL placeholder must not be treated as protection"
    );
}
