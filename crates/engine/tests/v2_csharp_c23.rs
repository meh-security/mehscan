use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-c23")
}

#[test]
fn relates_exact_standalone_input_to_filesystem_access() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("C23 fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let sources = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-console-readline-source")
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 4);
    assert!(
        sources
            .iter()
            .all(|item| item.location.path == "FilesystemPositive.cs")
    );

    let filesystem_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::FilesystemRead | Capability::FilesystemWrite
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(filesystem_paths.len(), 2);
    assert!(filesystem_paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path == "FilesystemPositive.cs")
    }));
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::DatabaseQuery)
            .count(),
        2
    );
}
