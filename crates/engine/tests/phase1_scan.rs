use std::path::PathBuf;

use mehscan_core::{Capability, FileStatus};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/phase1")
}

#[test]
fn enumerates_process_execution_and_reports_coverage() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.evidence.len(), 10);
    assert!(result.evidence.iter().all(|item| matches!(
        item.capability,
        Capability::ProcessExecution | Capability::ProcessArgumentSeparation
    )));
    assert!(
        result
            .evidence
            .iter()
            .all(|item| item.cwe_candidates == ["CWE-78"])
    );
    assert!(
        result
            .evidence
            .iter()
            .all(|item| item.captures.contains_key("command"))
    );
    assert!(
        result
            .evidence
            .iter()
            .any(|item| item.enclosing_symbol.as_deref() == Some("run"))
    );

    assert_eq!(result.coverage.totals.scanned, 10);
    assert_eq!(result.coverage.totals.parse_failed, 1);
    assert_eq!(result.coverage.totals.unsupported, 0);
    assert_eq!(result.coverage.totals.ignored, 1);
    assert_eq!(result.coverage.totals.secret_scanned, 0);
    assert_eq!(
        result.coverage.security_surfaces.get("process_execution"),
        Some(&9)
    );
    assert_eq!(
        result
            .coverage
            .security_surfaces
            .get("process_argument_separation"),
        Some(&1)
    );
    assert_eq!(result.coverage.ignored_subtrees, ["target/"]);
    assert!(
        result
            .coverage
            .files
            .iter()
            .any(|file| { file.path == "broken.py" && file.status == FileStatus::ParseFailed })
    );
    assert!(
        result
            .coverage
            .files
            .iter()
            .any(|file| { file.path == "unsupported.rs" && file.status == FileStatus::Scanned })
    );
}

#[test]
fn evidence_ids_are_deterministic() {
    let first = mehscan_engine::scan_path(fixture_root()).expect("first scan should work");
    let second = mehscan_engine::scan_path(fixture_root()).expect("second scan should work");
    let first_ids: Vec<_> = first.evidence.iter().map(|item| &item.id).collect();
    let second_ids: Vec<_> = second.evidence.iter().map(|item| &item.id).collect();
    assert_eq!(first_ids, second_ids);
}

#[test]
fn parallel_file_analysis_matches_single_worker_output() {
    let single = mehscan_engine::scan_path_profiled_with_options(
        fixture_root(),
        mehscan_engine::ScanOptions {
            include_tests: false,
            jobs: Some(1),
            scan_secrets: false,
            impact_scope: None,
        },
    )
    .expect("single-worker scan should work");
    let parallel = mehscan_engine::scan_path_profiled_with_options(
        fixture_root(),
        mehscan_engine::ScanOptions {
            include_tests: false,
            jobs: Some(4),
            scan_secrets: false,
            impact_scope: None,
        },
    )
    .expect("parallel scan should work");

    assert_eq!(single.0, parallel.0);
    assert_eq!(single.1.worker_count, 1);
    assert_eq!(parallel.1.worker_count, 4);
}
