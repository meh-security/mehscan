use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, FileStatus};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/parse-recovery")
}

#[test]
fn retains_valid_security_evidence_outside_recovered_syntax_errors() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("recovery fixture should scan");
    let expected = BTreeSet::from([
        "broken.cs",
        "broken.go",
        "broken.java",
        "broken.js",
        "broken.py",
        "broken.rs",
        "broken.ts",
    ]);
    let failed = result
        .coverage
        .files
        .iter()
        .filter(|file| file.status == FileStatus::ParseFailed)
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(failed, expected);
    assert_eq!(result.coverage.totals.parse_failed, expected.len());

    let recovered_evidence = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::ProcessExecution)
        .collect::<Vec<_>>();
    assert_eq!(recovered_evidence.len(), expected.len());
    let recovered = recovered_evidence
        .into_iter()
        .map(|item| item.location.path.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(recovered, expected);
    assert!(result.diagnostics.iter().all(|diagnostic| {
        diagnostic
            .message
            .contains("retained evidence outside invalid syntax ranges")
    }));
}

#[test]
fn funnel_retains_recovered_evidence_when_outlines_fail() {
    let scan = mehscan_engine::scan_path(fixture_root()).unwrap();
    let funnel = mehscan_engine::investigation::relationship_funnel(&fixture_root()).unwrap();
    assert_eq!(funnel.results.security_paths, scan.security_paths.len());
    assert_eq!(
        funnel.results.parse_failed_files,
        scan.coverage.totals.parse_failed
    );
    assert!(!funnel.results.outline_failures.is_empty());
    assert!(funnel.results.eligible_sink_observations > 0);
    assert!(
        funnel
            .results
            .interpretation
            .iter()
            .any(|s| s.contains("Outline extraction failed"))
    );
}
