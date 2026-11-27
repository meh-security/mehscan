use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-output")
}

#[test]
fn classifies_csharp_headers_and_logging_with_exact_controls() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let observations = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine == "mehscan csharp-output-policy 1")
        .collect::<Vec<_>>();
    let counts = observations
        .iter()
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });

    assert_eq!(counts["csharp-raw-response-header"], 1);
    assert_eq!(counts["csharp-raw-content-disposition"], 1);
    assert_eq!(counts["csharp-rendered-log-message"], 2);
    assert_eq!(counts["csharp-sensitive-value-logging-review"], 2);
    assert_eq!(counts["csharp-structured-log-template-control"], 2);
    assert_eq!(counts["csharp-http-header-newline-rejection"], 1);
    assert_eq!(counts["csharp-typed-content-disposition-control"], 1);

    assert!(observations.iter().any(|item| {
        item.location.path == "positive/OutputRisks.cs"
            && item.kind == EvidenceKind::SecurityConfiguration
            && item.cwe_candidates == ["CWE-532"]
    }));
    assert!(!observations.iter().any(|item| {
        item.location.path == "control/OutputControls.cs"
            && item.kind == EvidenceKind::Sink
            && item.capability == Capability::HttpHeaderOutput
    }));

    let header_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::HttpHeaderOutput && path.cwe_candidates == ["CWE-113"]
        })
        .collect::<Vec<_>>();
    let logging_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::Logging && path.cwe_candidates == ["CWE-117"])
        .collect::<Vec<_>>();
    assert_eq!(header_paths.len(), 2);
    assert_eq!(logging_paths.len(), 2);
    assert!(
        result
            .security_paths
            .iter()
            .filter(|path| {
                path.capability == Capability::HtmlOutput && path.cwe_candidates == ["CWE-79"]
            })
            .count()
            >= 2
    );
    assert!(header_paths.iter().chain(logging_paths.iter()).all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path == "positive/OutputRisks.cs")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        matches!(
            path.capability,
            Capability::HttpHeaderOutput | Capability::Logging
        ) && path
            .steps
            .iter()
            .any(|step| step.location.path == "control/OutputControls.cs")
    }));
}
