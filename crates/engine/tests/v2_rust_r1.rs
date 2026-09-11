use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, Language};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-rust-r1")
}

#[test]
fn scans_rust_sources_and_builds_only_synthetic_request_to_sink_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("Rust fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("Rust fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 4);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);
    assert_eq!(result.evidence.len(), 28, "{:#?}", result.evidence);
    assert_eq!(
        result.security_paths.len(),
        9,
        "{:#?}",
        result.security_paths
    );
    assert!(
        result
            .coverage
            .files
            .iter()
            .all(|file| { file.language == Some(Language::Rust) })
    );

    for rule in [
        "rust-axum-request-extractor",
        "rust-actix-request-data",
        "rust-process-execution",
        "rust-database-query",
        "rust-filesystem-read",
        "rust-file-content-input",
        "rust-filesystem-write",
        "rust-outbound-http",
        "rust-data-deserialization",
        "rust-axum-http-redirect",
        "rust-axum-html-output",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule),
            "missing {rule}"
        );
    }

    assert!(result.evidence.iter().all(|item| {
        item.location.path.starts_with("positive/")
            || item.kind != EvidenceKind::Source
            || item.capability != Capability::HttpRequestData
    }));
    assert!(result.security_paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path.starts_with("positive/"))
    }));

    let capability_counts = result.security_paths.iter().fold(
        BTreeMap::<Capability, usize>::new(),
        |mut counts, path| {
            *counts.entry(path.capability).or_default() += 1;
            counts
        },
    );
    assert_eq!(capability_counts[&Capability::ProcessExecution], 2);
    assert_eq!(capability_counts[&Capability::OutboundNetworkRequest], 2);
    for capability in [
        Capability::DatabaseQuery,
        Capability::FilesystemRead,
        Capability::Redirect,
        Capability::HtmlOutput,
        Capability::Deserialization,
    ] {
        assert_eq!(capability_counts[&capability], 1, "{capability:?}");
    }
}
