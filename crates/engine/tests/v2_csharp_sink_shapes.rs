use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, Confidence, EvidenceKind, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-csharp-sink-shapes")
}

#[test]
fn completes_typed_and_framework_csharp_sink_shapes_without_lookalike_paths() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let rule_counts = result
        .evidence
        .iter()
        .filter(|item| item.kind == EvidenceKind::Sink)
        .fold(BTreeMap::new(), |mut counts, item| {
            *counts.entry(item.rule_id.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(rule_counts["csharp-sql-command-text"], 2);
    assert_eq!(rule_counts["csharp-dapper-database-query"], 3);
    assert_eq!(rule_counts["csharp-aspnet-explicit-html-output"], 2);
    assert_eq!(rule_counts["csharp-controller-http-redirect"], 2);
    assert_eq!(rule_counts["csharp-filesystem-read"], 2);
    assert_eq!(rule_counts["csharp-filesystem-write"], 2);
    assert_eq!(rule_counts["csharp-webclient-outbound-http"], 2);

    let typed_sinks = result.evidence.iter().filter(|item| {
        matches!(
            item.rule_id.as_str(),
            "csharp-sql-command-text"
                | "csharp-dapper-database-query"
                | "csharp-webclient-outbound-http"
        )
    });
    assert!(typed_sinks.clone().all(|item| {
        item.location.path == "positive/CsharpSinks.cs"
            && item.tags.iter().any(|tag| tag == "typed-receiver")
    }));
    assert!(
        typed_sinks
            .filter(|item| item.rule_id != "csharp-sql-command-text")
            .all(|item| item.confidence == Confidence::Medium)
    );
    assert!(
        result
            .evidence
            .iter()
            .filter(|item| {
                matches!(
                    item.rule_id.as_str(),
                    "csharp-aspnet-explicit-html-output" | "csharp-controller-http-redirect"
                )
            })
            .all(|item| item.confidence == Confidence::Medium)
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.uncertainty_reasons
                .iter()
                .any(|reason| reason == "aspnet_parameter_binding_is_syntactic")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 15);
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Propagated
            && path
                .steps
                .iter()
                .all(|step| step.location.path == "positive/CsharpSinks.cs")
    }));

    let by_capability = paths.iter().fold(BTreeMap::new(), |mut counts, path| {
        *counts.entry(path.capability).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(by_capability[&Capability::DatabaseQuery], 5);
    assert_eq!(by_capability[&Capability::HtmlOutput], 2);
    assert_eq!(by_capability[&Capability::Redirect], 2);
    assert_eq!(by_capability[&Capability::FilesystemRead], 2);
    assert_eq!(by_capability[&Capability::FilesystemWrite], 2);
    assert_eq!(by_capability[&Capability::OutboundNetworkRequest], 2);
}
