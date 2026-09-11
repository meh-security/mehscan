use std::path::PathBuf;

use mehscan_core::{Capability, EvidenceKind, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-summaries")
}

#[test]
fn applies_bounded_node_function_and_continuation_summaries() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 16);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let summary_sources = result
        .evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Source
                && item
                    .provenance
                    .engine
                    .ends_with("bounded-parameter-return-summary")
        })
        .collect::<Vec<_>>();
    assert_eq!(summary_sources.len(), 3, "{summary_sources:#?}");
    let source = summary_sources
        .iter()
        .find(|source| source.location.path == "positive/handler.ts")
        .expect("TypeScript summary source");
    assert_eq!(source.location.path, "positive/handler.ts");
    assert_eq!(source.location.start.line, 16);
    assert!(source.context.http_routes.iter().any(|route| {
        route.method == "POST"
            && route.path == "/run"
            && route.access == HttpRouteAccess::Authenticated
            && route.guards == ["isAuthorized"]
    }));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.cwe_candidates == ["CWE-78"]
                && path.capability == Capability::ProcessExecution
                && path
                    .uncertainty_reasons
                    .iter()
                    .any(|reason| reason == "node_parameter_return_summary_is_syntactic")
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3, "{paths:#?}");
    assert!(paths.iter().any(|path| {
        path.steps.last().expect("sink step").location.path == "positive/handler.ts"
    }));
    let parameter_sink_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.uncertainty_reasons
                .iter()
                .any(|reason| reason == "node_parameter_sink_summary_is_syntactic")
        })
        .collect::<Vec<_>>();
    assert_eq!(parameter_sink_paths.len(), 9, "{parameter_sink_paths:#?}");
    let sink_cwes = parameter_sink_paths
        .iter()
        .flat_map(|path| path.cwe_candidates.iter().map(String::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        sink_cwes,
        [
            "CWE-22", "CWE-78", "CWE-79", "CWE-94", "CWE-502", "CWE-601", "CWE-918"
        ]
        .into_iter()
        .collect()
    );

    let continuation_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.uncertainty_reasons
                .iter()
                .any(|reason| reason == "node_async_continuation_summary_is_syntactic")
        })
        .collect::<Vec<_>>();
    assert_eq!(continuation_paths.len(), 2, "{continuation_paths:#?}");
    assert!(continuation_paths.iter().all(|path| {
        path.steps.last().expect("sink step").location.path == "positive/handler.ts"
    }));
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path
                .uncertainty_reasons
                .iter()
                .any(|reason| reason.contains("summary_is_syntactic")))
            .count(),
        14
    );
    assert!(!result.evidence.iter().any(|item| {
        (item
            .provenance
            .engine
            .ends_with("bounded-parameter-return-summary")
            || item
                .provenance
                .engine
                .ends_with("bounded-parameter-sink-summary")
            || item
                .provenance
                .engine
                .ends_with("bounded-async-continuation-summary"))
            && item.location.path.starts_with("negative/")
    }));
}
