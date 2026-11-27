use std::path::PathBuf;

use mehscan_core::{Capability, HttpRouteAccess};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-commonjs")
}

#[test]
fn resolves_commonjs_constructor_handlers_and_needle_ssrf() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::OutboundNetworkRequest
                && path.cwe_candidates == ["CWE-918"]
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 1, "{paths:#?}");
    assert_eq!(
        paths[0].steps.last().expect("sink").location.path,
        "positive/handler.js"
    );

    let sink = result
        .evidence
        .iter()
        .find(|item| {
            item.capability == Capability::OutboundNetworkRequest
                && item.location.path == "positive/handler.js"
        })
        .expect("Needle sink");
    assert!(sink.context.http_routes.iter().any(|route| {
        route.method == "GET"
            && route.path == "/research"
            && route.access == HttpRouteAccess::Unknown
            && route.guards == ["isLoggedIn"]
    }));

    assert!(!result.security_paths.iter().any(|path| {
        path.steps
            .iter()
            .any(|step| step.location.path.starts_with("negative/"))
    }));
}
