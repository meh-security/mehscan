use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, RuntimeEnvironment};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-js-runtime")
}

#[test]
fn distinguishes_browser_server_mixed_and_unknown_javascript_family_files() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("runtime fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 4);

    let runtime_by_path = result
        .evidence
        .iter()
        .fold(BTreeMap::new(), |mut runtimes, evidence| {
            let runtime = evidence
                .context
                .runtime_environment
                .expect("JavaScript-family evidence has runtime context");
            assert_eq!(
                runtimes
                    .entry(evidence.location.path.clone())
                    .or_insert(runtime),
                &runtime,
                "one file must have one conservative runtime classification"
            );
            runtimes
        });
    assert_eq!(
        runtime_by_path["frontend/browser.ts"],
        RuntimeEnvironment::Browser
    );
    assert_eq!(
        runtime_by_path["server/server.ts"],
        RuntimeEnvironment::Server
    );
    assert_eq!(runtime_by_path["mixed.tsx"], RuntimeEnvironment::Mixed);
    assert_eq!(runtime_by_path["unknown.tsx"], RuntimeEnvironment::Unknown);

    let outbound_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::OutboundNetworkRequest)
        .collect::<Vec<_>>();
    assert_eq!(outbound_paths.len(), 3);
    assert!(
        outbound_paths.iter().all(
            |path| path.steps.last().expect("sink step").location.path != "frontend/browser.ts"
        ),
        "browser requests remain evidence but are not promoted as server-side SSRF paths"
    );
    assert!(
        outbound_paths
            .iter()
            .any(|path| path.steps.last().expect("sink step").location.path == "server/server.ts")
    );
    assert!(
        outbound_paths
            .iter()
            .any(|path| path.steps.last().expect("sink step").location.path == "mixed.tsx")
    );
    assert!(
        outbound_paths
            .iter()
            .any(|path| path.steps.last().expect("sink step").location.path == "unknown.tsx")
    );
}
