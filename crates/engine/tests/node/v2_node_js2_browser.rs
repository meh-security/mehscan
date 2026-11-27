use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-js2-browser")
}

#[test]
fn extracts_executable_ejs_and_separates_browser_transport_relationships() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.discovered, 4);
    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.ignored, 1);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let risk = result
        .security_paths
        .iter()
        .filter(|path| {
            path.steps
                .iter()
                .any(|step| matches!(step.location.path.as_str(), "risk.ejs" | "react.jsx"))
        })
        .collect::<Vec<_>>();
    let capabilities = risk
        .iter()
        .map(|path| path.capability)
        .collect::<BTreeSet<_>>();
    assert!(capabilities.contains(&Capability::HtmlOutput), "{risk:#?}");
    assert!(
        capabilities.contains(&Capability::BrowserCredentialedRequest),
        "{risk:#?}"
    );
    assert!(
        capabilities.contains(&Capability::BrowserMessageSend),
        "{risk:#?}"
    );

    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::BrowserCredentialedRequest
            && path.state == SecurityPathState::Protected
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "safe.ejs")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.state != SecurityPathState::Protected
            && path
                .steps
                .iter()
                .any(|step| matches!(step.location.path.as_str(), "safe.ejs" | "tutorial.ejs"))
    }));
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "javascript-browser-message-origin-validation"
            && item.location.path == "safe.ejs"
    }));
}
