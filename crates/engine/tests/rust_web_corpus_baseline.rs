use std::path::PathBuf;

use mehscan_core::{Capability, ScanResult, SecurityPathState};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn state_for(
    result: &ScanResult,
    capability: Capability,
    fragment: &str,
) -> Option<SecurityPathState> {
    result
        .security_paths
        .iter()
        .find(|path| {
            path.capability == capability
                && path
                    .steps
                    .last()
                    .is_some_and(|step| step.location.path.contains(fragment))
        })
        .map(|path| path.state)
}

#[test]
#[ignore = "requires the optional local rust-vulnerable-apps corpus"]
fn optional_rust_r3_web_truth_preserves_framework_response_semantics() {
    let root = workspace_root().join("apps/rust/rust-vulnerable-apps");
    assert!(
        root.is_dir(),
        "optional corpus is missing: {}",
        root.display()
    );

    let ssrf = mehscan_engine::scan_path(root.join("ssrf")).expect("SSRF corpus should scan");
    assert_eq!(ssrf.coverage.totals.scanned, 3);
    assert_eq!(ssrf.coverage.totals.parse_failed, 0);
    assert_eq!(ssrf.evidence.len(), 11);
    assert_eq!(ssrf.security_paths.len(), 3);
    assert_eq!(
        state_for(
            &ssrf,
            Capability::OutboundNetworkRequest,
            "ssrf_001_bad_iron"
        ),
        Some(SecurityPathState::Propagated)
    );
    assert_eq!(
        state_for(
            &ssrf,
            Capability::OutboundNetworkRequest,
            "ssrf_002_bad_reqwest_client"
        ),
        Some(SecurityPathState::Propagated)
    );
    assert_eq!(
        state_for(
            &ssrf,
            Capability::OutboundNetworkRequest,
            "ssrf_003_good_reqwest"
        ),
        Some(SecurityPathState::Protected)
    );
    assert!(
        !ssrf
            .security_paths
            .iter()
            .any(|path| path.capability == Capability::HtmlOutput)
    );

    let xss = mehscan_engine::scan_path(root.join("xss")).expect("XSS corpus should scan");
    assert_eq!(xss.coverage.totals.scanned, 3);
    assert_eq!(xss.coverage.totals.parse_failed, 0);
    assert_eq!(xss.evidence.len(), 6);
    assert_eq!(xss.security_paths.len(), 2);
    assert_eq!(
        state_for(&xss, Capability::HtmlOutput, "xss_002_bad_iron"),
        Some(SecurityPathState::Propagated)
    );
    assert_eq!(
        state_for(&xss, Capability::HtmlOutput, "xss_003_good_iron_ammonia"),
        Some(SecurityPathState::Protected)
    );
    assert!(!xss.evidence.iter().any(|item| {
        item.capability == Capability::HtmlOutput && item.location.path.contains("xss_001_bad_warp")
    }));
}
