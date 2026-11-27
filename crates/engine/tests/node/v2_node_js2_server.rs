use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-js2-server")
}

#[test]
fn relates_js2_server_inputs_and_keeps_safe_controls_bounded() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 3);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let risk_paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.steps
                .iter()
                .any(|step| step.location.path == "risk.js")
        })
        .collect::<Vec<_>>();
    let cwes = risk_paths
        .iter()
        .flat_map(|path| path.cwe_candidates.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    assert!(
        [
            "CWE-78", "CWE-89", "CWE-502", "CWE-611", "CWE-918", "CWE-943"
        ]
        .into_iter()
        .all(|cwe| cwes.contains(cwe)),
        "{risk_paths:#?}"
    );
    assert!(risk_paths.iter().any(|path| {
        path.uncertainty_reasons
            .iter()
            .any(|reason| reason == "node_lexical_closure_capture_is_syntactic")
    }));

    assert!(result.security_paths.iter().any(|path| {
        path.capability == Capability::ProcessExecution
            && path.state == SecurityPathState::Protected
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "safe.js")
    }));
    assert!(!result.security_paths.iter().any(|path| {
        path.state != SecurityPathState::Protected
            && path
                .steps
                .iter()
                .any(|step| step.location.path == "safe.js")
    }));
    assert!(!result.evidence.iter().any(|item| {
        item.capability == Capability::XmlParsing && item.location.path == "safe.js"
    }));
}
