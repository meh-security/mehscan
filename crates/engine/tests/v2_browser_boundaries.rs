use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, RuntimeEnvironment};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-browser-boundaries")
}

#[test]
fn separates_browser_inputs_html_and_navigation_from_server_relations() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 8);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let browser = result
        .evidence
        .iter()
        .filter(|item| item.provenance.engine.ends_with("bounded-browser-boundary"))
        .collect::<Vec<_>>();
    assert!(
        browser
            .iter()
            .all(|item| { item.context.runtime_environment == Some(RuntimeEnvironment::Browser) })
    );

    let sources = browser
        .iter()
        .filter(|item| item.capability == Capability::BrowserInput)
        .collect::<Vec<_>>();
    assert!(
        sources
            .iter()
            .any(|item| item.rule_id.contains("message-source"))
    );
    assert!(
        sources
            .iter()
            .any(|item| item.rule_id.contains("storage-source"))
    );
    assert!(
        sources
            .iter()
            .any(|item| item.rule_id.contains("url-source"))
    );
    assert!(sources.iter().any(|item| {
        item.rule_id.contains("decoded-storage-source")
            && item.location.path == "positive/decoded.ts"
    }));
    assert!(sources.iter().all(|item| {
        !item.rule_id.contains("decoded-storage-source")
            || !item.location.path.starts_with("negative/")
    }));

    let react_sinks = browser
        .iter()
        .filter(|item| item.rule_id.contains("react-dangerous-html-output"))
        .collect::<Vec<_>>();
    assert_eq!(react_sinks.len(), 2, "{react_sinks:#?}");

    let relevant = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::HtmlOutput | Capability::BrowserNavigation
            ) && path
                .cwe_candidates
                .iter()
                .any(|cwe| cwe == "CWE-79" || cwe == "CWE-601")
        })
        .collect::<Vec<_>>();
    assert_eq!(relevant.len(), 10, "{relevant:#?}");
    assert!(relevant.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path.starts_with("positive/"))
    }));
    assert_eq!(
        relevant
            .iter()
            .map(|path| path.capability)
            .collect::<BTreeSet<_>>(),
        [Capability::HtmlOutput, Capability::BrowserNavigation]
            .into_iter()
            .collect()
    );

    let browser_source_ids = sources
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    assert!(result.security_paths.iter().all(|path| {
        if !browser_source_ids.contains(path.source_evidence_id.as_str()) {
            return true;
        }
        matches!(
            path.capability,
            Capability::HtmlOutput | Capability::BrowserNavigation
        )
    }));
}
