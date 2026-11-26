use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-python-p9")
}

#[test]
fn relates_only_unique_exact_helpers_and_rendered_jinja_templates() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");

    assert_eq!(result.coverage.totals.scanned, 1);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let helper_summaries = result
        .evidence
        .iter()
        .filter(|item| item.rule_id == "python-file-local-parameter-sink-summary")
        .collect::<Vec<_>>();
    assert_eq!(helper_summaries.len(), 4);
    assert_eq!(
        helper_summaries
            .iter()
            .map(|item| item.capability)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            Capability::FilesystemRead,
            Capability::OutboundNetworkRequest,
        ])
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "python-jinja-dynamic-template-evaluation")
            .count(),
        2
    );

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.cwe_candidates
                .iter()
                .any(|cwe| matches!(cwe.as_str(), "CWE-22" | "CWE-918" | "CWE-1336"))
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3);
    assert!(
        paths
            .iter()
            .all(|path| path.state != SecurityPathState::Protected)
    );
    assert_eq!(
        paths
            .iter()
            .flat_map(|path| path.cwe_candidates.iter().cloned())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "CWE-22".to_string(),
            "CWE-918".to_string(),
            "CWE-1336".to_string(),
        ])
    );
    assert!(paths.iter().all(|path| {
        path.steps
            .first()
            .is_some_and(|step| matches!(step.location.start.line, 15 | 24 | 33))
    }));
}
