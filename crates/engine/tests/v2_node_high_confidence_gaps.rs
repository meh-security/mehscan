use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-node-high-confidence-gaps")
}

#[test]
fn closes_selected_node_gaps_without_promoting_safe_siblings() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 8);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let relevant = result
        .security_paths
        .iter()
        .filter(|path| {
            matches!(
                path.capability,
                Capability::DatabaseQuery | Capability::XmlParsing | Capability::HtmlOutput
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(relevant.len(), 5, "{relevant:#?}");
    assert!(relevant.iter().all(|path| {
        path.state != SecurityPathState::Protected
            && path
                .steps
                .iter()
                .all(|step| step.location.path.starts_with("positive/"))
    }));

    let cwes = relevant
        .iter()
        .flat_map(|path| path.cwe_candidates.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    assert_eq!(cwes, ["CWE-79", "CWE-89", "CWE-611"].into_iter().collect());

    let sql = relevant
        .iter()
        .find(|path| path.capability == Capability::DatabaseQuery)
        .expect("bounded reassignment SQL path");
    assert!(
        sql.uncertainty_reasons
            .iter()
            .any(|reason| reason == "node_value_preserving_reassignment_is_syntactic")
    );

    let xml = relevant
        .iter()
        .find(|path| path.capability == Capability::XmlParsing)
        .expect("uploaded XML path");
    assert!(
        xml.uncertainty_reasons
            .iter()
            .any(|reason| reason == "node_libxml2_xxe_summary_is_syntactic")
    );

    let html = relevant
        .iter()
        .filter(|path| path.capability == Capability::HtmlOutput)
        .collect::<Vec<_>>();
    assert_eq!(html.len(), 3);
    assert!(html.iter().any(|path| {
        path.uncertainty_reasons
            .iter()
            .any(|reason| reason == "angular_rxjs_source_summary_is_syntactic")
    }));
    assert!(html.iter().any(|path| {
        result.evidence.iter().any(|item| {
            item.id == path.sink_evidence_id
                && item.enclosing_symbol.as_deref() == Some("trustProductDescription")
        })
    }));
}
