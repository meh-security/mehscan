use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v2-node-js2-closure")
}

#[test]
fn closes_exact_local_ejs_and_inline_mongodb_selector_gaps() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let ssti = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-1336"])
        .collect::<Vec<_>>();
    assert_eq!(ssti.len(), 1, "{ssti:#?}");
    assert_eq!(ssti[0].capability, Capability::TemplateEvaluation);
    assert_eq!(
        ssti[0].steps.last().expect("SSTI sink").location.path,
        "positive/app.js"
    );
    assert!(
        ssti[0]
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "node_parameter_sink_summary_is_syntactic")
    );

    let nosql = result
        .security_paths
        .iter()
        .filter(|path| path.cwe_candidates == ["CWE-943"])
        .collect::<Vec<_>>();
    assert_eq!(
        nosql.len(),
        1,
        "paths={nosql:#?}\nevidence={:#?}",
        result.evidence
    );
    assert_eq!(nosql[0].capability, Capability::DatabaseQuery);
    assert_eq!(
        nosql[0].steps.last().expect("NoSQL sink").location.path,
        "positive/app.js"
    );
    assert!(
        nosql[0]
            .uncertainty_reasons
            .iter()
            .any(|reason| reason == "node_object_input_relationship_is_syntactic")
    );

    assert!(!result.security_paths.iter().any(|path| {
        path.steps
            .last()
            .is_some_and(|step| step.location.path == "negative/app.js")
            && matches!(
                path.cwe_candidates.as_slice(),
                [cwe] if cwe == "CWE-1336" || cwe == "CWE-943"
            )
    }));
}
