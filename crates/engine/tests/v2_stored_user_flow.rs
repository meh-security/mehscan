use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-stored-user-flow")
}

#[test]
fn follows_only_allowlisted_model_fields_and_string_extractions() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.schema_version, "2.1");
    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.security_paths, repeated.security_paths);

    let sources = result
        .evidence
        .iter()
        .filter(|item| item.capability == Capability::StoredUserContent)
        .collect::<Vec<_>>();
    assert_eq!(sources.len(), 6);
    assert!(sources.iter().all(|source| {
        source.location.start.line == 5 && source.provenance.engine.ends_with("stored-model-source")
    }));

    let paths = result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == Capability::DynamicCodeExecution && path.cwe_candidates == ["CWE-94"]
        })
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), 3);
    assert!(paths.iter().all(|path| {
        path.state == SecurityPathState::Unknown
            && path
                .steps
                .iter()
                .all(|step| step.location.path.starts_with("positive/"))
            && path.steps.iter().any(|step| {
                step.symbol
                    .as_deref()
                    .is_some_and(|symbol| symbol.contains(" via username."))
            })
            && path
                .uncertainty_reasons
                .contains(&"stored_model_origin_is_syntactic".to_string())
    }));
}
