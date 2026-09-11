use std::collections::BTreeMap;
use std::path::PathBuf;

use mehscan_core::{Capability, SecurityPathState};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-java-j5")
}

#[test]
fn models_exact_java_queries_parameterization_and_persistent_object_mapping() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("fixture should scan");
    let repeated = mehscan_engine::scan_path(fixture_root()).expect("fixture should rescan");

    assert_eq!(result.coverage.totals.scanned, 6);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence, repeated.evidence);
    assert_eq!(result.security_paths, repeated.security_paths);

    let j5 = result
        .evidence
        .iter()
        .filter(|evidence| evidence.provenance.engine == "mehscan java-persistence-policy 1")
        .collect::<Vec<_>>();
    let counts = j5.iter().fold(BTreeMap::new(), |mut counts, evidence| {
        *counts.entry(evidence.rule_id.as_str()).or_insert(0usize) += 1;
        counts
    });
    assert_eq!(j5.len(), 14);
    assert_eq!(counts["java-typed-persistence-query"], 4);
    assert_eq!(counts["java-jpa-query-parameterization-control"], 1);
    assert_eq!(counts["java-named-jdbc-parameterization-control"], 1);
    assert_eq!(counts["java-spring-data-custom-query"], 2);
    assert_eq!(counts["java-spring-data-named-parameter-control"], 1);
    assert_eq!(counts["java-spring-data-request-entity-mass-assignment"], 1);
    assert_eq!(counts["java-bean-copy-persistent-mass-assignment"], 1);
    assert_eq!(counts["java-bean-copy-ignore-list-control"], 1);
    assert_eq!(counts["java-jackson-persistent-update-mass-assignment"], 1);
    assert_eq!(
        counts["java-sensitive-field-explicit-request-assignment"],
        1
    );
    assert!(
        !j5.iter()
            .any(|evidence| evidence.location.path == "Lookalikes.java")
    );

    let query_paths = result
        .security_paths
        .iter()
        .filter(|path| path.capability == Capability::DatabaseQuery)
        .collect::<Vec<_>>();
    assert_eq!(query_paths.len(), 2);
    assert!(query_paths.iter().all(|path| {
        path.state == SecurityPathState::Propagated && path.cwe_candidates == ["CWE-89"]
    }));
    assert!(query_paths.iter().all(|path| {
        result.evidence.iter().any(|evidence| {
            evidence.id == path.sink_evidence_id
                && evidence.rule_id == "java-typed-persistence-query"
        })
    }));
}
