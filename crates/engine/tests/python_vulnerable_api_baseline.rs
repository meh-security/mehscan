use std::collections::BTreeSet;
use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
#[ignore = "requires the optional local Vulnerable-API corpus"]
fn optional_python_p9_connexion_and_helper_baseline_matches_when_requested() {
    let corpus = workspace_root().join("apps/python/Vulnerable-API");
    assert!(corpus.is_dir(), "missing {}", corpus.display());
    let result = mehscan_engine::scan_path(corpus).expect("Vulnerable-API should scan");

    assert_eq!(result.coverage.totals.scanned, 8);
    assert_eq!(result.coverage.totals.ignored, 5);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence.len(), 30);
    assert_eq!(result.security_paths.len(), 4);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "python-connexion-openapi-handler-entrypoint")
            .count(),
        12
    );
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "python-openapi-operation-parameter")
            .count(),
        6
    );

    let paths = result
        .security_paths
        .iter()
        .map(|path| {
            (
                path.steps
                    .last()
                    .expect("path has sink")
                    .location
                    .path
                    .clone(),
                path.cwe_candidates.first().expect("path has CWE").clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        paths,
        BTreeSet::from([
            ("lfi.py".to_string(), "CWE-22".to_string()),
            ("rfi.py".to_string(), "CWE-918".to_string()),
            ("sqli.py".to_string(), "CWE-89".to_string()),
            ("ssti.py".to_string(), "CWE-1336".to_string()),
        ])
    );
}
