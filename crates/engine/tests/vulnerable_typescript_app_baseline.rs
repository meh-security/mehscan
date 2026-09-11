use std::path::PathBuf;

fn corpus() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript/vulnerable-typescript-app")
}

#[test]
#[ignore = "requires the optional pinned vulnerable TypeScript application"]
fn locks_the_js4_typescript_corpus_baseline() {
    let result = mehscan_engine::scan_path(corpus()).expect("TypeScript corpus should scan");

    assert_eq!(result.coverage.totals.discovered, 8);
    assert_eq!(result.coverage.totals.scanned, 1);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(
        (result.evidence.len(), result.security_paths.len()),
        (61, 11)
    );

    for (cwe, line) in [
        ("CWE-22", 104),
        ("CWE-321", 79),
        ("CWE-639", 161),
        ("CWE-915", 197),
        ("CWE-918", 125),
        ("CWE-942", 49),
        ("CWE-1321", 246),
    ] {
        assert!(
            result.security_paths.iter().any(|path| {
                path.cwe_candidates == [cwe]
                    && path.steps.last().is_some_and(|step| {
                        step.location.path == "src/server.ts" && step.location.start.line == line
                    })
            }),
            "missing {cwe} at src/server.ts:{line}"
        );
    }
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-deserialization-restriction" && item.location.start.line == 187
    }));
    for (rule, count) in [
        ("typescript-administrative-route-authorization-review", 1),
        ("typescript-environment-response-disclosure", 1),
        ("typescript-stack-trace-response-disclosure", 2),
    ] {
        assert_eq!(
            result
                .evidence
                .iter()
                .filter(|item| item.rule_id == rule)
                .count(),
            count,
            "unexpected count for {rule}"
        );
    }
    assert!(
        !result
            .security_paths
            .iter()
            .any(|path| path.cwe_candidates == ["CWE-89"] || path.cwe_candidates == ["CWE-611"])
    );
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "typescript-insecure-security-randomness"
            && item.location.path == "src/server.ts"
            && item.location.start.line == 231
            && item.cwe_candidates == ["CWE-330"]
    }));
}
