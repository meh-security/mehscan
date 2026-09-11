use std::collections::BTreeMap;
use std::path::PathBuf;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript/nodegoat")
}

#[test]
#[ignore = "requires the optional pinned NodeGoat corpus"]
fn locks_the_adjudicated_nodegoat_javascript_baseline() {
    let result = mehscan_engine::scan_path(corpus_root()).expect("NodeGoat should scan");

    assert_eq!(result.coverage.totals.discovered, 96);
    assert_eq!(result.coverage.totals.scanned, 27);
    assert_eq!(result.coverage.totals.ignored, 69);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(result.evidence.len(), 97);
    assert_eq!(result.security_paths.len(), 15);

    let cwes = result
        .security_paths
        .iter()
        .flat_map(|path| path.cwe_candidates.iter())
        .fold(BTreeMap::new(), |mut counts, cwe| {
            *counts.entry(cwe.as_str()).or_insert(0usize) += 1;
            counts
        });
    assert_eq!(cwes.get("CWE-94"), Some(&3));
    assert_eq!(cwes.get("CWE-601"), Some(&1));
    assert_eq!(cwes.get("CWE-918"), Some(&2));
    assert_eq!(cwes.get("CWE-639"), Some(&2));
    assert_eq!(cwes.get("CWE-916"), Some(&1));
    assert_eq!(cwes.get("CWE-943"), Some(&1));
    assert_eq!(cwes.get("CWE-79"), Some(&4));
    assert_eq!(cwes.get("CWE-117"), Some(&1));

    for (file, line, cwe) in [
        ("app/routes/allocations.js", 23, "CWE-639"),
        ("app/routes/allocations.js", 23, "CWE-943"),
        ("app/routes/benefits.js", 35, "CWE-639"),
        ("app/routes/session.js", 220, "CWE-916"),
    ] {
        assert!(
            result.security_paths.iter().any(|path| {
                path.cwe_candidates == [cwe]
                    && path.steps.last().is_some_and(|step| {
                        step.location.path == file && step.location.start.line == line
                    })
            }),
            "missing {cwe} path at {file}:{line}"
        );
    }

    for (file, line) in [
        ("app/routes/profile.js", 33),
        ("app/routes/memos.js", 27),
        ("app/routes/session.js", 269),
        ("app/routes/contributions.js", 21),
    ] {
        assert!(
            result.security_paths.iter().any(|path| {
                path.cwe_candidates == ["CWE-79"]
                    && path.steps.last().is_some_and(|step| {
                        step.location.path == file && step.location.start.line == line
                    })
            }),
            "missing stored-content candidate at {file}:{line}"
        );
    }

    for rule_id in [
        "javascript-login-session-fixation-risk",
        "javascript-weak-password-policy",
        "javascript-session-cookie-policy-review",
        "javascript-cookie-session-csrf-review",
        "javascript-credential-response-enumeration-risk",
        "javascript-sensitive-record-persistence-risk",
        "javascript-http-listener-deployment-review",
    ] {
        assert!(
            result.evidence.iter().any(|item| item.rule_id == rule_id),
            "missing request-boundary evidence {rule_id}"
        );
    }
    let benefits = result
        .evidence
        .iter()
        .find(|item| {
            item.location.path == "app/routes/benefits.js"
                && item.location.start.line == 35
                && item.cwe_candidates == ["CWE-639"]
        })
        .expect("benefits resource evidence");
    assert!(benefits.tags.iter().any(|tag| tag == "role-policy-review"));
    assert_eq!(
        benefits.captures["authorization_boundary"].text,
        "POST /benefits guards=[isLoggedIn]"
    );
}
