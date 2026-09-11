use std::collections::BTreeMap;
use std::path::PathBuf;

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript/vuln-nodejs-app")
}

#[test]
#[ignore = "requires the optional pinned vulnerable Node.js corpus"]
fn locks_the_js2_server_and_browser_baseline() {
    let result = mehscan_engine::scan_path(corpus_root()).expect("JS2 corpus should scan");

    assert_eq!(result.coverage.totals.discovered, 83);
    assert_eq!(result.coverage.totals.scanned, 40);
    assert_eq!(result.coverage.totals.ignored, 42);
    assert_eq!(result.coverage.totals.parse_failed, 1);
    assert_eq!(result.evidence.len(), 264);
    assert_eq!(result.security_paths.len(), 47);

    let cwes = result
        .security_paths
        .iter()
        .flat_map(|path| path.cwe_candidates.iter())
        .fold(BTreeMap::new(), |mut counts, cwe| {
            *counts.entry(cwe.as_str()).or_insert(0usize) += 1;
            counts
        });
    for (cwe, expected) in [
        ("CWE-78", 1),
        ("CWE-79", 22),
        ("CWE-89", 6),
        ("CWE-1336", 1),
        ("CWE-200", 1),
        ("CWE-352", 1),
        ("CWE-502", 1),
        ("CWE-611", 1),
        ("CWE-918", 4),
        ("CWE-943", 2),
    ] {
        assert_eq!(cwes.get(cwe), Some(&expected), "unexpected {cwe} count");
    }

    for (line, cwe) in [
        (53, "CWE-78"),
        (83, "CWE-89"),
        (111, "CWE-611"),
        (144, "CWE-502"),
        (167, "CWE-1336"),
        (214, "CWE-918"),
        (536, "CWE-943"),
        (557, "CWE-89"),
        (571, "CWE-89"),
        (580, "CWE-89"),
        (699, "CWE-943"),
    ] {
        assert!(
            result.security_paths.iter().any(|path| {
                path.cwe_candidates == [cwe]
                    && path.steps.last().is_some_and(|step| {
                        step.location.path == "controllers/vuln_controller.js"
                            && step.location.start.line == line
                    })
            }),
            "missing {cwe} at controllers/vuln_controller.js:{line}"
        );
    }

    for (file, line, cwe) in [
        ("views/user-edit.ejs", 40, "CWE-79"),
        ("views/organization.ejs", 75, "CWE-352"),
        ("views/webmessage-api-token-popup.ejs", 5, "CWE-200"),
        ("views/websocket-xss.ejs", 84, "CWE-79"),
        (
            "vuln_react_app/src/MyComponents/React_href_xss.js",
            68,
            "CWE-79",
        ),
        (
            "vuln_react_app/src/MyComponents/React_ref_innerHTML_xss.js",
            36,
            "CWE-79",
        ),
    ] {
        assert!(
            result.security_paths.iter().any(|path| {
                path.cwe_candidates == [cwe]
                    && path.steps.last().is_some_and(|step| {
                        step.location.path == file && step.location.start.line == line
                    })
            }),
            "missing {cwe} at {file}:{line}"
        );
    }
    assert!(result.evidence.iter().any(|item| {
        item.rule_id == "javascript-secure-security-randomness-control"
            && item.location.path == "controllers/auth_controller.js"
            && item.location.start.line == 54
    }));
}
