use std::path::PathBuf;

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("apps/javascript")
        .join(name)
}

#[test]
#[ignore = "requires the optional pinned vulnerable/fixed Express branch pair"]
fn locks_the_js3_express_branch_differential() {
    let vulnerable = mehscan_engine::scan_path(corpus("express-vulnerable"))
        .expect("vulnerable branch should scan");
    let fixed =
        mehscan_engine::scan_path(corpus("express-fixed")).expect("fixed branch should scan");

    assert_eq!(
        (vulnerable.evidence.len(), vulnerable.security_paths.len()),
        (12, 3)
    );
    assert_eq!((fixed.evidence.len(), fixed.security_paths.len()), (13, 0));
    assert!(vulnerable.security_paths.iter().any(|path| {
        path.cwe_candidates == ["CWE-89"]
            && path.steps.last().is_some_and(|step| {
                step.location.path == "index.js" && step.location.start.line == 44
            })
    }));
    assert!(
        !fixed
            .security_paths
            .iter()
            .any(|path| path.cwe_candidates == ["CWE-89"])
    );
    assert!(fixed.evidence.iter().any(|item| {
        item.rule_id == "javascript-postgres-parameterization-control"
            && item.location.path == "index.js"
            && item.location.start.line == 40
    }));
    assert!(vulnerable.evidence.iter().any(|item| {
        item.rule_id == "javascript-html-output"
            && item.location.start.line == 39
            && item.tags.iter().any(|tag| tag == "pug-output:raw")
    }));
    assert!(fixed.evidence.iter().any(|item| {
        item.rule_id == "javascript-html-output"
            && item.location.start.line == 33
            && item.tags.iter().any(|tag| tag == "pug-output:escaped")
    }));
    assert_eq!(
        fixed
            .evidence
            .iter()
            .filter(|item| {
                item.rule_id == "javascript-express-response-media-type-control"
                    && item.tags.iter().any(|tag| tag == "text-plain")
            })
            .count(),
        2
    );
}
