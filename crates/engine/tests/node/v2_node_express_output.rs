use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/v2-node-express-output")
        .join(name)
}

#[test]
fn pug_output_operators_and_plain_text_responses_bound_html_paths() {
    let raw = mehscan_engine::scan_path(fixture("raw")).expect("raw fixture should scan");
    let escaped =
        mehscan_engine::scan_path(fixture("escaped")).expect("escaped fixture should scan");

    let raw_render = raw
        .evidence
        .iter()
        .find(|item| item.rule_id == "javascript-html-output")
        .expect("raw render sink should remain visible");
    assert!(raw_render.tags.iter().any(|tag| tag == "pug-output:raw"));
    assert!(
        raw.security_paths
            .iter()
            .any(|path| path.cwe_candidates == ["CWE-79"])
    );

    let escaped_render = escaped
        .evidence
        .iter()
        .find(|item| {
            item.rule_id == "javascript-html-output" && item.captures.contains_key("template")
        })
        .expect("escaped render sink should remain visible");
    assert!(
        escaped_render
            .tags
            .iter()
            .any(|tag| tag == "pug-output:escaped")
    );
    assert!(
        !escaped
            .security_paths
            .iter()
            .any(|path| path.cwe_candidates == ["CWE-79"])
    );
    assert!(escaped.evidence.iter().any(|item| {
        item.rule_id == "javascript-express-response-media-type-control"
            && item
                .captures
                .get("media_type")
                .is_some_and(|capture| capture.text == "text/plain")
    }));
    assert!(escaped.evidence.iter().any(|item| {
        item.rule_id == "javascript-http-request-data" && item.location.start.line == 10
    }));
}
