use std::collections::BTreeSet;
use std::path::PathBuf;

use mehscan_core::Capability;

#[test]
fn inventories_explicit_framework_html_trust_boundaries() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/framework-trusted-html");
    let result = mehscan_engine::scan_path(root).expect("trusted HTML fixture should scan");

    let sinks = result
        .evidence
        .iter()
        .filter(|item| {
            item.capability == Capability::HtmlOutput
                && item.location.path == "positive.tsx"
                && item
                    .tags
                    .iter()
                    .any(|tag| tag == "review-origin:decision-critical")
        })
        .collect::<Vec<_>>();
    let rules = sinks
        .iter()
        .map(|item| item.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "tsx-angular-html-trust-bypass",
        "tsx-lit-unsafe-html-output",
        "tsx-vue-inner-html-output",
        "tsx-solid-inner-html-output",
        "tsx-react-dangerous-html-output",
    ] {
        assert!(rules.contains(expected), "missing {expected}: {rules:#?}");
    }
    assert!(
        sinks
            .iter()
            .all(|item| item.captures.contains_key("content"))
    );
    assert_eq!(
        sinks
            .iter()
            .filter(|item| item.rule_id == "tsx-solid-inner-html-output")
            .count(),
        1,
        "custom-component props are not intrinsic DOM innerHTML sinks"
    );
    assert!(result.evidence.iter().all(|item| {
        item.location.path != "lookalikes.tsx"
            || !matches!(
                item.rule_id.as_str(),
                "tsx-lit-unsafe-html-output"
                    | "tsx-vue-inner-html-output"
                    | "tsx-solid-inner-html-output"
            )
    }));
}
