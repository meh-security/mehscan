use std::path::PathBuf;

use mehscan_core::Capability;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/fixtures/v2-rust-r3")
}

#[test]
fn warp_plain_strings_remain_text_while_explicit_html_builds_a_path() {
    let result = mehscan_engine::scan_path(fixture_root()).expect("Rust R3 fixture should scan");
    assert_eq!(result.coverage.totals.scanned, 2);
    assert_eq!(result.coverage.totals.parse_failed, 0);
    assert_eq!(
        result
            .evidence
            .iter()
            .filter(|item| item.rule_id == "rust-warp-html-output")
            .count(),
        1
    );
    assert_eq!(
        result
            .security_paths
            .iter()
            .filter(|path| path.capability == Capability::HtmlOutput)
            .count(),
        1
    );
    assert!(result.security_paths.iter().all(|path| {
        path.steps
            .iter()
            .all(|step| step.location.path.starts_with("positive/"))
    }));
}
