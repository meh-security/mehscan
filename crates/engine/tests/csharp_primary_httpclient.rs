use std::path::PathBuf;

#[test]
fn primary_constructor_httpclient_is_a_sink_but_shadowed_parameter_is_not() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/csharp-primary-httpclient");
    let scan = mehscan_engine::scan_path(root).expect("fixture should scan");
    let outbound = scan
        .evidence
        .iter()
        .filter(|item| item.rule_id == "csharp-httpclient-outbound-http")
        .collect::<Vec<_>>();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].captures["endpoint"].text, "url");
    assert_eq!(
        outbound[0].enclosing_symbol.as_deref(),
        Some("DownloadAsync")
    );
}
