use mehscan_core::Capability;
use std::path::PathBuf;
#[test]
fn php_append_and_print_preserve_actual_output_data() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/php-output-handoffs");
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for symbol in ["accumulated_html", "printed_html"] {
        assert!(
            result
                .security_paths
                .iter()
                .any(|path| path.capability == Capability::HtmlOutput
                    && result.evidence.iter().any(|e| e.id == path.sink_evidence_id
                        && e.enclosing_symbol.as_deref() == Some(symbol))),
            "missing {symbol}"
        );
    }
    for symbol in [
        "overwritten_html",
        "numeric_not_text",
        "fixed_output",
        "helper_replaces_output",
        "helper_in_append_replaces_output",
        "reference_replaces_output",
    ] {
        assert!(
            !result.security_paths.iter().any(|path| result
                .evidence
                .iter()
                .any(|e| e.id == path.sink_evidence_id
                    && e.enclosing_symbol.as_deref() == Some(symbol))),
            "false output flow {symbol}"
        );
    }
}
