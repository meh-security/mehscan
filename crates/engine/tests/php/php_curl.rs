use mehscan_core::{Capability, EvidenceKind};
use std::path::PathBuf;
#[test]
fn curl_urls_keep_actual_same_handle_provenance_and_tls_is_inventory() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/php-curl");
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for symbol in ["curl_input", "curl_selected"] {
        assert!(
            result
                .security_paths
                .iter()
                .any(|path| path.capability == Capability::OutboundNetworkRequest
                    && result.evidence.iter().any(|e| e.id == path.sink_evidence_id
                        && e.enclosing_symbol.as_deref() == Some(symbol))),
            "missing {symbol}"
        );
    }
    for symbol in [
        "curl_unknown_option",
        "curl_unknown_helper",
        "curl_replaced_handle",
        "curl_option_array",
        "other_curl_owner",
        "local_curl",
    ] {
        assert!(
            !result
                .evidence
                .iter()
                .any(|e| e.rule_id == "php-curl-request"
                    && e.enclosing_symbol.as_deref() == Some(symbol)),
            "invalid handle {symbol}"
        );
    }
    assert!(!result.security_paths.iter().any(|path| {
        result.evidence.iter().any(|e| {
            e.id == path.sink_evidence_id
                && e.enclosing_symbol.as_deref() == Some("curl_replaced_url")
        })
    }));
    for symbol in [
        "curl_unchecked_https",
        "curl_checked_https",
        "curl_fixed_http",
        "curl_unused_https",
    ] {
        assert!(
            result
                .evidence
                .iter()
                .any(|e| e.kind == EvidenceKind::SecurityConfiguration
                    && e.capability == Capability::TlsConfiguration
                    && e.enclosing_symbol.as_deref() == Some(symbol)),
            "missing TLS inventory {symbol}"
        );
    }
}
