use mehscan_core::Capability;
use std::path::PathBuf;

#[test]
fn anchored_database_configs_have_bounded_identity_and_evidence() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/php-included-database");
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for symbol in ["included_pdo", "included_mysqli"] {
        let sink = result
            .evidence
            .iter()
            .find(|e| {
                e.capability == Capability::DatabaseQuery
                    && e.enclosing_symbol.as_deref() == Some(symbol)
            })
            .expect(symbol);
        assert_eq!(
            sink.captures["database_receiver_origin"].location.path,
            "config.php"
        );
        assert!(sink.captures["database_include"].text.contains("__DIR__"));
        assert!(
            result
                .security_paths
                .iter()
                .any(|path| path.sink_evidence_id == sink.id),
            "missing relationship {symbol}"
        );
    }
    for symbol in [
        "relative_unknown",
        "dynamic_unknown",
        "conditional_unknown",
        "reassigned_unknown",
        "helper_unknown",
        "additional_include_unknown",
        "replaced_local_origin",
        "sibling_owner",
        "mutating_config",
    ] {
        assert!(
            !result
                .evidence
                .iter()
                .any(|e| e.capability == Capability::DatabaseQuery
                    && e.enclosing_symbol.as_deref() == Some(symbol)),
            "invalid receiver {symbol}"
        );
    }
    assert!(!result.security_paths.iter().any(|path| {
        result.evidence.iter().any(|e| {
            e.id == path.sink_evidence_id && e.enclosing_symbol.as_deref() == Some("included_fixed")
        })
    }));
}
