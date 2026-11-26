use mehscan_core::Capability;
use std::path::PathBuf;

#[test]
fn json_request_fields_require_an_exact_unmutated_same_owner_body() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/php-json-body");
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for (symbol, capability) in [
        ("json_command", Capability::ProcessExecution),
        ("json_html", Capability::HtmlOutput),
        ("json_try_branch", Capability::ProcessExecution),
        ("json_split_body", Capability::ProcessExecution),
        ("json_object_sql", Capability::DatabaseQuery),
        ("json_object_explicit", Capability::HtmlOutput),
    ] {
        assert!(
            result
                .security_paths
                .iter()
                .any(|path| path.capability == capability
                    && result.evidence.iter().any(|e| e.id == path.sink_evidence_id
                        && e.enclosing_symbol.as_deref() == Some(symbol))),
            "missing {symbol}"
        );
    }
    for symbol in [
        "json_replaced",
        "json_field_replaced",
        "json_helper_mutated",
        "json_conditional",
        "json_file",
        "json_object",
        "other_owner",
        "json_reference",
        "lookalike",
        "json_split_replaced",
        "json_split_mutated",
        "json_wrong_object_mode",
        "json_object_field_replaced",
        "json_dynamic_property",
    ] {
        assert!(
            !result.evidence.iter().any(|e| matches!(
                e.rule_id.as_str(),
                "php-http-json-field" | "php-http-json-property"
            ) && e.enclosing_symbol.as_deref() == Some(symbol)),
            "invalid source {symbol}"
        );
    }
    assert!(!result.security_paths.iter().any(|path| {
        result.evidence.iter().any(|e| {
            e.id == path.sink_evidence_id
                && e.enclosing_symbol.as_deref() == Some("json_fixed_command")
        })
    }));
    for symbol in ["json_condition_is_not_data", "json_branch_overwrite"] {
        assert!(
            !result.security_paths.iter().any(|path| result
                .evidence
                .iter()
                .any(|e| e.id == path.sink_evidence_id
                    && e.enclosing_symbol.as_deref() == Some(symbol))),
            "false flow {symbol}"
        );
    }
    assert!(
        result
            .evidence
            .iter()
            .filter(|e| matches!(
                e.rule_id.as_str(),
                "php-http-json-field" | "php-http-json-property"
            ))
            .all(|e| e.captures.contains_key("request_body_producer"))
    );
    assert!(
        result
            .security_paths
            .iter()
            .filter(
                |path| result.evidence.iter().any(|e| e.id == path.sink_evidence_id
                    && e.enclosing_symbol.as_deref() == Some("json_try_branch"))
            )
            .all(|path| path.state != mehscan_core::SecurityPathState::Protected)
    );
}
