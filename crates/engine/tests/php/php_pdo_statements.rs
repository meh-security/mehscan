use mehscan_core::{Capability, EvidenceKind, SecurityPathState};
use std::path::PathBuf;
#[test]
fn pdo_execute_values_require_fixed_template_and_verified_statement_owner() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/php-pdo-statements");
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    let binding = result
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "php-pdo-statement-parameters"
                && e.enclosing_symbol.as_deref() == Some("statement_parameters")
        })
        .unwrap();
    assert_eq!(binding.capability, Capability::SqlParameterization);
    assert_eq!(binding.kind, EvidenceKind::Validation);
    assert!(binding.captures["query"].text.contains("WHERE id = ?"));
    assert!(binding.captures["parameters"].text.contains("$_GET"));
    assert!(
        binding.captures["statement_producer"]
            .text
            .contains("prepare")
    );
    for symbol in [
        "statement_interpolated",
        "statement_replaced",
        "statement_helper",
        "statement_unknown",
        "statement_other_owner",
        "statement_conditional",
    ] {
        assert!(
            !result
                .evidence
                .iter()
                .any(|e| e.rule_id == "php-pdo-statement-parameters"
                    && e.enclosing_symbol.as_deref() == Some(symbol)),
            "invalid binding {symbol}"
        );
    }
    assert!(
        result
            .security_paths
            .iter()
            .any(|path| path.capability == Capability::DatabaseQuery
                && path.state != SecurityPathState::Protected
                && result.evidence.iter().any(|e| e.id == path.sink_evidence_id
                    && e.enclosing_symbol.as_deref() == Some("statement_interpolated")))
    );
}
