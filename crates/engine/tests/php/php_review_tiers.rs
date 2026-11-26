use mehscan_core::{OperandFactKind, ReviewAdmissionDisposition};
use mehscan_engine::investigation::build_review_inventory;
use std::path::PathBuf;

#[test]
fn narrows_jobs_without_losing_stored_helper_and_code_loading_relationships() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/php-review-tiers");
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let entry = |name: &str| {
        inventory.entries.iter().find(|e| {
            e.symbol.as_deref() == Some(name)
                && matches!(e.rule_id.as_str(), "php-html-output" | "php-file-inclusion")
        })
    };
    for name in [
        "ordinary_layout",
        "fixed_include",
        "replaced_stored_row",
        "different_case",
        "fake_reader",
        "named_slot",
        "unpacked_slot",
    ] {
        assert!(
            entry(name).is_none(),
            "ordinary or unbound occurrence survived: {name}: {:#?}",
            inventory.entries
        );
        let raw = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.enclosing_symbol.as_deref() == Some(name)
                    && matches!(e.rule_id.as_str(), "php-html-output" | "php-file-inclusion")
            })
            .unwrap();
        assert!(
            inventory
                .admission_audit
                .counts
                .iter()
                .any(|c| c.disposition == ReviewAdmissionDisposition::InventoryOnly)
        );
        assert!(
            !inventory
                .admission_audit
                .closed_operands
                .iter()
                .any(|c| c.evidence_id == raw.id),
            "exclusion became a safe verdict"
        );
    }
    for name in [
        "request_near_fixed_include",
        "stored_row",
        "conditional_stored_row",
        "appended_stored_row",
        "render_stored_helper",
        "render_request_helper",
        "render_argument",
        "stored_file",
        "runtime_loader",
        "load_written_code",
        "raw_script",
    ] {
        let item = entry(name).unwrap_or_else(|| {
            panic!(
                "lost consequential research: {name}: {:#?}",
                inventory.entries
            )
        });
        assert_eq!(
            item.value_hint.as_ref().unwrap().reason,
            "php_relationship_research",
            "{name}"
        );
    }
    for name in [
        "stored_row",
        "render_stored_helper",
        "render_request_helper",
        "render_argument",
        "stored_file",
    ] {
        assert!(
            entry(name)
                .unwrap()
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::LocalOperandOrigin),
            "missing navigation: {name}"
        );
    }
    for name in ["raw_request", "request_loader"] {
        assert!(
            entry(name).unwrap().value_hint.is_none(),
            "shown raw input construction left Value: {name}"
        );
    }
    assert!(entry("numeric_request").is_none());
    assert!(
        entry("encoded_request").is_none_or(|e| e.value_hint.is_some()),
        "encoding is not a shown unsafe mechanism"
    );
    for rule in ["php-mysqli-query", "php-command-execution"] {
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.rule_id == rule && e.value_hint.is_none()),
            "lost independent dangerous rule: {rule}"
        );
    }
}
