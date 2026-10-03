use mehscan_core::{OperandFactKind, SecurityPathState};
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

struct Fixture(PathBuf);
impl Fixture {
    fn new(name: &str, source: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("mehscan-operand-{name}-{}", std::process::id()));
        fs::create_dir_all(path.join("src")).unwrap();
        fs::write(path.join("src/review.php"), source).unwrap();
        fs::write(
            path.join("src/helper.php"),
            "<?php return 'trusted in this checkout';",
        )
        .unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn records_exact_compound_operands_and_keeps_unresolved_security_questions() {
    let fixture = Fixture::new(
        "properties",
        r#"<?php
function dir_include() { require (__DIR__ . '/helper.php'); }
function parent_include() { require __DIR__ . '/../' . 'src/helper.php'; }
function file_include() { require dirname(__FILE__) . '/helper.php'; }
function config_include() { require APP_ROOT . '/helper.php'; }
function underscored_config_include() { require __SITE_ROOT__ . '/helper.php'; }
function missing_include() { require __DIR__ . '/missing.php'; }
function writable_include() { file_put_contents(__DIR__ . '/helper.php', $_POST['code']); require __DIR__ . '/helper.php'; }
function encoded_text($stored) { echo esc_html($stored); }
function encoded_script($stored) { echo htmlspecialchars($stored, ENT_NOQUOTES); }
function stored_output($stored) { echo $stored; }
function unrelated_source($stored) { $search = $_GET['search']; echo $stored; }
"#,
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for symbol in [
        "dir_include",
        "parent_include",
        "file_include",
        "missing_include",
        "writable_include",
    ] {
        let evidence = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.rule_id == "php-file-inclusion" && e.enclosing_symbol.as_deref() == Some(symbol)
            })
            .unwrap();
        let fact = &evidence.context.operand_facts[0];
        assert_eq!(
            fact.kind,
            OperandFactKind::FixedCodeRelativePath,
            "{symbol}"
        );
        assert_eq!(
            fact.value,
            if symbol == "missing_include" {
                "src/missing.php"
            } else {
                "src/helper.php"
            }
        );
        assert!(
            fact.remaining_checks
                .iter()
                .any(|c| c == "target_existence_and_content_trust")
        );
        assert_eq!(fact.location, evidence.captures["path"].location);
        assert!(
            inventory
                .entries
                .iter()
                .any(|entry| entry.symbol.as_deref() == Some(symbol)
                    && entry
                        .operand_facts
                        .iter()
                        .any(|summary| summary.kind == fact.kind && summary.value == fact.value)),
            "fact must survive inventory and admission: {symbol}"
        );
    }
    let config = inventory
        .entries
        .iter()
        .find(|e| e.symbol.as_deref() == Some("config_include"))
        .unwrap();
    assert_eq!(
        config.operand_facts[0].kind,
        OperandFactKind::ConfiguredRootPath
    );
    assert!(inventory.entries.iter().any(|entry| {
        entry.symbol.as_deref() == Some("underscored_config_include")
            && entry
                .operand_facts
                .iter()
                .any(|fact| fact.kind == OperandFactKind::ConfiguredRootPath)
    }));
    assert!(
        inventory
            .scan
            .evidence
            .iter()
            .any(|e| e.enclosing_symbol.as_deref() == Some("config_include")
                && e.context.operand_facts.iter().any(|fact| fact
                    .remaining_checks
                    .iter()
                    .any(|c| c == "root_definition_and_overrides")))
    );
    for symbol in ["encoded_text", "encoded_script"] {
        let evidence = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.rule_id == "php-html-output" && e.enclosing_symbol.as_deref() == Some(symbol)
            })
            .unwrap();
        assert_eq!(
            evidence.context.operand_facts[0].kind,
            OperandFactKind::EncodingCall
        );
        assert!(
            evidence.context.operand_facts[0]
                .remaining_checks
                .iter()
                .any(|c| c == "output_context")
        );
    }
    let stored = inventory
        .entries
        .iter()
        .find(|e| e.symbol.as_deref() == Some("stored_output"))
        .unwrap();
    assert!(stored.operand_facts.is_empty());
    let unrelated = inventory
        .entries
        .iter()
        .find(|e| e.symbol.as_deref() == Some("unrelated_source"))
        .unwrap();
    assert_eq!(unrelated.evidence_strength, "source_sink_cooccurrence");
    let selected = inventory
        .entries
        .iter()
        .filter(|e| !e.operand_facts.is_empty())
        .map(|e| e.review_id.clone())
        .collect::<BTreeSet<_>>();
    let jobs = mehscan_engine::investigation::build_selected_review_jobs(
        &fixture.0, &inventory, &selected, None,
    )
    .unwrap();
    assert_eq!(
        jobs.reviews.len() + jobs.observation_reviews.len(),
        selected.len()
    );
    assert!(
        jobs.observation_reviews
            .iter()
            .flat_map(|r| &r.evidence)
            .any(|e| !e.context.operand_facts.is_empty()),
        "facts reach selected bundles"
    );
}

#[test]
fn encoder_names_do_not_close_overridden_or_script_context_relationships() {
    let fixture = Fixture::new(
        "encoder-contract",
        r#"<?php
function esc_html($value) { return $value; }
function overridden() { echo esc_html($_GET['raw']); }
function script() { ?><script>let value = "<?php echo htmlspecialchars($_GET['raw'], ENT_NOQUOTES); ?>";</script><?php }
"#,
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for symbol in ["overridden", "script"] {
        let evidence = inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.rule_id == "php-html-output" && e.enclosing_symbol.as_deref() == Some(symbol)
            })
            .unwrap();
        assert_eq!(
            evidence.context.operand_facts[0].kind,
            OperandFactKind::EncodingCall
        );
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "hidden: {symbol}"
        );
        for path in inventory
            .scan
            .security_paths
            .iter()
            .filter(|p| p.sink_evidence_id == evidence.id)
        {
            assert_ne!(
                path.state,
                SecurityPathState::Protected,
                "false protection: {symbol}"
            );
        }
    }
}

#[test]
fn refuses_interpolation_streams_root_escape_and_partial_encoding() {
    let fixture = Fixture::new(
        "counterexamples",
        r#"<?php
function interpolated($page) { require __DIR__ . "/$page.php"; }
function request_path() { require __DIR__ . '/' . $_GET['page']; }
function escaped_root() { require __DIR__ . '/../../outside.php'; }
function stream() { require __DIR__ . '/php://input'; }
function redefined_dirname() { require Custom\dirname(__FILE__) . '/helper.php'; }
function changed_suffix() { $suffix = '/helper.php'; $suffix = $_GET['path']; require __DIR__ . $suffix; }
function mixed_output($stored) { echo esc_html($stored) . $_GET['raw']; }
function unknown_wrapper($stored) { echo Custom\esc_html($stored); }
function conditional_output($stored) { echo $_GET['raw'] ? esc_html($stored) : $stored; }
function reflected() { echo $_GET['raw']; }
function php_coercion() { require __DIR__ . ('/helper' . true); }
function php_escaped_string() { require __DIR__ . '/helper\n.php'; }
"#,
    );
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for symbol in [
        "interpolated",
        "request_path",
        "escaped_root",
        "stream",
        "redefined_dirname",
        "changed_suffix",
        "mixed_output",
        "unknown_wrapper",
        "conditional_output",
        "reflected",
        "php_coercion",
        "php_escaped_string",
    ] {
        let anchors = inventory
            .scan
            .evidence
            .iter()
            .filter(|e| {
                matches!(e.rule_id.as_str(), "php-file-inclusion" | "php-html-output")
                    && e.enclosing_symbol.as_deref() == Some(symbol)
            })
            .collect::<Vec<_>>();
        assert!(!anchors.is_empty(), "missing raw observation: {symbol}");
        assert!(
            anchors.iter().all(|e| e.context.operand_facts.is_empty()),
            "unsupported proof: {symbol}"
        );
        assert!(
            inventory
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "candidate hidden: {symbol}"
        );
    }
    for path in &inventory.scan.security_paths {
        if inventory.scan.evidence.iter().any(|e| {
            e.id == path.sink_evidence_id && e.enclosing_symbol.as_deref() == Some("mixed_output")
        }) {
            assert_ne!(path.state, SecurityPathState::Protected);
        }
    }
}
