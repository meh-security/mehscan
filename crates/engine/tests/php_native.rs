use std::path::PathBuf;

use mehscan_core::{Capability, Language, LiteralState, ScanResult, SecurityPathState};

fn scan() -> ScanResult {
    mehscan_engine::scan_path(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-php-native"),
    )
    .expect("PHP fixture should scan")
}

#[test]
fn php_review_outline_extracts_function_identity_from_mixed_grammar() {
    let encoded = serde_yaml::to_string(&ast_grep_language::SupportLang::PhpMixed).unwrap();
    assert_eq!(
        serde_yaml::from_str::<ast_grep_language::SupportLang>(&encoded).unwrap(),
        ast_grep_language::SupportLang::PhpMixed
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-php-native");
    let outline = mehscan_engine::investigation::get_file_outline(&root, "app.php")
        .expect("PHP outline should load");
    assert_eq!(outline.results.language, Language::Php);
    assert!(
        outline
            .results
            .symbols
            .iter()
            .any(|s| s.name == "direct_command")
    );
}

#[test]
fn php_file_policy_excludes_tests_generated_files_and_vendor() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-php-policy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join("vendor")).unwrap();
    let source = "<?php shell_exec($_GET['command']);";
    for path in [
        "app.php",
        "page.phtml",
        "LoginTest.php",
        "view.generated.php",
        "vendor/library.php",
    ] {
        std::fs::write(root.join(path), source).unwrap();
    }
    let normal = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(normal.coverage.languages[&Language::Php].scanned, 2);
    assert!(
        normal
            .coverage
            .ignored_subtrees
            .iter()
            .any(|p| p == "vendor/")
    );
    let included = mehscan_engine::scan_path_with_options(
        &root,
        mehscan_engine::ScanOptions {
            include_tests: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(included.coverage.languages[&Language::Php].scanned, 4);
    std::fs::remove_dir_all(&root).unwrap();
}

fn sink_paths(result: &ScanResult, symbol: &str, capability: Capability) -> usize {
    result
        .security_paths
        .iter()
        .filter(|path| {
            path.capability == capability
                && result.evidence.iter().any(|item| {
                    item.id == path.sink_evidence_id
                        && item.enclosing_symbol.as_deref() == Some(symbol)
                })
        })
        .count()
}

#[test]
fn php_native_boundaries_preserve_identity_scope_and_safe_alternatives() {
    let result = scan();
    assert_eq!(
        result.coverage.totals.parse_failed, 0,
        "{:?}",
        result.diagnostics
    );
    assert_eq!(result.coverage.languages[&Language::Php].scanned, 5);
    for symbol in [
        "direct_command",
        "alias_command",
        "global_api",
        "imported_api",
        "mixed_controls",
    ] {
        assert!(
            sink_paths(&result, symbol, Capability::ProcessExecution) > 0,
            "missing {symbol}"
        );
    }
    for symbol in [
        "interpolated_sql",
        "unsafe_prepare",
        "mysqli_sql",
        "visible_database",
        "imported_database",
        "unsafe_execute_query",
    ] {
        assert!(
            sink_paths(&result, symbol, Capability::DatabaseQuery) > 0,
            "missing {symbol}"
        );
    }
    for symbol in [
        "local_lookalike",
        "variable_callable",
        "alias_does_not_leak",
        "fallback_unknown",
        "named_argument_unknown",
        "unpacked_arguments_unknown",
        "inline_helper_unknown",
    ] {
        assert_eq!(
            sink_paths(&result, symbol, Capability::ProcessExecution),
            0,
            "lookalike {symbol}"
        );
    }
    for symbol in [
        "local_database",
        "unknown_receiver",
        "other_function_database",
        "replaced_database",
        "sibling_database",
        "helper_may_replace_receiver",
        "qualified_global_lookalike",
        "imported_global_lookalike",
        "prepared_safe",
    ] {
        assert_eq!(
            sink_paths(&result, symbol, Capability::DatabaseQuery),
            0,
            "unsafe admission {symbol}"
        );
    }
    assert_eq!(
        sink_paths(&result, "reassigned_safe", Capability::HtmlOutput),
        0
    );
    assert_eq!(
        sink_paths(&result, "literal_safe", Capability::HtmlOutput),
        0
    );
    assert_eq!(
        sink_paths(&result, "no_call_graph", Capability::HtmlOutput),
        0
    );
    assert!(sink_paths(&result, "reflected_html", Capability::HtmlOutput) > 0);
    assert!(sink_paths(&result, "uppercase_output", Capability::HtmlOutput) > 0);
    for path in &result.security_paths {
        if result.evidence.iter().any(|e| {
            e.id == path.sink_evidence_id && e.enclosing_symbol.as_deref() == Some("bound_safe")
        }) {
            assert_eq!(
                path.state,
                SecurityPathState::Protected,
                "safe bound query: {path:?}"
            );
        }
    }
    for (symbol, state) in [
        ("interpolated_sql", LiteralState::Partial),
        ("prepared_safe", LiteralState::Known),
    ] {
        let query = result
            .evidence
            .iter()
            .find(|e| e.rule_id == "php-pdo-query" && e.enclosing_symbol.as_deref() == Some(symbol))
            .expect("query evidence");
        assert_eq!(query.context.literals["query"].state, state, "{symbol}");
    }
    assert!(
        result
            .evidence
            .iter()
            .any(|e| e.rule_id == "php-html-encoding")
    );
    for path in &result.security_paths {
        if let Some(sink) = result
            .evidence
            .iter()
            .find(|e| e.id == path.sink_evidence_id)
        {
            if [
                "script_encoding_is_not_protection",
                "unrelated_control",
                "branch_only_control",
                "mixed_controls",
                "quoting_is_not_executable_authorization",
                "normalization_is_not_containment",
            ]
            .contains(&sink.enclosing_symbol.as_deref().unwrap_or_default())
            {
                assert_ne!(
                    path.state,
                    SecurityPathState::Protected,
                    "borrowed control: {:?}",
                    sink
                );
            }
        }
    }
    assert!(
        result
            .security_paths
            .iter()
            .any(|p| p.capability == Capability::Deserialization)
    );
    assert!(
        result
            .security_paths
            .iter()
            .any(|p| p.capability == Capability::DynamicCodeExecution)
    );
    assert!(sink_paths(&result, "native_eval", Capability::DynamicCodeExecution) > 0);
    assert_eq!(
        sink_paths(
            &result,
            "qualified_eval_lookalike",
            Capability::DynamicCodeExecution
        ),
        0
    );
    let again = scan();
    assert_eq!(result.evidence, again.evidence);
    assert_eq!(result.security_paths, again.security_paths);
}
