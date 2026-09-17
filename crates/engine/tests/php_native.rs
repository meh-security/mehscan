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
fn every_declared_php_role_has_executable_evidence_with_its_semantic_capture() {
    use mehscan_core::EvidenceKind;
    let result = scan();
    let handlers = result
        .evidence
        .iter()
        .filter(|e| {
            e.rule_id == "php-pdo-query"
                && e.location.path == "scope.php"
                && e.enclosing_symbol.as_deref() == Some("handler")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        handlers.len(),
        1,
        "Same-named methods must retain distinct receiver owners"
    );
    assert_eq!(
        handlers[0].location.start.line, 16,
        "Only First.handler has a native PDO parameter"
    );
    for (capability, kind, role) in [
        (Capability::HttpRequestData, EvidenceKind::Source, "field"),
        (Capability::DatabaseQuery, EvidenceKind::Sink, "query"),
        (
            Capability::SqlParameterization,
            EvidenceKind::Validation,
            "query",
        ),
        (Capability::ProcessExecution, EvidenceKind::Sink, "command"),
        (
            Capability::ProcessArgumentSeparation,
            EvidenceKind::Validation,
            "value",
        ),
        (Capability::DynamicCodeExecution, EvidenceKind::Sink, "code"),
        (Capability::FilesystemRead, EvidenceKind::Sink, "path"),
        (Capability::FilesystemWrite, EvidenceKind::Sink, "path"),
        (
            Capability::PathCanonicalization,
            EvidenceKind::Validation,
            "path",
        ),
        (
            Capability::OutboundNetworkRequest,
            EvidenceKind::Sink,
            "endpoint",
        ),
        (Capability::UrlParsing, EvidenceKind::Validation, "value"),
        (Capability::Redirect, EvidenceKind::Sink, "location"),
        (Capability::HtmlOutput, EvidenceKind::Sink, "content"),
        (Capability::HtmlEncoding, EvidenceKind::Sanitizer, "value"),
        (Capability::Deserialization, EvidenceKind::Sink, "payload"),
        (
            Capability::CryptographicHash,
            EvidenceKind::SecurityConfiguration,
            "algorithm",
        ),
        (Capability::FileUpload, EvidenceKind::Sink, "path"),
        (
            Capability::TlsConfiguration,
            EvidenceKind::SecurityConfiguration,
            "value",
        ),
    ] {
        assert!(
            result.evidence.iter().any(|e| e.capability == capability
                && e.kind == kind
                && e.captures.contains_key(role)),
            "Missing executable {capability:?}/{kind:?}/{role} evidence"
        );
    }
    let catalog = mehscan_engine::rules::load_builtin_rules().unwrap();
    let declared = catalog
        .iter()
        .filter(|r| r.language == Language::Php)
        .flat_map(|r| r.cwe.iter())
        .collect::<std::collections::BTreeSet<_>>();
    let observed = result
        .evidence
        .iter()
        .filter(|e| e.rule_id.starts_with("php-"))
        .flat_map(|e| e.cwe_candidates.iter())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        declared, observed,
        "Every PHP CWE declaration needs an executable fixture anchor"
    );
}

#[test]
fn php_stream_and_hash_parity_preserves_safe_purpose_and_control_limits() {
    let result = scan();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for symbol in [
        "stream_request",
        "stream_alias",
        "imported_stream",
        "parsed_is_not_allowed",
        "unrelated_url_parse",
    ] {
        assert!(
            sink_paths(&result, symbol, Capability::OutboundNetworkRequest) > 0,
            "{symbol}"
        );
    }
    assert_eq!(
        sink_paths(
            &result,
            "fixed_stream_path",
            Capability::OutboundNetworkRequest
        ),
        0
    );
    for (symbol, rule) in [
        ("local_stream", "php-url-stream-read"),
        ("local_parse", "php-url-parsing"),
        ("local_digest", "php-weak-hash-selection"),
        ("strong_password", "php-weak-hash-selection"),
    ] {
        assert!(
            !result
                .evidence
                .iter()
                .any(|e| e.rule_id == rule && e.enclosing_symbol.as_deref() == Some(symbol)),
            "{symbol}"
        );
    }
    // Non-security MD5 stays inventory; catalog presence is not a verdict.
    for symbol in [
        "weak_password",
        "weak_sha1",
        "checksum_only",
        "imported_digest",
    ] {
        let hash = result
            .evidence
            .iter()
            .find(|e| {
                e.rule_id == "php-weak-hash-selection"
                    && e.enclosing_symbol.as_deref() == Some(symbol)
            })
            .expect(symbol);
        assert!(hash.captures.contains_key("algorithm"));
        assert!(hash.captures.contains_key("value"));
    }
    for path in &result.security_paths {
        if path.capability == Capability::OutboundNetworkRequest
            && result.evidence.iter().any(|e| {
                e.id == path.sink_evidence_id
                    && matches!(
                        e.enclosing_symbol.as_deref(),
                        Some("parsed_is_not_allowed" | "unrelated_url_parse")
                    )
            })
        {
            assert_ne!(
                path.state,
                SecurityPathState::Protected,
                "Parsing is not destination authorization"
            );
        }
    }
}

#[test]
fn php_stream_review_supplies_wrapper_configuration_without_claiming_protection() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/v2-php-native");
    let jobs =
        mehscan_engine::investigation::build_all_path_review_jobs(&root, None, true).unwrap();
    let review = jobs
        .reviews
        .iter()
        .find(|review| {
            review.candidate.sink.enclosing_symbol.as_deref() == Some("stream_request")
                && review.candidate.capability == Capability::OutboundNetworkRequest
        })
        .expect("stream request review");
    assert!(
        review
            .facts
            .iter()
            .any(|fact| fact.role == "configuration_context"
                && fact.location.path == "php.ini"
                && fact.excerpt.contains("allow_url_fopen = On"))
    );
    assert_ne!(review.candidate.state, SecurityPathState::Protected);
    assert!(review.review_basis.is_some());
    assert_eq!(review.language, Some(Language::Php));
}

#[test]
fn php_inclusion_upload_and_redirect_boundaries_keep_argument_roles() {
    let result = scan();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for (symbol, rule, capture) in [
        ("unsafe_include", "php-file-inclusion", "path"),
        ("unsafe_require", "php-file-inclusion", "path"),
        ("unsafe_upload_move", "php-upload-move", "path"),
        ("unsafe_redirect", "php-header-redirect", "location"),
    ] {
        let evidence = result
            .evidence
            .iter()
            .find(|e| e.rule_id == rule && e.enclosing_symbol.as_deref() == Some(symbol))
            .expect(symbol);
        assert!(evidence.captures.contains_key(capture), "{symbol}");
    }
    for (symbol, rule) in [
        ("unrelated_header", "php-header-redirect"),
        ("misleading_header", "php-header-redirect"),
        ("redirect_lookalike", "php-header-redirect"),
        ("upload_lookalike", "php-upload-move"),
    ] {
        assert!(
            !result
                .evidence
                .iter()
                .any(|e| e.rule_id == rule && e.enclosing_symbol.as_deref() == Some(symbol)),
            "{symbol}"
        );
    }
    assert_eq!(
        sink_paths(&result, "fixed_include", Capability::FilesystemRead),
        0
    );
    assert_eq!(
        sink_paths(&result, "fixed_redirect", Capability::Redirect),
        0
    );
    let upload = result
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "php-upload-move"
                && e.enclosing_symbol.as_deref() == Some("unsafe_upload_move")
        })
        .unwrap();
    assert!(upload.captures["path"].text.contains("name"));
    assert!(!upload.captures["path"].text.contains("tmp_name"));
}

#[test]
fn php_native_boundaries_preserve_identity_scope_and_safe_alternatives() {
    let result = scan();
    assert_eq!(
        result.coverage.totals.parse_failed, 0,
        "{:?}",
        result.diagnostics
    );
    assert_eq!(result.coverage.languages[&Language::Php].scanned, 6);
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
        "mysqli_method_input",
        "mysqli_method_constructed",
        "mysqli_method_imported",
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
        "mysqli_method_bound",
        "mysqli_method_replaced",
        "mysqli_method_helper",
        "mysqli_method_conditional",
        "mysqli_method_unknown",
        "mysqli_method_lookalike",
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
    assert_eq!(
        sink_paths(&result, "bound_safe", Capability::DatabaseQuery),
        1,
        "Bound data should retain its explicitly protected relationship"
    );
    assert!(
        result
            .security_paths
            .iter()
            .filter(
                |path| result.evidence.iter().any(|e| e.id == path.sink_evidence_id
                    && e.enclosing_symbol.as_deref() == Some("bound_safe"))
            )
            .all(|path| path.state == SecurityPathState::Protected)
    );
    let binding = result
        .evidence
        .iter()
        .find(|e| {
            e.rule_id == "php-mysqli-parameterization"
                && e.enclosing_symbol.as_deref() == Some("bound_safe")
        })
        .expect("binding evidence");
    assert_eq!(binding.context.literals["query"].state, LiteralState::Known);
    assert!(binding.captures["parameters"].text.contains("$_GET"));
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
            && [
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
