use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language,
    LiteralValue, Location, Position, Provenance, RelationContract, Resolution, SecurityPath,
    SymbolConfidence, SymbolResolution, ValueTransform,
};

use crate::rules::CompiledRule;
use crate::secrets::SecretAllowlist;

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::csharp_handoff::CsharpHandoffProjectContext;
use super::csharp_model::CsharpModelProjectContext;
use super::csharp_rpc::CsharpRpcProjectContext;
use super::dotnet_project::DotnetProjectContext;
use super::literals::LiteralEnvironment;
use super::node_context::NodeProjectContext;
use super::object_input::ObjectInputProjectContext;
use super::reachability;
use super::symbols::{FileSymbolEnvironment, ProjectSymbolEnvironment};

pub(crate) enum ParseOutcome {
    Parsed {
        evidence: Vec<Evidence>,
        security_paths: Vec<SecurityPath>,
        secret_suppressed: usize,
        timing: FileScanTiming,
    },
    Failed {
        reason: String,
        evidence: Vec<Evidence>,
        secret_suppressed: usize,
        timing: FileScanTiming,
    },
    Recovered {
        reason: String,
        evidence: Vec<Evidence>,
        security_paths: Vec<SecurityPath>,
        secret_suppressed: usize,
        timing: FileScanTiming,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FileScanTiming {
    pub parse_context_microseconds: u128,
    pub declarative_rules_microseconds: u128,
    pub symbol_rules_microseconds: u128,
    pub summaries_microseconds: u128,
    pub security_paths_microseconds: u128,
    pub declarative_patterns_considered: usize,
    pub declarative_patterns_skipped: usize,
}

pub(crate) struct ScanDependencies<'a> {
    pub project_symbols: &'a ProjectSymbolEnvironment,
    pub secret_allowlist: &'a SecretAllowlist,
    pub scan_secrets: bool,
    pub include_nonproduction: bool,
    pub relations: &'a [RelationContract],
    pub node_context: &'a NodeProjectContext,
    pub object_input_context: &'a ObjectInputProjectContext,
    pub csharp_model_context: &'a CsharpModelProjectContext,
    pub csharp_handoff_context: &'a CsharpHandoffProjectContext,
    pub csharp_rpc_context: &'a CsharpRpcProjectContext,
    pub java_project_context: &'a super::java_context::JavaProjectContext,
    pub go_project_context: &'a super::go_context::GoProjectContext,
    pub drogon_project_context: &'a super::native_drogon::DrogonProjectContext,
    pub native_invalidation_context:
        &'a super::native_invalidation::NativeInvalidationProjectContext,
    pub python_project_context: &'a super::python_context::PythonProjectContext,
    pub rust_project_context: &'a super::rust_project::RustProjectContext,
    pub php_project_context: &'a super::php::PhpProjectContext,
    pub dotnet_project_context: &'a DotnetProjectContext,
    pub build_symbols: &'a BTreeMap<String, bool>,
}

pub(crate) fn scan_source(
    path: &str,
    source: &str,
    parser_language: SupportLang,
    language: Language,
    rules: &[CompiledRule],
    dependencies: ScanDependencies<'_>,
) -> ParseOutcome {
    let parse_started = Instant::now();
    // tree-sitter-javascript accepts most JSX in .js files, but JSX fragments
    // are represented by the TSX grammar. Keep the reported language as
    // JavaScript while selecting the recovery parser for this exact syntax.
    let parser_language = if language == Language::Javascript
        && parser_language == SupportLang::JavaScript
        && source.contains("<>")
        && source.contains("</>")
    {
        SupportLang::Tsx
    } else {
        parser_language
    };
    let ScanDependencies {
        project_symbols,
        secret_allowlist,
        scan_secrets,
        include_nonproduction,
        relations,
        node_context,
        object_input_context,
        csharp_model_context,
        csharp_handoff_context,
        csharp_rpc_context,
        java_project_context,
        go_project_context,
        drogon_project_context,
        native_invalidation_context,
        python_project_context,
        rust_project_context,
        php_project_context,
        dotnet_project_context,
        build_symbols,
    } = dependencies;
    let document = match StrDoc::try_new(source, parser_language) {
        Ok(document) => document,
        Err(error) => {
            let (secret_evidence, secret_suppressed) = scan_secrets_if_enabled(
                scan_secrets,
                path,
                source,
                &CommentRanges::default(),
                secret_allowlist,
            );
            return ParseOutcome::Failed {
                reason: error,
                evidence: secret_evidence,
                secret_suppressed,
                timing: FileScanTiming {
                    parse_context_microseconds: parse_started.elapsed().as_micros(),
                    ..FileScanTiming::default()
                },
            };
        }
    };
    let ast = AstGrep::doc(document);
    let root = ast.root();
    let kotlin_imports =
        (language == Language::Kotlin).then(|| super::kotlin::Imports::build(&root));
    let comments = CommentRanges::from_root(&root);
    let (secret_evidence, secret_suppressed) =
        scan_secrets_if_enabled(scan_secrets, path, source, &comments, secret_allowlist);
    let parse_issue_ranges = root
        .dfs()
        .filter(|node| node.is_error() || node.is_missing())
        .map(|node| node.range())
        .collect::<Vec<_>>();
    let conditional = ConditionalRegions::from_source(language, source, build_symbols);
    let literals = LiteralEnvironment::build(&root, language);
    let symbol_environment =
        FileSymbolEnvironment::build(path, &root, language, source, project_symbols);
    let parse_context_microseconds = parse_started.elapsed().as_micros();

    let mut evidence = Vec::new();
    let php_context = (language == Language::Php)
        .then(|| super::php::PhpContext::build(&root).with_project(path, php_project_context));
    let mut seen = BTreeSet::new();
    let declarative_started = Instant::now();
    let mut declarative_patterns_considered = 0;
    let mut declarative_patterns_skipped = 0;
    for compiled_rule in rules {
        for compiled_pattern in &compiled_rule.patterns {
            declarative_patterns_considered += 1;
            // PHP keywords and function names are case-insensitive. The AST
            // matcher remains authoritative; a case-sensitive text prefilter
            // must not discard a valid PHP match.
            if language != Language::Php
                && compiled_pattern
                    .required_source_text
                    .as_ref()
                    .is_some_and(|required| !source.contains(required))
            {
                declarative_patterns_skipped += 1;
                continue;
            }
            for matched in root.find_all(&compiled_pattern.pattern) {
                let range = matched.range();
                if comments.is_in_comment(range.clone()) {
                    continue;
                }
                if super::extended_database::is_rule(&compiled_rule.rule.id)
                    && language != Language::Kotlin
                    && language != Language::Php
                    && !super::extended_database::accepts(
                        &root,
                        matched.get_node(),
                        &compiled_rule.rule.id,
                        language,
                        matched.get_env().get_match("DATABASE"),
                        matched.get_env().get_match("TYPE"),
                    )
                {
                    continue;
                }
                if super::extended_boundaries::is_rule(&compiled_rule.rule.id)
                    && !super::extended_boundaries::accepts(
                        &root,
                        matched.get_node(),
                        &compiled_rule.rule.id,
                        language,
                        matched.get_env().get_match("BOUNDARY"),
                    )
                {
                    continue;
                }
                if php_context.as_ref().is_some_and(|context| {
                    !context.accepts(&compiled_rule.rule.id, matched.get_node())
                }) {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-axum-request-extractor"
                    && !matched
                        .get_env()
                        .get_match("EXTRACTOR")
                        .is_some_and(|extractor| {
                            super::rust_context::is_exact_axum_extractor(
                                &root,
                                extractor.text().trim(),
                            )
                        })
                {
                    continue;
                }
                if matches!(
                    compiled_rule.rule.id.as_str(),
                    "javascript-database-query"
                        | "typescript-database-query"
                        | "tsx-database-query"
                        | "python-database-query"
                ) {
                    let receiver = matched.get_env().get_match("DATABASE");
                    if receiver.is_some_and(|receiver| {
                        !super::database_receiver::accepts(&root, receiver, language)
                    }) {
                        continue;
                    }
                }
                if language == Language::Java
                    && compiled_rule.rule.id == "java-database-query"
                    && matched.get_node().field("name").is_some_and(|n| {
                        matches!(
                            n.text().as_ref(),
                            "execute" | "executeLargeUpdate" | "addBatch"
                        )
                    })
                    && !super::java_persistence::jdbc_statement_receiver(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-database-query"
                    && !super::rust_context::is_exact_database_query(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-file-content-input"
                    && !super::rust_context::is_exact_file_input(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-iron-request-data"
                    && !super::rust_context::is_exact_iron_request_access(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-outbound-http"
                    && !super::rust_context::is_exact_reqwest_request(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-iron-response-body"
                    && !super::rust_context::is_exact_iron_response(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-ammonia-html-sanitization"
                    && !super::rust_context::is_exact_ammonia_clean(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-permissive-cors-review"
                    && !super::rust_context::is_exact_permissive_cors(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-actix-html-output"
                    && !super::rust_context::is_exact_actix_html_response(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-file-log-write"
                    && !super::rust_context::is_exact_file_log_write(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-process-execution"
                    && !super::rust_context::is_exact_process_execution(&root, matched.get_node())
                {
                    continue;
                }
                if language == Language::Rust
                    && matches!(
                        compiled_rule.rule.id.as_str(),
                        "rust-process-argument-separation"
                            | "rust-url-parsing"
                            | "rust-reqwest-tls-verification"
                    )
                    && !super::rust_context::is_exact_review_control(
                        &root,
                        matched.get_node(),
                        &compiled_rule.rule.id,
                    )
                {
                    continue;
                }
                if language == Language::Rust
                    && matches!(
                        compiled_rule.rule.id.as_str(),
                        "rust-unsafe-boundary" | "rust-native-interop-boundary"
                    )
                    && !super::rust_context::is_reviewable_safety_boundary(
                        matched.get_node(),
                        include_nonproduction,
                    )
                {
                    continue;
                }
                if language == Language::Rust
                    && compiled_rule.rule.id == "rust-sql-parameterization"
                    && !matched.get_env().get_match("QUERY").is_some_and(|query| {
                        super::rust_context::is_effective_sql_parameterization(
                            &root,
                            matched.get_node(),
                            query.text().as_ref(),
                        )
                    })
                {
                    continue;
                }
                if language == Language::Go
                    && matches!(
                        compiled_rule.rule.id.as_str(),
                        "go-database-query" | "go-sql-parameterization"
                    )
                    && super::go_context::is_known_process_exec(matched.get_node())
                {
                    continue;
                }
                if language == Language::Go
                    && matches!(
                        compiled_rule.rule.id.as_str(),
                        "go-database-query" | "go-sql-parameterization"
                    )
                    && matched.get_env().get_match("DB").is_some_and(|receiver| {
                        super::extended_database::pgx_receiver(&root, matched.get_node(), receiver)
                    })
                {
                    continue;
                }
                if language == Language::Csharp
                    && !compiled_rule.rule.symbols.is_empty()
                    && !call_site(matched.get_node().clone()).is_some_and(|call| {
                        call.node.kind().as_ref() == "object_creation_expression"
                            || (call.observed.contains('.')
                                && !symbol_environment.has_declared_receiver(&call.observed))
                            || compiled_rule.rule.symbols.iter().any(|symbol| {
                                symbol_environment
                                    .resolve(&call.observed, &symbol.canonical)
                                    .is_some_and(|resolution| {
                                        resolution.confidence != SymbolConfidence::Ambiguous
                                    })
                            })
                    })
                {
                    continue;
                }
                if !compiled_rule.rule.symbols.is_empty()
                    && call_site(matched.get_node().clone()).is_some_and(|call| {
                        symbol_environment.has_shadowing_parameter(
                            &call.node,
                            &call.observed,
                            language,
                        )
                    })
                {
                    continue;
                }
                let deduplication_key = (compiled_rule.rule.id.clone(), range.start, range.end);
                if !super::extended_boundaries::is_rule(&compiled_rule.rule.id)
                    && kotlin_imports.as_ref().is_some_and(|imports| {
                        !super::kotlin::accept(
                            &root,
                            imports,
                            &compiled_rule.rule.id,
                            matched.get_node(),
                        )
                    })
                {
                    continue;
                }
                if !seen.insert(deduplication_key) {
                    continue;
                }
                let evidence_location = location(path, matched.get_node());
                let mut captures = BTreeMap::new();
                let mut literal_values = BTreeMap::new();
                for (semantic_name, variable_name) in &compiled_pattern.specification.captures {
                    let captured =
                        matched
                            .get_env()
                            .get_match(variable_name)
                            .cloned()
                            .or_else(|| {
                                matched
                                    .get_env()
                                    .get_multiple_matches(variable_name)
                                    .into_iter()
                                    .next()
                            });
                    if let Some(node) = captured {
                        literal_values.insert(semantic_name.clone(), literals.evaluate(&node));
                        captures.insert(
                            semantic_name.clone(),
                            Capture {
                                text: node.text().into_owned(),
                                location: location(path, &node),
                            },
                        );
                    }
                }
                if let Some(context) = &php_context {
                    captures.extend(context.supplemental_captures(
                        &compiled_rule.rule.id,
                        matched.get_node(),
                        path,
                    ));
                }
                if (compiled_rule.rule.id.ends_with("extended-nosql-command")
                    || compiled_rule.rule.id.ends_with("extended-nosql-request"))
                    && let Some(query) = matched.get_env().get_match("QUERY")
                {
                    let operands = super::extended_database::dynamodb_operands(query);
                    if operands.is_empty() {
                        continue;
                    }
                    captures.remove("nosql_query");
                    literal_values.remove("nosql_query");
                    for (role, operand) in ["nosql_query", "nosql_expression"]
                        .into_iter()
                        .zip(operands)
                    {
                        captures.insert(
                            role.into(),
                            Capture {
                                text: operand.text().into_owned(),
                                location: location(path, &operand),
                            },
                        );
                        literal_values.insert(role.into(), literals.evaluate(&operand));
                    }
                }
                if language == Language::Kotlin
                    && compiled_rule.rule.id == "kotlin-process-builder"
                    && let Some(command) = super::kotlin::process_command(&root, matched.get_node())
                {
                    literal_values.insert("command".into(), literals.evaluate(&command));
                    captures.insert(
                        "command".into(),
                        Capture {
                            text: command.text().into_owned(),
                            location: location(path, &command),
                        },
                    );
                }
                if language == Language::Kotlin
                    && compiled_rule.rule.id == "kotlin-file-write"
                    && let Some(content) = super::kotlin::file_content(matched.get_node())
                {
                    literal_values.insert("content".into(), literals.evaluate(&content));
                    captures.insert(
                        "content".into(),
                        Capture {
                            text: content.text().into_owned(),
                            location: location(path, &content),
                        },
                    );
                }
                evidence.push(Evidence {
                    id: evidence_id(path, &compiled_rule.rule.id, range.start, range.end),
                    kind: compiled_rule.rule.kind,
                    capability: compiled_rule.rule.capability,
                    location: evidence_location,
                    enclosing_symbol: enclosing_symbol(matched.get_node()),
                    captures,
                    cwe_candidates: compiled_rule.rule.cwe.clone(),
                    tags: compiled_rule.rule.tags.clone(),
                    confidence: compiled_rule.rule.confidence,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "ast-grep 0.45.1".to_string(),
                        rule_version: compiled_rule.rule.version,
                    },
                    context: evidence_context(
                        matched.get_node(),
                        &comments,
                        &conditional,
                        &literals,
                        literal_values,
                    ),
                    symbol_resolution: None,
                    rule_id: compiled_rule.rule.id.clone(),
                    related_evidence: Vec::new(),
                });
            }
        }
    }
    let declarative_rules_microseconds = declarative_started.elapsed().as_micros();

    let symbol_started = Instant::now();
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        if symbol_environment.has_shadowing_parameter(&call.node, &call.observed, language) {
            continue;
        }
        for compiled_rule in rules {
            for symbol in &compiled_rule.rule.symbols {
                if matches!(
                    language,
                    Language::Javascript | Language::Typescript | Language::Tsx
                ) && symbol_environment.has_declared_receiver(&call.observed)
                    && !symbol_environment.has_import_alias_receiver(&call.observed)
                {
                    continue;
                }
                let Some(symbol_resolution) =
                    symbol_environment.resolve(&call.observed, &symbol.canonical)
                else {
                    continue;
                };
                if symbol_resolution.confidence == SymbolConfidence::Ambiguous {
                    continue;
                }
                let range = call.node.range();
                let key = (compiled_rule.rule.id.as_str(), range.start, range.end);
                if let Some(existing) = evidence.iter_mut().find(|item| {
                    (
                        item.rule_id.as_str(),
                        item.location.start.byte_offset,
                        item.location.end.byte_offset,
                    ) == key
                }) {
                    existing.symbol_resolution = Some(symbol_resolution);
                    continue;
                }

                let mut captures = BTreeMap::new();
                let mut literal_values = BTreeMap::new();
                for (semantic_name, index) in &symbol.captures {
                    let Some(argument) = call.arguments.get(*index) else {
                        continue;
                    };
                    literal_values.insert(semantic_name.clone(), literals.evaluate(argument));
                    captures.insert(
                        semantic_name.clone(),
                        Capture {
                            text: argument.text().into_owned(),
                            location: location(path, argument),
                        },
                    );
                }
                evidence.push(Evidence {
                    id: evidence_id(path, &compiled_rule.rule.id, range.start, range.end),
                    kind: compiled_rule.rule.kind,
                    capability: compiled_rule.rule.capability,
                    location: location(path, &call.node),
                    enclosing_symbol: enclosing_symbol(&call.node),
                    captures,
                    cwe_candidates: compiled_rule.rule.cwe.clone(),
                    tags: compiled_rule.rule.tags.clone(),
                    confidence: compiled_rule.rule.confidence,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "ast-grep 0.45.1 + symbol-normalizer".to_string(),
                        rule_version: compiled_rule.rule.version,
                    },
                    context: evidence_context(
                        &call.node,
                        &comments,
                        &conditional,
                        &literals,
                        literal_values,
                    ),
                    symbol_resolution: Some(symbol_resolution),
                    rule_id: compiled_rule.rule.id.clone(),
                    related_evidence: Vec::new(),
                });
            }
        }
    }
    let symbol_rules_microseconds = symbol_started.elapsed().as_micros();
    let summaries_started = Instant::now();
    if let Some(imports) = kotlin_imports.as_ref() {
        super::kotlin::sources(
            path,
            &root,
            imports,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    }
    super::node_express::add_typed_express_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_ingress::add_bound_parameter_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_ingress::add_spring_parameter_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_sinks::add_typed_process_sinks(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_sinks::add_typed_outbound_sinks(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_network::add_java_network_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_filesystem::add_java_filesystem_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_crypto::add_java_crypto_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_output::add_java_output_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_context::add_java_project_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        java_project_context,
        &mut evidence,
    );
    super::java_security::add_spring_security_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_web_policy::add_java_web_policy_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_identity::add_java_identity_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_upload::add_java_upload_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        java_project_context,
        &mut evidence,
    );
    super::java_persistence::add_java_persistence_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::java_serialization::add_java_serialization_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    go_project_context.add_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    python_project_context.add_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    rust_project_context.add_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::go_grpc::add_go_grpc_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::go_filesystem::add_go_filesystem_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::go_ldap::add_go_ldap_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::go_policy::add_go_policy_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::go_vulnerability::add_go_vulnerability_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::go_web::add_go_web_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_rpc::add_rpc_parameter_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        csharp_rpc_context,
        &mut evidence,
    );
    super::csharp_sinks::add_typed_property_sinks(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_standalone::add_standalone_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_mainstream::add_mainstream_sinks(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_archive::add_archive_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_streaming_upload::add_streaming_upload_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_deserialization::add_deserialization_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        dotnet_project_context,
        &mut evidence,
    );
    super::csharp_injection::add_injection_evidence(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_mainstream::add_local_redirect_controls(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_identity::add_identity_policy_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_legacy_web::add_legacy_web_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_privilege::add_privilege_assignment_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_crypto::add_crypto_policy_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_output::add_output_policy_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::csharp_model::add_model_policy_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        csharp_model_context,
        &mut evidence,
    );
    super::csharp_sinks::annotate_dynamic_query_composition(
        path,
        &root,
        language,
        &literals,
        &mut evidence,
    );
    super::csharp_handoff::add_forwarded_parameter_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        csharp_handoff_context,
        &mut evidence,
    );
    // Standalone source admission is intentionally last among C# semantic
    // passes so it can see every supported impact sink in the symbol.
    super::csharp_standalone::add_standalone_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    add_express_pug_layout_sinks(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    add_stored_user_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &symbol_environment,
        &mut evidence,
    );
    add_stored_subtitle_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    add_fixed_format_transforms(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &symbol_environment,
        &mut evidence,
    );
    super::password_lifecycle::add_password_lifecycle(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &symbol_environment,
        &mut evidence,
    );
    super::identity_boundary::add_identity_boundary_observations(
        path,
        source,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::file_roles::add_file_role_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::node_policy::add_node_policy_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::node_randomness::add_node_randomness_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    object_input_context.add_observations(
        path,
        source,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    // Prefer an existing specialized selector/predicate over its whole-filter
    // extension, and an exact extended SDK query over the old syntax fallback.
    if matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        let request_objects: Vec<_> = evidence
            .iter()
            .filter(|e| {
                super::extended_database::is_rule(&e.rule_id)
                    && e.cwe_candidates.iter().any(|c| c == "CWE-943")
            })
            .filter_map(|e| {
                root.dfs().find(|n| {
                    n.range().start == e.location.start.byte_offset
                        && n.range().end == e.location.end.byte_offset
                })
            })
            .flat_map(|sink| super::extended_database::request_objects(&root, &sink))
            .collect();
        for request in request_objects {
            let prefix = match language {
                Language::Javascript => "javascript",
                Language::Typescript => "typescript",
                _ => "tsx",
            };
            let rule_id = format!("{prefix}-extended-nosql-request-object-source");
            let id = evidence_id(path, &rule_id, request.range().start, request.range().end);
            if evidence.iter().any(|e| e.id == id) {
                continue;
            }
            evidence.push(Evidence {
                id,
                kind: EvidenceKind::Source,
                capability: Capability::HttpRequestData,
                location: location(path, &request),
                enclosing_symbol: enclosing_symbol(&request),
                captures: BTreeMap::from([(
                    "field".into(),
                    Capture {
                        text: request.text().into_owned(),
                        location: location(path, &request),
                    },
                )]),
                cwe_candidates: vec!["CWE-20".into()],
                tags: vec!["request-object".into(), "nosql".into()],
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "ast-grep 0.45.1 + bounded-nosql-request-object".into(),
                    rule_version: 1,
                },
                context: evidence_context(
                    &request,
                    &comments,
                    &conditional,
                    &literals,
                    BTreeMap::new(),
                ),
                symbol_resolution: None,
                rule_id,
                related_evidence: vec![],
            });
        }
    }
    let specialized: BTreeSet<_> = evidence
        .iter()
        .filter(|e| {
            e.capability == Capability::DatabaseQuery
                && !super::extended_database::is_rule(&e.rule_id)
                && e.cwe_candidates.iter().any(|c| c == "CWE-943")
        })
        .map(|e| (e.location.start.byte_offset, e.location.end.byte_offset))
        .collect();
    evidence.retain(|e| {
        !(super::extended_database::is_rule(&e.rule_id)
            && e.cwe_candidates.iter().any(|c| c == "CWE-943")
            && specialized.contains(&(e.location.start.byte_offset, e.location.end.byte_offset)))
    });
    let extended: BTreeSet<_> = evidence
        .iter()
        .filter(|e| {
            super::extended_database::is_rule(&e.rule_id)
                && e.capability == Capability::DatabaseQuery
        })
        .map(|e| (e.location.start.byte_offset, e.location.end.byte_offset))
        .collect();
    evidence.retain(|e| {
        !(matches!(
            e.rule_id.as_str(),
            "go-dynamic-sql-prepare"
                | "java-database-query"
                | "javascript-database-query"
                | "typescript-database-query"
                | "tsx-database-query"
        ) && extended.contains(&(e.location.start.byte_offset, e.location.end.byte_offset)))
    });
    node_context.add_parameter_return_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.add_parameter_sink_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.add_xxe_parser_sinks(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.add_angular_rxjs_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.add_async_continuation_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.add_mongo_callback_result_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    add_embedded_vm_deserialization_sinks(path, language, &symbol_environment, &mut evidence);
    super::node_context::add_duplicate_key_object_mutation(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.add_dynamic_response_field_exposure(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::node_nest::add_nest_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::node_fastify::add_fastify_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::node_browser::add_browser_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::node_serverless::add_serverless_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::node_next_policy::add_next_policy_observations(
        path,
        source,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.add_js2_server_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::rust_context::add_rust_sql_sources(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::rust_context::add_rust_safety_function_observations(
        path,
        &root,
        language,
        include_nonproduction,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::rust_context::annotate_rust_build_script(path, language, &mut evidence);
    let mut native_arithmetic_paths = super::native_arithmetic::add_native_arithmetic_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    let mut native_domain_bound_paths =
        super::native_domain_bounds::add_native_domain_bound_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    let mut native_region_bound_paths =
        super::native_region_bounds::add_native_region_bound_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    let mut native_multiplication_paths =
        super::native_multiplication::add_native_multiplication_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    let mut native_signedness_paths = super::native_signedness::add_native_signedness_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    let mut native_heap_lifetime_paths =
        super::native_heap_lifetime::add_native_heap_lifetime_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    let mut native_cpp_ownership_paths =
        super::native_cpp_ownership::add_native_cpp_ownership_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    let mut native_libxml2_paths = super::native_libxml2::add_native_libxml2_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    let mut native_libarchive_paths = super::native_libarchive::add_native_libarchive_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    let mut native_toctou_paths = super::native_toctou::add_native_toctou_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    let mut native_drogon_paths = drogon_project_context.add_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    let mut native_invalidation_paths = native_invalidation_context.add_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    let mut native_serialized_blob_paths =
        super::native_serialized_blob::add_native_serialized_blob_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    let mut native_loaded_extent_paths =
        super::native_loaded_extent::add_native_loaded_extent_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    let mut native_remaining_input_paths =
        super::native_remaining_input::add_native_remaining_input_observations(
            path,
            &root,
            language,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );
    super::native_allocation::add_native_allocation_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        build_symbols,
        &mut evidence,
    );
    super::native_lifetime::add_native_lifetime_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::native_state::add_native_state_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    super::native_ownership::add_native_ownership_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        build_symbols,
        &mut evidence,
    );
    super::native_buffer::annotate_native_buffer_capacity(
        path,
        &root,
        language,
        &conditional,
        &mut evidence,
    );
    node_context.add_request_boundary_observations(
        path,
        &root,
        language,
        &comments,
        &conditional,
        &literals,
        &mut evidence,
    );
    node_context.annotate(path, &root, language, &mut evidence);
    go_project_context.annotate(path, language, &mut evidence);
    if !parse_issue_ranges.is_empty() {
        evidence.retain(|item| {
            item.kind == EvidenceKind::Secret
                || item
                    .tags
                    .iter()
                    .any(|tag| tag == "parse-recovery:locally-complete")
                    && matches!(
                        item.provenance.engine.as_str(),
                        "tree-sitter c-family arithmetic relationship"
                            | "tree-sitter c-family domain-bound relationship"
                            | "tree-sitter c-family destination-region relationship"
                            | "tree-sitter c-family multiplication relationship"
                            | "tree-sitter c-family signed-size relationship"
                            | "tree-sitter c-family local-heap-lifetime relationship"
                            | "tree-sitter c-family documented-invalidation relationship"
                            | "tree-sitter c-family serialized-blob extent relationship"
                            | "tree-sitter c-family loaded-memory-extent relationship"
                            | "tree-sitter c-family remaining-input relationship"
                            | "tree-sitter c++ allocation-ownership relationship"
                            | "tree-sitter c-family libxml2 parser-options relationship"
                            | "tree-sitter c-family libarchive extraction-options relationship"
                            | "tree-sitter c-family same-path check-use relationship"
                            | "tree-sitter c-family allocation-size relationship"
                            | "tree-sitter c-family callback-lifetime relationship"
                            | "tree-sitter c-family exceptional-state relationship"
                            | "tree-sitter c-family ownership-contract relationship"
                            | "mehscan bounded-drogon-request-identity 1"
                    )
                || !parse_issue_ranges
                    .iter()
                    .any(|range| location_overlaps_range(&item.location, range))
        });
    }
    evidence.sort_by(|left, right| {
        left.location
            .start
            .byte_offset
            .cmp(&right.location.start.byte_offset)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    let summaries_microseconds = summaries_started.elapsed().as_micros();
    let paths_started = Instant::now();
    let mut security_paths = super::security_paths::build_security_paths(
        path,
        &root,
        language,
        &evidence,
        &symbol_environment,
        relations,
    );
    if language == Language::Kotlin {
        security_paths.extend(super::kotlin::paths(&root, &evidence, relations));
    }
    let retained_evidence_ids = evidence
        .iter()
        .map(|item| item.id.as_str())
        .collect::<BTreeSet<_>>();
    native_arithmetic_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_domain_bound_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_region_bound_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_multiplication_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_signedness_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_heap_lifetime_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_cpp_ownership_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_libxml2_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_libarchive_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_toctou_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_drogon_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_invalidation_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_serialized_blob_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_loaded_extent_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    native_remaining_input_paths.retain(|path| {
        retained_evidence_ids.contains(path.source_evidence_id.as_str())
            && retained_evidence_ids.contains(path.sink_evidence_id.as_str())
            && path
                .protection_evidence_ids
                .iter()
                .all(|id| retained_evidence_ids.contains(id.as_str()))
    });
    security_paths.append(&mut native_arithmetic_paths);
    security_paths.append(&mut native_domain_bound_paths);
    security_paths.append(&mut native_region_bound_paths);
    security_paths.append(&mut native_multiplication_paths);
    security_paths.append(&mut native_signedness_paths);
    security_paths.append(&mut native_heap_lifetime_paths);
    security_paths.append(&mut native_cpp_ownership_paths);
    security_paths.append(&mut native_libxml2_paths);
    security_paths.append(&mut native_libarchive_paths);
    security_paths.append(&mut native_toctou_paths);
    security_paths.append(&mut native_drogon_paths);
    security_paths.append(&mut native_invalidation_paths);
    security_paths.append(&mut native_serialized_blob_paths);
    security_paths.append(&mut native_loaded_extent_paths);
    security_paths.append(&mut native_remaining_input_paths);
    security_paths.sort_by(|left, right| left.id.cmp(&right.id));
    let security_paths_microseconds = paths_started.elapsed().as_micros();
    evidence.extend(secret_evidence);
    evidence.sort_by(|left, right| {
        left.location
            .start
            .byte_offset
            .cmp(&right.location.start.byte_offset)
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    let timing = FileScanTiming {
        parse_context_microseconds,
        declarative_rules_microseconds,
        symbol_rules_microseconds,
        summaries_microseconds,
        security_paths_microseconds,
        declarative_patterns_considered,
        declarative_patterns_skipped,
    };
    if parse_issue_ranges.is_empty() {
        ParseOutcome::Parsed {
            evidence,
            security_paths,
            secret_suppressed,
            timing,
        }
    } else {
        ParseOutcome::Recovered {
            reason: "parser produced ERROR or missing nodes; retained evidence outside invalid syntax ranges"
                .to_string(),
            evidence,
            security_paths,
            secret_suppressed,
            timing,
        }
    }
}

fn location_overlaps_range(location: &Location, range: &std::ops::Range<usize>) -> bool {
    let start = location.start.byte_offset;
    let end = location.end.byte_offset;
    if range.start == range.end {
        start <= range.start && range.start < end
    } else {
        start < range.end && range.start < end
    }
}

fn scan_secrets_if_enabled(
    enabled: bool,
    path: &str,
    source: &str,
    comments: &CommentRanges,
    allowlist: &SecretAllowlist,
) -> (Vec<Evidence>, usize) {
    if !enabled {
        return (Vec::new(), 0);
    }
    let scan = crate::secrets::scan_source(path, source, comments, allowlist);
    (scan.evidence, scan.suppressed)
}

#[allow(clippy::too_many_arguments)]
fn add_express_pug_layout_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = match language {
        Language::Javascript => "javascript-express-pug-layout-filesystem-read",
        Language::Typescript => "typescript-express-pug-layout-filesystem-read",
        Language::Tsx => "tsx-express-pug-layout-filesystem-read",
        _ => return,
    };
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if call.observed != "res.render"
            || call.arguments.len() < 2
            || comments.is_in_comment(call.node.range())
            || !matches!(
                literals.evaluate(&call.arguments[0]).value,
                Some(LiteralValue::String(_))
            )
        {
            continue;
        }
        let Some(request_body) = direct_request_body_spread(&call.arguments[1]) else {
            continue;
        };
        let scope = function_scope_bounds(&call.node, root);
        let enclosing = enclosing_symbol(&call.node);
        let Some(source) = evidence
            .iter()
            .filter(|item| {
                item.kind == EvidenceKind::Source
                    && item.capability == Capability::HttpRequestData
                    && item
                        .captures
                        .get("name")
                        .is_some_and(|name| name.text == "layout")
                    && item.location.end.byte_offset <= call.node.range().start
                    && scope.0 <= item.location.start.byte_offset
                    && item.location.end.byte_offset <= scope.1
                    && item.enclosing_symbol == enclosing
            })
            .max_by_key(|item| item.location.end.byte_offset)
        else {
            continue;
        };
        let template = &call.arguments[0];
        let mut captures = BTreeMap::new();
        captures.insert(
            "path".to_string(),
            Capture {
                text: request_body.text().into_owned(),
                location: location(path, &request_body),
            },
        );
        captures.insert(
            "template".to_string(),
            Capture {
                text: template.text().into_owned(),
                location: location(path, template),
            },
        );
        let mut literal_values = BTreeMap::new();
        literal_values.insert("template".to_string(), literals.evaluate(template));
        evidence.push(Evidence {
            id: evidence_id(
                path,
                rule_id,
                call.node.range().start,
                call.node.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::FilesystemRead,
            location: location(path, &call.node),
            enclosing_symbol: enclosing,
            captures,
            cwe_candidates: vec!["CWE-22".to_string()],
            tags: vec![
                "filesystem".to_string(),
                "template".to_string(),
                "express".to_string(),
                "pug".to_string(),
                "layout-options".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "ast-grep 0.45.1 + express-pug-layout-options".to_string(),
                rule_version: 1,
            },
            context: evidence_context(&call.node, comments, conditional, literals, literal_values),
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: vec![source.id.clone()],
        });
    }
}

fn direct_request_body_spread<'tree>(
    options: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if options.kind().as_ref() != "object" {
        return None;
    }
    options
        .children()
        .filter(|child| child.kind().as_ref() == "spread_element")
        .find_map(|spread| {
            spread
                .children()
                .find(|child| child.is_named() && child.text().trim() == "req.body")
        })
}

#[allow(clippy::too_many_arguments)]
fn add_fixed_format_transforms<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    symbols: &FileSymbolEnvironment,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = match language {
        Language::Javascript => "javascript-fixed-format-transform",
        Language::Typescript => "typescript-fixed-format-transform",
        Language::Tsx => "tsx-fixed-format-transform",
        _ => return,
    };
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if call.arguments.len() != 1 || comments.is_in_comment(call.node.range()) {
            continue;
        }
        let Some((symbol_resolution, summary)) = symbols.resolve_fixed_format(&call.observed)
        else {
            continue;
        };
        let binding = call.observed.split('.').next().unwrap_or_default();
        if imported_binding_is_shadowed(&call.node, root, binding) {
            continue;
        }
        let value = &call.arguments[0];
        let mut captures = BTreeMap::new();
        captures.insert(
            "value".to_string(),
            Capture {
                text: value.text().into_owned(),
                location: location(path, value),
            },
        );
        let mut context =
            evidence_context(&call.node, comments, conditional, literals, BTreeMap::new());
        context.value_transform = Some(ValueTransform {
            output_format: summary.output_format,
            exact_length: summary.exact_length,
            algorithm: summary.algorithm,
        });
        evidence.push(Evidence {
            id: evidence_id(
                path,
                rule_id,
                call.node.range().start,
                call.node.range().end,
            ),
            kind: EvidenceKind::Sanitizer,
            capability: Capability::FixedFormatTransform,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures,
            cwe_candidates: Vec::new(),
            tags: vec![
                "value-transform".to_string(),
                "fixed-width".to_string(),
                "lowercase-hexadecimal-output".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "ast-grep 0.45.1 + project-fixed-format-summary".to_string(),
                rule_version: 1,
            },
            context,
            symbol_resolution: Some(symbol_resolution),
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn imported_binding_is_shadowed(
    call: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
    binding: &str,
) -> bool {
    if !is_simple_identifier(binding) {
        return true;
    }
    let scope = function_scope_bounds(call, root);
    if call
        .ancestors()
        .find(|ancestor| is_function_scope(ancestor.kind().as_ref()))
        .and_then(|function| function.field("parameters"))
        .is_some_and(|parameters| {
            parameters
                .dfs()
                .any(|node| node.kind().as_ref() == "identifier" && node.text().trim() == binding)
        })
    {
        return true;
    }
    root.dfs()
        .filter(|node| {
            node.range().start < call.range().start
                && function_scope_bounds(node, root) == scope
                && matches!(
                    node.kind().as_ref(),
                    "variable_declarator" | "assignment_expression" | "assignment"
                )
        })
        .filter_map(|node| node.field("name").or_else(|| node.field("left")))
        .any(|left| left.text().trim() == binding)
}

fn add_embedded_vm_deserialization_sinks(
    path: &str,
    language: Language,
    symbols: &FileSymbolEnvironment,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = match language {
        Language::Javascript => "javascript-yaml-deserialization",
        Language::Typescript => "typescript-yaml-deserialization",
        Language::Tsx => "tsx-yaml-deserialization",
        _ => return,
    };
    let derived = evidence
        .iter()
        .filter(|item| {
            item.capability == mehscan_core::Capability::DynamicCodeExecution
                && item.symbol_resolution.as_ref().is_some_and(|resolution| {
                    matches!(
                        resolution.canonical.as_str(),
                        "vm.runInContext" | "vm.runInNewContext"
                    )
                })
        })
        .filter_map(|outer| {
            let code = outer.captures.get("code")?;
            let (loader, payload) = constant_yaml_wrapper(&code.text)?;
            let observed = format!("{loader}.load");
            let symbol_resolution = symbols.resolve(&observed, "js-yaml.load")?;
            let mut captures = BTreeMap::new();
            captures.insert(
                "loader".to_string(),
                Capture {
                    text: loader.to_string(),
                    location: code.location.clone(),
                },
            );
            captures.insert(
                "payload".to_string(),
                Capture {
                    text: payload.to_string(),
                    location: code.location.clone(),
                },
            );
            let mut context = outer.context.clone();
            context.literals.clear();
            Some(Evidence {
                id: evidence_id(
                    path,
                    rule_id,
                    outer.location.start.byte_offset,
                    outer.location.end.byte_offset,
                ),
                kind: mehscan_core::EvidenceKind::Sink,
                capability: mehscan_core::Capability::Deserialization,
                location: outer.location.clone(),
                enclosing_symbol: outer.enclosing_symbol.clone(),
                captures,
                cwe_candidates: vec!["CWE-502".to_string()],
                tags: vec![
                    "deserialization".to_string(),
                    "yaml".to_string(),
                    "constant-vm-wrapper".to_string(),
                ],
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "ast-grep 0.45.1 + constant-vm-wrapper".to_string(),
                    rule_version: 1,
                },
                context,
                symbol_resolution: Some(symbol_resolution),
                rule_id: rule_id.to_string(),
                related_evidence: vec![outer.id.clone()],
            })
        })
        .collect::<Vec<_>>();
    evidence.extend(derived);
}

fn constant_yaml_wrapper(code: &str) -> Option<(String, String)> {
    let code = code.trim();
    let quote = code.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"')
        || code.as_bytes().last().copied() != Some(quote)
        || code.len() < 2
        || code[1..code.len() - 1].contains('\\')
    {
        return None;
    }
    let compact = code[1..code.len() - 1]
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let inner = compact
        .strip_prefix("JSON.stringify(")
        .and_then(|value| value.strip_suffix(')'))
        .unwrap_or(compact.as_str());
    let (loader, payload) = inner.split_once(".load(")?;
    let payload = payload.strip_suffix(')')?;
    if !is_simple_identifier(loader)
        || !is_simple_identifier(payload)
        || payload.contains(['(', ')', ','])
    {
        return None;
    }
    Some((loader.to_string(), payload.to_string()))
}

fn is_simple_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(|first| {
        (first == '_' || first.is_alphabetic())
            && characters.all(|character| character == '_' || character.is_alphanumeric())
    })
}

struct ModelLookupBinding {
    name: String,
    assignment_end: usize,
    scope: (usize, usize),
    symbol_resolution: SymbolResolution,
}

#[allow(clippy::too_many_arguments)]
fn add_stored_user_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    symbols: &FileSymbolEnvironment,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = match language {
        Language::Javascript => "javascript-stored-user-content",
        Language::Typescript => "typescript-stored-user-content",
        Language::Tsx => "tsx-stored-user-content",
        _ => return,
    };
    let mut lookups = root
        .dfs()
        .filter_map(|node| model_lookup_binding(node, root, symbols))
        .collect::<Vec<_>>();
    lookups.sort_by_key(|lookup| lookup.assignment_end);

    for node in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "member_expression" | "member_access_expression"
        )
    }) {
        let Some(object) = node.field("object").or_else(|| node.field("expression")) else {
            continue;
        };
        let Some(property) = node.field("property").or_else(|| node.field("name")) else {
            continue;
        };
        if property.text().trim() != "username" || comments.is_in_comment(node.range()) {
            continue;
        }
        let object_name = object.text();
        let object_name = object_name.trim().trim_end_matches('?');
        if !is_simple_identifier(object_name) {
            continue;
        }
        let scope = function_scope_bounds(&node, root);
        let Some(lookup) = lookups.iter().rev().find(|lookup| {
            lookup.name == object_name
                && lookup.scope == scope
                && lookup.assignment_end <= node.range().start
        }) else {
            continue;
        };
        if binding_is_reassigned(
            root,
            object_name,
            lookup.assignment_end,
            node.range().start,
            scope,
        ) {
            continue;
        }

        let range = node.range();
        let mut captures = BTreeMap::new();
        captures.insert(
            "field".to_string(),
            Capture {
                text: property.text().into_owned(),
                location: location(path, &property),
            },
        );
        evidence.push(Evidence {
            id: evidence_id(path, rule_id, range.start, range.end),
            kind: mehscan_core::EvidenceKind::Source,
            capability: mehscan_core::Capability::StoredUserContent,
            location: location(path, &node),
            enclosing_symbol: enclosing_symbol(&node),
            captures,
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "stored-data".to_string(),
                "user-content".to_string(),
                "attacker-controlled".to_string(),
                "model-lookup".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "ast-grep 0.45.1 + stored-model-source".to_string(),
                rule_version: 1,
            },
            context: evidence_context(&node, comments, conditional, literals, BTreeMap::new()),
            symbol_resolution: Some(lookup.symbol_resolution.clone()),
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_stored_subtitle_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = match language {
        Language::Javascript => "javascript-stored-subtitle-content",
        Language::Typescript => "typescript-stored-subtitle-content",
        Language::Tsx => "tsx-stored-subtitle-content",
        _ => return,
    };
    let Some(helper) = verified_subtitle_helper(root, evidence) else {
        return;
    };
    let helper_range = helper.node.range();
    let related_evidence = helper.filesystem_evidence_id;
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if call.observed != helper.name
            || !call.arguments.is_empty()
            || comments.is_in_comment(call.node.range())
            || (helper_range.start <= call.node.range().start
                && call.node.range().end <= helper_range.end)
        {
            continue;
        }
        let range = call.node.range();
        let mut captures = BTreeMap::new();
        captures.insert(
            "field".to_string(),
            Capture {
                text: call.node.text().into_owned(),
                location: location(path, &call.node),
            },
        );
        evidence.push(Evidence {
            id: evidence_id(path, rule_id, range.start, range.end),
            kind: EvidenceKind::Source,
            capability: Capability::StoredUserContent,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures,
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "stored-data".to_string(),
                "subtitle".to_string(),
                "local-file".to_string(),
                "html-content".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "ast-grep 0.45.1 + local-subtitle-file-source".to_string(),
                rule_version: 1,
            },
            context: evidence_context(&call.node, comments, conditional, literals, BTreeMap::new()),
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: vec![related_evidence.clone()],
        });
    }
}

struct VerifiedSubtitleHelper<'tree> {
    name: String,
    node: Node<'tree, StrDoc<SupportLang>>,
    filesystem_evidence_id: String,
}

fn verified_subtitle_helper<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    evidence: &[Evidence],
) -> Option<VerifiedSubtitleHelper<'tree>> {
    let node = root.dfs().find(|node| {
        node.kind().as_ref() == "function_declaration"
            && node
                .field("name")
                .is_some_and(|name| name.text().trim() == "getSubsFromFile")
            && node
                .field("parameters")
                .is_some_and(|parameters| parameters.children().all(|child| !child.is_named()))
    })?;
    let compact = node
        .text()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let config_read = compact.contains(
        "constsubtitles=config.get<string>('application.promotion.subtitles')??'owasp_promo.vtt'",
    ) || compact.contains(
        "constsubtitles=config.get('application.promotion.subtitles')??'owasp_promo.vtt'",
    );
    let file_read = compact.contains(
        "constdata=fs.readFileSync('frontend/dist/frontend/assets/public/videos/'+subtitles,'utf8')",
    );
    if !config_read || !file_read || !compact.contains("returndata.toString()") {
        return None;
    }
    let filesystem_evidence_id = evidence
        .iter()
        .find(|item| {
            item.kind == EvidenceKind::Sink
                && item.capability == Capability::FilesystemRead
                && item.enclosing_symbol.as_deref() == Some("getSubsFromFile")
                && item.symbol_resolution.as_ref().is_some_and(|resolution| {
                    resolution.canonical == "fs.readFileSync"
                        && resolution.confidence == SymbolConfidence::Exact
                })
                && item.captures.get("path").is_some_and(|capture| {
                    capture
                        .text
                        .chars()
                        .filter(|character| !character.is_whitespace())
                        .collect::<String>()
                        == "'frontend/dist/frontend/assets/public/videos/'+subtitles"
                })
        })?
        .id
        .clone();
    Some(VerifiedSubtitleHelper {
        name: "getSubsFromFile".to_string(),
        node,
        filesystem_evidence_id,
    })
}

fn model_lookup_binding(
    node: Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
    symbols: &FileSymbolEnvironment,
) -> Option<ModelLookupBinding> {
    let (left, right) = match node.kind().as_ref() {
        "variable_declarator" => (node.field("name")?, node.field("value")?),
        "assignment_expression" | "assignment" => (node.field("left")?, node.field("right")?),
        _ => return None,
    };
    let name = left.text();
    let name = name.trim();
    if !is_simple_identifier(name) {
        return None;
    }
    let expression = unwrap_lookup_expression(right);
    let call = call_site(expression)?;
    let (_, method) = call.observed.rsplit_once('.')?;
    if !matches!(method, "findByPk" | "findOne") {
        return None;
    }
    let symbol_resolution = symbols.resolve(
        &call.observed,
        &format!("../models/user.UserModel.{method}"),
    )?;
    if symbol_resolution.confidence == SymbolConfidence::Ambiguous {
        return None;
    }
    Some(ModelLookupBinding {
        name: name.to_string(),
        assignment_end: node.range().end,
        scope: function_scope_bounds(&node, root),
        symbol_resolution,
    })
}

fn unwrap_lookup_expression(
    mut node: Node<'_, StrDoc<SupportLang>>,
) -> Node<'_, StrDoc<SupportLang>> {
    loop {
        if !matches!(
            node.kind().as_ref(),
            "await_expression" | "parenthesized_expression"
        ) {
            return node;
        }
        let children = node
            .children()
            .filter(|child| child.is_named())
            .collect::<Vec<_>>();
        if children.len() != 1 {
            return node;
        }
        node = children[0].clone();
    }
}

fn function_scope_bounds(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> (usize, usize) {
    node.ancestors()
        .find(|ancestor| is_function_scope(ancestor.kind().as_ref()))
        .map(|ancestor| (ancestor.range().start, ancestor.range().end))
        .unwrap_or_else(|| (root.range().start, root.range().end))
}

fn binding_is_reassigned(
    root: &Node<'_, StrDoc<SupportLang>>,
    binding: &str,
    start: usize,
    end: usize,
    scope: (usize, usize),
) -> bool {
    root.dfs()
        .filter(|node| {
            start <= node.range().start
                && node.range().end <= end
                && function_scope_bounds(node, root) == scope
                && matches!(
                    node.kind().as_ref(),
                    "assignment_expression" | "assignment" | "augmented_assignment"
                )
        })
        .filter_map(|node| node.field("left"))
        .any(|left| left.text().trim() == binding)
}

fn is_function_scope(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
    )
}

fn evidence_context<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    literal_values: BTreeMap<String, mehscan_core::LiteralEvaluation>,
) -> EvidenceContext {
    EvidenceContext {
        comment: comments.is_in_comment(node.range()),
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        literals: literal_values,
        secret: None,
        value_transform: None,
        http_routes: Vec::new(),
        resource_policy: None,
        runtime_environment: None,
    }
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    observed: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if !matches!(
        node.kind().as_ref(),
        "call_expression" | "invocation_expression" | "method_invocation" | "call"
    ) {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let text = node.text();
    let observed = text.get(..callee_length)?.trim().to_string();
    if observed.is_empty() {
        return None;
    }
    let arguments = arguments
        .children()
        .filter(|child| child.is_named())
        .collect();
    Some(CallSite {
        node,
        observed,
        arguments,
    })
}

pub(super) fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}

pub(super) fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    // Stable FNV-1a is sufficient for identity/deduplication and avoids a UUID dependency.
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use ast_grep_core::Pattern;
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::Go;

    #[test]
    fn go_single_argument_call_pattern_matches() {
        let ast = Go.ast_grep("package p\nfunc f() { exec.Command(command) }");
        let pattern = Pattern::contextual(
            "package pattern\nfunc patternContext() { exec.Command($COMMAND) }",
            "call_expression",
            Go,
        )
        .expect("valid contextual pattern");
        assert!(ast.root().find(pattern).is_some());
    }
}
