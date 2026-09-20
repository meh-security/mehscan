use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, LiteralState, LiteralValue, Location, Position, Provenance,
    Resolution, ResourcePolicyContext, ResourcePolicyState, RuntimeEnvironment, SymbolConfidence,
    SymbolResolution, SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const DUPLICATE_KEY_ENGINE: &str = "ast-grep 0.45.1 + duplicate-key-object-mutation";
const DYNAMIC_RESPONSE_FIELD_ENGINE: &str = "ast-grep 0.45.1 + dynamic-sensitive-response-field";
const PARAMETER_RETURN_ENGINE: &str = "ast-grep 0.45.1 + bounded-parameter-return-summary";
const PARAMETER_SINK_ENGINE: &str = "ast-grep 0.45.1 + bounded-parameter-sink-summary";
const ASYNC_CONTINUATION_ENGINE: &str = "ast-grep 0.45.1 + bounded-async-continuation-summary";
const MONGO_CALLBACK_ENGINE: &str = "ast-grep 0.45.1 + bounded-mongo-callback-result-summary";
const XXE_PARSER_ENGINE: &str = "ast-grep 0.45.1 + bounded-libxml2-xxe-summary";
const ANGULAR_RXJS_ENGINE: &str = "ast-grep 0.45.1 + bounded-angular-rxjs-summary";
const EXPRESS_RESPONSE_MEDIA_ENGINE: &str = "ast-grep 0.45.1 + bounded-express-response-media-type";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PugOutputMode {
    Escaped,
    Raw,
    Mixed,
}

fn trace_node_context_step(path: &str, step: &str) {
    if std::env::var_os("MEHSCAN_TRACE_PHASES").is_some() {
        eprintln!("mehscan_node_context {path} {step}");
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpressRouteSummary {
    handler: String,
    method: String,
    path: String,
    access: HttpRouteAccess,
    guards: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpressMountedMiddleware {
    receiver: String,
    path: String,
    byte_offset: usize,
    guards: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParameterReturnSummary {
    canonical: String,
    parameter_index: usize,
    returned_suffix: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SummarySink {
    Process,
    DynamicCode,
    FilesystemRead,
    OutboundRequest,
    Redirect,
    Deserialization,
    HtmlOutput,
    TemplateEvaluation,
    SqlQuery,
    NosqlQuery,
    ResourceAccess,
    PasswordStorage,
}

impl SummarySink {
    const fn capability(self) -> Capability {
        match self {
            Self::Process => Capability::ProcessExecution,
            Self::DynamicCode => Capability::DynamicCodeExecution,
            Self::FilesystemRead => Capability::FilesystemRead,
            Self::OutboundRequest => Capability::OutboundNetworkRequest,
            Self::Redirect => Capability::Redirect,
            Self::Deserialization => Capability::Deserialization,
            Self::HtmlOutput => Capability::HtmlOutput,
            Self::TemplateEvaluation => Capability::TemplateEvaluation,
            Self::SqlQuery => Capability::DatabaseQuery,
            Self::NosqlQuery => Capability::DatabaseQuery,
            Self::ResourceAccess => Capability::ResourceAccess,
            Self::PasswordStorage => Capability::CryptographicHash,
        }
    }

    const fn cwe(self) -> &'static str {
        match self {
            Self::Process => "CWE-78",
            Self::DynamicCode => "CWE-94",
            Self::FilesystemRead => "CWE-22",
            Self::OutboundRequest => "CWE-918",
            Self::Redirect => "CWE-601",
            Self::Deserialization => "CWE-502",
            Self::HtmlOutput => "CWE-79",
            Self::TemplateEvaluation => "CWE-1336",
            Self::SqlQuery => "CWE-89",
            Self::NosqlQuery => "CWE-943",
            Self::ResourceAccess => "CWE-639",
            Self::PasswordStorage => "CWE-916",
        }
    }

    const fn role(self) -> &'static str {
        match self {
            Self::Process => "command",
            Self::DynamicCode => "code",
            Self::FilesystemRead => "path",
            Self::OutboundRequest => "endpoint",
            Self::Redirect => "location",
            Self::Deserialization => "payload",
            Self::HtmlOutput => "content",
            Self::TemplateEvaluation => "template",
            Self::SqlQuery => "query",
            Self::NosqlQuery => "nosql_query",
            Self::ResourceAccess => "filter",
            Self::PasswordStorage => "password",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParameterSinkSummary {
    canonical: String,
    parameter_index: usize,
    sink: SummarySink,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallbackForwardSummary {
    canonical: String,
    value_index: usize,
    callback_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MongoCallbackResultSummary {
    canonical: String,
    callback_index: usize,
    result_index: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct XxeParserSummary {
    canonical: String,
    parameter_index: usize,
}

struct PromiseContinuation<'tree> {
    value: Node<'tree, StrDoc<SupportLang>>,
    callback: Node<'tree, StrDoc<SupportLang>>,
    canonical: &'static str,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NodeProjectContext {
    runtime_by_path: BTreeMap<String, RuntimeEnvironment>,
    routes_by_handler: BTreeMap<String, Vec<ExpressRouteSummary>>,
    owner_field_overwrite_guards: BTreeSet<String>,
    sensitive_model_fields: BTreeMap<String, BTreeSet<String>>,
    express_wrappers: BTreeSet<String>,
    parameter_returns: BTreeMap<String, ParameterReturnSummary>,
    parameter_sinks: BTreeMap<String, Vec<ParameterSinkSummary>>,
    callback_forwards: BTreeMap<String, CallbackForwardSummary>,
    mongo_callback_results: BTreeMap<String, MongoCallbackResultSummary>,
    xxe_parsers: BTreeMap<String, XxeParserSummary>,
    has_express_session: bool,
    csrf_middleware_paths: BTreeSet<String>,
    has_graphql_http: bool,
    has_mongodb_driver: bool,
    graphql_resolvers: BTreeSet<String>,
    pug_templates: BTreeMap<String, PugOutputMode>,
}

impl NodeProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let sources = sources
            .filter(|(_, language, _)| is_node_language(*language))
            .collect::<Vec<_>>();
        let mut context = Self::default();
        for (path, language, source) in &sources {
            context.runtime_by_path.insert(
                (*path).to_string(),
                classify_runtime_environment(path, *language, source),
            );
        }
        for (path, language, source) in &sources {
            context.has_graphql_http |= source.contains("express-graphql");
            context.has_mongodb_driver |= source.contains("require('mongodb')")
                || source.contains("require(\"mongodb\")")
                || source.contains("from 'mongodb'")
                || source.contains("from \"mongodb\"");
            let Ok(document) = StrDoc::try_new(source, parser_language(*language)) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            if root.dfs().any(|node| node.is_error() || node.is_missing()) {
                continue;
            }
            collect_owner_field_overwrite_guards(source, &mut context.owner_field_overwrite_guards);
            trace_node_context_step(path, "parameter_returns");
            collect_parameter_return_summaries(path, &root, &mut context.parameter_returns);
            trace_node_context_step(path, "parameter_sinks");
            collect_parameter_sink_summaries(path, &root, &mut context.parameter_sinks);
            if has_ejs_import(source) {
                trace_node_context_step(path, "local_template_sinks");
                collect_local_template_parameter_sinks(path, &root, &mut context.parameter_sinks);
            }
            trace_node_context_step(path, "callback_forwards");
            collect_callback_forward_summaries(path, &root, &mut context.callback_forwards);
            trace_node_context_step(path, "mongo_callback_results");
            collect_mongo_callback_result_summaries(
                path,
                &root,
                &mut context.mongo_callback_results,
            );
            trace_node_context_step(path, "xxe_parsers");
            collect_xxe_parser_summaries(path, &root, &mut context.xxe_parsers);
            trace_node_context_step(path, "express_wrappers");
            collect_express_wrappers(path, &root, &mut context.express_wrappers);
            trace_node_context_step(path, "graphql_resolvers");
            collect_graphql_resolvers(path, &root, &mut context.graphql_resolvers);
            trace_node_context_step(path, "request_boundary_flags");
            let (has_session, has_csrf) = node_request_boundary_flags(path, &root);
            context.has_express_session |= has_session;
            if has_csrf {
                context.csrf_middleware_paths.insert((*path).to_string());
            }
        }
        for (path, language, source) in sources {
            if !needs_project_context(source) {
                continue;
            }
            let Ok(document) = StrDoc::try_new(source, parser_language(language)) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            if root.dfs().any(|node| node.is_error() || node.is_missing()) {
                continue;
            }
            trace_node_context_step(path, "express_routes");
            collect_express_routes(
                path,
                &root,
                &context.express_wrappers,
                &mut context.routes_by_handler,
            );
            trace_node_context_step(path, "sensitive_model_fields");
            collect_sensitive_model_fields(&root, &mut context.sensitive_model_fields);
            trace_node_context_step(path, "done");
        }
        for routes in context.routes_by_handler.values_mut() {
            routes.sort_by(|left, right| {
                left.method
                    .cmp(&right.method)
                    .then_with(|| left.path.cmp(&right.path))
                    .then_with(|| left.guards.cmp(&right.guards))
            });
            routes.dedup();
        }
        context
    }

    pub(crate) fn with_pug_templates<'a>(
        mut self,
        templates: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        for (path, source) in templates {
            let Some(name) = path
                .replace('\\', "/")
                .rsplit('/')
                .next()
                .and_then(|file| file.strip_suffix(".pug"))
                .map(|name| name.to_ascii_lowercase())
            else {
                continue;
            };
            let Some(mode) = pug_output_mode(source) else {
                continue;
            };
            self.pug_templates
                .entry(name)
                .and_modify(|current| {
                    if *current != mode {
                        *current = PugOutputMode::Mixed;
                    }
                })
                .or_insert(mode);
        }
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_request_boundary_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) {
            return;
        }
        add_login_session_rotation(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_literal_password_policy(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_registration_and_recovery_policy(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_express_session_policy(
            self,
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_js2_server_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) {
            return;
        }
        add_mysql_query_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_postgres_query_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_express_response_media_type_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        if self.has_mongodb_driver {
            add_mongodb_where_observations(
                path,
                root,
                language,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if self.has_graphql_http {
            add_graphql_resolver_sources(
                self,
                path,
                root,
                language,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_parameter_return_sources<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) || self.parameter_returns.is_empty() {
            return;
        }
        let imports = javascript_imports(path, root);
        let current_module = module_path(path).unwrap_or_default();
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            if comments.is_in_comment(call.node.range()) {
                continue;
            }
            if is_direct_return_value(&call.node) {
                continue;
            }
            let Some(canonical) = resolve_handler(&call.callee, &current_module, &imports) else {
                continue;
            };
            let Some(summary) = self.parameter_returns.get(&canonical) else {
                continue;
            };
            let Some(argument) = call.arguments.get(summary.parameter_index) else {
                continue;
            };
            if !request_argument_matches(argument, &call.node, &summary.returned_suffix) {
                continue;
            }
            let rule_id = language_rule(language, "parameter-return-request-source");
            let id = evidence_id(
                path,
                rule_id,
                call.node.range().start,
                call.node.range().end,
            );
            if evidence.iter().any(|item| item.id == id) {
                continue;
            }
            evidence.push(Evidence {
                id,
                kind: EvidenceKind::Source,
                capability: Capability::HttpRequestData,
                location: location(path, &call.node),
                enclosing_symbol: enclosing_symbol(&call.node),
                captures: BTreeMap::from([("value".to_string(), capture(path, &call.node))]),
                cwe_candidates: Vec::new(),
                tags: vec![
                    "interprocedural".to_string(),
                    "parameter-to-return".to_string(),
                    "maximum-depth-1".to_string(),
                ],
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: PARAMETER_RETURN_ENGINE.to_string(),
                    rule_version: 1,
                },
                context: evidence_context(&call.node, comments, conditional, literals),
                symbol_resolution: Some(SymbolResolution {
                    canonical: summary.canonical.clone(),
                    observed: call.callee.clone(),
                    method: SymbolResolutionMethod::Alias,
                    confidence: SymbolConfidence::High,
                }),
                rule_id: rule_id.to_string(),
                related_evidence: Vec::new(),
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_parameter_sink_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) || self.parameter_sinks.is_empty() {
            return;
        }
        let imports = javascript_imports(path, root);
        let current_module = module_path(path).unwrap_or_default();
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            if comments.is_in_comment(call.node.range()) {
                continue;
            }
            let Some(canonical) = resolve_handler(&call.callee, &current_module, &imports) else {
                continue;
            };
            let Some(summaries) = self.parameter_sinks.get(&canonical) else {
                continue;
            };
            for summary in summaries {
                let Some(argument) = call.arguments.get(summary.parameter_index) else {
                    continue;
                };
                let rule_id = language_rule(language, "parameter-sink-summary");
                let id = evidence_id(
                    path,
                    &format!(
                        "{rule_id}-{}-parameter-{}",
                        summary.sink.role(),
                        summary.parameter_index
                    ),
                    call.node.range().start,
                    call.node.range().end,
                );
                if evidence.iter().any(|item| item.id == id) {
                    continue;
                }
                let mut related_evidence = Vec::new();
                if summary.sink == SummarySink::PasswordStorage {
                    let source_rule = language_rule(language, "dao-password-material");
                    let source_id = evidence_id(
                        path,
                        source_rule,
                        argument.range().start,
                        argument.range().end,
                    );
                    if !evidence.iter().any(|item| item.id == source_id) {
                        evidence.push(Evidence {
                            id: source_id.clone(),
                            kind: EvidenceKind::Source,
                            capability: Capability::CredentialMaterial,
                            location: location(path, argument),
                            enclosing_symbol: enclosing_symbol(&call.node),
                            captures: BTreeMap::from([(
                                "name".to_string(),
                                capture(path, argument),
                            )]),
                            cwe_candidates: Vec::new(),
                            tags: vec![
                                "credential".to_string(),
                                "password".to_string(),
                                "dao-parameter".to_string(),
                            ],
                            confidence: Confidence::Medium,
                            provenance: Provenance {
                                resolution: Resolution::Ast,
                                engine: PARAMETER_SINK_ENGINE.to_string(),
                                rule_version: 1,
                            },
                            context: evidence_context(argument, comments, conditional, literals),
                            symbol_resolution: None,
                            rule_id: source_rule.to_string(),
                            related_evidence: Vec::new(),
                        });
                    }
                    related_evidence.push(source_id);
                } else if matches!(
                    summary.sink,
                    SummarySink::SqlQuery | SummarySink::NosqlQuery | SummarySink::ResourceAccess
                ) && let Some(origin) = request_origin_for_argument(&call.node, argument)
                {
                    let source_rule = language_rule(language, "dao-request-parameter");
                    let source_id = evidence_id(
                        path,
                        source_rule,
                        argument.range().start,
                        argument.range().end,
                    );
                    if !evidence.iter().any(|item| item.id == source_id) {
                        evidence.push(Evidence {
                            id: source_id.clone(),
                            kind: EvidenceKind::Source,
                            capability: Capability::HttpRequestData,
                            location: location(path, argument),
                            enclosing_symbol: enclosing_symbol(&call.node),
                            captures: BTreeMap::from([
                                ("name".to_string(), capture(path, argument)),
                                ("origin".to_string(), capture(path, &origin)),
                            ]),
                            cwe_candidates: Vec::new(),
                            tags: vec![
                                "http".to_string(),
                                "request".to_string(),
                                "dao-parameter".to_string(),
                                "maximum-depth-1".to_string(),
                            ],
                            confidence: Confidence::Medium,
                            provenance: Provenance {
                                resolution: Resolution::Ast,
                                engine: PARAMETER_SINK_ENGINE.to_string(),
                                rule_version: 1,
                            },
                            context: evidence_context(argument, comments, conditional, literals),
                            symbol_resolution: None,
                            rule_id: source_rule.to_string(),
                            related_evidence: Vec::new(),
                        });
                    }
                    related_evidence.push(source_id);
                }
                evidence.push(Evidence {
                    id,
                    kind: EvidenceKind::Sink,
                    capability: summary.sink.capability(),
                    location: location(path, &call.node),
                    enclosing_symbol: enclosing_symbol(&call.node),
                    captures: BTreeMap::from([(
                        summary.sink.role().to_string(),
                        capture(path, argument),
                    )]),
                    cwe_candidates: vec![summary.sink.cwe().to_string()],
                    tags: vec![
                        "interprocedural".to_string(),
                        "parameter-to-sink".to_string(),
                        "maximum-depth-1".to_string(),
                        match summary.sink {
                            SummarySink::TemplateEvaluation => "local-template-render",
                            SummarySink::SqlQuery => "postgres-js-unsafe-query",
                            SummarySink::NosqlQuery => "legacy-mongodb-javascript-predicate",
                            SummarySink::ResourceAccess => "legacy-mongodb-resource-selector",
                            SummarySink::PasswordStorage => "legacy-mongodb-password-storage",
                            _ => "bounded-helper",
                        }
                        .to_string(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: PARAMETER_SINK_ENGINE.to_string(),
                        rule_version: 1,
                    },
                    context: evidence_context(&call.node, comments, conditional, literals),
                    symbol_resolution: Some(SymbolResolution {
                        canonical: summary.canonical.clone(),
                        observed: call.callee.clone(),
                        method: SymbolResolutionMethod::Alias,
                        confidence: SymbolConfidence::High,
                    }),
                    rule_id: rule_id.to_string(),
                    related_evidence,
                });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_xxe_parser_sinks<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) || self.xxe_parsers.is_empty() {
            return;
        }
        let imports = javascript_imports(path, root);
        let current_module = module_path(path).unwrap_or_default();
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            if comments.is_in_comment(call.node.range()) {
                continue;
            }
            let Some(canonical) = resolve_handler(&call.callee, &current_module, &imports) else {
                continue;
            };
            let Some(summary) = self.xxe_parsers.get(&canonical) else {
                continue;
            };
            let Some(payload) = call.arguments.get(summary.parameter_index) else {
                continue;
            };
            let rule_id = language_rule(language, "xxe-parser-summary");
            let id = evidence_id(
                path,
                rule_id,
                call.node.range().start,
                call.node.range().end,
            );
            if evidence.iter().any(|item| item.id == id) {
                continue;
            }
            evidence.push(Evidence {
                id,
                kind: EvidenceKind::Sink,
                capability: Capability::XmlParsing,
                location: location(path, &call.node),
                enclosing_symbol: enclosing_symbol(&call.node),
                captures: BTreeMap::from([("payload".to_string(), capture(path, payload))]),
                cwe_candidates: vec!["CWE-611".to_string()],
                tags: vec![
                    "xml".to_string(),
                    "external-entity".to_string(),
                    "libxml2-wasm".to_string(),
                    "parameter-to-parser".to_string(),
                    "maximum-depth-1".to_string(),
                ],
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: XXE_PARSER_ENGINE.to_string(),
                    rule_version: 1,
                },
                context: evidence_context(&call.node, comments, conditional, literals),
                symbol_resolution: Some(SymbolResolution {
                    canonical: summary.canonical.clone(),
                    observed: call.callee.clone(),
                    method: SymbolResolutionMethod::Alias,
                    confidence: SymbolConfidence::High,
                }),
                rule_id: rule_id.to_string(),
                related_evidence: Vec::new(),
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_angular_rxjs_sources<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) {
            return;
        }
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            let callee = compact(&call.callee).to_ascii_lowercase();
            let direct_reviewed_service = [
                "productservice.search(",
                "feedbackservice.find(",
                "userservice.find(",
                "trackorderservice.find(",
            ]
            .iter()
            .any(|service| callee.contains(service));
            if terminal_symbol(&call.callee) != "subscribe"
                || comments.is_in_comment(call.node.range())
            {
                continue;
            }
            let Some(callback) = subscribe_next_callback(&call) else {
                continue;
            };
            let source_bindings = if direct_reviewed_service {
                function_parameter_names(&callback)
                    .into_iter()
                    .collect::<BTreeSet<_>>()
            } else {
                angular_fork_join_service_bindings(root, &call, &callback)
            };
            if source_bindings.is_empty() {
                continue;
            }
            let callback_text = callback.text();
            if callback_text.contains("bypassSecurityTrust")
                || callback_text.contains("document.write")
            {
                push_angular_callback_sources(
                    path,
                    language,
                    &callback,
                    &call.callee,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            push_angular_local_trust_helper_sources(
                path,
                language,
                root,
                &callback,
                &source_bindings,
                &call.callee,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_async_continuation_sources<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) {
            return;
        }
        let imports = javascript_imports(path, root);
        let current_module = module_path(path).unwrap_or_default();
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            if comments.is_in_comment(call.node.range()) {
                continue;
            }
            if let Some(continuation) = promise_resolve_continuation(&call) {
                if request_argument_matches(&continuation.value, &call.node, "") {
                    push_continuation_source(
                        path,
                        language,
                        &continuation.callback,
                        continuation.canonical,
                        &call.callee,
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
                continue;
            }
            let Some(canonical) = resolve_handler(&call.callee, &current_module, &imports) else {
                continue;
            };
            let Some(summary) = self.callback_forwards.get(&canonical) else {
                continue;
            };
            let (Some(value), Some(callback)) = (
                call.arguments.get(summary.value_index),
                call.arguments.get(summary.callback_index),
            ) else {
                continue;
            };
            if request_argument_matches(value, &call.node, "") {
                push_continuation_source(
                    path,
                    language,
                    callback,
                    &summary.canonical,
                    &call.callee,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_mongo_callback_result_sources<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) || self.mongo_callback_results.is_empty() {
            return;
        }
        let imports = javascript_imports(path, root);
        let current_module = module_path(path).unwrap_or_default();
        for node in root.dfs() {
            let Some(call) = call_site(node) else {
                continue;
            };
            if comments.is_in_comment(call.node.range()) {
                continue;
            }
            let Some(canonical) = resolve_handler(&call.callee, &current_module, &imports) else {
                continue;
            };
            let Some(summary) = self.mongo_callback_results.get(&canonical) else {
                continue;
            };
            let Some(callback) = call.arguments.get(summary.callback_index) else {
                continue;
            };
            if !is_function_node(callback) {
                continue;
            }
            let parameters = function_parameter_nodes(callback);
            let Some(result) = parameters.get(summary.result_index) else {
                continue;
            };
            let result_name = result.text().into_owned();
            for value_use in callback
                .dfs()
                .filter(|candidate| {
                    candidate.kind().as_ref() == "identifier"
                        && candidate.range() != result.range()
                        && candidate.text().trim() == result_name
                        && nearest_function_range(candidate) == Some(callback.range())
                        && is_express_html_output_use(candidate, callback)
                })
                .take(6)
            {
                let rule_id = language_rule(language, "mongo-callback-stored-source");
                let id = evidence_id(
                    path,
                    rule_id,
                    value_use.range().start,
                    value_use.range().end,
                );
                if evidence.iter().any(|item| item.id == id) {
                    continue;
                }
                evidence.push(Evidence {
                    id,
                    kind: EvidenceKind::Source,
                    capability: Capability::StoredUserContent,
                    location: location(path, &value_use),
                    enclosing_symbol: enclosing_symbol(callback),
                    captures: BTreeMap::from([("value".to_string(), capture(path, &value_use))]),
                    cwe_candidates: Vec::new(),
                    tags: vec![
                        "mongodb".to_string(),
                        "stored-data".to_string(),
                        "callback-result".to_string(),
                        "maximum-depth-1".to_string(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: MONGO_CALLBACK_ENGINE.to_string(),
                        rule_version: 1,
                    },
                    context: evidence_context(&value_use, comments, conditional, literals),
                    symbol_resolution: Some(SymbolResolution {
                        canonical: summary.canonical.clone(),
                        observed: call.callee.clone(),
                        method: SymbolResolutionMethod::Alias,
                        confidence: SymbolConfidence::High,
                    }),
                    rule_id: rule_id.to_string(),
                    related_evidence: Vec::new(),
                });
            }
        }
    }

    pub(crate) fn annotate(
        &self,
        path: &str,
        root: &Node<'_, StrDoc<SupportLang>>,
        language: Language,
        evidence: &mut [Evidence],
    ) {
        if !is_node_language(language) {
            return;
        }
        if let Some(runtime) = self.runtime_by_path.get(path).copied() {
            for item in evidence.iter_mut() {
                item.context.runtime_environment = Some(runtime);
            }
        }
        self.annotate_pug_render_context(evidence);
        let Some(module) = module_path(path) else {
            return;
        };
        for item in evidence.iter_mut() {
            let symbol = enclosing_commonjs_method(root, item.location.start.byte_offset)
                .or_else(|| item.enclosing_symbol.clone());
            let Some(symbol) = symbol else { continue };
            let handler = format!("{module}.{symbol}");
            let routes = self.routes_by_handler.get(&handler);
            if let Some(routes) = routes {
                item.context.http_routes = routes
                    .iter()
                    .map(|route| HttpRouteContext {
                        method: route.method.clone(),
                        path: route.path.clone(),
                        access: route.access,
                        guards: route.guards.clone(),
                    })
                    .collect();
                let administrative_operation = ["admin", "benefit", "manage", "privilege"]
                    .iter()
                    .any(|marker| handler.to_ascii_lowercase().contains(marker));
                let authenticated_without_role = !routes.is_empty()
                    && routes
                        .iter()
                        .all(|route| route.access == HttpRouteAccess::Authenticated);
                if item.capability == Capability::ResourceAccess
                    && item.cwe_candidates.iter().any(|cwe| cwe == "CWE-639")
                    && administrative_operation
                    && authenticated_without_role
                {
                    item.tags.extend([
                        "role-policy-review".to_string(),
                        "authenticated-without-observed-role-guard".to_string(),
                    ]);
                    let mut boundary =
                        item.captures
                            .values()
                            .next()
                            .cloned()
                            .unwrap_or_else(|| Capture {
                                text: String::new(),
                                location: item.location.clone(),
                            });
                    boundary.text = routes
                        .iter()
                        .map(|route| {
                            format!(
                                "{} {} guards=[{}]",
                                route.method,
                                route.path,
                                route.guards.join(", ")
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; ");
                    item.captures
                        .insert("authorization_boundary".to_string(), boundary);
                }
            }
            if item.capability != Capability::ResourceAccess {
                continue;
            }
            if resource_filter_has_owner_scope(root, item) {
                item.context.resource_policy = Some(ResourcePolicyContext {
                    state: ResourcePolicyState::OwnerScoped,
                    basis: "owner_or_tenant_filter_value_traces_to_authenticated_identity"
                        .to_string(),
                });
            } else if routes.is_some_and(|routes| {
                resource_filter_has_route_bound_owner_scope(
                    root,
                    item,
                    routes,
                    &self.owner_field_overwrite_guards,
                )
            }) {
                item.context.resource_policy = Some(ResourcePolicyContext {
                    state: ResourcePolicyState::OwnerScoped,
                    basis: "request_owner_field_is_overwritten_by_authenticated_route_guard"
                        .to_string(),
                });
            } else if let Some(basis) = shared_domain_resource_basis(root, item) {
                item.context.resource_policy = Some(ResourcePolicyContext {
                    state: ResourcePolicyState::SharedResource,
                    basis: basis.to_string(),
                });
            } else if self.is_paired_public_catalog(root, &module, &symbol, item) {
                item.context.resource_policy = Some(ResourcePolicyContext {
                    state: ResourcePolicyState::PublicCatalog,
                    basis: "paired_read_only_collection_and_item_routes".to_string(),
                });
            }
        }
    }

    fn annotate_pug_render_context(&self, evidence: &mut [Evidence]) {
        for item in evidence.iter_mut().filter(|item| {
            item.kind == EvidenceKind::Sink && item.capability == Capability::HtmlOutput
        }) {
            let Some(template) = item.captures.get("template") else {
                continue;
            };
            let name = template
                .text
                .trim()
                .trim_matches(['\'', '"'])
                .replace('\\', "/")
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let Some(mode) = self.pug_templates.get(&name) else {
                continue;
            };
            let tag = match mode {
                PugOutputMode::Escaped => "pug-output:escaped",
                PugOutputMode::Raw => "pug-output:raw",
                PugOutputMode::Mixed => "pug-output:mixed",
            };
            if !item.tags.iter().any(|existing| existing == tag) {
                item.tags.push(tag.to_string());
            }
            let mut operator = template.clone();
            operator.text = match mode {
                PugOutputMode::Escaped => "= (escaped buffered output)",
                PugOutputMode::Raw => "!= (raw buffered output)",
                PugOutputMode::Mixed => "mixed escaped and raw output",
            }
            .to_string();
            item.captures
                .insert("template_output_mode".to_string(), operator);
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_dynamic_response_field_exposure<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if !is_node_language(language) {
            return;
        }
        let Some(sensitive_fields) = self
            .sensitive_model_fields
            .iter()
            .find_map(|(model, fields)| {
                (normalize_property_name(model) == "user").then_some(fields)
            })
            .filter(|fields| !fields.is_empty())
        else {
            return;
        };

        for node in root.dfs() {
            let Some(candidate) =
                dynamic_response_field_candidate(root, node, comments, literals, sensitive_fields)
            else {
                continue;
            };
            let source_rule = match language {
                Language::Javascript => "javascript-express-query-field-selection",
                Language::Typescript => "typescript-express-query-field-selection",
                Language::Tsx => "tsx-express-query-field-selection",
                _ => unreachable!(),
            };
            let sink_rule = match language {
                Language::Javascript => "javascript-dynamic-sensitive-response-field",
                Language::Typescript => "typescript-dynamic-sensitive-response-field",
                Language::Tsx => "tsx-dynamic-sensitive-response-field",
                _ => unreachable!(),
            };
            let source_id = evidence_id(
                path,
                source_rule,
                candidate.request_field.range().start,
                candidate.request_field.range().end,
            );
            if !evidence.iter().any(|item| item.id == source_id) {
                let mut captures = BTreeMap::new();
                captures.insert("name".to_string(), capture(path, &candidate.request_field));
                evidence.push(Evidence {
                    id: source_id.clone(),
                    kind: EvidenceKind::Source,
                    capability: Capability::HttpRequestData,
                    location: location(path, &candidate.request_field),
                    enclosing_symbol: enclosing_symbol(&candidate.request_field),
                    captures,
                    cwe_candidates: vec!["CWE-20".to_string()],
                    tags: vec![
                        "http".to_string(),
                        "request".to_string(),
                        "attacker-controlled".to_string(),
                        "express".to_string(),
                        "response-field-selection".to_string(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: DYNAMIC_RESPONSE_FIELD_ENGINE.to_string(),
                        rule_version: 1,
                    },
                    context: evidence_context(
                        &candidate.request_field,
                        comments,
                        conditional,
                        literals,
                    ),
                    symbol_resolution: None,
                    rule_id: source_rule.to_string(),
                    related_evidence: Vec::new(),
                });
            }

            let sink_id = evidence_id(
                path,
                sink_rule,
                candidate.computed_read.range().start,
                candidate.computed_read.range().end,
            );
            if evidence.iter().any(|item| item.id == sink_id) {
                continue;
            }
            let mut captures = BTreeMap::new();
            captures.insert(
                "field_selector".to_string(),
                capture(path, &candidate.field_selector),
            );
            captures.insert(
                "selected_value".to_string(),
                capture(path, &candidate.computed_read),
            );
            captures.insert(
                "response".to_string(),
                capture(path, &candidate.response_call),
            );
            captures.insert(
                "response_assignment".to_string(),
                capture(path, &candidate.response_assignment),
            );
            let mut tags = vec![
                "data-exposure".to_string(),
                "dynamic-field".to_string(),
                "sensitive-model-field".to_string(),
                "express-response".to_string(),
            ];
            tags.push(format!(
                "sensitive-fields:{}",
                sensitive_fields
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            evidence.push(Evidence {
                id: sink_id,
                kind: EvidenceKind::Sink,
                capability: Capability::ResourceAccess,
                location: location(path, &candidate.computed_read),
                enclosing_symbol: enclosing_symbol(&candidate.computed_read),
                captures,
                cwe_candidates: vec!["CWE-200".to_string()],
                tags,
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: DYNAMIC_RESPONSE_FIELD_ENGINE.to_string(),
                    rule_version: 1,
                },
                context: evidence_context(
                    &candidate.computed_read,
                    comments,
                    conditional,
                    literals,
                ),
                symbol_resolution: None,
                rule_id: sink_rule.to_string(),
                related_evidence: vec![source_id],
            });
        }
    }

    fn is_paired_public_catalog(
        &self,
        root: &Node<'_, StrDoc<SupportLang>>,
        module: &str,
        symbol: &str,
        sink: &Evidence,
    ) -> bool {
        if !sink.location.path.ends_with(module)
            && module_path(&sink.location.path).as_deref() != Some(module)
        {
            return false;
        }
        let sink_node = smallest_node_containing(root, location_range(&sink.location));
        if !sink_node.is_some_and(|node| node.text().contains(".findOne(")) {
            return false;
        }
        let Some(model) = sink
            .captures
            .get("model")
            .map(|capture| capture.text.trim())
        else {
            return false;
        };
        let item_handler = format!("{module}.{symbol}");
        let Some(item_routes) = self.routes_by_handler.get(&item_handler) else {
            return false;
        };
        for item_route in item_routes
            .iter()
            .filter(|route| route.method == "GET" && route.access == HttpRouteAccess::Unknown)
        {
            let Some(collection_path) = collection_route(&item_route.path) else {
                continue;
            };
            for routes in self.routes_by_handler.values() {
                for collection in routes.iter().filter(|route| {
                    route.method == "GET"
                        && route.path == collection_path
                        && route.access == HttpRouteAccess::Unknown
                        && route.handler.starts_with(&format!("{module}."))
                }) {
                    let export = collection
                        .handler
                        .strip_prefix(&format!("{module}."))
                        .unwrap_or_default();
                    if handler_reads_collection(root, export, model)
                        && handler_is_read_only_for_model(root, symbol, model)
                        && handler_is_read_only_for_model(root, export, model)
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}

fn request_origin_for_argument<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    argument: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let argument_text = compact(argument.text().as_ref()).replace("?.", ".");
    if [
        "req.body.",
        "req.query.",
        "req.params.",
        "request.body.",
        "request.query.",
        "request.params.",
    ]
    .iter()
    .any(|prefix| argument_text.starts_with(prefix))
    {
        return Some(argument.clone());
    }
    let name = simple_identifier(&argument_text)?;
    let function = call.ancestors().find(is_function_node)?;
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && node.range().end <= call.range().start
                && nearest_function_range(node) == Some(function.range())
        })
        .find_map(|declaration| {
            let binding = declaration.field("name")?;
            let value = declaration.field("value")?;
            let value_text = compact(value.text().as_ref()).replace("?.", ".");
            let request_value = matches!(
                value_text.as_str(),
                "req.body"
                    | "req.query"
                    | "req.params"
                    | "request.body"
                    | "request.query"
                    | "request.params"
            ) || [
                "req.body.",
                "req.query.",
                "req.params.",
                "request.body.",
                "request.query.",
                "request.params.",
            ]
            .iter()
            .any(|prefix| value_text.starts_with(prefix));
            if !request_value {
                return None;
            }
            if binding.text().trim() == name
                || binding.dfs().any(|node| {
                    node.kind().as_ref().contains("identifier") && node.text().trim() == name
                })
            {
                Some(value)
            } else {
                None
            }
        })
}

fn enclosing_commonjs_method(
    root: &Node<'_, StrDoc<SupportLang>>,
    byte_offset: usize,
) -> Option<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter_map(|assignment| {
            let left = assignment.field("left")?;
            let right = assignment.field("right")?;
            if !is_function_node(&right)
                || !(right.range().start <= byte_offset && byte_offset <= right.range().end)
            {
                return None;
            }
            let left = compact(left.text().as_ref());
            left.strip_prefix("this.")
                .and_then(simple_identifier)
                .map(str::to_string)
        })
        .min_by_key(String::len)
}

pub(crate) fn classify_runtime_environment(
    path: &str,
    language: Language,
    source: &str,
) -> RuntimeEnvironment {
    if !is_node_language(language) {
        return RuntimeEnvironment::Unknown;
    }

    let normalized_path = path.replace('\\', "/").to_ascii_lowercase();
    let components = normalized_path.split('/').collect::<Vec<_>>();
    let browser_path = components.iter().any(|component| {
        matches!(
            *component,
            "frontend" | "wwwroot" | "browser" | "public" | "static" | "assets"
        )
    });
    let server_path = components
        .iter()
        .any(|component| matches!(*component, "server" | "backend"));

    let server_module = contains_imported_module(
        source,
        &[
            "node:",
            "child_process",
            "fs",
            "http",
            "https",
            "net",
            "tls",
            "express",
            "fastify",
            "koa",
            "@nestjs/",
            "aws-lambda",
            "@azure/functions",
            "@vercel/node",
            "next/server",
        ],
    );
    let next_pages_api =
        contains_imported_module(source, &["next"]) && source.contains("NextApiRequest");
    let browser_module = contains_imported_module(
        source,
        &["@angular/", "react-dom/client", "@remix-run/react"],
    );

    let server = server_module
        || next_pages_api
        || server_path
        || contains_directive(source, "use server")
        || source.contains("__dirname")
        || source.contains("__filename")
        || source.contains("process.env");
    let browser = browser_path
        || browser_module
        || contains_directive(source, "use client")
        || [
            "document.",
            "window.",
            "navigator.",
            "localStorage",
            "sessionStorage",
            "XMLHttpRequest",
            "indexedDB",
            "import.meta.env",
        ]
        .iter()
        .any(|indicator| source.contains(indicator));

    match (server, browser) {
        (true, true) => RuntimeEnvironment::Mixed,
        (true, false) => RuntimeEnvironment::Server,
        (false, true) => RuntimeEnvironment::Browser,
        (false, false) => RuntimeEnvironment::Unknown,
    }
}

fn contains_directive(source: &str, directive: &str) -> bool {
    let single_quoted = format!("'{directive}'");
    let double_quoted = format!("\"{directive}\"");
    source.lines().take(8).any(|line| {
        let line = line.trim_start();
        line.starts_with(&single_quoted) || line.starts_with(&double_quoted)
    })
}

fn contains_imported_module(source: &str, modules: &[&str]) -> bool {
    modules.iter().any(|module| {
        ['\'', '"'].iter().any(|quote| {
            let references = if module.ends_with([':', '/']) {
                vec![
                    format!("from {quote}{module}"),
                    format!("require({quote}{module}"),
                    format!("import({quote}{module}"),
                ]
            } else {
                vec![
                    format!("from {quote}{module}{quote}"),
                    format!("from {quote}{module}/"),
                    format!("require({quote}{module}{quote}"),
                    format!("require({quote}{module}/"),
                    format!("import({quote}{module}{quote}"),
                    format!("import({quote}{module}/"),
                ]
            };
            references
                .iter()
                .any(|reference| source.contains(reference))
        })
    })
}

fn needs_project_context(source: &str) -> bool {
    source.contains(".init(")
        || [".get(", ".post(", ".put(", ".patch(", ".delete(", ".use("]
            .iter()
            .any(|registration| source.contains(registration))
}

struct DynamicResponseFieldCandidate<'tree> {
    request_field: Node<'tree, StrDoc<SupportLang>>,
    field_selector: Node<'tree, StrDoc<SupportLang>>,
    computed_read: Node<'tree, StrDoc<SupportLang>>,
    response_assignment: Node<'tree, StrDoc<SupportLang>>,
    response_call: Node<'tree, StrDoc<SupportLang>>,
}

fn dynamic_response_field_candidate<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    assignment: Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    sensitive_fields: &BTreeSet<String>,
) -> Option<DynamicResponseFieldCandidate<'tree>> {
    if assignment.kind().as_ref() != "assignment_expression"
        || comments.is_in_comment(assignment.range())
    {
        return None;
    }
    let left = assignment.field("left")?;
    let right = assignment.field("right")?;
    let (left_object, left_index) = computed_access(&left)?;
    let (right_object, right_index) = computed_access(&right)?;
    let field = selector_identifier(&left_index)?;
    if selector_identifier(&right_index)? != field {
        return None;
    }
    let response_object_text = left_object.text();
    let response_object = simple_identifier(response_object_text.trim())?.to_string();
    let selected_object = compact(right_object.text().as_ref()).replace("?.", ".");
    let authenticated_user = selected_object.strip_suffix(".data")?;
    simple_identifier(authenticated_user)?;

    let scope = function_scope(&assignment, root);
    let user_value =
        latest_assigned_value(root, authenticated_user, assignment.range().start, &scope)?;
    let user_lookup = call_site(user_value)?;
    if !matches!(terminal_symbol(&user_lookup.callee), "get" | "from")
        || !user_lookup.callee.contains("authenticatedUsers.")
    {
        return None;
    }

    let loop_node = assignment.ancestors().find(|ancestor| {
        ancestor.kind().as_ref() == "for_in_statement"
            && ancestor.text().contains(" of ")
            && ancestor.range().start >= scope.start
    })?;
    let loop_left = loop_node.field("left")?;
    if !loop_left
        .dfs()
        .any(|node| node.is_named() && node.text().trim() == field)
    {
        return None;
    }
    let loop_right = loop_node.field("right")?;
    let requested_fields = simple_identifier(loop_right.text().trim())?.to_string();
    let requested_declaration =
        latest_declaration(root, &requested_fields, loop_node.range().start, &scope)?;
    let requested_initializer = requested_declaration.field("value")?;
    let requested_text = compact(requested_initializer.text().as_ref());
    if !requested_text.contains(".split(") || !requested_text.contains(".map(") {
        return None;
    }
    let source_binding = requested_initializer
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .find_map(|node| {
            let call = call_site(node)?;
            call.callee
                .strip_suffix(".split")
                .and_then(simple_identifier)
                .map(str::to_string)
        })?;
    let source_declaration = latest_declaration(
        root,
        &source_binding,
        requested_declaration.range().start,
        &scope,
    )?;
    let source_initializer = source_declaration.field("value")?;
    let request_field = source_initializer
        .dfs()
        .filter(|node| node.is_named())
        .filter(|node| {
            let text = compact(node.text().as_ref()).replace("?.", ".");
            text.starts_with("req.query.") && text.matches('.').count() == 2
        })
        .min_by_key(|node| node.range().end - node.range().start)?;

    if fixed_allowlist_applies(
        root,
        literals,
        &scope,
        &requested_initializer,
        &loop_node,
        &assignment,
        &field,
        sensitive_fields,
    ) {
        return None;
    }

    let response_assignment = root
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "assignment_expression"
                && assignment.range().end < node.range().start
                && node.range().end <= scope.end
                && function_scope(node, root) == scope
        })
        .find(|node| {
            node.field("right").is_some_and(|value| {
                matches!(value.kind().as_ref(), "object" | "object_expression")
                    && value
                        .dfs()
                        .any(|child| child.is_named() && child.text().trim() == response_object)
            }) && node
                .field("left")
                .is_some_and(|binding| simple_identifier(binding.text().trim()).is_some())
        })?;
    let response_binding = response_assignment.field("left")?.text().trim().to_string();
    let response_call = root
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "call_expression"
                && response_assignment.range().end < node.range().start
                && node.range().end <= scope.end
                && function_scope(node, root) == scope
        })
        .find(|node| {
            call_site(node.clone()).is_some_and(|call| {
                matches!(terminal_symbol(&call.callee), "json" | "jsonp")
                    && call.callee.starts_with("res.")
                    && call
                        .arguments
                        .iter()
                        .any(|argument| argument.text().trim() == response_binding)
            })
        })?;

    Some(DynamicResponseFieldCandidate {
        request_field,
        field_selector: left_index,
        computed_read: right,
        response_assignment,
        response_call,
    })
}

#[allow(clippy::too_many_arguments)]
fn fixed_allowlist_applies<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    scope: &std::ops::Range<usize>,
    requested_initializer: &Node<'tree, StrDoc<SupportLang>>,
    loop_node: &Node<'tree, StrDoc<SupportLang>>,
    assignment: &Node<'tree, StrDoc<SupportLang>>,
    field: &str,
    sensitive_fields: &BTreeSet<String>,
) -> bool {
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && scope.start <= node.range().start
                && node.range().end < assignment.range().start
                && function_scope(node, root) == *scope
        })
        .any(|declaration| {
            let Some(name) = declaration
                .field("name")
                .and_then(|name| simple_identifier(name.text().trim()).map(str::to_string))
            else {
                return false;
            };
            let Some(value) = declaration.field("value") else {
                return false;
            };
            let evaluation = literals.evaluate(&value);
            let Some(LiteralValue::Array(values)) = evaluation.value else {
                return false;
            };
            if evaluation.state != LiteralState::Known || values.is_empty() {
                return false;
            }
            let allowed = values
                .into_iter()
                .map(|value| match value {
                    LiteralValue::String(value) => Some(normalize_property_name(&value)),
                    _ => None,
                })
                .collect::<Option<BTreeSet<_>>>();
            let Some(allowed) = allowed else {
                return false;
            };
            if !allowed.is_disjoint(sensitive_fields) {
                return false;
            }
            let membership = format!("{name}.includes({field})");
            let requested_text = compact(requested_initializer.text().as_ref());
            if requested_text.contains(&format!(".filter({field}=>{membership})"))
                || requested_text.contains(&format!(".filter(({field})=>{membership})"))
            {
                return true;
            }
            assignment.ancestors().any(|ancestor| {
                ancestor.kind().as_ref() == "if_statement"
                    && ancestor.range().start >= loop_node.range().start
                    && ancestor.field("condition").is_some_and(|condition| {
                        let condition = compact(condition.text().as_ref());
                        condition == membership
                            || condition == format!("{membership}===true")
                            || condition == format!("true==={membership}")
                    })
                    && ancestor.field("consequence").is_some_and(|consequence| {
                        consequence.range().start <= assignment.range().start
                            && assignment.range().end <= consequence.range().end
                    })
            })
        })
}

fn computed_access<'tree>(node: &Node<'tree, StrDoc<SupportLang>>) -> Option<NodePair<'tree>> {
    matches!(node.kind().as_ref(), "subscript_expression").then_some(())?;
    Some((node.field("object")?, node.field("index")?))
}

fn selector_identifier(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.dfs()
        .filter(|child| child.is_named())
        .map(|child| child.text())
        .find_map(|text| simple_identifier(text.trim()).map(str::to_string))
}

fn collect_sensitive_model_fields(
    root: &Node<'_, StrDoc<SupportLang>>,
    models: &mut BTreeMap<String, BTreeSet<String>>,
) {
    for node in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
    {
        let Some(call) = call_site(node) else {
            continue;
        };
        let Some(model) = call
            .callee
            .strip_suffix(".init")
            .and_then(simple_identifier)
        else {
            continue;
        };
        let Some(attributes) = call.arguments.first() else {
            continue;
        };
        if !matches!(attributes.kind().as_ref(), "object" | "object_expression") {
            continue;
        }
        let fields = attributes
            .children()
            .filter(|property| property.is_named())
            .filter_map(|property| property.field("key"))
            .filter_map(|key| exact_property_key(&key))
            .filter(|field| is_sensitive_field(field))
            .collect::<BTreeSet<_>>();
        if !fields.is_empty() {
            models.entry(model.to_string()).or_default().extend(fields);
        }
    }
}

fn is_sensitive_field(field: &str) -> bool {
    matches!(
        normalize_property_name(field).as_str(),
        "password"
            | "passwordhash"
            | "passwd"
            | "accesstoken"
            | "refreshtoken"
            | "sessiontoken"
            | "deluxetoken"
            | "totpsecret"
            | "mfasecret"
            | "twofactorsecret"
            | "recoverycode"
            | "recoverycodes"
            | "apikey"
            | "clientsecret"
            | "privatekey"
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_duplicate_key_object_mutation<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !is_node_language(language) {
        return;
    }
    for node in root.dfs() {
        let Some(candidate) = duplicate_key_candidate(root, node, comments) else {
            continue;
        };
        let source_rule = match language {
            Language::Javascript => "javascript-express-raw-body",
            Language::Typescript => "typescript-express-raw-body",
            Language::Tsx => "tsx-express-raw-body",
            _ => unreachable!(),
        };
        let sink_rule = match language {
            Language::Javascript => "javascript-sequelize-duplicate-key-mutation",
            Language::Typescript => "typescript-sequelize-duplicate-key-mutation",
            Language::Tsx => "tsx-sequelize-duplicate-key-mutation",
            _ => unreachable!(),
        };
        let source_id = evidence_id(
            path,
            source_rule,
            candidate.raw_body.range().start,
            candidate.raw_body.range().end,
        );
        if !evidence.iter().any(|item| item.id == source_id) {
            let mut captures = BTreeMap::new();
            captures.insert("name".to_string(), capture(path, &candidate.raw_body));
            evidence.push(Evidence {
                id: source_id.clone(),
                kind: EvidenceKind::Source,
                capability: Capability::HttpRequestData,
                location: location(path, &candidate.raw_body),
                enclosing_symbol: enclosing_symbol(&candidate.raw_body),
                captures,
                cwe_candidates: vec!["CWE-20".to_string()],
                tags: vec![
                    "http".to_string(),
                    "request".to_string(),
                    "attacker-controlled".to_string(),
                    "express".to_string(),
                    "raw-body".to_string(),
                ],
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: DUPLICATE_KEY_ENGINE.to_string(),
                    rule_version: 1,
                },
                context: evidence_context(&candidate.raw_body, comments, conditional, literals),
                symbol_resolution: None,
                rule_id: source_rule.to_string(),
                related_evidence: Vec::new(),
            });
        }

        let mut captures = BTreeMap::new();
        captures.insert("model".to_string(), capture(path, &candidate.model));
        captures.insert(
            "filter".to_string(),
            capture(path, &candidate.persisted_object),
        );
        captures.insert(
            "duplicate_key".to_string(),
            capture(path, &candidate.duplicate_key),
        );
        captures.insert(
            "validated_value".to_string(),
            capture(path, &candidate.validated_value),
        );
        captures.insert(
            "persisted_value".to_string(),
            capture(path, &candidate.persisted_value),
        );
        let sink_id = evidence_id(
            path,
            sink_rule,
            candidate.save_call.range().start,
            candidate.save_call.range().end,
        );
        if evidence.iter().any(|item| item.id == sink_id) {
            continue;
        }
        evidence.push(Evidence {
            id: sink_id,
            kind: EvidenceKind::Sink,
            capability: Capability::ResourceAccess,
            location: location(path, &candidate.save_call),
            enclosing_symbol: enclosing_symbol(&candidate.save_call),
            captures,
            cwe_candidates: vec!["CWE-639".to_string()],
            tags: vec![
                "authorization".to_string(),
                "object-mutation".to_string(),
                "duplicate-key".to_string(),
                "sequelize".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: DUPLICATE_KEY_ENGINE.to_string(),
                rule_version: 1,
            },
            context: evidence_context(&candidate.save_call, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: sink_rule.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

struct DuplicateKeyCandidate<'tree> {
    raw_body: Node<'tree, StrDoc<SupportLang>>,
    save_call: Node<'tree, StrDoc<SupportLang>>,
    model: Node<'tree, StrDoc<SupportLang>>,
    persisted_object: Node<'tree, StrDoc<SupportLang>>,
    duplicate_key: Node<'tree, StrDoc<SupportLang>>,
    validated_value: Node<'tree, StrDoc<SupportLang>>,
    persisted_value: Node<'tree, StrDoc<SupportLang>>,
}

type NodePair<'tree> = (
    Node<'tree, StrDoc<SupportLang>>,
    Node<'tree, StrDoc<SupportLang>>,
);

fn duplicate_key_candidate<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    save_call: Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
) -> Option<DuplicateKeyCandidate<'tree>> {
    let save = call_site(save_call.clone())?;
    if terminal_symbol(&save.callee) != "save" || !save.arguments.is_empty() {
        return None;
    }
    let instance = save.callee.strip_suffix(".save")?.trim();
    if simple_identifier(instance).is_none() || comments.is_in_comment(save_call.range()) {
        return None;
    }
    let scope = function_scope(&save_call, root);
    let instance_declaration = latest_declaration(root, instance, save_call.range().start, &scope)?;
    let build = call_site(instance_declaration.field("value")?)?;
    if terminal_symbol(&build.callee) != "build" || build.arguments.len() != 1 {
        return None;
    }
    let model_text = build.callee.strip_suffix(".build")?.trim();
    simple_identifier(model_text)?;
    let model = smallest_named_text_node(&instance_declaration, model_text)?;
    let object_text = build.arguments[0].text();
    let object_name = simple_identifier(object_text.trim())?;
    let object_declaration = latest_declaration(
        root,
        object_name,
        instance_declaration.range().start,
        &scope,
    )?;
    let persisted_object = object_declaration.field("value")?;
    if persisted_object.kind().as_ref() != "object" {
        return None;
    }

    for property in persisted_object
        .clone()
        .children()
        .filter(|node| node.is_named())
    {
        let (Some(key), Some(value)) = (property.field("key"), property.field("value")) else {
            continue;
        };
        let Some(array) = last_element_array(value.text().trim()) else {
            continue;
        };
        let Some(duplicate_key) = exact_property_key(&key) else {
            continue;
        };
        let if_statement = save_call.ancestors().find(|ancestor| {
            ancestor.kind().as_ref() == "if_statement"
                && ancestor.field("alternative").is_some_and(|alternative| {
                    contains_range(alternative.range(), save_call.range())
                })
        })?;
        let condition = if_statement.field("condition")?;
        let Some(validated_value) = condition
            .dfs()
            .filter(|node| node.is_named())
            .find(|node| compact(node.text().as_ref()) == format!("{array}[0]"))
        else {
            continue;
        };
        if !condition.text().contains("!=") || !rejecting_consequence(&if_statement) {
            continue;
        }
        let Some((raw_body, key_literal)) = repeated_key_origin(
            root,
            &scope,
            &array,
            &duplicate_key,
            if_statement.range().start,
        ) else {
            continue;
        };
        return Some(DuplicateKeyCandidate {
            raw_body,
            save_call,
            model,
            persisted_object,
            duplicate_key: key_literal,
            validated_value,
            persisted_value: value,
        });
    }
    None
}

fn repeated_key_origin<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    scope: &std::ops::Range<usize>,
    array: &str,
    property_key: &str,
    before: usize,
) -> Option<NodePair<'tree>> {
    let array_declaration = latest_declaration(root, array, before, scope)?;
    if compact(array_declaration.field("value")?.text().as_ref()) != "[]" {
        return None;
    }
    for node in root.dfs().filter(|node| {
        scope.start <= node.range().start
            && node.range().end <= before
            && node.kind().as_ref() == "call_expression"
    }) {
        let call = call_site(node.clone())?;
        if call.callee != format!("{array}.push") || call.arguments.len() != 1 {
            continue;
        }
        let loop_node = node.ancestors().find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "for_statement" | "for_in_statement" | "while_statement"
            )
        })?;
        let key_condition = node.ancestors().find(|ancestor| {
            ancestor.kind().as_ref() == "if_statement"
                && contains_range(loop_node.range(), ancestor.range())
        })?;
        let condition = key_condition.field("condition")?;
        let key_literal = condition
            .dfs()
            .find(|candidate| exact_quoted(candidate.text().as_ref()) == Some(property_key))?;
        let pushed = compact(call.arguments[0].text().as_ref());
        let result = pushed.split('[').next().and_then(simple_identifier)?;
        if !pushed.ends_with("].value") {
            continue;
        }
        let result_declaration = latest_declaration(root, result, loop_node.range().start, scope)?;
        let parser_call = call_site(result_declaration.field("value")?)?;
        let raw_body = parser_call
            .arguments
            .iter()
            .flat_map(Node::dfs)
            .find(|candidate| {
                candidate.kind().as_ref() == "member_expression"
                    && candidate
                        .field("property")
                        .is_some_and(|property| property.text().trim() == "rawBody")
            })?;
        if !request_receiver_is_typed(&raw_body, scope) {
            continue;
        }
        return Some((raw_body, key_literal));
    }
    None
}

fn request_receiver_is_typed(
    raw_body: &Node<'_, StrDoc<SupportLang>>,
    scope: &std::ops::Range<usize>,
) -> bool {
    let Some(function) = raw_body
        .ancestors()
        .find(|ancestor| ancestor.range() == *scope)
    else {
        return false;
    };
    let Some(parameters) = function.field("parameters") else {
        return false;
    };
    let object = raw_body
        .field("object")
        .map(|node| node.text().into_owned());
    object.is_some_and(|text| {
        let compact_object = compact(&text);
        compact_object.contains("req")
            && parameters.text().contains("req")
            && parameters.text().contains("Request")
    })
}

fn rejecting_consequence(if_statement: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if_statement
        .field("consequence")
        .is_some_and(|consequence| {
            let text = compact(consequence.text().as_ref());
            text.contains("res.status(") && (text.contains(".send(") || text.contains(".json("))
        })
}

fn last_element_array(text: &str) -> Option<String> {
    let text = compact(text);
    let (array, index) = text.split_once('[')?;
    let index = index.strip_suffix(']')?;
    let array = simple_identifier(array)?;
    (index == format!("{array}.length-1")).then(|| array.to_string())
}

fn collect_express_routes(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    wrappers: &BTreeSet<String>,
    routes: &mut BTreeMap<String, Vec<ExpressRouteSummary>>,
) {
    let imports = javascript_imports(path, root);
    let current_module = module_path(path).unwrap_or_default();
    let mounted_middleware = root
        .dfs()
        .filter_map(|node| {
            let byte_offset = node.range().start;
            let call = call_site(node)?;
            let (receiver, verb) = call.callee.rsplit_once('.')?;
            if !matches!(receiver, "app" | "router") || verb != "use" || call.arguments.len() < 2 {
                return None;
            }
            let route_text = call.arguments[0].text();
            let route_path = exact_quoted(route_text.as_ref())?;
            let guards = call.arguments[1..]
                .iter()
                .filter_map(guard_name)
                .collect::<Vec<_>>();
            (!guards.is_empty()).then(|| ExpressMountedMiddleware {
                receiver: receiver.to_string(),
                path: route_path.to_string(),
                byte_offset,
                guards,
            })
        })
        .collect::<Vec<_>>();
    for node in root.dfs() {
        let byte_offset = node.range().start;
        let Some(call) = call_site(node) else {
            continue;
        };
        let Some((receiver, verb)) = call.callee.rsplit_once('.') else {
            continue;
        };
        if !matches!(receiver, "app" | "router")
            || !matches!(verb, "get" | "post" | "put" | "delete" | "patch")
            || call.arguments.len() < 2
        {
            continue;
        }
        let route_text = call.arguments[0].text();
        let Some(route_path) = exact_quoted(route_text.as_ref()) else {
            continue;
        };
        let handler_argument = call.arguments.last().expect("route has handler");
        let Some(handler_symbol) =
            unwrap_handler(handler_argument, &current_module, &imports, wrappers, 0)
        else {
            continue;
        };
        let Some(handler) = resolve_handler(&handler_symbol, &current_module, &imports) else {
            continue;
        };
        let mut guards = mounted_middleware
            .iter()
            .filter(|middleware| {
                middleware.receiver == receiver
                    && middleware.byte_offset < byte_offset
                    && express_route_is_under_mount(route_path, &middleware.path)
            })
            .flat_map(|middleware| middleware.guards.iter().cloned())
            .collect::<Vec<_>>();
        guards.extend(
            call.arguments[1..call.arguments.len() - 1]
                .iter()
                .filter_map(guard_name),
        );
        guards.sort();
        guards.dedup();
        // Express middleware is application-defined. Preserve exact route and
        // mount attachments, but leave their meaning to bounded review.
        let access = HttpRouteAccess::Unknown;
        routes
            .entry(handler.clone())
            .or_default()
            .push(ExpressRouteSummary {
                handler,
                method: verb.to_ascii_uppercase(),
                path: route_path.to_string(),
                access,
                guards,
            });
    }
}

fn express_route_is_under_mount(route: &str, mount: &str) -> bool {
    route == mount
        || route
            .strip_prefix(mount)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[derive(Clone, Debug)]
struct ImportTarget {
    module: String,
    export: Option<String>,
}

fn javascript_imports(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> BTreeMap<String, ImportTarget> {
    let mut imports = BTreeMap::new();
    for node in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = node.text();
        let Some((clause, module_text)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        let Some(imported) = exact_quoted(module_text.trim().trim_end_matches(';')) else {
            continue;
        };
        let Some(module) = resolve_module(path, imported) else {
            continue;
        };
        let clause = clause.trim();
        if let Some(alias) = clause.strip_prefix("* as ") {
            imports.insert(
                alias.trim().to_string(),
                ImportTarget {
                    module,
                    export: None,
                },
            );
        } else if clause.starts_with('{') {
            for entry in clause.trim_matches(['{', '}']).split(',') {
                let words = entry.split_whitespace().collect::<Vec<_>>();
                let Some(imported_name) = words.first().copied() else {
                    continue;
                };
                let visible = if words.get(1) == Some(&"as") {
                    words.get(2).copied().unwrap_or(imported_name)
                } else {
                    imported_name
                };
                imports.insert(
                    visible.to_string(),
                    ImportTarget {
                        module: module.clone(),
                        export: Some(imported_name.to_string()),
                    },
                );
            }
        } else if let Some(local) = simple_identifier(clause) {
            imports.insert(
                local.to_string(),
                ImportTarget {
                    module,
                    export: None,
                },
            );
        }
    }

    // CommonJS remains common in production Express applications. Keep this
    // bounded to direct `require` bindings and instances constructed from
    // those bindings so same-name methods do not gain invented identity.
    for declarator in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let (Some(name), Some(value)) = (declarator.field("name"), declarator.field("value"))
        else {
            continue;
        };
        let Some((module, export)) = commonjs_require_target(path, &value) else {
            continue;
        };
        if let Some(local) = simple_identifier(name.text().trim()) {
            imports.insert(local.to_string(), ImportTarget { module, export });
            continue;
        }
        if !matches!(name.kind().as_ref(), "object_pattern" | "object") {
            continue;
        }
        for property in name.children().filter(|child| child.is_named()) {
            let imported = property
                .field("key")
                .or_else(|| property.field("name"))
                .or_else(|| {
                    (property.kind().as_ref() == "shorthand_property_identifier_pattern")
                        .then_some(property.clone())
                });
            let local = property
                .field("value")
                .or_else(|| property.field("name"))
                .or_else(|| imported.clone());
            let (Some(imported), Some(local)) = (imported, local) else {
                continue;
            };
            let imported_text = imported.text();
            let local_text = local.text();
            let (Some(imported), Some(local)) = (
                simple_identifier(imported_text.trim()),
                simple_identifier(local_text.trim()),
            ) else {
                continue;
            };
            imports.insert(
                local.to_string(),
                ImportTarget {
                    module: module.clone(),
                    export: Some(imported.to_string()),
                },
            );
        }
    }

    let imported_constructors = imports.clone();
    for declarator in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let (Some(name), Some(value)) = (declarator.field("name"), declarator.field("value"))
        else {
            continue;
        };
        let name_text = name.text();
        let Some(local) = simple_identifier(name_text.trim()) else {
            continue;
        };
        if value.kind().as_ref() != "new_expression" {
            continue;
        }
        let constructor = value
            .field("constructor")
            .or_else(|| value.children().find(|child| child.is_named()));
        let Some(constructor) = constructor else {
            continue;
        };
        let Some(target) = imported_constructors.get(constructor.text().trim()) else {
            continue;
        };
        imports.insert(
            local.to_string(),
            ImportTarget {
                module: target.module.clone(),
                export: None,
            },
        );
    }
    imports
}

fn commonjs_require_target(
    path: &str,
    value: &Node<'_, StrDoc<SupportLang>>,
) -> Option<(String, Option<String>)> {
    if let Some(call) = call_site(value.clone())
        && call.callee == "require"
        && call.arguments.len() == 1
    {
        let imported_text = call.arguments[0].text();
        let imported = exact_quoted(imported_text.trim())?;
        return Some((resolve_module(path, imported)?, None));
    }
    if value.kind().as_ref() != "member_expression" {
        return None;
    }
    let object = value.field("object")?;
    let property = value.field("property")?;
    let call = call_site(object)?;
    if call.callee != "require" || call.arguments.len() != 1 {
        return None;
    }
    let imported_text = call.arguments[0].text();
    let property_text = property.text();
    let imported = exact_quoted(imported_text.trim())?;
    let export = simple_identifier(property_text.trim())?.to_string();
    Some((resolve_module(path, imported)?, Some(export)))
}

fn unwrap_handler(
    node: &Node<'_, StrDoc<SupportLang>>,
    current_module: &str,
    imports: &BTreeMap<String, ImportTarget>,
    wrappers: &BTreeSet<String>,
    depth: usize,
) -> Option<String> {
    if depth > 1 {
        return None;
    }
    if let Some(call) = call_site(node.clone()) {
        let wrapper = resolve_handler(&call.callee, current_module, imports);
        if call.arguments.len() == 1
            && (terminal_symbol(&call.callee) == "asyncHandler"
                || wrapper.as_ref().is_some_and(|name| wrappers.contains(name)))
        {
            return unwrap_handler(
                &call.arguments[0],
                current_module,
                imports,
                wrappers,
                depth + 1,
            );
        }
        return Some(call.callee);
    }
    let text = node.text();
    (!text.contains("=>")).then(|| text.trim().to_string())
}

fn collect_parameter_return_summaries(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    summaries: &mut BTreeMap<String, ParameterReturnSummary>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    for (name, function) in exported_functions(root) {
        let parameters = function_parameter_names(&function);
        let Some(expression) = single_effective_return(&function) else {
            continue;
        };
        for (parameter_index, parameter) in parameters.iter().enumerate() {
            let Some(returned_suffix) =
                parameter_return_suffix(expression.text().as_ref(), parameter)
            else {
                continue;
            };
            let canonical = format!("{module}.{name}");
            summaries.insert(
                canonical.clone(),
                ParameterReturnSummary {
                    canonical,
                    parameter_index,
                    returned_suffix,
                },
            );
            break;
        }
    }
}

fn collect_parameter_sink_summaries(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    summaries: &mut BTreeMap<String, Vec<ParameterSinkSummary>>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    for (name, function) in exported_functions(root) {
        let parameters = function_parameter_names(&function);
        let mut matches = Vec::new();
        if !function_has_control_flow(&function) {
            matches.extend(calls_in_function(&function).filter_map(|call| {
                let sink = summary_sink(&call.callee)?;
                if matches!(sink, SummarySink::Redirect | SummarySink::HtmlOutput) {
                    let compact_callee = compact(&call.callee);
                    let receiver = compact_callee
                        .rsplit_once('.')
                        .map(|(receiver, _)| receiver)?;
                    if !parameters.iter().any(|parameter| parameter == receiver) {
                        return None;
                    }
                }
                let sink_argument = call.arguments.first()?;
                let sink_argument = compact(sink_argument.text().as_ref());
                let parameter_index = parameters
                    .iter()
                    .position(|parameter| parameter == &sink_argument)?;
                Some((parameter_index, sink))
            }));
        }
        matches.extend(legacy_mongo_parameter_sinks(root, &function, &parameters));
        matches.extend(postgres_js_parameter_sinks(root, &function, &parameters));
        matches.sort_by_key(|(index, sink)| (*index, *sink as u8));
        matches.dedup();
        if matches.is_empty() {
            continue;
        }
        let canonical = format!("{module}.{name}");
        summaries
            .entry(canonical.clone())
            .or_default()
            .extend(
                matches
                    .into_iter()
                    .map(|(parameter_index, sink)| ParameterSinkSummary {
                        canonical: canonical.clone(),
                        parameter_index,
                        sink,
                    }),
            );
    }
}

fn collect_local_template_parameter_sinks(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    summaries: &mut BTreeMap<String, Vec<ParameterSinkSummary>>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    let imports = javascript_imports(path, root);
    for (name, function) in named_functions(root) {
        let parameters = function_parameter_names(&function);
        if parameters.is_empty() {
            continue;
        }
        for call in calls_in_function(&function) {
            if !is_ejs_render(&call.callee, &imports) {
                continue;
            }
            let Some(template) = call.arguments.first() else {
                continue;
            };
            for (parameter_index, parameter) in parameters.iter().enumerate() {
                if !template_depends_on_parameter(root, &function, template, parameter) {
                    continue;
                }
                let canonical = format!("{module}.{name}");
                let summary = ParameterSinkSummary {
                    canonical: canonical.clone(),
                    parameter_index,
                    sink: SummarySink::TemplateEvaluation,
                };
                let entries = summaries.entry(canonical).or_default();
                if !entries.contains(&summary) {
                    entries.push(summary);
                }
            }
        }
    }
}

fn has_ejs_import(source: &str) -> bool {
    [
        "require('ejs')",
        "require(\"ejs\")",
        "from 'ejs'",
        "from \"ejs\"",
    ]
    .iter()
    .any(|import| source.contains(import))
}

fn named_functions<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<(String, Node<'tree, StrDoc<SupportLang>>)> {
    let mut functions = Vec::new();
    for node in root.dfs() {
        if node.kind().as_ref() == "function_declaration" {
            if let Some(name) = node
                .field("name")
                .and_then(|name| simple_identifier(name.text().trim()).map(str::to_string))
            {
                functions.push((name, node));
            }
            continue;
        }
        if node.kind().as_ref() != "variable_declarator" {
            continue;
        }
        let (Some(name), Some(value)) = (node.field("name"), node.field("value")) else {
            continue;
        };
        if is_function_node(&value)
            && let Some(name) = simple_identifier(name.text().trim())
        {
            functions.push((name.to_string(), value));
        }
    }
    functions
}

fn is_ejs_render(callee: &str, imports: &BTreeMap<String, ImportTarget>) -> bool {
    if let Some((receiver, method)) = callee.split_once('.') {
        return method == "render"
            && imports
                .get(receiver)
                .is_some_and(|target| target.module == "ejs" && target.export.is_none());
    }
    imports
        .get(callee)
        .is_some_and(|target| target.module == "ejs" && target.export.as_deref() == Some("render"))
}

fn template_depends_on_parameter(
    root: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
    template: &Node<'_, StrDoc<SupportLang>>,
    parameter: &str,
) -> bool {
    if expression_uses_identifier(template, function, parameter) {
        return true;
    }
    let template_text = compact(template.text().as_ref());
    let Some(name) = simple_identifier(&template_text) else {
        return false;
    };
    latest_assigned_value(root, name, template.range().start, &function.range())
        .is_some_and(|value| expression_uses_identifier(&value, function, parameter))
}

fn expression_uses_identifier(
    expression: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
) -> bool {
    expression.dfs().any(|node| {
        node.kind().as_ref() == "identifier"
            && node.text().trim() == name
            && nearest_function_range(&node) == Some(function.range())
    })
}

fn legacy_mongo_parameter_sinks(
    root: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
    parameters: &[String],
) -> Vec<(usize, SummarySink)> {
    if !root.text().contains(".collection(") {
        return Vec::new();
    }
    let text = compact(function.text().as_ref());
    let has_query = [".find(", ".findOne(", ".update(", ".remove(", ".delete("]
        .iter()
        .any(|operation| text.contains(operation));
    if !has_query && !text.contains(".insert(") {
        return Vec::new();
    }
    let mut matches = Vec::new();
    if text.contains("$where:") {
        for (index, parameter) in parameters.iter().enumerate() {
            if text.contains(&format!("${{{parameter}}}")) {
                matches.push((index, SummarySink::NosqlQuery));
            }
        }
    }
    if has_query {
        for (index, parameter) in parameters.iter().enumerate() {
            let normalized = normalize_property_name(parameter);
            if matches!(
                normalized.as_str(),
                "userid" | "ownerid" | "accountid" | "tenantid" | "resourceid"
            ) && (text.contains(&format!("parseInt({parameter}"))
                || text.contains(&format!("{parameter}:"))
                || text.contains(&format!(":{parameter}")))
            {
                matches.push((index, SummarySink::ResourceAccess));
            }
        }
    }
    if text.contains(".insert(") {
        for (index, parameter) in parameters.iter().enumerate() {
            if normalize_property_name(parameter) != "password" {
                continue;
            }
            let transformed = calls_in_function(function).any(|call| {
                let callee = call.callee.to_ascii_lowercase();
                ["bcrypt", "argon2", "scrypt", "pbkdf2"]
                    .iter()
                    .any(|algorithm| callee.contains(algorithm))
                    && call
                        .arguments
                        .iter()
                        .any(|argument| argument.text().contains(parameter))
            });
            if !transformed && text.contains(parameter) {
                matches.push((index, SummarySink::PasswordStorage));
            }
        }
    }
    matches
}

fn collect_callback_forward_summaries(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    summaries: &mut BTreeMap<String, CallbackForwardSummary>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    for (name, function) in exported_functions(root) {
        if function_has_control_flow(&function) {
            continue;
        }
        let parameters = function_parameter_names(&function);
        let forwards = calls_in_function(&function)
            .filter_map(|call| {
                let callback_index = parameters
                    .iter()
                    .position(|parameter| parameter == &call.callee)?;
                if call.arguments.len() != 1 {
                    return None;
                }
                let argument = compact(call.arguments[0].text().as_ref());
                let value_index = parameters
                    .iter()
                    .position(|parameter| parameter == &argument)?;
                (value_index != callback_index).then_some((value_index, callback_index))
            })
            .collect::<Vec<_>>();
        if forwards.len() != 1 {
            continue;
        }
        let canonical = format!("{module}.{name}");
        summaries.insert(
            canonical.clone(),
            CallbackForwardSummary {
                canonical,
                value_index: forwards[0].0,
                callback_index: forwards[0].1,
            },
        );
    }
}

fn collect_mongo_callback_result_summaries(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    summaries: &mut BTreeMap<String, MongoCallbackResultSummary>,
) {
    if !root.text().contains(".collection(") {
        return;
    }
    let Some(module) = module_path(path) else {
        return;
    };
    for (name, function) in exported_functions(root) {
        let parameters = function_parameter_names(&function);
        let Some(callback_index) = parameters.iter().position(|parameter| {
            matches!(
                normalize_property_name(parameter).as_str(),
                "callback" | "cb" | "done" | "next"
            )
        }) else {
            continue;
        };
        let callback = &parameters[callback_index];
        let text = compact(function.text().as_ref());
        let reads_mongo = [".find(", ".findOne("]
            .iter()
            .any(|operation| text.contains(operation));
        if !reads_mongo {
            continue;
        }
        let forwards_result = function.dfs().filter_map(call_site).any(|call| {
            (call.callee == *callback
                && call.arguments.len() >= 2
                && matches!(call.arguments[0].text().trim(), "null" | "undefined"))
                || (matches!(
                    terminal_symbol(&call.callee),
                    "find" | "findOne" | "toArray"
                ) && call
                    .arguments
                    .iter()
                    .any(|argument| argument.text().trim() == callback))
        });
        if !forwards_result {
            continue;
        }
        let canonical = format!("{module}.{name}");
        summaries.insert(
            canonical.clone(),
            MongoCallbackResultSummary {
                canonical,
                callback_index,
                result_index: 1,
            },
        );
    }
}

fn is_express_html_output_use(
    node: &Node<'_, StrDoc<SupportLang>>,
    callback: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    node.ancestors()
        .take_while(|ancestor| ancestor.range() != callback.range())
        .filter_map(call_site)
        .any(|call| {
            matches!(
                terminal_symbol(&call.callee),
                "render" | "send" | "write" | "end"
            )
        })
}

fn collect_xxe_parser_summaries(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    summaries: &mut BTreeMap<String, XxeParserSummary>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    let file_text = root.text();
    if !file_text.contains("xmlRegisterFsInputProviders") {
        return;
    }
    for (name, function) in exported_functions(root) {
        let parameters = function_parameter_names(&function);
        let function_text = function.text();
        let Some(parameter_index) = parameters.iter().position(|parameter| {
            function_text.contains("XML_PARSE_NOENT")
                && function_text.contains("XML_PARSE_DTDLOAD")
                && function_text.contains("vm.runInContext")
                && function_text.contains(&format!("XmlDocument.fromString({parameter}"))
        }) else {
            continue;
        };
        let canonical = format!("{module}.{name}");
        summaries.insert(
            canonical.clone(),
            XxeParserSummary {
                canonical,
                parameter_index,
            },
        );
    }
}

fn calls_in_function<'node, 'tree>(
    function: &'node Node<'tree, StrDoc<SupportLang>>,
) -> impl Iterator<Item = CallSite<'tree>> + 'node {
    function
        .dfs()
        .filter_map(call_site)
        .filter(|call| nearest_function_range(&call.node) == Some(function.range()))
}

fn function_has_control_flow(function: &Node<'_, StrDoc<SupportLang>>) -> bool {
    function.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "if_statement"
                | "switch_statement"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "do_statement"
                | "try_statement"
        ) && nearest_function_range(&node) == Some(function.range())
    })
}

fn summary_sink(callee: &str) -> Option<SummarySink> {
    let callee = compact(callee);
    match callee.as_str() {
        "child_process.exec"
        | "child_process.execSync"
        | "child_process.execFile"
        | "child_process.execFileSync"
        | "child_process.spawn"
        | "child_process.spawnSync"
        | "child_process.fork" => Some(SummarySink::Process),
        "eval" | "global.eval" => Some(SummarySink::DynamicCode),
        "fs.readFile" | "fs.readFileSync" => Some(SummarySink::FilesystemRead),
        "fetch" | "axios.get" | "axios.post" | "axios.put" | "axios.patch" | "axios.delete"
        | "axios.head" | "axios.options" | "http.get" | "https.get" | "request.get"
        | "needle.get" => Some(SummarySink::OutboundRequest),
        "yaml.load" | "jsyaml.load" | "js_yaml.load" => Some(SummarySink::Deserialization),
        _ if terminal_symbol(&callee) == "redirect" => Some(SummarySink::Redirect),
        _ if matches!(terminal_symbol(&callee), "send" | "write") => Some(SummarySink::HtmlOutput),
        _ => None,
    }
}

fn postgres_js_parameter_sinks(
    root: &Node<'_, StrDoc<SupportLang>>,
    function: &Node<'_, StrDoc<SupportLang>>,
    parameters: &[String],
) -> Vec<(usize, SummarySink)> {
    let imports = javascript_imports("module.ts", root);
    let constructors = imports
        .iter()
        .filter_map(|(visible, target)| (target.module == "postgres").then_some(visible.as_str()))
        .collect::<BTreeSet<_>>();
    if constructors.is_empty() {
        return Vec::new();
    }
    let clients = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = compact(&declaration.field("value")?.text()).replace('!', "");
            constructors
                .iter()
                .any(|constructor| value.contains(&format!("{constructor}(")))
                .then(|| name.text().trim().to_string())
        })
        .collect::<BTreeSet<_>>();
    calls_in_function(function)
        .filter(|call| {
            let callee = compact(&call.callee).replace('!', "");
            clients
                .iter()
                .any(|client| callee == format!("{client}.unsafe"))
        })
        .filter_map(|call| call.arguments.first().cloned())
        .flat_map(|query| {
            let query = query.text().into_owned();
            parameters
                .iter()
                .enumerate()
                .filter(move |(_, parameter)| contains_identifier(&query, parameter))
                .map(|(index, _)| (index, SummarySink::SqlQuery))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn contains_identifier(text: &str, identifier: &str) -> bool {
    text.match_indices(identifier).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let end = start + identifier.len();
        let after = text[end..].chars().next();
        before.is_none_or(|character| !is_identifier_character(character))
            && after.is_none_or(|character| !is_identifier_character(character))
    })
}

fn is_identifier_character(character: char) -> bool {
    character == '_' || character == '$' || character.is_alphanumeric()
}

fn collect_express_wrappers(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    wrappers: &mut BTreeSet<String>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    for (name, function) in exported_functions(root) {
        let parameters = function_parameter_names(&function);
        if parameters.len() != 1 || !function_returns_handler_call(&function, &parameters[0]) {
            continue;
        }
        wrappers.insert(format!("{module}.{name}"));
    }
}

fn exported_functions<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<(String, Node<'tree, StrDoc<SupportLang>>)> {
    let mut functions = Vec::new();
    let mut constructors = Vec::new();
    let commonjs_exports = commonjs_exported_names(root);
    for node in root.dfs() {
        if node.kind().as_ref() == "function_declaration" {
            if let Some(name) = node
                .field("name")
                .and_then(|name| simple_identifier(name.text().trim()).map(str::to_string))
                && (is_exported(&node) || commonjs_exports.contains(&name))
            {
                constructors.push(node.clone());
                functions.push((name, node));
            }
            continue;
        }
        if node.kind().as_ref() != "variable_declarator" {
            continue;
        }
        let Some(name) = node
            .field("name")
            .and_then(|name| simple_identifier(name.text().trim()).map(str::to_string))
        else {
            continue;
        };
        if !is_exported(&node) && !commonjs_exports.contains(&name) {
            continue;
        }
        let Some(value) = node.field("value") else {
            continue;
        };
        if is_function_node(&value) {
            constructors.push(value.clone());
            functions.push((name, value));
        }
    }
    for constructor in constructors {
        for assignment in constructor
            .dfs()
            .filter(|node| node.kind().as_ref() == "assignment_expression")
        {
            if nearest_function_range(&assignment) != Some(constructor.range()) {
                continue;
            }
            let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
            else {
                continue;
            };
            let left = compact(left.text().as_ref());
            let Some(method) = left.strip_prefix("this.").and_then(simple_identifier) else {
                continue;
            };
            if is_function_node(&right) {
                functions.push((method.to_string(), right));
            }
        }
    }
    functions
}

fn commonjs_exported_names(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let left = compact(left.text().as_ref());
        if left == "module.exports" {
            if let Some(name) = simple_identifier(right.text().trim()) {
                names.insert(name.to_string());
            } else if matches!(right.kind().as_ref(), "object" | "object_pattern") {
                names.extend(
                    right
                        .dfs()
                        .filter(|node| node.kind().as_ref().contains("identifier"))
                        .filter_map(|node| {
                            simple_identifier(node.text().trim()).map(str::to_string)
                        }),
                );
            }
            continue;
        }
        let Some(export) = left
            .strip_prefix("module.exports.")
            .or_else(|| left.strip_prefix("exports."))
            .and_then(simple_identifier)
        else {
            continue;
        };
        if right.text().trim() == export {
            names.insert(export.to_string());
        }
    }
    names
}

fn is_exported(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors()
        .take_while(|ancestor| ancestor.kind().as_ref() != "program")
        .any(|ancestor| ancestor.kind().as_ref() == "export_statement")
}

fn is_function_node(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "method_definition"
    )
}

fn function_parameter_names(function: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    let mut parameters = function
        .field("parameters")
        .map(|parameters| {
            parameters
                .children()
                .filter(|child| child.is_named())
                .filter_map(parameter_identifier)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if parameters.is_empty()
        && let Some(parameter) = function.field("parameter").and_then(parameter_identifier)
    {
        parameters.push(parameter);
    }
    parameters
}

fn parameter_identifier(parameter: Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if parameter.kind().as_ref() == "identifier" {
        return simple_identifier(parameter.text().trim()).map(str::to_string);
    }
    for field in ["pattern", "name"] {
        if let Some(identifier) = parameter.field(field)
            && let Some(name) = simple_identifier(identifier.text().trim())
        {
            return Some(name.to_string());
        }
    }
    parameter
        .dfs()
        .find(|node| node.kind().as_ref() == "identifier")
        .and_then(|node| simple_identifier(node.text().trim()).map(str::to_string))
}

fn single_effective_return<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let body = function.field("body")?;
    if !matches!(body.kind().as_ref(), "statement_block" | "block") {
        return (!is_function_node(&body)).then_some(body);
    }
    if body.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "if_statement"
                | "switch_statement"
                | "for_statement"
                | "for_in_statement"
                | "while_statement"
                | "do_statement"
                | "try_statement"
        ) && nearest_function_range(&node) == Some(function.range())
    }) {
        return None;
    }
    let returns = body
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "return_statement"
                && nearest_function_range(node) == Some(function.range())
        })
        .filter_map(|node| node.children().find(|child| child.is_named()))
        .collect::<Vec<_>>();
    (returns.len() == 1).then(|| returns[0].clone())
}

fn nearest_function_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(is_function_node)
        .map(|function| function.range())
}

fn parameter_return_suffix(expression: &str, parameter: &str) -> Option<String> {
    let expression = compact(expression);
    let suffix = expression.strip_prefix(parameter)?;
    if !suffix.is_empty() && !suffix.starts_with('.') && !suffix.starts_with('[') {
        return None;
    }
    if suffix.contains('(')
        || suffix.contains('?')
        || suffix.contains('`')
        || suffix.chars().any(|character| {
            !(character.is_ascii_alphanumeric()
                || matches!(character, '_' | '.' | '[' | ']' | '\'' | '"'))
        })
    {
        return None;
    }
    Some(suffix.to_string())
}

fn function_returns_handler_call(function: &Node<'_, StrDoc<SupportLang>>, handler: &str) -> bool {
    function.dfs().any(|inner| {
        is_function_node(&inner)
            && inner.range() != function.range()
            && nearest_function_range(&inner) == Some(function.range())
            && inner.dfs().any(|node| {
                call_site(node).is_some_and(|call| {
                    call.callee == handler
                        && call.arguments.len() >= 2
                        && nearest_function_range(&call.node) == Some(inner.range())
                })
            })
    })
}

fn request_argument_matches(
    argument: &Node<'_, StrDoc<SupportLang>>,
    call: &Node<'_, StrDoc<SupportLang>>,
    returned_suffix: &str,
) -> bool {
    let argument_text = compact(argument.text().as_ref());
    let request_access = format!("{argument_text}{returned_suffix}").to_ascii_lowercase();
    if ![".body", ".query", ".params", ".headers", ".cookies"]
        .iter()
        .any(|field| request_access.contains(field))
    {
        return false;
    }
    let root_name = argument_text
        .split(['.', '['])
        .next()
        .and_then(simple_identifier);
    let Some(root_name) = root_name else {
        return false;
    };
    let Some(function) = call.ancestors().find(is_function_node) else {
        return false;
    };
    function_parameter_names(&function)
        .iter()
        .any(|parameter| parameter == root_name)
        && (matches!(root_name, "req" | "request" | "ctx" | "context")
            || function
                .field("parameters")
                .is_some_and(|parameters| parameters.text().contains("Request")))
}

fn promise_resolve_continuation<'tree>(
    then_call: &CallSite<'tree>,
) -> Option<PromiseContinuation<'tree>> {
    if terminal_symbol(&then_call.callee) != "then" || then_call.arguments.len() != 1 {
        return None;
    }
    let function = then_call.node.field("function")?;
    let promise_node = function.field("object")?;
    let promise_call = call_site(promise_node)?;
    if compact(&promise_call.callee) != "Promise.resolve" || promise_call.arguments.len() != 1 {
        return None;
    }
    let callback = then_call.arguments[0].clone();
    if !is_function_node(&callback) || function_parameter_nodes(&callback).len() != 1 {
        return None;
    }
    Some(PromiseContinuation {
        value: promise_call.arguments[0].clone(),
        callback,
        canonical: "Promise.resolve.then",
    })
}

fn subscribe_next_callback<'tree>(
    subscribe_call: &CallSite<'tree>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if subscribe_call.arguments.len() != 1 {
        return None;
    }
    let argument = subscribe_call.arguments[0].clone();
    if is_function_node(&argument) {
        return Some(argument);
    }
    argument
        .children()
        .filter(|child| child.is_named())
        .find_map(|property| {
            let key = property.field("key")?;
            if normalize_property_name(key.text().as_ref()) != "next" {
                return None;
            }
            property.field("value").filter(is_function_node)
        })
}

#[allow(clippy::too_many_arguments)]
fn push_angular_callback_sources<'tree>(
    path: &str,
    language: Language,
    callback: &Node<'tree, StrDoc<SupportLang>>,
    observed: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(parameters) = callback
        .field("parameters")
        .or_else(|| callback.field("parameter"))
    else {
        return;
    };
    let bindings = parameters
        .dfs()
        .filter(|node| node.kind().as_ref() == "identifier")
        .take(4)
        .collect::<Vec<_>>();
    for binding in bindings {
        let name = binding.text().into_owned();
        for value_use in callback
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "identifier"
                    && node.range() != binding.range()
                    && node.text().trim() == name
                    && nearest_function_range(node) == Some(callback.range())
            })
            .take(4)
        {
            push_angular_source_evidence(
                path,
                language,
                callback,
                observed,
                &value_use,
                "callback-parameter-use",
                "maximum-depth-1",
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        let aliases = callback
            .dfs()
            .filter(|node| node.kind().as_ref() == "assignment_expression")
            .filter_map(|assignment| {
                let left = assignment.field("left")?;
                let right = assignment.field("right")?;
                (compact(right.text().as_ref()) == name).then(|| compact(left.text().as_ref()))
            })
            .take(4)
            .collect::<BTreeSet<_>>();
        if aliases.is_empty() {
            continue;
        }
        for loop_node in callback
            .dfs()
            .filter(|node| node.kind().as_ref() == "for_in_statement")
        {
            let Some(iterated) = loop_node.field("right") else {
                continue;
            };
            if !aliases.contains(&compact(iterated.text().as_ref())) {
                continue;
            }
            let Some(loop_binding) = loop_node
                .field("left")
                .and_then(|left| left.dfs().find(|node| node.kind().as_ref() == "identifier"))
            else {
                continue;
            };
            let loop_name = loop_binding.text().into_owned();
            let Some(body) = loop_node.field("body") else {
                continue;
            };
            for value_use in body
                .dfs()
                .filter(|node| {
                    node.kind().as_ref() == "identifier"
                        && node.range() != loop_binding.range()
                        && node.text().trim() == loop_name
                        && nearest_function_range(node) == Some(callback.range())
                        && node.parent().is_some_and(|parent| {
                            matches!(
                                parent.kind().as_ref(),
                                "member_expression" | "subscript_expression"
                            ) && parent
                                .field("object")
                                .is_some_and(|object| object.range() == node.range())
                        })
                })
                .take(4)
            {
                push_angular_source_evidence(
                    path,
                    language,
                    callback,
                    observed,
                    &value_use,
                    "callback-parameter-alias-loop-use",
                    "maximum-depth-2",
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_angular_local_trust_helper_sources<'tree>(
    path: &str,
    language: Language,
    root: &Node<'tree, StrDoc<SupportLang>>,
    callback: &Node<'tree, StrDoc<SupportLang>>,
    source_bindings: &BTreeSet<String>,
    observed: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in calls_in_function(callback).take(4) {
        let helper_name = terminal_symbol(&call.callee);
        let Some((argument_index, _)) = call.arguments.iter().enumerate().find(|(_, argument)| {
            source_bindings.contains(compact(argument.text().as_ref()).as_str())
        }) else {
            continue;
        };
        let Some(helper) = root.dfs().find(|node| {
            node.kind().as_ref() == "method_definition"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == helper_name)
        }) else {
            continue;
        };
        let parameters = function_parameter_names(&helper);
        let Some(parameter) = parameters.get(argument_index) else {
            continue;
        };
        for sink in calls_in_function(&helper)
            .filter(|sink| terminal_symbol(&sink.callee) == "bypassSecurityTrustHtml")
            .take(2)
        {
            let Some(content) = sink.arguments.first() else {
                continue;
            };
            let Some(value_use) = content.dfs().find(|node| {
                node.kind().as_ref() == "identifier" && node.text().trim() == parameter
            }) else {
                continue;
            };
            push_angular_source_evidence(
                path,
                language,
                &helper,
                observed,
                &value_use,
                "callback-parameter-local-helper-use",
                "maximum-depth-2",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn angular_fork_join_service_bindings(
    root: &Node<'_, StrDoc<SupportLang>>,
    subscription: &CallSite<'_>,
    callback: &Node<'_, StrDoc<SupportLang>>,
) -> BTreeSet<String> {
    let callee = compact(&subscription.callee);
    if !callee.to_ascii_lowercase().contains("forkjoin(") {
        return BTreeSet::new();
    }
    let Some(parameters) = callback.field("parameters") else {
        return BTreeSet::new();
    };
    let scope = nearest_function_range(&subscription.node).unwrap_or_else(|| root.range());
    let reviewed_services = [
        "productservice.search",
        "feedbackservice.find",
        "userservice.find",
        "trackorderservice.find",
    ];
    callee
        .split(|character: char| !is_identifier_character(character))
        .filter_map(simple_identifier)
        .filter(|binding| contains_identifier(parameters.text().as_ref(), binding))
        .filter(|binding| {
            latest_declaration(root, binding, subscription.node.range().start, &scope)
                .and_then(|declaration| declaration.field("value"))
                .and_then(call_site)
                .is_some_and(|producer| {
                    let producer = compact(&producer.callee).to_ascii_lowercase();
                    reviewed_services
                        .iter()
                        .any(|service| producer.contains(service))
                })
        })
        .map(str::to_string)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_angular_source_evidence<'tree>(
    path: &str,
    language: Language,
    callback: &Node<'tree, StrDoc<SupportLang>>,
    observed: &str,
    value_use: &Node<'tree, StrDoc<SupportLang>>,
    use_tag: &str,
    depth_tag: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = language_rule(language, "angular-rxjs-stored-source");
    let id = evidence_id(
        path,
        rule_id,
        value_use.range().start,
        value_use.range().end,
    );
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind: EvidenceKind::Source,
        capability: Capability::StoredUserContent,
        location: location(path, value_use),
        enclosing_symbol: enclosing_symbol(callback),
        captures: BTreeMap::from([("value".to_string(), capture(path, value_use))]),
        cwe_candidates: Vec::new(),
        tags: vec![
            "angular".to_string(),
            "rxjs".to_string(),
            "service-response".to_string(),
            use_tag.to_string(),
            depth_tag.to_string(),
            "maximum-bindings-4".to_string(),
            "maximum-uses-per-binding-4".to_string(),
        ],
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ANGULAR_RXJS_ENGINE.to_string(),
            rule_version: 1,
        },
        context: evidence_context(value_use, comments, conditional, literals),
        symbol_resolution: Some(SymbolResolution {
            canonical: "rxjs.Observable.subscribe.next".to_string(),
            observed: observed.to_string(),
            method: SymbolResolutionMethod::Alias,
            confidence: SymbolConfidence::High,
        }),
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

#[allow(clippy::too_many_arguments)]
fn push_continuation_source<'tree>(
    path: &str,
    language: Language,
    callback: &Node<'tree, StrDoc<SupportLang>>,
    canonical: &str,
    observed: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !is_function_node(callback) {
        return;
    }
    let parameters = function_parameter_nodes(callback);
    if parameters.len() != 1 {
        return;
    }
    let parameter = &parameters[0];
    let parameter_name = parameter.text().into_owned();
    let uses = callback
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "identifier"
                && node.range() != parameter.range()
                && node.text().trim() == parameter_name
                && nearest_function_range(node) == Some(callback.range())
        })
        .take(4)
        .collect::<Vec<_>>();
    let rule_id = language_rule(language, "async-continuation-request-source");
    for value_use in uses {
        let id = evidence_id(
            path,
            rule_id,
            value_use.range().start,
            value_use.range().end,
        );
        if evidence.iter().any(|item| item.id == id) {
            continue;
        }
        evidence.push(Evidence {
            id,
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location(path, &value_use),
            enclosing_symbol: enclosing_symbol(callback),
            captures: BTreeMap::from([("value".to_string(), capture(path, &value_use))]),
            cwe_candidates: Vec::new(),
            tags: vec![
                "async-continuation".to_string(),
                "callback-parameter-use".to_string(),
                "maximum-depth-1".to_string(),
                "maximum-uses-4".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ASYNC_CONTINUATION_ENGINE.to_string(),
                rule_version: 1,
            },
            context: evidence_context(&value_use, comments, conditional, literals),
            symbol_resolution: Some(SymbolResolution {
                canonical: canonical.to_string(),
                observed: observed.to_string(),
                method: SymbolResolutionMethod::Alias,
                confidence: SymbolConfidence::High,
            }),
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn function_parameter_nodes<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    let mut parameters = function
        .field("parameters")
        .map(|parameters| {
            parameters
                .children()
                .filter(|child| child.is_named())
                .filter_map(parameter_identifier_node)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if parameters.is_empty()
        && let Some(parameter) = function
            .field("parameter")
            .and_then(parameter_identifier_node)
    {
        parameters.push(parameter);
    }
    parameters
}

fn parameter_identifier_node(
    parameter: Node<'_, StrDoc<SupportLang>>,
) -> Option<Node<'_, StrDoc<SupportLang>>> {
    if parameter.kind().as_ref() == "identifier" {
        return Some(parameter);
    }
    for field in ["pattern", "name"] {
        if let Some(identifier) = parameter.field(field)
            && identifier.kind().as_ref() == "identifier"
        {
            return Some(identifier);
        }
    }
    parameter
        .dfs()
        .find(|node| node.kind().as_ref() == "identifier")
}

fn is_direct_return_value(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if node.parent().is_some_and(|parent| {
        parent.kind().as_ref() == "return_statement"
            && parent
                .children()
                .find(|child| child.is_named())
                .is_some_and(|value| value.range() == node.range())
    }) {
        return true;
    }
    node.parent().is_some_and(|parent| {
        parent.kind().as_ref() == "arrow_function"
            && parent
                .field("body")
                .is_some_and(|body| body.range() == node.range())
    })
}

fn resolve_handler(
    observed: &str,
    current_module: &str,
    imports: &BTreeMap<String, ImportTarget>,
) -> Option<String> {
    if let Some((head, tail)) = observed.split_once('.') {
        let target = imports.get(head)?;
        if target.export.is_some() || simple_identifier(tail).is_none() {
            return None;
        }
        return Some(format!("{}.{}", target.module, tail));
    }
    let observed = simple_identifier(observed)?;
    if let Some(target) = imports.get(observed) {
        return Some(format!("{}.{}", target.module, target.export.as_deref()?));
    }
    Some(format!("{current_module}.{observed}"))
}

fn guard_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if let Some(call) = call_site(node.clone()) {
        return Some(call.callee);
    }
    let text = node.text();
    let name = simple_identifier(text.trim())?;
    Some(name.to_string())
}

fn handler_reads_collection(
    root: &Node<'_, StrDoc<SupportLang>>,
    handler: &str,
    model: &str,
) -> bool {
    handler_node(root, handler).is_some_and(|function| {
        function.dfs().any(|node| {
            call_site(node).is_some_and(|call| call.callee == format!("{model}.findAll"))
        })
    })
}

fn handler_is_read_only_for_model(
    root: &Node<'_, StrDoc<SupportLang>>,
    handler: &str,
    model: &str,
) -> bool {
    let Some(function) = handler_node(root, handler) else {
        return false;
    };
    !function.dfs().any(|node| {
        call_site(node).is_some_and(|call| {
            matches!(
                call.callee.strip_prefix(&format!("{model}.")),
                Some("create" | "update" | "destroy" | "upsert" | "bulkCreate")
            )
        })
    })
}

fn handler_node<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "function_declaration")
        .find(|node| {
            node.field("name")
                .is_some_and(|field| field.text().trim() == name)
        })
}

fn collection_route(path: &str) -> Option<String> {
    let (prefix, terminal) = path.rsplit_once('/')?;
    terminal.starts_with(':').then(|| prefix.to_string())
}

/// Records middleware only when its repository definition shows the owner
/// field being overwritten from authenticated server-side identity. A route
/// helper name by itself is not proof of this behavior.
fn collect_owner_field_overwrite_guards(source: &str, guards: &mut BTreeSet<String>) {
    let mut declarations = source
        .match_indices("export const ")
        .map(|(index, marker)| (index, index + marker.len()))
        .chain(
            source
                .match_indices("export function ")
                .map(|(index, marker)| (index, index + marker.len())),
        )
        .collect::<Vec<_>>();
    declarations.sort_by_key(|(index, _)| *index);
    for (position, (_, name_start)) in declarations.iter().enumerate() {
        let name = source[*name_start..]
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
            .collect::<String>();
        if name.is_empty() {
            continue;
        }
        let body_end = declarations
            .get(position + 1)
            .map_or(source.len(), |(index, _)| *index);
        let body = &source[*name_start..body_end];
        let overwrites_owner = body.lines().any(|line| {
            let compact_line = compact(line);
            let Some((_, value)) = compact_line
                .split_once("req.body.UserId=")
                .or_else(|| compact_line.split_once("req.body.userId="))
            else {
                return false;
            };
            value.contains("req.user.")
                || value.contains("authenticatedUser")
                || value.contains("authenticatedUsers")
                || value.contains("decodedToken")
                || value.contains("jwt.verify")
        });
        if overwrites_owner && body.contains("next()") {
            guards.insert(name);
        }
    }
}

fn resource_filter_has_owner_scope(root: &Node<'_, StrDoc<SupportLang>>, sink: &Evidence) -> bool {
    let Some(filter) = sink.captures.get("filter") else {
        return false;
    };
    let Some(filter_node) = smallest_node_containing(root, location_range(&filter.location)) else {
        return false;
    };
    if !matches!(filter_node.kind().as_ref(), "object" | "object_expression") {
        return false;
    }
    let scope = function_scope(&filter_node, root);
    filter_node
        .children()
        .filter(|child| child.is_named())
        .any(|property| {
            let shorthand = matches!(
                property.kind().as_ref(),
                "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
            );
            let key = property
                .field("key")
                .or_else(|| shorthand.then(|| property.clone()));
            let Some(key) = key else { return false };
            if !matches!(
                normalize_property_name(key.text().as_ref()).as_str(),
                "userid"
                    | "ownerid"
                    | "accountid"
                    | "tenantid"
                    | "organizationid"
                    | "organisationid"
            ) {
                return false;
            }
            let value = property
                .field("value")
                .or_else(|| shorthand.then_some(property));
            value.is_some_and(|value| {
                resource_owner_value_is_authenticated(
                    root,
                    value,
                    sink.location.start.byte_offset,
                    &scope,
                    2,
                )
            })
        })
}

fn resource_filter_has_route_bound_owner_scope(
    root: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
    routes: &[ExpressRouteSummary],
    verified_guards: &BTreeSet<String>,
) -> bool {
    if routes.is_empty()
        || !routes.iter().all(|route| {
            route
                .guards
                .iter()
                .any(|guard| verified_guards.contains(terminal_symbol(guard)))
        })
    {
        return false;
    }
    let Some(filter) = sink.captures.get("filter") else {
        return false;
    };
    let Some(filter_node) = smallest_node_containing(root, location_range(&filter.location)) else {
        return false;
    };
    if !matches!(filter_node.kind().as_ref(), "object" | "object_expression") {
        return false;
    }
    let model_is_user = sink.captures.get("model").is_some_and(|capture| {
        matches!(
            terminal_symbol(capture.text.trim()),
            "User" | "UserModel" | "Account" | "AccountModel"
        )
    });
    filter_node
        .children()
        .filter(|child| child.is_named())
        .any(|property| {
            let Some(key) = property.field("key") else {
                return false;
            };
            let key = normalize_property_name(key.text().as_ref());
            if key != "userid" && !(key == "id" && model_is_user) {
                return false;
            }
            property.field("value").is_some_and(|value| {
                compact(value.text().as_ref()).replace("?.", ".") == "req.body.UserId"
            })
        })
}

fn resource_owner_value_is_authenticated(
    root: &Node<'_, StrDoc<SupportLang>>,
    value: Node<'_, StrDoc<SupportLang>>,
    before: usize,
    scope: &std::ops::Range<usize>,
    remaining_hops: usize,
) -> bool {
    let text = compact(value.text().as_ref()).replace("?.", ".");
    if text.starts_with("req.user.")
        || text.starts_with("request.user.")
        || text.starts_with("ctx.state.user.")
    {
        return true;
    }
    if value.dfs().filter_map(call_site).any(|call| {
        call.callee.contains("authenticatedUsers.")
            && matches!(terminal_symbol(&call.callee), "from" | "get")
    }) {
        return true;
    }
    if remaining_hops == 0
        || text.starts_with("req.")
        || text.starts_with("request.")
        || text.starts_with("ctx.request.")
    {
        return false;
    }
    let identifier = text
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .next()
        .and_then(simple_identifier);
    let Some(identifier) = identifier else {
        return false;
    };
    let Some(assigned) = latest_assigned_value(root, identifier, before, scope) else {
        return false;
    };
    resource_owner_value_is_authenticated(
        root,
        assigned.clone(),
        assigned.range().start,
        scope,
        remaining_hops - 1,
    )
}

fn shared_domain_resource_basis(
    root: &Node<'_, StrDoc<SupportLang>>,
    sink: &Evidence,
) -> Option<&'static str> {
    let model = terminal_symbol(sink.captures.get("model")?.text.trim());
    let filter = compact(sink.captures.get("filter")?.text.as_str());
    let filter_node =
        smallest_node_containing(root, location_range(&sink.captures.get("filter")?.location))?;
    let scope = function_scope(&filter_node, root);
    let source = root.text();
    let source = source.as_ref();
    if scope.end > source.len()
        || !source.is_char_boundary(scope.start)
        || !source.is_char_boundary(scope.end)
    {
        return None;
    }
    let body = &source[scope];
    if matches!(model, "Quantity" | "QuantityModel")
        && filter.contains("ProductId:")
        && body.contains(".quantity")
    {
        return Some("product_inventory_record_used_for_stock_or_quantity_policy");
    }
    if matches!(model, "Delivery" | "DeliveryModel")
        && filter.contains("id:")
        && body.contains(".price")
        && body.contains(".eta")
    {
        return Some("delivery_catalog_record_used_for_price_and_eta");
    }
    None
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn pug_output_mode(source: &str) -> Option<PugOutputMode> {
    let mut escaped = false;
    let mut raw = false;
    for line in source.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with("//") || line.starts_with("-") {
            continue;
        }
        if line.contains("!=") {
            raw = true;
        } else if line.split_whitespace().any(|token| token == "=")
            || line.contains("= '")
            || line.contains("= \"")
        {
            escaped = true;
        }
    }
    match (escaped, raw) {
        (true, true) => Some(PugOutputMode::Mixed),
        (true, false) => Some(PugOutputMode::Escaped),
        (false, true) => Some(PugOutputMode::Raw),
        (false, false) => None,
    }
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if !matches!(
        node.kind().as_ref(),
        "call_expression" | "invocation_expression"
    ) {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let text = node.text();
    let callee = text.get(..callee_length)?.trim().to_string();
    let arguments = arguments
        .children()
        .filter(|child| child.is_named())
        .collect();
    Some(CallSite {
        node,
        callee,
        arguments,
    })
}

#[allow(clippy::too_many_arguments)]
fn add_express_response_media_type_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) || !call.callee.ends_with(".send") {
            continue;
        }
        let normalized = call
            .callee
            .chars()
            .filter(|character| !character.is_whitespace() && !matches!(character, '\'' | '"'))
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if !normalized.contains(".set(content-type,text/plain).send") {
            continue;
        }
        let rule_id = language_rule(language, "express-response-media-type-control");
        let id = evidence_id(
            path,
            rule_id,
            call.node.range().start,
            call.node.range().end,
        );
        if evidence.iter().any(|item| item.id == id) {
            continue;
        }
        let mut media_type = capture(path, &call.node);
        media_type.text = "text/plain".to_string();
        let mut captures = BTreeMap::from([("media_type".to_string(), media_type)]);
        if let Some(content) = call.arguments.first() {
            captures.insert("content".to_string(), capture(path, content));
        }
        evidence.push(Evidence {
            id,
            kind: EvidenceKind::SecurityConfiguration,
            capability: Capability::HttpHeaderOutput,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures,
            cwe_candidates: Vec::new(),
            tags: vec![
                "http-response".to_string(),
                "content-type".to_string(),
                "non-html-response".to_string(),
                "text-plain".to_string(),
                "same-chain".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: EXPRESS_RESPONSE_MEDIA_ENGINE.to_string(),
                rule_version: 1,
            },
            context: evidence_context(&call.node, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn latest_declaration<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    before: usize,
    scope: &std::ops::Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && scope.start <= node.range().start
                && node.range().end <= before
                && function_scope(node, root) == *scope
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
                && node.field("value").is_some()
        })
        .max_by_key(|node| node.range().start)
}

fn latest_assigned_value<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    before: usize,
    scope: &std::ops::Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter_map(|node| {
            if scope.start > node.range().start
                || node.range().end > before
                || function_scope(&node, root) != *scope
            {
                return None;
            }
            match node.kind().as_ref() {
                "variable_declarator"
                    if node
                        .field("name")
                        .is_some_and(|field| field.text().trim() == name) =>
                {
                    node.field("value").map(|value| (node.range().start, value))
                }
                "assignment_expression"
                    if node
                        .field("left")
                        .is_some_and(|field| field.text().trim() == name) =>
                {
                    node.field("right").map(|value| (node.range().start, value))
                }
                _ => None,
            }
        })
        .max_by_key(|(start, _)| *start)
        .map(|(_, value)| value)
}

fn function_scope(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> std::ops::Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        })
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn smallest_named_text_node<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    text: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.dfs()
        .filter(|candidate| candidate.is_named() && candidate.text().trim() == text)
        .min_by_key(|candidate| candidate.range().end - candidate.range().start)
}

fn exact_property_key(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let text = node.text();
    exact_quoted(text.as_ref())
        .or_else(|| simple_identifier(text.trim()))
        .map(str::to_string)
}

fn exact_quoted(text: &str) -> Option<&str> {
    let text = text.trim();
    let quote = *text.as_bytes().first()?;
    if !matches!(quote, b'\'' | b'"')
        || text.as_bytes().last().copied() != Some(quote)
        || text.len() < 2
        || text[1..text.len() - 1].contains('\\')
    {
        return None;
    }
    Some(&text[1..text.len() - 1])
}

fn terminal_symbol(symbol: &str) -> &str {
    symbol.rsplit('.').next().unwrap_or(symbol)
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| {
            (first == '_' || first.is_ascii_alphabetic())
                && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
        })
        .then_some(text)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn normalize_property_name(text: &str) -> String {
    text.trim_matches(['\'', '"', '`'])
        .chars()
        .filter(|character| *character != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn collect_graphql_resolvers(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    resolvers: &mut BTreeSet<String>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    for declaration in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        if !normalize_property_name(name.text().as_ref()).contains("graphqlroot")
            || !matches!(value.kind().as_ref(), "object" | "object_expression")
        {
            continue;
        }
        for property in value.children().filter(|child| child.is_named()) {
            let resolver = property
                .field("value")
                .or_else(|| property.field("name"))
                .or_else(|| {
                    matches!(
                        property.kind().as_ref(),
                        "shorthand_property_identifier" | "shorthand_property_identifier_pattern"
                    )
                    .then_some(property.clone())
                });
            let Some(resolver) = resolver else {
                continue;
            };
            let resolver_text = resolver.text();
            let Some(resolver) = simple_identifier(resolver_text.trim()) else {
                continue;
            };
            resolvers.insert(format!("{module}.{resolver}"));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_mysql_query_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let imports = javascript_imports(path, root);
    let mysql_aliases = imports
        .iter()
        .filter_map(|(visible, target)| {
            matches!(target.module.as_str(), "mysql" | "mysql2").then_some(visible.as_str())
        })
        .collect::<BTreeSet<_>>();
    if mysql_aliases.is_empty() {
        return;
    }
    let mut connections = BTreeSet::new();
    for declaration in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        let name_text = name.text();
        let Some(binding) = simple_identifier(name_text.trim()) else {
            continue;
        };
        let Some(factory) = call_site(value) else {
            continue;
        };
        let Some((receiver, method)) = factory.callee.rsplit_once('.') else {
            continue;
        };
        if method == "createConnection" && mysql_aliases.contains(receiver) {
            connections.insert(binding.to_string());
        }
    }
    for query_call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(query_call.node.range()) {
            continue;
        }
        let Some(connection) = connections.iter().find(|connection| {
            query_call.callee == format!("{connection}.query")
                || query_call.callee == format!("{connection}.promise().query")
        }) else {
            continue;
        };
        if !query_call
            .node
            .field("function")
            .and_then(|f| f.field("object"))
            .is_some_and(|receiver| super::database_receiver::proven(root, &receiver, language))
        {
            continue;
        }
        evidence.retain(|item| {
            !(item.capability == Capability::DatabaseQuery
                && matches!(
                    item.rule_id.as_str(),
                    "javascript-database-query"
                        | "typescript-database-query"
                        | "tsx-database-query"
                )
                && item.location.path == path
                && item.location.start.byte_offset == query_call.node.range().start)
        });
        let Some(query) = query_call.arguments.first() else {
            continue;
        };
        let parameter_values = query_call
            .arguments
            .get(1)
            .filter(|argument| !is_function_node(argument));
        let sink_rule = language_rule(language, "mysql-query");
        let sink_id = evidence_id(
            path,
            sink_rule,
            query_call.node.range().start,
            query_call.node.range().end,
        );
        if !evidence.iter().any(|item| item.id == sink_id) {
            let mut captures = BTreeMap::from([("query".to_string(), capture(path, query))]);
            let mut tags = vec![
                "database".to_string(),
                "sql".to_string(),
                "mysql-instance".to_string(),
            ];
            if let Some(values) = parameter_values {
                captures.insert("parameters".to_string(), capture(path, values));
                tags.push("parameter-values-observed".to_string());
            }
            let mut item = Evidence {
                id: sink_id,
                kind: EvidenceKind::Sink,
                capability: Capability::DatabaseQuery,
                location: location(path, &query_call.node),
                enclosing_symbol: enclosing_symbol(&query_call.node),
                captures,
                cwe_candidates: vec!["CWE-89".to_string()],
                tags,
                confidence: Confidence::High,
                provenance: js2_provenance(),
                context: evidence_context(&query_call.node, comments, conditional, literals),
                symbol_resolution: Some(SymbolResolution {
                    canonical: "mysql2.Connection.query".to_string(),
                    observed: query_call.callee.clone(),
                    method: SymbolResolutionMethod::Alias,
                    confidence: SymbolConfidence::High,
                }),
                rule_id: sink_rule.to_string(),
                related_evidence: Vec::new(),
            };
            item.captures.get_mut("query").expect("query capture").text = query.text().into_owned();
            evidence.push(item);
        }
        if let Some(values) = parameter_values {
            let rule = language_rule(language, "mysql-parameterization-control");
            let id = evidence_id(path, rule, values.range().start, values.range().end);
            if !evidence.iter().any(|item| item.id == id) {
                evidence.push(Evidence {
                    id,
                    kind: EvidenceKind::Sanitizer,
                    capability: Capability::SqlParameterization,
                    location: location(path, values),
                    enclosing_symbol: enclosing_symbol(&query_call.node),
                    captures: BTreeMap::from([
                        ("query".to_string(), capture(path, query)),
                        ("values".to_string(), capture(path, values)),
                    ]),
                    cwe_candidates: vec!["CWE-89".to_string()],
                    tags: vec![
                        "database".to_string(),
                        "mysql".to_string(),
                        "parameterized".to_string(),
                        "control".to_string(),
                    ],
                    confidence: Confidence::High,
                    provenance: js2_provenance(),
                    context: evidence_context(values, comments, conditional, literals),
                    symbol_resolution: Some(SymbolResolution {
                        canonical: "mysql2.Connection.query".to_string(),
                        observed: format!("{connection}.query"),
                        method: SymbolResolutionMethod::Alias,
                        confidence: SymbolConfidence::High,
                    }),
                    rule_id: rule.to_string(),
                    related_evidence: Vec::new(),
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_postgres_query_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let imports = javascript_imports(path, root);
    add_postgres_js_unsafe_observations(
        path,
        root,
        language,
        &imports,
        comments,
        conditional,
        literals,
        evidence,
    );
    let constructors = imports
        .iter()
        .filter_map(|(visible, target)| {
            (target.module == "pg" && target.export.as_deref() == Some("Client"))
                .then_some(visible.as_str())
        })
        .collect::<BTreeSet<_>>();
    if constructors.is_empty() {
        return;
    }
    let mut clients = BTreeSet::new();
    for declaration in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        let name_text = name.text();
        let Some(binding) = simple_identifier(name_text.trim()) else {
            continue;
        };
        let value = compact(value.text().as_ref());
        if constructors
            .iter()
            .any(|constructor| value.starts_with(&format!("new{constructor}(")))
        {
            clients.insert(binding.to_string());
        }
    }
    for query_call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(query_call.node.range()) {
            continue;
        }
        let Some(client) = clients
            .iter()
            .find(|client| query_call.callee == format!("{client}.query"))
        else {
            continue;
        };
        evidence.retain(|item| {
            !(item.capability == Capability::DatabaseQuery
                && matches!(
                    item.rule_id.as_str(),
                    "javascript-database-query"
                        | "typescript-database-query"
                        | "tsx-database-query"
                )
                && item.location.path == path
                && item.location.start.byte_offset == query_call.node.range().start)
        });
        let Some(query) = query_call.arguments.first() else {
            continue;
        };
        let values = query_call
            .arguments
            .get(1)
            .filter(|argument| !is_function_node(argument));
        let sink_rule = language_rule(language, "postgres-query");
        let sink_id = evidence_id(
            path,
            sink_rule,
            query_call.node.range().start,
            query_call.node.range().end,
        );
        if !evidence.iter().any(|item| item.id == sink_id) {
            let mut captures = BTreeMap::from([("query".to_string(), capture(path, query))]);
            let mut tags = vec![
                "database".to_string(),
                "sql".to_string(),
                "postgres-client-instance".to_string(),
            ];
            if let Some(values) = values {
                captures.insert("parameters".to_string(), capture(path, values));
                tags.push("parameter-values-observed".to_string());
            }
            evidence.push(Evidence {
                id: sink_id,
                kind: EvidenceKind::Sink,
                capability: Capability::DatabaseQuery,
                location: location(path, &query_call.node),
                enclosing_symbol: enclosing_symbol(&query_call.node),
                captures,
                cwe_candidates: vec!["CWE-89".to_string()],
                tags,
                confidence: Confidence::High,
                provenance: js2_provenance(),
                context: evidence_context(&query_call.node, comments, conditional, literals),
                symbol_resolution: Some(SymbolResolution {
                    canonical: "pg.Client.query".to_string(),
                    observed: query_call.callee.clone(),
                    method: SymbolResolutionMethod::Alias,
                    confidence: SymbolConfidence::High,
                }),
                rule_id: sink_rule.to_string(),
                related_evidence: Vec::new(),
            });
        }
        if let Some(values) = values {
            let rule = language_rule(language, "postgres-parameterization-control");
            let id = evidence_id(path, rule, values.range().start, values.range().end);
            if evidence.iter().any(|item| item.id == id) {
                continue;
            }
            evidence.push(Evidence {
                id,
                kind: EvidenceKind::Sanitizer,
                capability: Capability::SqlParameterization,
                location: location(path, values),
                enclosing_symbol: enclosing_symbol(&query_call.node),
                captures: BTreeMap::from([
                    ("query".to_string(), capture(path, query)),
                    ("values".to_string(), capture(path, values)),
                ]),
                cwe_candidates: vec!["CWE-89".to_string()],
                tags: vec![
                    "database".to_string(),
                    "postgresql".to_string(),
                    "parameterized".to_string(),
                    "control".to_string(),
                ],
                confidence: Confidence::High,
                provenance: js2_provenance(),
                context: evidence_context(values, comments, conditional, literals),
                symbol_resolution: Some(SymbolResolution {
                    canonical: "pg.Client.query".to_string(),
                    observed: format!("{client}.query"),
                    method: SymbolResolutionMethod::Alias,
                    confidence: SymbolConfidence::High,
                }),
                rule_id: rule.to_string(),
                related_evidence: Vec::new(),
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_postgres_js_unsafe_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    imports: &BTreeMap<String, ImportTarget>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let constructors = imports
        .iter()
        .filter_map(|(visible, target)| (target.module == "postgres").then_some(visible.as_str()))
        .collect::<BTreeSet<_>>();
    if constructors.is_empty() {
        return;
    }
    let clients = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = compact(&declaration.field("value")?.text()).replace('!', "");
            constructors
                .iter()
                .any(|constructor| value.contains(&format!("{constructor}(")))
                .then(|| name.text().trim().to_string())
        })
        .collect::<BTreeSet<_>>();
    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        let callee = compact(&call.callee).replace('!', "");
        let Some(client) = clients
            .iter()
            .find(|client| callee == format!("{client}.unsafe"))
        else {
            continue;
        };
        let Some(query) = call.arguments.first() else {
            continue;
        };
        let rule_id = language_rule(language, "postgres-js-unsafe-query");
        let id = evidence_id(
            path,
            rule_id,
            call.node.range().start,
            call.node.range().end,
        );
        if evidence.iter().any(|item| item.id == id) {
            continue;
        }
        evidence.push(Evidence {
            id,
            kind: EvidenceKind::Sink,
            capability: Capability::DatabaseQuery,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures: BTreeMap::from([("query".to_string(), capture(path, query))]),
            cwe_candidates: vec!["CWE-89".to_string()],
            tags: vec![
                "database".to_string(),
                "sql".to_string(),
                "postgres-js".to_string(),
                "unsafe-query".to_string(),
            ],
            confidence: Confidence::High,
            provenance: js2_provenance(),
            context: evidence_context(&call.node, comments, conditional, literals),
            symbol_resolution: Some(SymbolResolution {
                canonical: "postgres.Sql.unsafe".to_string(),
                observed: format!("{client}.unsafe"),
                method: SymbolResolutionMethod::Alias,
                confidence: SymbolConfidence::High,
            }),
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_mongodb_where_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) || !call.callee.ends_with(".find") {
            continue;
        }
        let Some(filter) = call.arguments.first() else {
            continue;
        };
        let Some(query) = object_property(filter, "$where") else {
            continue;
        };
        let rule = language_rule(language, "mongodb-where-query");
        let id = evidence_id(path, rule, call.node.range().start, call.node.range().end);
        if evidence.iter().any(|item| item.id == id) {
            continue;
        }
        evidence.push(Evidence {
            id,
            kind: EvidenceKind::Sink,
            capability: Capability::DatabaseQuery,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures: BTreeMap::from([("nosql_query".to_string(), capture(path, &query))]),
            cwe_candidates: vec!["CWE-943".to_string()],
            tags: vec![
                "database".to_string(),
                "mongodb".to_string(),
                "where-javascript".to_string(),
            ],
            confidence: Confidence::High,
            provenance: js2_provenance(),
            context: evidence_context(&call.node, comments, conditional, literals),
            symbol_resolution: Some(SymbolResolution {
                canonical: "mongodb.Collection.find".to_string(),
                observed: call.callee,
                method: SymbolResolutionMethod::ImportedNamespace,
                confidence: SymbolConfidence::High,
            }),
            rule_id: rule.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_graphql_resolver_sources<'tree>(
    context: &NodeProjectContext,
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(module) = module_path(path) else {
        return;
    };
    for member in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "member_expression")
    {
        if comments.is_in_comment(member.range()) {
            continue;
        }
        let (Some(object), Some(property)) = (member.field("object"), member.field("property"))
        else {
            continue;
        };
        let object_text = object.text();
        let Some(object_name) = simple_identifier(object_text.trim()) else {
            continue;
        };
        let Some(function) = nearest_function(&member) else {
            continue;
        };
        if !function_parameter_nodes(&function)
            .iter()
            .any(|parameter| parameter.text().trim() == object_name)
        {
            continue;
        }
        let Some(symbol) = enclosing_symbol(&member) else {
            continue;
        };
        if !context
            .graphql_resolvers
            .contains(&format!("{module}.{symbol}"))
        {
            continue;
        }
        let property_text = normalize_property_name(property.text().as_ref());
        if matches!(
            property_text.as_str(),
            "user" | "request" | "context" | "headers"
        ) {
            continue;
        }
        let rule = language_rule(language, "graphql-resolver-argument-source");
        let id = evidence_id(path, rule, member.range().start, member.range().end);
        if evidence.iter().any(|item| item.id == id) {
            continue;
        }
        evidence.push(Evidence {
            id,
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location(path, &member),
            enclosing_symbol: Some(symbol),
            captures: BTreeMap::from([("value".to_string(), capture(path, &member))]),
            cwe_candidates: Vec::new(),
            tags: vec![
                "graphql".to_string(),
                "resolver-argument".to_string(),
                format!("field:{property_text}"),
            ],
            confidence: Confidence::High,
            provenance: js2_provenance(),
            context: evidence_context(&member, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: rule.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn js2_provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: "ast-grep 0.45.1 + bounded-node-js2-server".to_string(),
        rule_version: 1,
    }
}

fn node_request_boundary_flags(path: &str, root: &Node<'_, StrDoc<SupportLang>>) -> (bool, bool) {
    let imports = javascript_imports(path, root);
    let mut has_session = false;
    let mut has_csrf = false;
    for outer in root.dfs().filter_map(call_site) {
        if terminal_symbol(&outer.callee) != "use" {
            continue;
        }
        let Some(inner) = outer.arguments.first().cloned().and_then(call_site) else {
            continue;
        };
        let Some(module) = imported_call_module(&imports, &inner.callee) else {
            continue;
        };
        has_session |= module == "express-session" || module == "cookie-session";
        has_csrf |= matches!(
            module,
            "csurf" | "csrf-csrf" | "lusca" | "@fastify/csrf-protection"
        );
    }
    (has_session, has_csrf)
}

fn nearest_function<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors().find(|ancestor| is_function_node(ancestor))
}

fn imported_call_module<'a>(
    imports: &'a BTreeMap<String, ImportTarget>,
    callee: &str,
) -> Option<&'a str> {
    let head = callee.split('.').next()?;
    imports.get(head).map(|target| target.module.as_str())
}

#[allow(clippy::too_many_arguments)]
fn add_login_session_rotation<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        if comments.is_in_comment(assignment.range()) {
            continue;
        }
        let (Some(left), Some(_)) = (assignment.field("left"), assignment.field("right")) else {
            continue;
        };
        let left_text = compact(left.text().as_ref()).to_ascii_lowercase();
        if ![
            "req.session.userid",
            "req.session.user",
            "req.session.accountid",
            "req.session.authenticated",
            "req.session.isauthenticated",
        ]
        .contains(&left_text.as_str())
        {
            continue;
        }
        let Some(callback) = nearest_function(&assignment) else {
            continue;
        };
        let Some(authentication) = callback.ancestors().filter_map(call_site).find(|call| {
            matches!(
                terminal_symbol(&call.callee).to_ascii_lowercase().as_str(),
                "validatelogin" | "authenticate" | "verifycredentials" | "checkpassword"
            )
        }) else {
            continue;
        };
        let regeneration = assignment.ancestors().filter_map(call_site).find(|call| {
            terminal_symbol(&call.callee).eq_ignore_ascii_case("regenerate")
                && compact(&call.callee)
                    .to_ascii_lowercase()
                    .contains("session.regenerate")
        });
        let (kind, suffix, tags, confidence) = if regeneration.is_some() {
            (
                EvidenceKind::Guard,
                "login-session-regeneration-control",
                vec![
                    "session".to_string(),
                    "login".to_string(),
                    "identifier-rotation".to_string(),
                    "control".to_string(),
                ],
                Confidence::High,
            )
        } else {
            (
                EvidenceKind::SecurityConfiguration,
                "login-session-fixation-risk",
                vec![
                    "session".to_string(),
                    "login".to_string(),
                    "identity-established".to_string(),
                    "missing-session-regeneration".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
                Confidence::High,
            )
        };
        let mut authentication_capture = capture(path, &authentication.node);
        authentication_capture.text = authentication.callee.clone();
        let mut captures = BTreeMap::from([
            (
                "identity_assignment".to_string(),
                capture(path, &assignment),
            ),
            ("authentication".to_string(), authentication_capture),
        ]);
        if let Some(regeneration) = regeneration {
            captures.insert(
                "regeneration".to_string(),
                capture(path, &regeneration.node),
            );
        }
        push_request_policy_evidence(
            path,
            language,
            suffix,
            &assignment,
            kind,
            Capability::Authentication,
            vec!["CWE-384".to_string()],
            tags,
            confidence,
            captures,
            comments,
            conditional,
            literals,
            evidence,
        );
        let rule_id = language_rule(language, suffix);
        if let Some(item) = evidence.iter_mut().find(|item| {
            item.rule_id == rule_id && item.location.start.byte_offset == assignment.range().start
        }) && let Some(symbol) = assigned_enclosing_function_name(&assignment)
        {
            item.enclosing_symbol = Some(symbol);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_literal_password_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for declarator in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        let (Some(name), Some(value)) = (declarator.field("name"), declarator.field("value"))
        else {
            continue;
        };
        if comments.is_in_comment(declarator.range()) || !value.text().trim().starts_with('/') {
            continue;
        }
        let name_text = name.text();
        let Some(binding) = simple_identifier(name_text.trim()) else {
            continue;
        };
        let binding = binding.to_string();
        let Some(function) = nearest_function(&declarator) else {
            continue;
        };
        let used_for_password = function.dfs().filter_map(call_site).any(|call| {
            call.callee == format!("{binding}.test")
                && call.arguments.first().is_some_and(|argument| {
                    normalize_property_name(argument.text().as_ref()).contains("password")
                })
        });
        if !used_for_password {
            continue;
        }
        let regex = compact(value.text().as_ref());
        let minimum = regex_minimum_length(&regex);
        let has_digit = regex.contains("\\d") || regex.contains("[0-9]");
        let has_lower = regex.contains("[a-z]");
        let has_upper = regex.contains("[A-Z]");
        let weak = minimum.is_some_and(|minimum| minimum <= 4);
        let strong = minimum.is_some_and(|minimum| minimum >= 12)
            || (minimum.is_some_and(|minimum| minimum >= 8) && has_digit && has_lower && has_upper);
        let (kind, suffix, tags, confidence) = if weak {
            (
                EvidenceKind::SecurityConfiguration,
                "weak-password-policy",
                vec![
                    "password-policy".to_string(),
                    format!("minimum-length:{}", minimum.unwrap_or_default()),
                    "trivially-weak-minimum".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
                Confidence::High,
            )
        } else if strong {
            (
                EvidenceKind::Guard,
                "strong-password-policy-control",
                vec![
                    "password-policy".to_string(),
                    format!("minimum-length:{}", minimum.unwrap_or_default()),
                    "control".to_string(),
                ],
                Confidence::High,
            )
        } else {
            continue;
        };
        push_request_policy_evidence(
            path,
            language,
            suffix,
            &value,
            kind,
            Capability::Authentication,
            vec!["CWE-521".to_string()],
            tags,
            confidence,
            BTreeMap::from([
                ("policy".to_string(), capture(path, &value)),
                ("binding".to_string(), capture(path, &name)),
            ]),
            comments,
            conditional,
            literals,
            evidence,
        );
        let rule_id = language_rule(language, suffix);
        if let Some(item) = evidence.iter_mut().find(|item| {
            item.rule_id == rule_id && item.location.start.byte_offset == value.range().start
        }) && let Some(symbol) = assigned_enclosing_function_name(&declarator)
        {
            item.enclosing_symbol = Some(symbol);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_registration_and_recovery_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for property in root.dfs() {
        let (Some(key), Some(value)) = (property.field("key"), property.field("value")) else {
            continue;
        };
        if normalize_property_name(key.text().as_ref()) != "password"
            || !matches!(value.kind().as_ref(), "object" | "object_expression")
            || comments.is_in_comment(value.range())
        {
            continue;
        }
        let normalized = compact(value.text().as_ref()).to_ascii_lowercase();
        let stores_hashed_password = normalized.contains("setdatavalue('password'")
            || normalized.contains("setdatavalue(\"password\"");
        let has_hash = normalized.contains("hash(") || normalized.contains("digest(");
        let has_local_policy = normalized.contains("validate:")
            || normalized.contains("isstrongpassword")
            || normalized.contains(".length<")
            || normalized.contains(".length<=")
            || normalized.contains(".test(")
            || normalized.contains(".min(");
        if !stores_hashed_password || !has_hash || has_local_policy {
            continue;
        }
        push_request_policy_evidence(
            path,
            language,
            "password-storage-policy-review",
            &value,
            EvidenceKind::SecurityConfiguration,
            Capability::Authentication,
            vec!["CWE-521".to_string()],
            vec![
                "password-policy".to_string(),
                "password-storage-boundary".to_string(),
                "local-strength-validation-not-observed".to_string(),
                "recommendation:review-effective-policy".to_string(),
            ],
            Confidence::Medium,
            BTreeMap::from([("password_field".to_string(), capture(path, &value))]),
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for call in root.dfs().filter_map(call_site) {
        if terminal_symbol(&call.callee) != "post" || comments.is_in_comment(call.node.range()) {
            continue;
        }
        let Some(route_text) = call
            .arguments
            .first()
            .map(|route| route.text().into_owned())
        else {
            continue;
        };
        let Some(route) = exact_quoted(&route_text) else {
            continue;
        };
        let route = route.to_ascii_lowercase();
        if !["user", "register", "signup"]
            .iter()
            .any(|marker| route.contains(marker))
        {
            continue;
        }
        let Some(handler) = call
            .arguments
            .get(1)
            .filter(|handler| is_function_node(handler))
        else {
            continue;
        };
        let normalized = compact(handler.text().as_ref()).to_ascii_lowercase();
        let checks_non_empty =
            normalized.contains("email.length!==0") && normalized.contains("password.length!==0");
        let sends_rejection = normalized.contains("res.status(") && normalized.contains(".send(");
        let falls_through = normalized.contains("next()")
            && !normalized.contains("returnres.status(")
            && !normalized.contains("elsereturnnext()")
            && !normalized.contains("elsenext()");
        if checks_non_empty && sends_rejection && falls_through {
            let mut route_capture = capture(path, &call.arguments[0]);
            route_capture.text = route.clone();
            push_request_policy_evidence(
                path,
                language,
                "registration-rejection-fallthrough-review",
                handler,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                vec!["CWE-20".to_string()],
                vec![
                    "registration".to_string(),
                    "required-fields".to_string(),
                    "rejection-response-falls-through".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
                Confidence::High,
                BTreeMap::from([
                    ("route".to_string(), route_capture),
                    ("handler".to_string(), capture(path, handler)),
                ]),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for comparison in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "binary_expression")
    {
        if comments.is_in_comment(comparison.range()) {
            continue;
        }
        let is_inequality = comparison
            .children()
            .filter(|child| !child.is_named())
            .any(|operator| matches!(operator.text().trim(), "!=" | "!=="));
        let normalized = compact(comparison.text().as_ref()).to_ascii_lowercase();
        if !normalized.contains("passwordrepeat")
            || !normalized.contains("password")
            || !is_inequality
        {
            continue;
        }
        let Some((function, function_text)) = comparison
            .ancestors()
            .filter(is_function_node)
            .map(|function| {
                let text = compact(function.text().as_ref()).to_ascii_lowercase();
                (function, text)
            })
            .find(|(_, text)| text.contains("next()"))
        else {
            continue;
        };
        let mismatch_is_only_observed = function_text.contains("next()")
            && !function_text.contains("res.status(")
            && !function_text.contains("throw")
            && !function_text.contains("next(newerror");
        if !mismatch_is_only_observed {
            continue;
        }
        push_request_policy_evidence(
            path,
            language,
            "password-confirmation-not-enforced-review",
            &comparison,
            EvidenceKind::SecurityConfiguration,
            Capability::Authentication,
            vec!["CWE-20".to_string()],
            vec![
                "registration".to_string(),
                "password-confirmation".to_string(),
                "mismatch-not-rejected".to_string(),
                "recommendation:fix-application".to_string(),
            ],
            Confidence::High,
            BTreeMap::from([("comparison".to_string(), capture(path, &comparison))]),
            comments,
            conditional,
            literals,
            evidence,
        );
        let rule_id = language_rule(language, "password-confirmation-not-enforced-review");
        if let Some(item) = evidence.iter_mut().find(|item| {
            item.rule_id == rule_id && item.location.start.byte_offset == comparison.range().start
        }) {
            item.enclosing_symbol = enclosing_symbol(&function);
        }
    }

    for function in root.dfs().filter(|node| is_function_node(node)) {
        let calls = calls_in_function(&function).collect::<Vec<_>>();
        let Some(answer_lookup) = calls.iter().find(|call| {
            terminal_symbol(&call.callee) == "findOne"
                && call.callee.to_ascii_lowercase().contains("securityanswer")
        }) else {
            continue;
        };
        let changes_password = calls.iter().any(|call| {
            terminal_symbol(&call.callee) == "update"
                && call.arguments.first().is_some_and(|argument| {
                    compact(argument.text().as_ref())
                        .to_ascii_lowercase()
                        .contains("password:")
                })
        });
        if !changes_password || comments.is_in_comment(answer_lookup.node.range()) {
            continue;
        }
        push_request_policy_evidence(
            path,
            language,
            "knowledge-based-password-recovery-review",
            &answer_lookup.node,
            EvidenceKind::SecurityConfiguration,
            Capability::Authentication,
            vec!["CWE-640".to_string()],
            vec![
                "password-recovery".to_string(),
                "knowledge-based-answer".to_string(),
                "account-password-update".to_string(),
                "recommendation:review-effective-policy".to_string(),
            ],
            Confidence::Medium,
            BTreeMap::from([(
                "answer_lookup".to_string(),
                capture(path, &answer_lookup.node),
            )]),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn assigned_enclosing_function_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    for ancestor in node.ancestors() {
        match ancestor.kind().as_ref() {
            "variable_declarator" => {
                let name = ancestor.field("name")?;
                if let Some(name) = simple_identifier(name.text().trim()) {
                    return Some(name.to_string());
                }
            }
            "assignment_expression" => {
                let left = ancestor.field("left")?;
                let left_text = left.text();
                let name = terminal_symbol(left_text.as_ref());
                if let Some(name) = simple_identifier(name) {
                    return Some(name.to_string());
                }
            }
            _ => {}
        }
    }
    None
}

fn regex_minimum_length(regex: &str) -> Option<usize> {
    let start = regex.find('{')? + 1;
    let rest = &regex[start..];
    let end = rest.find([',', '}'])?;
    rest[..end].parse().ok()
}

#[allow(clippy::too_many_arguments)]
fn add_express_session_policy<'tree>(
    context: &NodeProjectContext,
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !context.has_express_session {
        return;
    }
    let imports = javascript_imports(path, root);
    for outer in root.dfs().filter_map(call_site) {
        if terminal_symbol(&outer.callee) != "use" || comments.is_in_comment(outer.node.range()) {
            continue;
        }
        let Some(inner) = outer.arguments.first().cloned().and_then(call_site) else {
            continue;
        };
        let Some(module) = imported_call_module(&imports, &inner.callee) else {
            continue;
        };
        if matches!(
            module,
            "csurf" | "csrf-csrf" | "lusca" | "@fastify/csrf-protection"
        ) {
            push_request_policy_evidence(
                path,
                language,
                "project-csrf-middleware-control",
                &outer.node,
                EvidenceKind::Guard,
                Capability::HttpRequestHandling,
                vec!["CWE-352".to_string()],
                vec![
                    "csrf".to_string(),
                    "project-wide".to_string(),
                    "control".to_string(),
                ],
                Confidence::High,
                BTreeMap::from([("middleware".to_string(), capture(path, &outer.node))]),
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }
        if module != "express-session" && module != "cookie-session" {
            continue;
        }
        let Some(options) = inner.arguments.first() else {
            continue;
        };
        let cookie = object_property(options, "cookie");
        let http_only = cookie
            .as_ref()
            .and_then(|cookie| object_property(cookie, "httpOnly"))
            .map(|value| compact(value.text().as_ref()).to_ascii_lowercase());
        let secure = cookie
            .as_ref()
            .and_then(|cookie| object_property(cookie, "secure"))
            .map(|value| compact(value.text().as_ref()).to_ascii_lowercase());
        let same_site = cookie
            .as_ref()
            .and_then(|cookie| object_property(cookie, "sameSite"))
            .map(|value| compact(value.text().as_ref()).to_ascii_lowercase());
        let explicitly_weak = http_only.as_deref() == Some("false")
            || secure.as_deref() == Some("false")
            || matches!(same_site.as_deref(), Some("false" | "'none'" | "\"none\""));
        let explicitly_hardened = http_only.as_deref() == Some("true")
            && secure.as_deref() == Some("true")
            && same_site.as_deref().is_some_and(|value| {
                matches!(
                    value,
                    "true" | "'lax'" | "\"lax\"" | "'strict'" | "\"strict\""
                )
            });
        let (kind, suffix, mut tags, confidence) = if explicitly_weak {
            (
                EvidenceKind::SecurityConfiguration,
                "session-cookie-policy-risk",
                vec![
                    "session-cookie".to_string(),
                    "explicitly-weak".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
                Confidence::High,
            )
        } else if explicitly_hardened {
            (
                EvidenceKind::Guard,
                "session-cookie-policy-control",
                vec![
                    "session-cookie".to_string(),
                    "hardened".to_string(),
                    "control".to_string(),
                ],
                Confidence::High,
            )
        } else {
            (
                EvidenceKind::SecurityConfiguration,
                "session-cookie-policy-review",
                vec![
                    "session-cookie".to_string(),
                    "framework-default-dependent".to_string(),
                    "recommendation:review-effective-policy".to_string(),
                ],
                Confidence::Medium,
            )
        };
        tags.extend([
            format!("http-only:{}", http_only.as_deref().unwrap_or("default")),
            format!("secure:{}", secure.as_deref().unwrap_or("default")),
            format!("same-site:{}", same_site.as_deref().unwrap_or("default")),
        ]);
        let mut cookie_cwes = Vec::new();
        if http_only.as_deref() == Some("false") || explicitly_hardened {
            cookie_cwes.push("CWE-1004".to_string());
        }
        if secure.as_deref() != Some("true") || explicitly_hardened {
            cookie_cwes.push("CWE-614".to_string());
        }
        if !same_site.as_deref().is_some_and(|value| {
            matches!(
                value,
                "true" | "'lax'" | "\"lax\"" | "'strict'" | "\"strict\""
            )
        }) || explicitly_hardened
        {
            cookie_cwes.push("CWE-1275".to_string());
        }
        push_request_policy_evidence(
            path,
            language,
            suffix,
            &inner.node,
            kind,
            Capability::CookieConfiguration,
            cookie_cwes,
            tags,
            confidence,
            BTreeMap::from([("session_options".to_string(), capture(path, options))]),
            comments,
            conditional,
            literals,
            evidence,
        );

        let mut routes = context
            .routes_by_handler
            .values()
            .flatten()
            .filter(|route| {
                matches!(route.method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE")
                    && (!route.guards.is_empty()
                        || matches!(
                            route.access,
                            HttpRouteAccess::Authenticated | HttpRouteAccess::RoleRestricted
                        ))
            })
            .map(|route| format!("{} {}", route.method, route.path))
            .collect::<Vec<_>>();
        routes.sort();
        routes.dedup();
        if !routes.is_empty() && !context.csrf_middleware_paths.contains(path) {
            let mut route_capture = capture(path, &inner.node);
            route_capture.text = routes.join(", ");
            push_request_policy_evidence(
                path,
                language,
                "cookie-session-csrf-review",
                &inner.node,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                vec!["CWE-352".to_string()],
                vec![
                    "csrf".to_string(),
                    "cookie-authenticated".to_string(),
                    "state-changing-routes".to_string(),
                    "project-csrf-middleware-not-observed".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
                Confidence::Medium,
                BTreeMap::from([
                    ("session_middleware".to_string(), capture(path, &inner.node)),
                    ("state_changing_routes".to_string(), route_capture),
                ]),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn object_property<'tree>(
    object: &Node<'tree, StrDoc<SupportLang>>,
    expected: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if !matches!(object.kind().as_ref(), "object" | "object_expression") {
        return None;
    }
    object
        .children()
        .filter(|child| child.is_named())
        .find_map(|property| {
            let key = property.field("key")?;
            (normalize_property_name(key.text().as_ref()) == normalize_property_name(expected))
                .then(|| property.field("value"))
                .flatten()
        })
}

#[allow(clippy::too_many_arguments)]
fn push_request_policy_evidence<'tree>(
    path: &str,
    language: Language,
    suffix: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    cwe_candidates: Vec<String>,
    tags: Vec<String>,
    confidence: Confidence,
    captures: BTreeMap<String, Capture>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = language_rule(language, suffix);
    let id = evidence_id(path, rule_id, node.range().start, node.range().end);
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates,
        tags,
        confidence,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "ast-grep 0.45.1 + bounded-node-request-boundary".to_string(),
            rule_version: 1,
        },
        context: evidence_context(node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn module_path(path: &str) -> Option<String> {
    let path = path.replace('\\', "/");
    let path = path.trim_start_matches("./");
    let path = [".tsx", ".jsx", ".ts", ".js"]
        .iter()
        .find_map(|extension| path.strip_suffix(extension))
        .unwrap_or(path);
    (!path.is_empty()).then_some(path.to_string())
}

fn resolve_module(importer: &str, imported: &str) -> Option<String> {
    if let Some(project_relative) = imported.strip_prefix("@/") {
        return module_path(&format!("src/{project_relative}"));
    }
    if !imported.starts_with('.') {
        return module_path(imported);
    }
    let mut segments = importer
        .replace('\\', "/")
        .split('/')
        .map(str::to_string)
        .collect::<Vec<_>>();
    segments.pop()?;
    for segment in imported.replace('\\', "/").split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            value => segments.push(value.to_string()),
        }
    }
    module_path(&segments.join("/"))
}

fn is_node_language(language: Language) -> bool {
    matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    )
}

fn parser_language(language: Language) -> SupportLang {
    match language {
        Language::Javascript => SupportLang::JavaScript,
        Language::Typescript => SupportLang::TypeScript,
        Language::Tsx => SupportLang::Tsx,
        _ => unreachable!(),
    }
}

fn language_rule(language: Language, suffix: &str) -> &'static str {
    match (language, suffix) {
        (Language::Javascript, "parameter-return-request-source") => {
            "javascript-parameter-return-request-source"
        }
        (Language::Typescript, "parameter-return-request-source") => {
            "typescript-parameter-return-request-source"
        }
        (Language::Tsx, "parameter-return-request-source") => "tsx-parameter-return-request-source",
        (Language::Javascript, "parameter-sink-summary") => "javascript-parameter-sink-summary",
        (Language::Typescript, "parameter-sink-summary") => "typescript-parameter-sink-summary",
        (Language::Tsx, "parameter-sink-summary") => "tsx-parameter-sink-summary",
        (Language::Javascript, "dao-password-material") => "javascript-dao-password-material",
        (Language::Typescript, "dao-password-material") => "typescript-dao-password-material",
        (Language::Tsx, "dao-password-material") => "tsx-dao-password-material",
        (Language::Javascript, "dao-request-parameter") => "javascript-dao-request-parameter",
        (Language::Typescript, "dao-request-parameter") => "typescript-dao-request-parameter",
        (Language::Tsx, "dao-request-parameter") => "tsx-dao-request-parameter",
        (Language::Javascript, "mongo-callback-stored-source") => {
            "javascript-mongo-callback-stored-source"
        }
        (Language::Typescript, "mongo-callback-stored-source") => {
            "typescript-mongo-callback-stored-source"
        }
        (Language::Tsx, "mongo-callback-stored-source") => "tsx-mongo-callback-stored-source",
        (Language::Javascript, "async-continuation-request-source") => {
            "javascript-async-continuation-request-source"
        }
        (Language::Typescript, "async-continuation-request-source") => {
            "typescript-async-continuation-request-source"
        }
        (Language::Tsx, "async-continuation-request-source") => {
            "tsx-async-continuation-request-source"
        }
        (Language::Javascript, "xxe-parser-summary") => "javascript-xxe-parser-summary",
        (Language::Typescript, "xxe-parser-summary") => "typescript-xxe-parser-summary",
        (Language::Tsx, "xxe-parser-summary") => "tsx-xxe-parser-summary",
        (Language::Javascript, "angular-rxjs-stored-source") => {
            "javascript-angular-rxjs-stored-source"
        }
        (Language::Typescript, "angular-rxjs-stored-source") => {
            "typescript-angular-rxjs-stored-source"
        }
        (Language::Tsx, "angular-rxjs-stored-source") => "tsx-angular-rxjs-stored-source",
        (Language::Javascript, "login-session-regeneration-control") => {
            "javascript-login-session-regeneration-control"
        }
        (Language::Typescript, "login-session-regeneration-control") => {
            "typescript-login-session-regeneration-control"
        }
        (Language::Tsx, "login-session-regeneration-control") => {
            "tsx-login-session-regeneration-control"
        }
        (Language::Javascript, "login-session-fixation-risk") => {
            "javascript-login-session-fixation-risk"
        }
        (Language::Typescript, "login-session-fixation-risk") => {
            "typescript-login-session-fixation-risk"
        }
        (Language::Tsx, "login-session-fixation-risk") => "tsx-login-session-fixation-risk",
        (Language::Javascript, "weak-password-policy") => "javascript-weak-password-policy",
        (Language::Typescript, "weak-password-policy") => "typescript-weak-password-policy",
        (Language::Tsx, "weak-password-policy") => "tsx-weak-password-policy",
        (Language::Javascript, "password-storage-policy-review") => {
            "javascript-password-storage-policy-review"
        }
        (Language::Typescript, "password-storage-policy-review") => {
            "typescript-password-storage-policy-review"
        }
        (Language::Tsx, "password-storage-policy-review") => "tsx-password-storage-policy-review",
        (Language::Javascript, "registration-rejection-fallthrough-review") => {
            "javascript-registration-rejection-fallthrough-review"
        }
        (Language::Typescript, "registration-rejection-fallthrough-review") => {
            "typescript-registration-rejection-fallthrough-review"
        }
        (Language::Tsx, "registration-rejection-fallthrough-review") => {
            "tsx-registration-rejection-fallthrough-review"
        }
        (Language::Javascript, "password-confirmation-not-enforced-review") => {
            "javascript-password-confirmation-not-enforced-review"
        }
        (Language::Typescript, "password-confirmation-not-enforced-review") => {
            "typescript-password-confirmation-not-enforced-review"
        }
        (Language::Tsx, "password-confirmation-not-enforced-review") => {
            "tsx-password-confirmation-not-enforced-review"
        }
        (Language::Javascript, "knowledge-based-password-recovery-review") => {
            "javascript-knowledge-based-password-recovery-review"
        }
        (Language::Typescript, "knowledge-based-password-recovery-review") => {
            "typescript-knowledge-based-password-recovery-review"
        }
        (Language::Tsx, "knowledge-based-password-recovery-review") => {
            "tsx-knowledge-based-password-recovery-review"
        }
        (Language::Javascript, "strong-password-policy-control") => {
            "javascript-strong-password-policy-control"
        }
        (Language::Typescript, "strong-password-policy-control") => {
            "typescript-strong-password-policy-control"
        }
        (Language::Tsx, "strong-password-policy-control") => "tsx-strong-password-policy-control",
        (Language::Javascript, "project-csrf-middleware-control") => {
            "javascript-project-csrf-middleware-control"
        }
        (Language::Typescript, "project-csrf-middleware-control") => {
            "typescript-project-csrf-middleware-control"
        }
        (Language::Tsx, "project-csrf-middleware-control") => "tsx-project-csrf-middleware-control",
        (Language::Javascript, "session-cookie-policy-risk") => {
            "javascript-session-cookie-policy-risk"
        }
        (Language::Typescript, "session-cookie-policy-risk") => {
            "typescript-session-cookie-policy-risk"
        }
        (Language::Tsx, "session-cookie-policy-risk") => "tsx-session-cookie-policy-risk",
        (Language::Javascript, "session-cookie-policy-control") => {
            "javascript-session-cookie-policy-control"
        }
        (Language::Typescript, "session-cookie-policy-control") => {
            "typescript-session-cookie-policy-control"
        }
        (Language::Tsx, "session-cookie-policy-control") => "tsx-session-cookie-policy-control",
        (Language::Javascript, "session-cookie-policy-review") => {
            "javascript-session-cookie-policy-review"
        }
        (Language::Typescript, "session-cookie-policy-review") => {
            "typescript-session-cookie-policy-review"
        }
        (Language::Tsx, "session-cookie-policy-review") => "tsx-session-cookie-policy-review",
        (Language::Javascript, "cookie-session-csrf-review") => {
            "javascript-cookie-session-csrf-review"
        }
        (Language::Typescript, "cookie-session-csrf-review") => {
            "typescript-cookie-session-csrf-review"
        }
        (Language::Tsx, "cookie-session-csrf-review") => "tsx-cookie-session-csrf-review",
        (Language::Javascript, "mysql-query") => "javascript-mysql-query",
        (Language::Typescript, "mysql-query") => "typescript-mysql-query",
        (Language::Tsx, "mysql-query") => "tsx-mysql-query",
        (Language::Javascript, "mongodb-where-query") => "javascript-mongodb-where-query",
        (Language::Typescript, "mongodb-where-query") => "typescript-mongodb-where-query",
        (Language::Tsx, "mongodb-where-query") => "tsx-mongodb-where-query",
        (Language::Javascript, "mysql-parameterization-control") => {
            "javascript-mysql-parameterization-control"
        }
        (Language::Typescript, "mysql-parameterization-control") => {
            "typescript-mysql-parameterization-control"
        }
        (Language::Tsx, "mysql-parameterization-control") => "tsx-mysql-parameterization-control",
        (Language::Javascript, "postgres-query") => "javascript-postgres-query",
        (Language::Typescript, "postgres-query") => "typescript-postgres-query",
        (Language::Tsx, "postgres-query") => "tsx-postgres-query",
        (Language::Javascript, "postgres-js-unsafe-query") => "javascript-postgres-js-unsafe-query",
        (Language::Typescript, "postgres-js-unsafe-query") => "typescript-postgres-js-unsafe-query",
        (Language::Tsx, "postgres-js-unsafe-query") => "tsx-postgres-js-unsafe-query",
        (Language::Javascript, "postgres-parameterization-control") => {
            "javascript-postgres-parameterization-control"
        }
        (Language::Typescript, "postgres-parameterization-control") => {
            "typescript-postgres-parameterization-control"
        }
        (Language::Tsx, "postgres-parameterization-control") => {
            "tsx-postgres-parameterization-control"
        }
        (Language::Javascript, "express-response-media-type-control") => {
            "javascript-express-response-media-type-control"
        }
        (Language::Typescript, "express-response-media-type-control") => {
            "typescript-express-response-media-type-control"
        }
        (Language::Tsx, "express-response-media-type-control") => {
            "tsx-express-response-media-type-control"
        }
        (Language::Javascript, "graphql-resolver-argument-source") => {
            "javascript-graphql-resolver-argument-source"
        }
        (Language::Typescript, "graphql-resolver-argument-source") => {
            "typescript-graphql-resolver-argument-source"
        }
        (Language::Tsx, "graphql-resolver-argument-source") => {
            "tsx-graphql-resolver-argument-source"
        }
        _ => unreachable!(),
    }
}

fn evidence_context<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> EvidenceContext {
    EvidenceContext {
        comment: comments.is_in_comment(node.range()),
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        ..EvidenceContext::default()
    }
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
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

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

fn smallest_node_containing<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    range: std::ops::Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| contains_range(node.range(), range.clone()))
        .min_by_key(|node| node.range().end - node.range().start)
}

fn contains_range(outer: std::ops::Range<usize>, inner: std::ops::Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn location_range(location: &Location) -> std::ops::Range<usize> {
    location.start.byte_offset..location.end.byte_offset
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_javascript_and_typescript_runtime_conservatively() {
        assert_eq!(
            classify_runtime_environment(
                "src/server/app.ts",
                Language::Typescript,
                "import type { Express } from 'express';\nexport const app: Express = build();",
            ),
            RuntimeEnvironment::Server
        );
        assert_eq!(
            classify_runtime_environment(
                "src/frontend/search.ts",
                Language::Typescript,
                "import { Component } from '@angular/core';\ndocument.querySelector('#q');",
            ),
            RuntimeEnvironment::Browser
        );
        assert_eq!(
            classify_runtime_environment(
                "src/hybrid.tsx",
                Language::Tsx,
                "'use client';\nimport { readFile } from 'node:fs';",
            ),
            RuntimeEnvironment::Mixed
        );
        assert_eq!(
            classify_runtime_environment(
                "src/components/card.tsx",
                Language::Tsx,
                "export function Card({ title }: { title: string }) { return <p>{title}</p> }",
            ),
            RuntimeEnvironment::Unknown,
            "TSX is not necessarily browser-only because server rendering is common"
        );
        assert_eq!(
            classify_runtime_environment(
                "src/config.mts",
                Language::Typescript,
                "export { readFile } from 'node:fs/promises';",
            ),
            RuntimeEnvironment::Server
        );
    }

    #[test]
    fn annotates_all_javascript_family_evidence_with_runtime() {
        let source =
            "import express from 'express';\nexpress().get('/', (_, res) => res.send('ok'));";
        let context = NodeProjectContext::from_sources(std::iter::once((
            "src/server.ts",
            Language::Typescript,
            source,
        )));
        let document = StrDoc::try_new(source, SupportLang::TypeScript).expect("valid source");
        let ast = AstGrep::doc(document);
        let mut evidence = vec![Evidence {
            id: "runtime-test".to_string(),
            kind: EvidenceKind::Sink,
            capability: Capability::HtmlOutput,
            location: location("src/server.ts", &ast.root()),
            enclosing_symbol: None,
            captures: BTreeMap::new(),
            cwe_candidates: vec!["CWE-79".to_string()],
            tags: Vec::new(),
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "test".to_string(),
                rule_version: 1,
            },
            context: EvidenceContext::default(),
            symbol_resolution: None,
            rule_id: "runtime-test".to_string(),
            related_evidence: Vec::new(),
        }];
        context.annotate(
            "src/server.ts",
            &ast.root(),
            Language::Typescript,
            &mut evidence,
        );
        assert_eq!(
            evidence[0].context.runtime_environment,
            Some(RuntimeEnvironment::Server)
        );
    }

    #[test]
    fn recognizes_checked_first_persisted_last_shape() {
        let source = include_str!(
            "../../../../tests/fixtures/v2-duplicate-key-mutation/positive/duplicate-key.ts"
        );
        let document = StrDoc::try_new(source, SupportLang::TypeScript).expect("valid source");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let comments = CommentRanges::from_root(&root);
        let saves = root
            .dfs()
            .filter(|node| {
                call_site(node.clone()).is_some_and(|call| call.callee.ends_with(".save"))
            })
            .collect::<Vec<_>>();
        assert_eq!(saves.len(), 1);
        assert!(
            duplicate_key_candidate(&root, saves[0].clone(), &comments).is_some(),
            "checked-first and persisted-last duplicate-key mutation should be recognized"
        );
    }

    #[test]
    fn recognizes_request_selected_sensitive_response_fields() {
        let model_source =
            include_str!("../../../../tests/fixtures/v2-dynamic-response-field/model.ts");
        let model_document =
            StrDoc::try_new(model_source, SupportLang::TypeScript).expect("valid model source");
        let model_ast = AstGrep::doc(model_document);
        let mut models = BTreeMap::new();
        collect_sensitive_model_fields(&model_ast.root(), &mut models);
        let sensitive = models.get("User").expect("sensitive User schema fields");
        assert!(sensitive.contains("password"));
        assert!(sensitive.contains("totpSecret"));

        let route_source = include_str!(
            "../../../../tests/fixtures/v2-dynamic-response-field/positive/dynamic-fields.ts"
        );
        let route_document =
            StrDoc::try_new(route_source, SupportLang::TypeScript).expect("valid route source");
        let route_ast = AstGrep::doc(route_document);
        let root = route_ast.root();
        let comments = CommentRanges::from_root(&root);
        let literals = LiteralEnvironment::build(&root, Language::Typescript);
        let candidates = root
            .dfs()
            .filter_map(|node| {
                dynamic_response_field_candidate(&root, node, &comments, &literals, sensitive)
            })
            .collect::<Vec<_>>();
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].request_field.text().trim(),
            "req.query?.fields"
        );
    }

    #[test]
    fn owner_scope_requires_an_authenticated_identity_value() {
        fn owner_scope_classifications(source: &str, middleware_source: &str) -> (bool, bool) {
            let document = StrDoc::try_new(source, SupportLang::TypeScript).expect("valid source");
            let ast = AstGrep::doc(document);
            let root = ast.root();
            let filter = root
                .dfs()
                .filter(|node| matches!(node.kind().as_ref(), "object" | "object_expression"))
                .find(|node| {
                    let text = compact(node.text().as_ref());
                    text.starts_with("{UserId:") || text.starts_with("{id:")
                })
                .expect("resource filter");
            let evidence = Evidence {
                id: "resource-test".to_string(),
                kind: EvidenceKind::Sink,
                capability: Capability::ResourceAccess,
                location: location("route.ts", &filter),
                enclosing_symbol: Some("handler".to_string()),
                captures: BTreeMap::from([
                    (
                        "filter".to_string(),
                        Capture {
                            text: filter.text().into_owned(),
                            location: location("route.ts", &filter),
                        },
                    ),
                    (
                        "model".to_string(),
                        Capture {
                            text: "UserModel".to_string(),
                            location: location("route.ts", &filter),
                        },
                    ),
                ]),
                cwe_candidates: vec!["CWE-639".to_string()],
                tags: Vec::new(),
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "test".to_string(),
                    rule_version: 1,
                },
                context: EvidenceContext::default(),
                symbol_resolution: None,
                rule_id: "typescript-sequelize-resource-access".to_string(),
                related_evidence: Vec::new(),
            };
            let routes = [ExpressRouteSummary {
                handler: "route.handler".to_string(),
                method: "GET".to_string(),
                path: "/resource/:id".to_string(),
                access: HttpRouteAccess::Authenticated,
                guards: vec!["security.appendUserId".to_string()],
            }];
            let mut verified_guards = BTreeSet::new();
            collect_owner_field_overwrite_guards(middleware_source, &mut verified_guards);
            (
                resource_filter_has_owner_scope(&root, &evidence),
                resource_filter_has_route_bound_owner_scope(
                    &root,
                    &evidence,
                    &routes,
                    &verified_guards,
                ),
            )
        }

        assert_eq!(
            owner_scope_classifications(
                "function handler(req) { return Wallet.findOne({ where: { UserId: req.body.UserId } }) }",
                ""
            ),
            (false, false),
            "a guard name alone must not establish authenticated owner scope"
        );
        assert_eq!(
            owner_scope_classifications(
                "function handler(req) { return Wallet.findOne({ where: { UserId: req.body.UserId } }) }",
                "export const appendUserId = () => (req, res, next) => { req.body.UserId = authenticatedUsers.get(req).data.id; next() }"
            ),
            (false, true),
            "the repository middleware definition proves the owner overwrite"
        );
        assert_eq!(
            owner_scope_classifications(
                "function handler(req) { return UserModel.findOne({ where: { id: req.body.UserId } }) }",
                "export const appendUserId = () => (req, res, next) => { req.body.UserId = authenticatedUsers.get(req).data.id; next() }"
            ),
            (false, true),
            "a verified owner overwrite also scopes lookup of the user record itself"
        );
        assert_eq!(
            owner_scope_classifications(
                "function handler(req) { const user = security.authenticatedUsers.from(req); return Wallet.findOne({ where: { UserId: user.data.id } }) }",
                ""
            ),
            (true, false)
        );
    }

    #[test]
    fn express_routes_inherit_only_prior_boundary_matched_middleware() {
        let source = "function checkout (req, res) { res.send('ok') }\n\
            function baskets (req, res) { res.send('ok') }\n\
            function late (req, res) { res.send('ok') }\n\
            app.use('/rest/basket', security.isAuthorized(), security.appendUserId())\n\
            app.post('/rest/basket/:id/checkout', checkout)\n\
            app.post('/rest/baskets/:id', baskets)\n\
            app.post('/rest/late/:id', late)\n\
            app.use('/rest/late', security.appendUserId())";
        let document = StrDoc::try_new(source, SupportLang::TypeScript).expect("valid source");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let mut routes = BTreeMap::new();
        collect_express_routes("server.ts", &root, &BTreeSet::new(), &mut routes);
        let route = |path: &str| {
            routes
                .values()
                .flatten()
                .find(|route| route.path == path)
                .expect("route summary")
        };

        let checkout = route("/rest/basket/:id/checkout");
        assert_eq!(checkout.access, HttpRouteAccess::Unknown);
        assert!(
            checkout
                .guards
                .iter()
                .any(|guard| guard == "security.appendUserId")
        );
        assert!(route("/rest/baskets/:id").guards.is_empty());
        assert!(route("/rest/late/:id").guards.is_empty());
    }

    #[test]
    fn angular_rxjs_sources_follow_one_member_alias_into_a_loop() {
        let source = "this.userService.find().subscribe({ next: (users) => { this.rows = users; for (const user of this.rows) { this.sanitizer.bypassSecurityTrustHtml(`${user.email}`) } } })";
        let document = StrDoc::try_new(source, SupportLang::TypeScript).expect("valid source");
        let ast = AstGrep::doc(document);
        let root = ast.root();
        let comments = CommentRanges::from_root(&root);
        let conditional =
            ConditionalRegions::from_source(Language::Typescript, source, &BTreeMap::new());
        let literals = LiteralEnvironment::build(&root, Language::Typescript);
        let mut evidence = Vec::new();
        NodeProjectContext::default().add_angular_rxjs_sources(
            "component.ts",
            &root,
            Language::Typescript,
            &comments,
            &conditional,
            &literals,
            &mut evidence,
        );

        assert!(evidence.iter().any(|item| {
            item.tags
                .iter()
                .any(|tag| tag == "callback-parameter-alias-loop-use")
                && item
                    .captures
                    .get("value")
                    .is_some_and(|capture| capture.text == "user")
        }));
    }
}
