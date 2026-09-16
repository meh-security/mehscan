use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution, SymbolConfidence,
    SymbolResolution, SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "ast-grep 0.45.1 + bounded-serverless-boundary";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Flavor {
    Aws,
    Azure,
    Vercel,
    NextApp,
    NextPages,
}

impl Flavor {
    fn tag(self) -> &'static str {
        match self {
            Self::Aws => "aws-lambda",
            Self::Azure => "azure-functions",
            Self::Vercel => "vercel",
            Self::NextApp => "nextjs-app-router",
            Self::NextPages => "nextjs-pages-api",
        }
    }

    fn canonical_request(self) -> &'static str {
        match self {
            Self::Aws => "aws-lambda.APIGatewayProxyEvent",
            Self::Azure => "@azure/functions.HttpRequest",
            Self::Vercel => "@vercel/node.VercelRequest",
            Self::NextApp => "next/server.NextRequest",
            Self::NextPages => "next.NextApiRequest",
        }
    }
}

#[derive(Default)]
struct Imports {
    request_types: BTreeMap<String, Flavor>,
    handler_types: BTreeMap<String, Flavor>,
    namespaces: BTreeMap<String, String>,
    azure_apps: BTreeSet<String>,
    next_responses: BTreeSet<String>,
    next_auth_helpers: BTreeSet<String>,
}

#[derive(Clone)]
struct RouteMeta {
    flavor: Flavor,
    method: String,
    path: String,
    access: HttpRouteAccess,
    guards: Vec<String>,
}

#[derive(Default)]
struct AzureRegistrations {
    by_range: BTreeMap<(usize, usize), RouteMeta>,
    by_name: BTreeMap<String, RouteMeta>,
}

#[derive(Clone)]
struct ValueBinding<'tree> {
    name: String,
    node: Node<'tree, StrDoc<SupportLang>>,
    field: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_serverless_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language == Language::Javascript {
        add_commonjs_aws_observations(path, root, comments, conditional, literals, evidence);
        add_javascript_next_pages_observations(
            path,
            root,
            comments,
            conditional,
            literals,
            evidence,
        );
        return;
    }
    if !matches!(language, Language::Typescript | Language::Tsx) {
        return;
    }
    let imports = serverless_imports(root);
    if imports.request_types.is_empty()
        && imports.handler_types.is_empty()
        && imports.namespaces.is_empty()
        && imports.azure_apps.is_empty()
        && imports.next_responses.is_empty()
    {
        return;
    }
    let azure = azure_registrations(root, &imports.azure_apps);
    for function in root.dfs().filter(is_function) {
        let Some((route, request, mut values)) =
            admitted_request_binding(path, &function, &imports, &azure)
        else {
            continue;
        };
        if route.flavor == Flavor::NextApp {
            values.extend(next_app_context_bindings(&function));
            if let Some(request) = request.as_ref() {
                values.extend(next_local_request_bindings(&function, request));
            }
        }
        push_entrypoint(
            path,
            language,
            &function,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        if let Some(request) = &request {
            values.extend(local_destructured_bindings(
                &function,
                request,
                route.flavor,
            ));
            add_request_member_sources(
                path,
                language,
                &function,
                request,
                &route,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        add_binding_use_sources(
            path,
            language,
            &function,
            &values,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        if route.flavor == Flavor::NextApp {
            add_next_url_search_sources(
                path,
                language,
                &function,
                request.as_ref(),
                &route,
                comments,
                conditional,
                literals,
                evidence,
            );
            add_next_form_data_sources(
                path,
                language,
                &function,
                request.as_ref(),
                &route,
                comments,
                conditional,
                literals,
                evidence,
            );
            add_next_response_observations(
                path,
                language,
                &function,
                &imports.next_responses,
                &route,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_javascript_next_pages_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(route_path) = next_pages_api_route_path(path) else {
        return;
    };
    let Some(function) = default_exported_function(root) else {
        return;
    };
    let Some(parameters) = function.field("parameters") else {
        return;
    };
    let Some(parameter) = parameters.children().find(|child| child.is_named()) else {
        return;
    };
    let Some(request_name) = parameter_identifier(&parameter) else {
        return;
    };
    let (access, guards) = next_pages_javascript_route_access(&function, &request_name);
    let route = RouteMeta {
        flavor: Flavor::NextPages,
        method: next_pages_method(&function, &request_name),
        path: route_path,
        access,
        guards,
    };
    let request = ValueBinding {
        name: request_name,
        node: parameter,
        field: String::new(),
    };
    push_entrypoint(
        path,
        Language::Javascript,
        &function,
        &route,
        comments,
        conditional,
        literals,
        evidence,
    );
    let values = local_destructured_bindings(&function, &request, route.flavor);
    add_request_member_sources(
        path,
        Language::Javascript,
        &function,
        &request,
        &route,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_binding_use_sources(
        path,
        Language::Javascript,
        &function,
        &values,
        &route,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_commonjs_aws_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let aws_aliases = commonjs_require_aliases(root, "aws-sdk");
    for function in root.dfs().filter(is_function) {
        let Some(handler_name) = commonjs_exported_handler(&function) else {
            continue;
        };
        let Some(parameters) = function.field("parameters") else {
            continue;
        };
        let Some(parameter) = parameters.children().find(|child| child.is_named()) else {
            continue;
        };
        let Some(request_name) = parameter_identifier(&parameter) else {
            continue;
        };
        let helpers = request_forwarded_helpers(root, &function, &request_name);
        if !function_has_aws_request_shape(&function, &request_name)
            && !helpers
                .iter()
                .any(|(helper, request)| function_has_aws_request_shape(helper, &request.name))
        {
            continue;
        }
        let route = RouteMeta {
            flavor: Flavor::Aws,
            method: "ANY".to_string(),
            path: "<api-gateway-route>".to_string(),
            access: HttpRouteAccess::Unknown,
            guards: Vec::new(),
        };
        let request = ValueBinding {
            name: request_name,
            node: parameter,
            field: String::new(),
        };
        push_entrypoint(
            path,
            Language::Javascript,
            &function,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        if let Some(item) = evidence.last_mut()
            && item.provenance.engine == ENGINE
            && item.location.start.byte_offset == function.range().start
        {
            item.captures.insert(
                "handler".to_string(),
                text_capture(path, &function, &handler_name),
            );
        }
        add_request_member_sources(
            path,
            Language::Javascript,
            &function,
            &request,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        let handler_values = local_request_value_bindings(&function, &request, Flavor::Aws);
        remove_bound_member_sources(path, &function, &request, Flavor::Aws, evidence);
        add_binding_use_sources(
            path,
            Language::Javascript,
            &function,
            &handler_values,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        for (helper, helper_request) in &helpers {
            add_request_member_sources(
                path,
                Language::Javascript,
                helper,
                helper_request,
                &route,
                comments,
                conditional,
                literals,
                evidence,
            );
            let helper_values = local_request_value_bindings(helper, helper_request, Flavor::Aws);
            remove_bound_member_sources(path, helper, helper_request, Flavor::Aws, evidence);
            add_binding_use_sources(
                path,
                Language::Javascript,
                helper,
                &helper_values,
                &route,
                comments,
                conditional,
                literals,
                evidence,
            );
            add_aws_sdk_operations(
                path,
                helper,
                &aws_aliases,
                &route,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        add_aws_sdk_operations(
            path,
            &function,
            &aws_aliases,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_lambda_response_observations(
            path,
            &function,
            &route,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn remove_bound_member_sources(
    path: &str,
    function: &Node<'_, StrDoc<SupportLang>>,
    request: &ValueBinding<'_>,
    flavor: Flavor,
    evidence: &mut Vec<Evidence>,
) {
    let ranges = function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && nearest_function_range(node) == Some(function.range())
        })
        .filter_map(|declaration| {
            let value = declaration.field("value")?;
            request_field(&normalized(&value.text()), &request.name, flavor)?;
            Some(value.range())
        })
        .collect::<Vec<_>>();
    evidence.retain(|item| {
        !(item.location.path == path
            && item.rule_id == "javascript-serverless-request-source"
            && ranges.iter().any(|range| {
                item.location.start.byte_offset == range.start
                    && item.location.end.byte_offset == range.end
            }))
    });
}

fn local_request_value_bindings<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    request: &ValueBinding<'tree>,
    flavor: Flavor,
) -> Vec<ValueBinding<'tree>> {
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && nearest_function_range(node) == Some(function.range())
        })
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            if name.kind().as_ref() != "identifier" {
                return None;
            }
            let value = declaration.field("value")?;
            let field = request_field(&normalized(&value.text()), &request.name, flavor)?;
            Some(ValueBinding {
                name: name.text().trim().to_string(),
                node: name,
                field: field.to_string(),
            })
        })
        .collect()
}

fn commonjs_exported_handler(function: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let parent = function.parent()?;
    if parent.kind().as_ref() != "assignment_expression"
        || !parent
            .field("right")
            .is_some_and(|right| right.range() == function.range())
    {
        return None;
    }
    let left = normalized(&parent.field("left")?.text());
    left.strip_prefix("exports.")
        .or_else(|| left.strip_prefix("module.exports."))
        .filter(|name| is_identifier(name))
        .map(str::to_string)
}

fn parameter_identifier(parameter: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let pattern = parameter
        .field("pattern")
        .or_else(|| parameter.field("name"))
        .unwrap_or_else(|| parameter.clone());
    (pattern.kind().as_ref() == "identifier").then(|| pattern.text().trim().to_string())
}

fn function_has_aws_request_shape(function: &Node<'_, StrDoc<SupportLang>>, request: &str) -> bool {
    function.dfs().any(|node| {
        nearest_function_range(&node) == Some(function.range())
            && matches!(
                node.kind().as_ref(),
                "member_expression" | "subscript_expression"
            )
            && request_field(&normalized(&node.text()), request, Flavor::Aws).is_some()
    })
}

fn request_forwarded_helpers<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    handler: &Node<'tree, StrDoc<SupportLang>>,
    request: &str,
) -> Vec<(Node<'tree, StrDoc<SupportLang>>, ValueBinding<'tree>)> {
    let names = handler
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "call_expression"
                && nearest_function_range(node) == Some(handler.range())
        })
        .filter_map(|call| {
            let callee = call.field("function")?;
            if callee.kind().as_ref() != "identifier" {
                return None;
            }
            let passes_request = call.field("arguments")?.children().any(|argument| {
                argument.is_named()
                    && argument.kind().as_ref() == "identifier"
                    && argument.text().as_ref() == request
            });
            passes_request.then(|| callee.text().into_owned())
        })
        .collect::<BTreeSet<_>>();
    root.dfs()
        .filter(is_function)
        .filter_map(|function| {
            let symbol = function_symbol(&function)?;
            if !names.contains(&symbol) {
                return None;
            }
            let parameter = function
                .field("parameters")?
                .children()
                .find(|child| child.is_named())?;
            let name = parameter_identifier(&parameter)?;
            Some((
                function,
                ValueBinding {
                    name,
                    node: parameter,
                    field: String::new(),
                },
            ))
        })
        .collect()
}

fn commonjs_require_aliases(
    root: &Node<'_, StrDoc<SupportLang>>,
    module: &str,
) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = declaration.field("value")?;
            let compact_value = compact(&value.text());
            (compact_value == format!("require('{module}')")
                || compact_value == format!("require(\"{module}\")"))
            .then(|| name.text().trim().to_string())
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn add_aws_sdk_operations<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    aws_aliases: &BTreeSet<String>,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if aws_aliases.is_empty() {
        return;
    }
    let mut clients = BTreeMap::<String, &'static str>::new();
    for declaration in function.dfs().filter(|node| {
        node.kind().as_ref() == "variable_declarator"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        let value = normalized(&value.text());
        let service = aws_aliases.iter().find_map(|alias| {
            (value == format!("new{alias}.DynamoDB.DocumentClient()"))
                .then_some("dynamodb")
                .or_else(|| (value == format!("new{alias}.S3()")).then_some("s3"))
        });
        if let Some(service) = service {
            clients.insert(name.text().trim().to_string(), service);
        }
    }
    for call in function.dfs().filter(|node| {
        node.kind().as_ref() == "call_expression"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let observed = normalized(&callee.text());
        let Some((client, method)) = observed.rsplit_once('.') else {
            continue;
        };
        let Some(service) = clients.get(client).copied() else {
            continue;
        };
        let Some(argument) = call
            .field("arguments")
            .and_then(|arguments| arguments.children().find(|child| child.is_named()))
        else {
            continue;
        };
        match (service, method) {
            ("dynamodb", "put" | "update" | "delete" | "get" | "query" | "scan") => {
                push_serverless_fact(
                    path,
                    Language::Javascript,
                    &call,
                    &argument,
                    EvidenceKind::SensitiveOperation,
                    Capability::DatabaseQuery,
                    "aws-dynamodb-operation",
                    "operation",
                    Vec::new(),
                    vec!["aws", "dynamodb", method, "data-store", "context-only"],
                    route,
                    Some(("aws-sdk.DynamoDB.DocumentClient", &observed)),
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            ("s3", "putObject" | "upload" | "getObject" | "deleteObject") => {
                push_serverless_fact(
                    path,
                    Language::Javascript,
                    &call,
                    &argument,
                    EvidenceKind::SensitiveOperation,
                    if matches!(method, "getObject") {
                        Capability::FilesystemRead
                    } else {
                        Capability::FilesystemWrite
                    },
                    "aws-s3-object-operation",
                    "object",
                    Vec::new(),
                    vec!["aws", "s3", method, "object-store", "context-only"],
                    route,
                    Some(("aws-sdk.S3", &observed)),
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
                let argument_text = compact(&argument.text());
                if argument_text.contains("ACL:'public-read'")
                    || argument_text.contains("ACL:\"public-read\"")
                {
                    push_serverless_fact(
                        path,
                        Language::Javascript,
                        &argument,
                        &argument,
                        EvidenceKind::SecurityConfiguration,
                        Capability::Authorization,
                        "aws-s3-public-object-acl",
                        "acl",
                        vec!["CWE-732"],
                        vec![
                            "aws",
                            "s3",
                            "public-read",
                            "object-acl",
                            "deployment-context-required",
                        ],
                        route,
                        Some(("aws-sdk.S3.ACL", "public-read")),
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_lambda_response_observations<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for object in function.dfs().filter(|node| {
        node.kind().as_ref() == "object" && nearest_function_range(node) == Some(function.range())
    }) {
        if let Some(body) = object_property(&object, "body")
            && normalized(&body.text()).ends_with(".stack")
        {
            push_serverless_fact(
                path,
                Language::Javascript,
                &body,
                &body,
                EvidenceKind::Sink,
                Capability::HttpRequestHandling,
                "lambda-stack-trace-response",
                "body",
                vec!["CWE-209"],
                vec![
                    "aws",
                    "lambda",
                    "http-response",
                    "stack-trace",
                    "sensitive-output",
                ],
                route,
                Some(("aws-lambda.APIGatewayProxyResult.body", &body.text())),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        let Some(headers) = object_property(&object, "headers") else {
            continue;
        };
        let Some(location) =
            object_property(&headers, "Location").or_else(|| object_property(&headers, "location"))
        else {
            continue;
        };
        push_serverless_fact(
            path,
            Language::Javascript,
            &location,
            &location,
            EvidenceKind::Sink,
            Capability::Redirect,
            "lambda-redirect-response",
            "location",
            vec!["CWE-601"],
            vec!["aws", "lambda", "http-response", "redirect"],
            route,
            Some((
                "aws-lambda.APIGatewayProxyResult.headers.Location",
                &location.text(),
            )),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_serverless_fact<'tree>(
    path: &str,
    language: Language,
    anchor: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    suffix: &str,
    role: &str,
    cwes: Vec<&str>,
    tags: Vec<&str>,
    route: &RouteMeta,
    symbol: Option<(&str, &str)>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(anchor.range()) {
        return;
    }
    let rule_id = format!("{}-{suffix}", language_prefix(language));
    let id = evidence_id(path, &rule_id, anchor.range().start, anchor.range().end);
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    let related_evidence = evidence
        .iter()
        .filter(|item| {
            item.kind == EvidenceKind::Source
                && item.capability == Capability::HttpRequestData
                && item.enclosing_symbol == function_symbol_for_node(anchor)
        })
        .map(|item| item.id.clone())
        .collect();
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, anchor),
        enclosing_symbol: function_symbol_for_node(anchor).or_else(|| enclosing_symbol(anchor)),
        captures: BTreeMap::from([(role.to_string(), capture(path, value))]),
        cwe_candidates: cwes.into_iter().map(str::to_string).collect(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(anchor, literals)),
            availability: Some(conditional.availability_for(anchor.range())),
            http_routes: vec![HttpRouteContext {
                method: route.method.clone(),
                path: route.path.clone(),
                access: route.access,
                guards: route.guards.clone(),
            }],
            ..EvidenceContext::default()
        },
        symbol_resolution: symbol.map(|(canonical, observed)| SymbolResolution {
            canonical: canonical.to_string(),
            observed: observed.to_string(),
            method: SymbolResolutionMethod::Alias,
            confidence: SymbolConfidence::High,
        }),
        rule_id,
        related_evidence,
    });
}

fn serverless_imports(root: &Node<'_, StrDoc<SupportLang>>) -> Imports {
    let mut imports = Imports::default();
    for import in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = import.text();
        let Some((clause, module)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        let Some(module) = exact_quoted(module.trim().trim_end_matches(';')) else {
            continue;
        };
        if !matches!(
            module,
            "aws-lambda"
                | "@azure/functions"
                | "@vercel/node"
                | "next/server"
                | "next"
                | "@/lib/auth"
        ) {
            continue;
        }
        let clause = clause.trim().strip_prefix("type ").unwrap_or(clause.trim());
        if let Some(namespace) = clause.strip_prefix("* as ") {
            imports
                .namespaces
                .insert(namespace.trim().to_string(), module.to_string());
            if module == "@azure/functions" {
                imports
                    .azure_apps
                    .insert(format!("{}.app", namespace.trim()));
            }
            continue;
        }
        if !clause.starts_with('{') {
            continue;
        }
        for entry in clause.trim_matches(['{', '}']).split(',') {
            let words = entry.split_whitespace().collect::<Vec<_>>();
            let words = words.strip_prefix(&["type"]).unwrap_or(words.as_slice());
            let Some(imported) = words.first().copied() else {
                continue;
            };
            let visible = if words.get(1) == Some(&"as") {
                words.get(2).copied().unwrap_or(imported)
            } else {
                imported
            };
            match (module, imported) {
                (
                    "aws-lambda",
                    "APIGatewayProxyEvent"
                    | "APIGatewayProxyEventV2"
                    | "APIGatewayEvent"
                    | "ALBEvent",
                ) => {
                    imports
                        .request_types
                        .insert(visible.to_string(), Flavor::Aws);
                }
                ("aws-lambda", "APIGatewayProxyHandler" | "APIGatewayProxyHandlerV2") => {
                    imports
                        .handler_types
                        .insert(visible.to_string(), Flavor::Aws);
                }
                ("@azure/functions", "HttpRequest") => {
                    imports
                        .request_types
                        .insert(visible.to_string(), Flavor::Azure);
                }
                ("@azure/functions", "app") => {
                    imports.azure_apps.insert(visible.to_string());
                }
                ("@vercel/node", "VercelRequest") => {
                    imports
                        .request_types
                        .insert(visible.to_string(), Flavor::Vercel);
                }
                ("next/server", "NextRequest") => {
                    imports
                        .request_types
                        .insert(visible.to_string(), Flavor::NextApp);
                }
                ("next/server", "NextResponse") => {
                    imports.next_responses.insert(visible.to_string());
                }
                ("next", "NextApiRequest") => {
                    imports
                        .request_types
                        .insert(visible.to_string(), Flavor::NextPages);
                }
                ("@/lib/auth", "getUserFromRequest") => {
                    imports.next_auth_helpers.insert(visible.to_string());
                }
                _ => {}
            }
        }
    }

    for _ in 0..2 {
        let aliases = root
            .dfs()
            .filter_map(|node| request_type_alias(node, &imports))
            .collect::<Vec<_>>();
        let mut changed = false;
        for (name, flavor) in aliases {
            changed |= imports.request_types.insert(name, flavor).is_none();
        }
        if !changed {
            break;
        }
    }
    imports
}

fn request_type_alias(
    node: Node<'_, StrDoc<SupportLang>>,
    imports: &Imports,
) -> Option<(String, Flavor)> {
    match node.kind().as_ref() {
        "type_alias_declaration" => {
            let name = node.field("name")?.text().trim().to_string();
            let value = node
                .field("value")
                .or_else(|| node.children().filter(|child| child.is_named()).last())?;
            flavor_for_type(&value.text(), imports).map(|flavor| (name, flavor))
        }
        "interface_declaration" => {
            let name = node.field("name")?.text().trim().to_string();
            let text = compact(&node.text());
            let extends = text.split_once("extends")?.1.split_once('{')?.0;
            extends
                .split(',')
                .find_map(|base| flavor_for_type(base, imports))
                .map(|flavor| (name, flavor))
        }
        _ => None,
    }
}

fn flavor_for_type(text: &str, imports: &Imports) -> Option<Flavor> {
    let text = compact(text);
    let text = text.trim_start_matches(':');
    if text.contains('|') {
        return None;
    }
    text.split('&').find_map(|part| {
        let base = part.split_once('<').map_or(part, |(base, _)| base);
        imports.request_types.get(base).copied().or_else(|| {
            imports.namespaces.iter().find_map(|(namespace, module)| {
                let name = base.strip_prefix(&format!("{namespace}."))?;
                match (module.as_str(), name) {
                    (
                        "aws-lambda",
                        "APIGatewayProxyEvent"
                        | "APIGatewayProxyEventV2"
                        | "APIGatewayEvent"
                        | "ALBEvent",
                    ) => Some(Flavor::Aws),
                    ("@azure/functions", "HttpRequest") => Some(Flavor::Azure),
                    ("@vercel/node", "VercelRequest") => Some(Flavor::Vercel),
                    ("next/server", "NextRequest") => Some(Flavor::NextApp),
                    ("next", "NextApiRequest") => Some(Flavor::NextPages),
                    _ => None,
                }
            })
        })
    })
}

fn contextual_handler_flavor(
    function: &Node<'_, StrDoc<SupportLang>>,
    imports: &Imports,
) -> Option<Flavor> {
    let parent = function.parent()?;
    let type_node = (parent.kind().as_ref() == "variable_declarator"
        && parent
            .field("value")
            .is_some_and(|value| value.range() == function.range()))
    .then(|| parent.field("type"))
    .flatten()?;
    let text = compact(&type_node.text());
    let base = text
        .trim_start_matches(':')
        .split_once('<')
        .map_or(text.trim_start_matches(':'), |(base, _)| base);
    imports.handler_types.get(base).copied().or_else(|| {
        imports.namespaces.iter().find_map(|(namespace, module)| {
            (module == "aws-lambda"
                && matches!(
                    base.strip_prefix(&format!("{namespace}.")),
                    Some("APIGatewayProxyHandler" | "APIGatewayProxyHandlerV2")
                ))
            .then_some(Flavor::Aws)
        })
    })
}

fn azure_registrations(
    root: &Node<'_, StrDoc<SupportLang>>,
    apps: &BTreeSet<String>,
) -> AzureRegistrations {
    let mut registrations = AzureRegistrations::default();
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
    {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let observed = compact(&callee.text());
        let Some(app) = observed.strip_suffix(".http") else {
            continue;
        };
        if !apps.contains(app) {
            continue;
        }
        let Some(arguments) = call.field("arguments") else {
            continue;
        };
        let arguments = arguments
            .children()
            .filter(|child| child.is_named())
            .collect::<Vec<_>>();
        let (Some(name), Some(options)) = (arguments.first(), arguments.get(1)) else {
            continue;
        };
        let route = object_property(options, "route")
            .and_then(|node| exact_quoted(&node.text()).map(str::to_string))
            .or_else(|| exact_quoted(&name.text()).map(str::to_string))
            .unwrap_or_else(|| "<dynamic>".to_string());
        let method = object_property(options, "methods")
            .map(|node| {
                node.text()
                    .trim_matches(['[', ']'])
                    .split(',')
                    .filter_map(|part| exact_quoted(part.trim()))
                    .map(|part| part.to_ascii_uppercase())
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .filter(|method| !method.is_empty())
            .unwrap_or_else(|| "ANY".to_string());
        let auth_level = object_property(options, "authLevel")
            .and_then(|node| exact_quoted(&node.text()).map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string());
        let Some(handler) = object_property(options, "handler") else {
            continue;
        };
        let meta = RouteMeta {
            flavor: Flavor::Azure,
            method,
            path: format!("/{route}"),
            access: HttpRouteAccess::Unknown,
            guards: vec![format!("azure_auth_level:{auth_level}")],
        };
        if is_function(&handler) {
            registrations
                .by_range
                .insert(range_key(handler.range()), meta);
        } else if handler.kind().as_ref() == "identifier" {
            registrations
                .by_name
                .insert(handler.text().into_owned(), meta);
        }
    }
    registrations
}

fn object_property<'tree>(
    object: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    object
        .children()
        .filter(|child| child.is_named() && child.kind().as_ref() == "pair")
        .find(|pair| {
            pair.field("key")
                .is_some_and(|key| key.text().trim_matches(['\'', '"']) == name)
        })?
        .field("value")
}

fn admitted_request_binding<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    imports: &Imports,
    azure: &AzureRegistrations,
) -> Option<(
    RouteMeta,
    Option<ValueBinding<'tree>>,
    Vec<ValueBinding<'tree>>,
)> {
    let symbol = function_symbol(function);
    let azure_route = azure
        .by_range
        .get(&range_key(function.range()))
        .cloned()
        .or_else(|| {
            symbol
                .as_ref()
                .and_then(|name| azure.by_name.get(name))
                .cloned()
        });
    let next_app_route = next_app_route(path, function, imports);
    let parameters = function.field("parameters")?;
    let parameter = parameters.children().find(|child| child.is_named())?;
    let annotated_flavor = parameter
        .field("type")
        .and_then(|type_node| flavor_for_type(&type_node.text(), imports));
    let contextual = contextual_handler_flavor(function, imports);
    let flavor = azure_route
        .as_ref()
        .map(|route| route.flavor)
        .or(contextual)
        .or(annotated_flavor)
        .or_else(|| next_app_route.as_ref().map(|route| route.flavor))?;

    let exported = is_exported(function);
    let route = if let Some(route) = azure_route {
        route
    } else if let Some(route) = next_app_route {
        route
    } else {
        if !exported {
            return None;
        }
        match flavor {
            Flavor::NextApp => {
                let method = symbol.as_deref()?;
                if !matches!(
                    method,
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
                ) {
                    return None;
                }
                RouteMeta {
                    flavor,
                    method: method.to_string(),
                    path: next_route_path(path),
                    access: HttpRouteAccess::Unknown,
                    guards: Vec::new(),
                }
            }
            Flavor::NextPages => RouteMeta {
                flavor,
                method: "ANY".to_string(),
                path: next_pages_api_route_path(path)
                    .unwrap_or_else(|| "<next-api-route>".to_string()),
                access: HttpRouteAccess::Unknown,
                guards: Vec::new(),
            },
            Flavor::Aws => RouteMeta {
                flavor,
                method: "ANY".to_string(),
                path: "<api-gateway-route>".to_string(),
                access: HttpRouteAccess::Unknown,
                guards: Vec::new(),
            },
            Flavor::Vercel => RouteMeta {
                flavor,
                method: "ANY".to_string(),
                path: "<vercel-function>".to_string(),
                access: HttpRouteAccess::Unknown,
                guards: Vec::new(),
            },
            Flavor::Azure => return None,
        }
    };

    let pattern = parameter
        .field("pattern")
        .or_else(|| parameter.field("name"))?;
    if pattern.kind().as_ref() == "identifier" {
        let request = ValueBinding {
            name: pattern.text().trim().to_string(),
            node: pattern,
            field: String::new(),
        };
        Some((route, Some(request), Vec::new()))
    } else if pattern.kind().as_ref() == "object_pattern" {
        let values = object_bindings(&pattern.text())
            .into_iter()
            .filter(|(field, _)| field_allowed(flavor, field))
            .filter_map(|(field, name)| {
                Some(ValueBinding {
                    node: identifier_node(&pattern, &name)?,
                    name,
                    field,
                })
            })
            .collect();
        Some((route, None, values))
    } else {
        None
    }
}

fn next_app_route(
    path: &str,
    function: &Node<'_, StrDoc<SupportLang>>,
    imports: &Imports,
) -> Option<RouteMeta> {
    if imports.next_responses.is_empty() || !is_exported(function) {
        return None;
    }
    let method = function_symbol(function)?;
    if !matches!(
        method.as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
    ) {
        return None;
    }
    let route_path = next_route_path(path);
    let (access, guards) = next_route_access(function, imports);
    (route_path != "<next-app-route>").then_some(RouteMeta {
        flavor: Flavor::NextApp,
        method,
        path: route_path,
        access,
        guards,
    })
}

fn next_route_access(
    function: &Node<'_, StrDoc<SupportLang>>,
    imports: &Imports,
) -> (HttpRouteAccess, Vec<String>) {
    for declaration in function.dfs().filter(|node| {
        node.kind().as_ref() == "variable_declarator"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        if name.kind().as_ref() != "identifier" {
            continue;
        }
        let value = normalized(&value.text());
        let Some(helper) = imports
            .next_auth_helpers
            .iter()
            .find(|helper| value.starts_with(&format!("{helper}(")) && value.ends_with(')'))
        else {
            continue;
        };
        let principal = name.text().trim().to_string();
        let rejects_unauthenticated = function.dfs().any(|node| {
            if node.kind().as_ref() != "if_statement"
                || nearest_function_range(&node) != Some(function.range())
                || node.range().start <= declaration.range().end
            {
                return false;
            }
            let Some(condition) = node.field("condition") else {
                return false;
            };
            let condition = normalized(&condition.text());
            let condition = condition.trim_matches(['(', ')']);
            let rejects_principal = condition == format!("!{principal}")
                || condition == format!("{principal}==null")
                || condition == format!("{principal}===null");
            rejects_principal
                && node.field("consequence").is_some_and(|branch| {
                    let branch = normalized(&branch.text());
                    branch.contains("return")
                        && (branch.contains("status:401") || branch.contains("status(401)"))
                })
        });
        if rejects_unauthenticated {
            return (
                HttpRouteAccess::Authenticated,
                vec![format!("{helper}:rejects-401")],
            );
        }
    }
    (HttpRouteAccess::Unknown, Vec::new())
}

fn next_app_context_bindings<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<ValueBinding<'tree>> {
    let Some(parameters) = function.field("parameters") else {
        return Vec::new();
    };
    let Some(context) = parameters
        .children()
        .filter(|child| child.is_named())
        .nth(1)
    else {
        return Vec::new();
    };
    let Some(pattern) = context.field("pattern").or_else(|| context.field("name")) else {
        return Vec::new();
    };
    if pattern.kind().as_ref() != "object_pattern" {
        return Vec::new();
    }
    object_bindings(&pattern.text())
        .into_iter()
        .filter(|(field, _)| field == "params")
        .filter_map(|(field, name)| {
            Some(ValueBinding {
                node: identifier_node(&pattern, &name)?,
                name,
                field,
            })
        })
        .collect()
}

fn next_local_request_bindings<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    request: &ValueBinding<'tree>,
) -> Vec<ValueBinding<'tree>> {
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && nearest_function_range(node) == Some(function.range())
        })
        .flat_map(|declaration| {
            let (Some(pattern), Some(value)) =
                (declaration.field("name"), declaration.field("value"))
            else {
                return Vec::new();
            };
            let value = normalized(&value.text());
            let value = value.strip_prefix("await").unwrap_or(&value);
            if value != format!("{}.json()", request.name)
                && value != format!("{}.formData()", request.name)
            {
                return Vec::new();
            }
            let field = "body";
            if pattern.kind().as_ref() == "identifier" {
                return vec![ValueBinding {
                    name: pattern.text().trim().to_string(),
                    node: pattern,
                    field: field.to_string(),
                }];
            }
            if pattern.kind().as_ref() != "object_pattern" {
                return Vec::new();
            }
            object_bindings(&pattern.text())
                .into_iter()
                .filter_map(|(_, name)| {
                    Some(ValueBinding {
                        node: identifier_node(&pattern, &name)?,
                        name,
                        field: field.to_string(),
                    })
                })
                .collect()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn add_next_form_data_sources<'tree>(
    path: &str,
    language: Language,
    function: &Node<'tree, StrDoc<SupportLang>>,
    request: Option<&ValueBinding<'tree>>,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(request) = request else {
        return;
    };
    let aliases = function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && nearest_function_range(node) == Some(function.range())
        })
        .filter_map(|declaration| {
            let name = declaration.field("name")?;
            let value = normalized(&declaration.field("value")?.text());
            let value = value.strip_prefix("await").unwrap_or(&value);
            (name.kind().as_ref() == "identifier"
                && value == format!("{}.formData()", request.name))
            .then(|| name.text().trim().to_string())
        })
        .collect::<BTreeSet<_>>();
    for call in function.dfs().filter(|node| {
        node.kind().as_ref() == "call_expression"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let observed = normalized(&callee.text());
        if aliases
            .iter()
            .any(|alias| observed == format!("{alias}.get"))
        {
            push_source(
                path,
                language,
                &call,
                "body",
                &observed,
                route,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_next_url_search_sources<'tree>(
    path: &str,
    language: Language,
    function: &Node<'tree, StrDoc<SupportLang>>,
    request: Option<&ValueBinding<'tree>>,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(request) = request else {
        return;
    };
    let mut search_aliases = BTreeSet::new();
    let mut url_aliases = BTreeSet::new();
    for declaration in function.dfs().filter(|node| {
        node.kind().as_ref() == "variable_declarator"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let (Some(name), Some(value)) = (declaration.field("name"), declaration.field("value"))
        else {
            continue;
        };
        let value_text = normalized(&value.text());
        if !value_text.starts_with("newURL(")
            || !value_text.contains(&format!("{}.url", request.name))
        {
            continue;
        }
        if name.kind().as_ref() == "object_pattern" {
            search_aliases.extend(
                object_bindings(&name.text())
                    .into_iter()
                    .filter(|(field, _)| field == "searchParams")
                    .map(|(_, binding)| binding),
            );
        } else if name.kind().as_ref() == "identifier" {
            url_aliases.insert(name.text().trim().to_string());
        }
    }
    for call in function.dfs().filter(|node| {
        node.kind().as_ref() == "call_expression"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let observed = normalized(&callee.text());
        let admitted = search_aliases
            .iter()
            .any(|alias| observed == format!("{alias}.get"))
            || url_aliases
                .iter()
                .any(|alias| observed == format!("{alias}.searchParams.get"));
        if admitted {
            push_source(
                path,
                language,
                &call,
                "query",
                &observed,
                route,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_next_response_observations<'tree>(
    path: &str,
    language: Language,
    function: &Node<'tree, StrDoc<SupportLang>>,
    responses: &BTreeSet<String>,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in function.dfs().filter(|node| {
        node.kind().as_ref() == "call_expression"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let observed = normalized(&callee.text());
        if !responses
            .iter()
            .any(|response| observed == format!("{response}.redirect"))
        {
            continue;
        }
        let Some(location) = call
            .field("arguments")
            .and_then(|arguments| arguments.children().find(|child| child.is_named()))
        else {
            continue;
        };
        if next_relative_redirect_fallback(&call, &location) {
            push_serverless_fact(
                path,
                language,
                &call,
                &location,
                EvidenceKind::Validation,
                Capability::RedirectDestinationValidation,
                "nextjs-relative-redirect-control",
                "location",
                Vec::new(),
                vec![
                    "nextjs",
                    "app-router",
                    "redirect",
                    "relative-fallback",
                    "same-origin-base",
                    "control",
                ],
                route,
                Some(("web.URL", &location.text())),
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }
        push_serverless_fact(
            path,
            language,
            &call,
            &location,
            EvidenceKind::Sink,
            Capability::Redirect,
            "nextjs-response-redirect",
            "location",
            vec!["CWE-601"],
            vec!["nextjs", "app-router", "http-response", "redirect"],
            route,
            Some(("next/server.NextResponse.redirect", &observed)),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    for response in function.dfs().filter(|node| {
        node.kind().as_ref() == "new_expression"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let Some(constructor) = response.field("constructor") else {
            continue;
        };
        if normalized(&constructor.text()) != "Response" {
            continue;
        }
        let Some(arguments) = response.field("arguments") else {
            continue;
        };
        let arguments = arguments
            .children()
            .filter(|child| child.is_named())
            .collect::<Vec<_>>();
        let (Some(body), Some(options)) = (arguments.first(), arguments.get(1)) else {
            continue;
        };
        let options_text = compact(&options.text()).to_ascii_lowercase();
        if !options_text.contains("content-type") || !options_text.contains("text/html") {
            continue;
        }
        push_serverless_fact(
            path,
            language,
            &response,
            body,
            EvidenceKind::Sink,
            Capability::HtmlOutput,
            "nextjs-response-html-output",
            "content",
            vec!["CWE-79"],
            vec![
                "nextjs",
                "app-router",
                "http-response",
                "html",
                "explicit-content-type",
            ],
            route,
            Some(("web.Response", "Response")),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn next_relative_redirect_fallback(
    call: &Node<'_, StrDoc<SupportLang>>,
    location: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let location = normalized(&location.text());
    let Some(arguments) = location.strip_prefix("newURL(") else {
        return false;
    };
    let Some((candidate, rest)) = arguments.split_once(',') else {
        return false;
    };
    if !is_identifier(candidate) || !rest.ends_with(".origin).toString()") {
        return false;
    }
    let Some(catch) = call
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "catch_clause")
    else {
        return false;
    };
    catch
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "try_statement")
        .is_some_and(|statement| {
            compact(&statement.text()).contains(&format!("newURL({candidate})"))
        })
}

// These arguments are the shared scan context plus the function/request pair;
// keeping them explicit avoids a second context abstraction used by one helper.
#[allow(clippy::too_many_arguments)]
fn add_request_member_sources<'tree>(
    path: &str,
    language: Language,
    function: &Node<'tree, StrDoc<SupportLang>>,
    request: &ValueBinding<'tree>,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for node in function.dfs().filter(|node| {
        nearest_function_range(node) == Some(function.range())
            && matches!(
                node.kind().as_ref(),
                "member_expression" | "subscript_expression"
            )
    }) {
        let observed = normalized(&node.text());
        let Some(field) = request_field(&observed, &request.name, route.flavor) else {
            continue;
        };
        if member_is_call_callee(&node)
            || node.parent().is_some_and(|parent| {
                matches!(
                    parent.kind().as_ref(),
                    "member_expression" | "subscript_expression"
                ) && request_field(&normalized(&parent.text()), &request.name, route.flavor)
                    .is_some()
            })
        {
            continue;
        }
        push_source(
            path,
            language,
            &node,
            field,
            &observed,
            route,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    for call in function.dfs().filter(|node| {
        node.kind().as_ref() == "call_expression"
            && nearest_function_range(node) == Some(function.range())
    }) {
        let Some(callee) = call.field("function") else {
            continue;
        };
        let observed = normalized(&callee.text());
        let Some(field) = request_call_field(&observed, &request.name, route.flavor) else {
            continue;
        };
        push_source(
            path,
            language,
            &call,
            field,
            &observed,
            route,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn local_destructured_bindings<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    request: &ValueBinding<'tree>,
    flavor: Flavor,
) -> Vec<ValueBinding<'tree>> {
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && nearest_function_range(node) == Some(function.range())
        })
        .flat_map(|declaration| {
            let (Some(pattern), Some(value)) =
                (declaration.field("name"), declaration.field("value"))
            else {
                return Vec::new();
            };
            if pattern.kind().as_ref() != "object_pattern"
                || normalized(&value.text()) != request.name
            {
                return Vec::new();
            }
            object_bindings(&pattern.text())
                .into_iter()
                .filter(|(field, _)| field_allowed(flavor, field))
                .filter_map(|(field, name)| {
                    Some(ValueBinding {
                        node: identifier_node(&pattern, &name)?,
                        name,
                        field,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn add_binding_use_sources<'tree>(
    path: &str,
    language: Language,
    function: &Node<'tree, StrDoc<SupportLang>>,
    bindings: &[ValueBinding<'tree>],
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for binding in bindings {
        for node in function.dfs().filter(|node| {
            node.kind().as_ref() == "identifier"
                && node.text().as_ref() == binding.name
                && nearest_function_range(node) == Some(function.range())
                && node.range() != binding.node.range()
                && identifier_is_value_use(node)
        }) {
            push_source(
                path,
                language,
                &node,
                &binding.field,
                &binding.name,
                route,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn request_field<'a>(observed: &str, request: &str, flavor: Flavor) -> Option<&'a str> {
    let tail = observed.strip_prefix(&format!("{request}."))?;
    let field = tail.split(['.', '[']).next()?;
    field_allowed(flavor, field).then_some(match field {
        "queryStringParameters" | "rawQueryString" | "query" | "nextUrl" => "query",
        "pathParameters" | "rawPath" | "params" => "params",
        "multiValueHeaders" | "headers" => "headers",
        "cookies" => "cookies",
        "body" => "body",
        "url" => "url",
        _ => "request",
    })
}

fn request_call_field<'a>(observed: &str, request: &str, flavor: Flavor) -> Option<&'a str> {
    let tail = observed.strip_prefix(&format!("{request}."))?;
    match flavor {
        Flavor::Azure => match tail {
            "json" | "text" | "formData" | "arrayBuffer" | "blob" => Some("body"),
            value if value.starts_with("query.get") => Some("query"),
            value if value.starts_with("headers.get") => Some("headers"),
            _ => None,
        },
        Flavor::NextApp => match tail {
            "json" | "text" | "formData" | "arrayBuffer" | "blob" => Some("body"),
            value if value.starts_with("nextUrl.searchParams.get") => Some("query"),
            value if value.starts_with("headers.get") => Some("headers"),
            value if value.starts_with("cookies.get") => Some("cookies"),
            _ => None,
        },
        _ => None,
    }
}

fn field_allowed(flavor: Flavor, field: &str) -> bool {
    match flavor {
        Flavor::Aws => matches!(
            field,
            "body"
                | "queryStringParameters"
                | "pathParameters"
                | "headers"
                | "multiValueHeaders"
                | "cookies"
                | "rawPath"
                | "rawQueryString"
        ),
        Flavor::Azure => matches!(field, "body" | "query" | "params" | "headers" | "url"),
        Flavor::Vercel | Flavor::NextPages => {
            matches!(field, "body" | "query" | "cookies" | "headers" | "url")
        }
        Flavor::NextApp => matches!(field, "nextUrl" | "url" | "headers" | "cookies"),
    }
}

#[allow(clippy::too_many_arguments)]
fn push_entrypoint<'tree>(
    path: &str,
    language: Language,
    function: &Node<'tree, StrDoc<SupportLang>>,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        language,
        function,
        function,
        EvidenceKind::Entrypoint,
        Capability::HttpRequestHandling,
        "serverless-http-entrypoint",
        "route",
        &route.path,
        route,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_source<'tree>(
    path: &str,
    language: Language,
    node: &Node<'tree, StrDoc<SupportLang>>,
    field: &str,
    observed: &str,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let previous_len = evidence.len();
    push_evidence(
        path,
        language,
        node,
        node,
        EvidenceKind::Source,
        Capability::HttpRequestData,
        "serverless-request-source",
        "value",
        observed,
        route,
        comments,
        conditional,
        literals,
        evidence,
    );
    if evidence.len() > previous_len
        && let Some(item) = evidence.last_mut()
    {
        item.captures
            .insert("field".to_string(), text_capture(path, node, field));
    }
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    language: Language,
    anchor: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    suffix: &str,
    role: &str,
    observed: &str,
    route: &RouteMeta,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(anchor.range())
        || evidence.iter().any(|item| {
            item.provenance.engine == ENGINE
                && item.capability == capability
                && item.location.start.byte_offset == anchor.range().start
                && item.location.end.byte_offset == anchor.range().end
        })
    {
        return;
    }
    let rule_id = format!("{}-{suffix}", language_prefix(language));
    evidence.push(Evidence {
        id: evidence_id(path, &rule_id, anchor.range().start, anchor.range().end),
        kind,
        capability,
        location: location(path, anchor),
        enclosing_symbol: function_symbol_for_node(anchor).or_else(|| enclosing_symbol(anchor)),
        captures: BTreeMap::from([(
            role.to_string(),
            if role == "route" {
                text_capture(path, value, observed)
            } else {
                capture(path, value)
            },
        )]),
        cwe_candidates: if kind == EvidenceKind::Source {
            vec!["CWE-20".to_string()]
        } else {
            vec!["CWE-306".to_string(), "CWE-862".to_string()]
        },
        tags: vec![
            "http".to_string(),
            "serverless".to_string(),
            route.flavor.tag().to_string(),
            if kind == EvidenceKind::Source {
                "attacker-controlled"
            } else {
                "entrypoint"
            }
            .to_string(),
        ],
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(anchor, literals)),
            availability: Some(conditional.availability_for(anchor.range())),
            http_routes: vec![HttpRouteContext {
                method: route.method.clone(),
                path: route.path.clone(),
                access: route.access,
                guards: route.guards.clone(),
            }],
            ..EvidenceContext::default()
        },
        symbol_resolution: Some(SymbolResolution {
            canonical: route.flavor.canonical_request().to_string(),
            observed: observed.to_string(),
            method: SymbolResolutionMethod::Alias,
            confidence: SymbolConfidence::High,
        }),
        rule_id,
        related_evidence: Vec::new(),
    });
}

fn object_bindings(text: &str) -> Vec<(String, String)> {
    text.trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() || entry.starts_with("...") || entry.contains('{') {
                return None;
            }
            let (field, binding) = entry.split_once(':').unwrap_or((entry, entry));
            let field = field.trim().trim_end_matches('?');
            let binding = binding.split('=').next()?.trim();
            is_identifier(binding).then(|| (field.to_string(), binding.to_string()))
        })
        .collect()
}

fn identifier_node<'tree>(
    pattern: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    pattern.dfs().find(|node| {
        matches!(
            node.kind().as_ref(),
            "identifier" | "shorthand_property_identifier_pattern"
        ) && node.text().as_ref() == name
    })
}

fn member_is_call_callee(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.parent().is_some_and(|parent| {
        parent.kind().as_ref() == "call_expression"
            && parent
                .field("function")
                .is_some_and(|callee| callee.range() == node.range())
    })
}

fn identifier_is_value_use(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    !node.parent().is_some_and(|parent| {
        matches!(
            parent.kind().as_ref(),
            "required_parameter"
                | "optional_parameter"
                | "variable_declarator"
                | "pair"
                | "property_signature"
        ) && parent
            .field("name")
            .or_else(|| parent.field("key"))
            .is_some_and(|name| name.range() == node.range())
    })
}

fn is_exported(function: &Node<'_, StrDoc<SupportLang>>) -> bool {
    function.ancestors().take(3).any(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "export_statement" | "export_clause"
        ) || ancestor.text().trim_start().starts_with("export ")
    })
}

fn function_symbol(function: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    function
        .field("name")
        .map(|name| name.text().into_owned())
        .or_else(|| {
            let parent = function.parent()?;
            (parent.kind().as_ref() == "variable_declarator")
                .then(|| parent.field("name"))
                .flatten()
                .map(|name| name.text().into_owned())
        })
}

fn function_symbol_for_node(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.ancestors()
        .find(is_function)
        .and_then(|function| function_symbol(&function))
}

fn is_function(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "generator_function"
            | "generator_function_declaration"
            | "method_definition"
    )
}

fn nearest_function_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(is_function)
        .map(|function| function.range())
}

fn default_exported_function<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if let Some(function) = root.dfs().find(|function| {
        is_function(function)
            && function.parent().is_some_and(|parent| {
                parent.kind().as_ref() == "export_statement"
                    && parent.text().trim_start().starts_with("export default ")
            })
    }) {
        return Some(function);
    }
    let exported_name = root.dfs().find_map(|node| {
        (node.kind().as_ref() == "export_statement")
            .then(|| node.text())
            .and_then(|text| {
                let compact = compact(&text);
                let name = compact.strip_prefix("exportdefault")?.trim_end_matches(';');
                is_identifier(name).then(|| name.to_string())
            })
    })?;
    root.dfs().find(|function| {
        is_function(function) && function_symbol(function) == Some(exported_name.clone())
    })
}

fn next_pages_api_route_path(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    let tail = normalized
        .strip_prefix("pages/api/")
        .or_else(|| normalized.rsplit_once("/pages/api/").map(|(_, tail)| tail))?;
    let route = [".js", ".jsx", ".ts", ".tsx"]
        .into_iter()
        .find_map(|extension| tail.strip_suffix(extension))?;
    let route = route.strip_suffix("/index").unwrap_or(route);
    Some(format!("/api/{route}"))
}

fn next_pages_method(function: &Node<'_, StrDoc<SupportLang>>, request: &str) -> String {
    let mut methods = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "binary_expression")
        .filter_map(|comparison| {
            let left = compact(&comparison.field("left")?.text());
            let right = comparison.field("right")?;
            if left != format!("{request}.method") {
                return None;
            }
            let value = right.text();
            let value = value.trim().trim_matches(['\'', '"']).to_ascii_uppercase();
            matches!(
                value.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            )
            .then_some(value)
        })
        .collect::<BTreeSet<_>>();
    (methods.len() == 1)
        .then(|| methods.pop_first())
        .flatten()
        .unwrap_or_else(|| "ANY".to_string())
}

fn next_pages_javascript_route_access(
    function: &Node<'_, StrDoc<SupportLang>>,
    request: &str,
) -> (HttpRouteAccess, Vec<String>) {
    let text = compact(&function.text());
    let session_binding = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .find_map(|declaration| {
            let name = declaration.field("name")?;
            let value = compact(&declaration.field("value")?.text());
            (value.starts_with("awaitgetServerSession(") && value.contains(&format!("{request},")))
                .then(|| name.text().trim().to_string())
        });
    let Some(session) = session_binding else {
        return (HttpRouteAccess::Unknown, Vec::new());
    };
    if text.contains(&format!("if(!{session})"))
        && (text.contains("status(401)") || text.contains("status:401"))
    {
        (
            HttpRouteAccess::Authenticated,
            vec!["getServerSession:rejects-401".to_string()],
        )
    } else {
        (HttpRouteAccess::Unknown, Vec::new())
    }
}

fn next_route_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let Some((_, tail)) = normalized.rsplit_once("/app/") else {
        return "<next-app-route>".to_string();
    };
    let route = tail
        .strip_suffix("/route.ts")
        .or_else(|| tail.strip_suffix("/route.tsx"));
    route.map_or_else(
        || "<next-app-route>".to_string(),
        |route| {
            let parts = route
                .split('/')
                .filter(|part| !part.starts_with('(') && !part.starts_with('@'))
                .collect::<Vec<_>>();
            format!("/{}", parts.join("/"))
        },
    )
}

fn range_key(range: std::ops::Range<usize>) -> (usize, usize) {
    (range.start, range.end)
}

fn language_prefix(language: Language) -> &'static str {
    match language {
        Language::Javascript => "javascript",
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => unreachable!(),
    }
}

fn exact_quoted(text: &str) -> Option<&str> {
    let text = text.trim();
    let quote = text.chars().next()?;
    matches!(quote, '\'' | '"')
        .then(|| text.strip_prefix(quote)?.strip_suffix(quote))
        .flatten()
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn normalized(text: &str) -> String {
    compact(text).replace("?.", ".")
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters.next().is_some_and(|first| {
        (first == '_' || first == '$' || first.is_alphabetic())
            && characters.all(|character| {
                character == '_' || character == '$' || character.is_alphanumeric()
            })
    })
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn text_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: &str) -> Capture {
    Capture {
        text: text.to_string(),
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
