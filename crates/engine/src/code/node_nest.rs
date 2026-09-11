use std::collections::BTreeMap;

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

const NEST_ENGINE: &str = "ast-grep 0.45.1 + bounded-nestjs-boundary";

#[derive(Clone, Debug)]
struct NestDecorator {
    canonical: String,
    observed: String,
    arguments: Vec<String>,
}

#[derive(Clone)]
struct NestRoute<'tree> {
    method_node: Node<'tree, StrDoc<SupportLang>>,
    route_node: Node<'tree, StrDoc<SupportLang>>,
    symbol: String,
    method: String,
    path: String,
    access: HttpRouteAccess,
    guards: Vec<String>,
    pipes: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_nest_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::Typescript | Language::Tsx) {
        return;
    }
    let imports = nest_imports(root);
    if imports.is_empty() {
        return;
    }
    push_global_pipe_observations(
        path,
        root,
        language,
        &imports,
        comments,
        conditional,
        literals,
        evidence,
    );
    if !imports.values().any(|name| name == "Controller") {
        return;
    }

    let routes = nest_routes(root, &imports);
    for route in &routes {
        push_entrypoint(
            path,
            language,
            route,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_parameter_sources(
            path,
            language,
            route,
            &imports,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_guard_observations(
            path,
            language,
            route,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_pipe_observations(
            path,
            language,
            route,
            &imports,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_response_alias_sinks(
            path,
            language,
            route,
            &imports,
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for item in evidence.iter_mut() {
        let Some(symbol) = item.enclosing_symbol.as_deref() else {
            continue;
        };
        for route in routes.iter().filter(|route| route.symbol == symbol) {
            let context = route_context(route);
            if !item.context.http_routes.contains(&context) {
                item.context.http_routes.push(context);
            }
        }
    }
}

fn nest_imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    let mut imports = BTreeMap::new();
    for node in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = node.text();
        let Some((clause, module)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        if exact_quoted(module.trim().trim_end_matches(';')) != Some("@nestjs/common") {
            continue;
        }
        let clause = clause.trim().strip_prefix("type ").unwrap_or(clause.trim());
        if !clause.starts_with('{') {
            continue;
        }
        for entry in clause.trim_matches(['{', '}']).split(',') {
            let words = entry.split_whitespace().collect::<Vec<_>>();
            let Some(imported) = words.first().copied() else {
                continue;
            };
            let visible = if words.get(1) == Some(&"as") {
                words.get(2).copied().unwrap_or(imported)
            } else {
                imported
            };
            imports.insert(visible.to_string(), imported.to_string());
        }
    }
    imports
}

fn nest_routes<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeMap<String, String>,
) -> Vec<NestRoute<'tree>> {
    let mut routes = Vec::new();
    for class in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "abstract_class_declaration"
        )
    }) {
        let class_decorators = associated_decorators(&class);
        let Some(controller) = class_decorators.iter().find_map(|node| {
            let decorator = resolve_decorator(node, imports)?;
            (decorator.canonical == "Controller").then_some(decorator)
        }) else {
            continue;
        };
        let controller_path = route_argument_path(&controller);
        let class_guards = guard_decorators(&class_decorators, imports);
        let class_pipes = pipe_decorators(&class_decorators, imports);
        for method_node in class.dfs().filter(|node| {
            node.kind().as_ref() == "method_definition"
                && nearest_class_range(node) == Some(class.range())
        }) {
            let Some(symbol) = method_node
                .field("name")
                .map(|name| name.text().into_owned())
            else {
                continue;
            };
            let decorators = associated_decorators(&method_node);
            let Some((route_node, route_decorator, method)) = decorators.iter().find_map(|node| {
                let decorator = resolve_decorator(node, imports)?;
                route_method(&decorator.canonical)
                    .map(|method| (node.clone(), decorator, method.to_string()))
            }) else {
                continue;
            };
            let method_path = route_argument_path(&route_decorator);
            let mut guards = class_guards.clone();
            guards.extend(guard_decorators(&decorators, imports));
            guards.sort();
            guards.dedup();
            let access = guard_access(&guards);
            let mut pipes = class_pipes.clone();
            pipes.extend(pipe_decorators(&decorators, imports));
            routes.push(NestRoute {
                method_node,
                route_node,
                symbol,
                method,
                path: join_route_path(&controller_path, &method_path),
                access,
                guards,
                pipes,
            });
        }
    }
    routes
}

fn associated_decorators<'tree>(
    owner: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    let mut decorators = owner
        .prev_all()
        .filter(|sibling| sibling.is_named())
        .take_while(|sibling| sibling.kind().as_ref() == "decorator")
        .collect::<Vec<_>>();
    decorators.reverse();
    decorators
}

fn resolve_decorator(
    node: &Node<'_, StrDoc<SupportLang>>,
    imports: &BTreeMap<String, String>,
) -> Option<NestDecorator> {
    let call = node
        .children()
        .find(|child| child.kind().as_ref() == "call_expression")?;
    let observed = call.field("function")?.text().trim().to_string();
    let canonical = imports.get(&observed)?.clone();
    let arguments = call
        .field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .map(|argument| argument.text().trim().to_string())
        .collect();
    Some(NestDecorator {
        canonical,
        observed,
        arguments,
    })
}

fn route_method(canonical: &str) -> Option<&'static str> {
    match canonical {
        "Get" => Some("GET"),
        "Post" => Some("POST"),
        "Put" => Some("PUT"),
        "Patch" => Some("PATCH"),
        "Delete" => Some("DELETE"),
        "Options" => Some("OPTIONS"),
        "Head" => Some("HEAD"),
        "All" => Some("ALL"),
        _ => None,
    }
}

fn guard_decorators(
    decorators: &[Node<'_, StrDoc<SupportLang>>],
    imports: &BTreeMap<String, String>,
) -> Vec<String> {
    decorators
        .iter()
        .filter_map(|node| resolve_decorator(node, imports))
        .filter(|decorator| decorator.canonical == "UseGuards")
        .flat_map(|decorator| decorator.arguments)
        .filter(|guard| !guard.is_empty())
        .collect()
}

fn pipe_decorators<'tree>(
    decorators: &[Node<'tree, StrDoc<SupportLang>>],
    imports: &BTreeMap<String, String>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    decorators
        .iter()
        .filter(|node| {
            resolve_decorator(node, imports)
                .is_some_and(|decorator| decorator.canonical == "UsePipes")
        })
        .cloned()
        .collect()
}

fn guard_access(guards: &[String]) -> HttpRouteAccess {
    if guards.iter().any(|guard| {
        let guard = guard.to_ascii_lowercase();
        guard.contains("role") || guard.contains("permission") || guard.contains("admin")
    }) {
        HttpRouteAccess::RoleRestricted
    } else if guards.iter().any(|guard| {
        let guard = guard.to_ascii_lowercase();
        guard.contains("auth") || guard.contains("jwt") || guard.contains("session")
    }) {
        HttpRouteAccess::Authenticated
    } else {
        HttpRouteAccess::Unknown
    }
}

fn route_context(route: &NestRoute<'_>) -> HttpRouteContext {
    HttpRouteContext {
        method: route.method.clone(),
        path: route.path.clone(),
        access: route.access,
        guards: route.guards.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn push_entrypoint<'tree>(
    path: &str,
    language: Language,
    route: &NestRoute<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        language,
        &route.route_node,
        EvidenceKind::Entrypoint,
        Capability::HttpRequestHandling,
        "nestjs-http-entrypoint",
        Vec::new(),
        BTreeMap::from([("route".to_string(), capture(path, &route.route_node))]),
        vec!["http", "entrypoint", "nestjs"],
        Some(route_context(route)),
        None,
        Some(&route.symbol),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_parameter_sources<'tree>(
    path: &str,
    language: Language,
    route: &NestRoute<'tree>,
    imports: &BTreeMap<String, String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(parameters) = route.method_node.field("parameters") else {
        return;
    };
    for parameter in parameters.children().filter(|child| child.is_named()) {
        let decorators = parameter
            .dfs()
            .filter(|node| node.kind().as_ref() == "decorator")
            .collect::<Vec<_>>();
        let Some(decorator) = decorators.iter().find_map(|node| {
            let decorator = resolve_decorator(node, imports)?;
            is_request_parameter_decorator(&decorator.canonical).then_some(decorator)
        }) else {
            continue;
        };
        let Some(identifier) = parameter_identifier_node(parameter.clone()) else {
            continue;
        };
        let mut captures = BTreeMap::from([
            ("parameter".to_string(), capture(path, &identifier)),
            ("value".to_string(), capture(path, &identifier)),
        ]);
        if let Some(selector) = literal_argument(&decorator, 0) {
            captures.insert(
                "selector".to_string(),
                text_capture(path, &identifier, selector),
            );
        }
        push_evidence(
            path,
            language,
            &identifier,
            EvidenceKind::Source,
            Capability::HttpRequestData,
            "nestjs-request-parameter",
            vec!["CWE-20"],
            captures,
            vec![
                "http",
                "request",
                "attacker-controlled",
                "nestjs",
                "decorated-parameter",
            ],
            Some(route_context(route)),
            Some((&decorator.canonical, &decorator.observed)),
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn is_request_parameter_decorator(canonical: &str) -> bool {
    matches!(
        canonical,
        "Body"
            | "Query"
            | "Param"
            | "Headers"
            | "Ip"
            | "HostParam"
            | "Session"
            | "UploadedFile"
            | "UploadedFiles"
            | "Req"
            | "Request"
    )
}

#[allow(clippy::too_many_arguments)]
fn push_guard_observations<'tree>(
    path: &str,
    language: Language,
    route: &NestRoute<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if route.guards.is_empty() {
        return;
    }
    let capability = if route.access == HttpRouteAccess::RoleRestricted {
        Capability::Authorization
    } else {
        Capability::Authentication
    };
    push_evidence(
        path,
        language,
        &route.route_node,
        EvidenceKind::Guard,
        capability,
        "nestjs-use-guards",
        Vec::new(),
        BTreeMap::from([(
            "guards".to_string(),
            text_capture(path, &route.route_node, route.guards.join(",")),
        )]),
        vec!["http", "guard", "nestjs", "needs-verification"],
        Some(route_context(route)),
        None,
        Some(&route.symbol),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_pipe_observations<'tree>(
    path: &str,
    language: Language,
    route: &NestRoute<'tree>,
    imports: &BTreeMap<String, String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for pipe in &route.pipes {
        let Some(decorator) = resolve_decorator(pipe, imports) else {
            continue;
        };
        let validation_pipe = decorator
            .arguments
            .iter()
            .any(|argument| imported_constructor_name(argument, imports) == Some("ValidationPipe"));
        if !validation_pipe {
            continue;
        }
        let tags = validation_pipe_tags(&pipe.text(), false);
        push_evidence(
            path,
            language,
            pipe,
            EvidenceKind::Validation,
            Capability::HttpRequestData,
            "nestjs-validation-pipe",
            Vec::new(),
            BTreeMap::from([("pipe".to_string(), capture(path, pipe))]),
            tags,
            Some(route_context(route)),
            Some(("ValidationPipe", "ValidationPipe")),
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_global_pipe_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    imports: &BTreeMap<String, String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        if !call.callee.ends_with(".useGlobalPipes")
            || !call.arguments.iter().any(|argument| {
                imported_constructor_name(&argument.text(), imports) == Some("ValidationPipe")
            })
        {
            continue;
        }
        push_evidence(
            path,
            language,
            &call.node,
            EvidenceKind::Validation,
            Capability::HttpRequestData,
            "nestjs-global-validation-pipe",
            Vec::new(),
            BTreeMap::from([("pipe".to_string(), capture(path, &call.node))]),
            validation_pipe_tags(&call.node.text(), true),
            None,
            Some(("ValidationPipe", "ValidationPipe")),
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn validation_pipe_tags(text: &str, global: bool) -> Vec<&'static str> {
    let text = compact(text);
    let mut tags = vec![
        "http",
        "validation",
        "nestjs",
        "validation-pipe",
        "context-only",
    ];
    if global {
        tags.push("global-pipe");
    }
    if text.contains("whitelist:true") {
        tags.push("whitelist:true");
    }
    if text.contains("forbidNonWhitelisted:true") {
        tags.push("forbid-non-whitelisted:true");
    }
    if text.contains("transform:true") {
        tags.push("transform:true");
    }
    tags
}

fn imported_constructor_name<'a>(
    argument: &str,
    imports: &'a BTreeMap<String, String>,
) -> Option<&'a str> {
    let compact = compact(argument);
    let name = compact
        .strip_prefix("new")?
        .split_once('(')
        .map_or(compact.strip_prefix("new")?, |(name, _)| name);
    imports.get(name).map(String::as_str)
}

#[allow(clippy::too_many_arguments)]
fn push_response_alias_sinks<'tree>(
    path: &str,
    language: Language,
    route: &NestRoute<'tree>,
    imports: &BTreeMap<String, String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(parameters) = route.method_node.field("parameters") else {
        return;
    };
    let aliases = parameters
        .children()
        .filter(|child| child.is_named())
        .filter_map(|parameter| {
            let response = parameter.dfs().any(|node| {
                node.kind().as_ref() == "decorator"
                    && resolve_decorator(&node, imports).is_some_and(|decorator| {
                        matches!(decorator.canonical.as_str(), "Res" | "Response")
                    })
            });
            response
                .then(|| parameter_identifier_node(parameter))
                .flatten()
                .map(|identifier| identifier.text().into_owned())
        })
        .collect::<Vec<_>>();
    if aliases.is_empty() {
        return;
    }
    for call in route.method_node.dfs().filter_map(call_site) {
        if nearest_method_range(&call.node) != Some(route.method_node.range()) {
            continue;
        }
        let Some((receiver, terminal)) = call.callee.rsplit_once('.') else {
            continue;
        };
        if !aliases.iter().any(|alias| alias == receiver) {
            continue;
        }
        let (kind, capability, rule, cwe, role) = match terminal {
            "send" | "render" => (
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                "nestjs-response-html-output",
                "CWE-79",
                "content",
            ),
            "redirect" => (
                EvidenceKind::Sink,
                Capability::Redirect,
                "nestjs-response-redirect",
                "CWE-601",
                "location",
            ),
            _ => continue,
        };
        let Some(argument) = call.arguments.last() else {
            continue;
        };
        if evidence.iter().any(|item| {
            item.capability == capability
                && item.location.start.byte_offset == call.node.range().start
        }) {
            continue;
        }
        push_evidence(
            path,
            language,
            &call.node,
            kind,
            capability,
            rule,
            vec![cwe],
            BTreeMap::from([(role.to_string(), capture(path, argument))]),
            vec!["http", "response", "nestjs", "decorated-response-parameter"],
            Some(route_context(route)),
            Some(("@nestjs/common.Response", receiver)),
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let callee = node.text().get(..callee_length)?.trim().to_string();
    Some(CallSite {
        node,
        callee,
        arguments: arguments
            .children()
            .filter(|child| child.is_named())
            .collect(),
    })
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    language: Language,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    suffix: &str,
    cwes: Vec<&str>,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    route: Option<HttpRouteContext>,
    symbol: Option<(&str, &str)>,
    enclosing_override: Option<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range()) {
        return;
    }
    let rule_id = format!("{}-{suffix}", language_prefix(language));
    let id = evidence_id(path, &rule_id, node.range().start, node.range().end);
    if let Some(existing) = evidence.iter_mut().find(|item| item.id == id) {
        if let Some(route) = route.as_ref()
            && !existing.context.http_routes.contains(route)
        {
            existing.context.http_routes.push(route.clone());
        }
        return;
    }
    let mut context = EvidenceContext {
        comment: false,
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        ..EvidenceContext::default()
    };
    if let Some(route) = route {
        context.http_routes.push(route);
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_override
            .map(str::to_string)
            .or_else(|| enclosing_symbol(node)),
        captures,
        cwe_candidates: cwes.into_iter().map(str::to_string).collect(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: NEST_ENGINE.to_string(),
            rule_version: 1,
        },
        context,
        symbol_resolution: symbol.map(|(canonical, observed)| SymbolResolution {
            canonical: canonical.to_string(),
            observed: observed.to_string(),
            method: SymbolResolutionMethod::Alias,
            confidence: SymbolConfidence::High,
        }),
        rule_id,
        related_evidence: Vec::new(),
    });
}

fn language_prefix(language: Language) -> &'static str {
    match language {
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => unreachable!(),
    }
}

fn parameter_identifier_node(
    parameter: Node<'_, StrDoc<SupportLang>>,
) -> Option<Node<'_, StrDoc<SupportLang>>> {
    if parameter.kind().as_ref() == "identifier" {
        return Some(parameter);
    }
    for field in ["pattern", "name"] {
        if let Some(identifier) = parameter.field(field) {
            if identifier.kind().as_ref() == "identifier" {
                return Some(identifier);
            }
            if let Some(identifier) = identifier
                .dfs()
                .find(|node| node.kind().as_ref() == "identifier")
            {
                return Some(identifier);
            }
        }
    }
    parameter.dfs().find(|node| {
        node.kind().as_ref() == "identifier"
            && !node
                .ancestors()
                .take_while(|ancestor| ancestor.range() != parameter.range())
                .any(|ancestor| ancestor.kind().as_ref() == "decorator")
    })
}

fn nearest_class_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "class_declaration" | "abstract_class_declaration"
            )
        })
        .map(|class| class.range())
}

fn nearest_method_range(node: &Node<'_, StrDoc<SupportLang>>) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_definition")
        .map(|method| method.range())
}

fn join_route_path(controller: &str, method: &str) -> String {
    let segments = [controller, method]
        .into_iter()
        .map(|segment| segment.trim_matches('/'))
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn literal_argument(decorator: &NestDecorator, index: usize) -> Option<String> {
    exact_quoted(decorator.arguments.get(index)?).map(str::to_string)
}

fn route_argument_path(decorator: &NestDecorator) -> String {
    if decorator.arguments.is_empty() {
        String::new()
    } else {
        literal_argument(decorator, 0).unwrap_or_else(|| "<dynamic>".to_string())
    }
}

fn exact_quoted(text: &str) -> Option<&str> {
    let text = text.trim();
    let first = text.chars().next()?;
    let inner = matches!(first, '\'' | '"' | '`')
        .then(|| text.strip_prefix(first)?.strip_suffix(first))
        .flatten()?;
    (!(first == '`' && inner.contains("${"))).then_some(inner)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn text_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: String) -> Capture {
    Capture {
        text,
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
