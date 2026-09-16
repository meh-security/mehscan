use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution, ResourcePolicyContext,
    ResourcePolicyState, SecurityPath, SecurityPathProvenance, SecurityPathState, SecurityPathStep,
    SecurityPathStepKind,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

pub(crate) const DROGON_PARAMETER_RULE_ID: &str = "cpp-drogon-request-parameter";
const RESOURCE_RULE: &str = "cpp-drogon-orm-resource-access";
const ENTRYPOINT_RULE: &str = "cpp-drogon-http-entrypoint";
const REQUIREMENT_RULE: &str = "cpp-drogon-route-authentication-requirement";
const FILTER_GUARD_RULE: &str = "cpp-drogon-verified-token-filter";
const PRINCIPAL_RULE: &str = "cpp-drogon-authenticated-principal";
const OWNER_GUARD_RULE: &str = "cpp-drogon-principal-resource-guard";
const ENGINE: &str = "mehscan bounded-drogon-request-identity 1";

#[derive(Clone, Debug, Eq, PartialEq)]
struct DrogonRoute {
    registration_path: String,
    start: usize,
    end: usize,
    handler: String,
    method: String,
    path: String,
    filters: Vec<String>,
    principal_keys: Vec<String>,
    access: HttpRouteAccess,
}

impl DrogonRoute {
    fn context(&self) -> HttpRouteContext {
        HttpRouteContext {
            method: self.method.clone(),
            path: self.path.clone(),
            access: self.access,
            guards: self.filters.clone(),
        }
    }

    fn needs_authentication_review(&self) -> bool {
        !self.filters.is_empty()
            || matches!(self.method.as_str(), "PUT" | "PATCH" | "DELETE")
            || self.path.contains('{')
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DrogonProjectContext {
    routes_by_handler: BTreeMap<String, Vec<DrogonRoute>>,
    routes_by_file: BTreeMap<String, Vec<DrogonRoute>>,
}

impl DrogonProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let sources = sources
            .filter(|(_, language, _)| *language == Language::Cpp)
            .collect::<Vec<_>>();
        let verified_decoders = verified_decoder_names(&sources);
        let authenticated_filters = authenticated_filter_summaries(&sources, &verified_decoders);
        let mut routes_by_handler: BTreeMap<String, Vec<DrogonRoute>> = BTreeMap::new();
        let mut routes_by_file: BTreeMap<String, Vec<DrogonRoute>> = BTreeMap::new();
        for (path, _, source) in &sources {
            for mut route in parse_routes(path, source) {
                route.access = if route
                    .filters
                    .iter()
                    .any(|filter| authenticated_filters.contains_key(filter))
                {
                    HttpRouteAccess::Authenticated
                } else {
                    HttpRouteAccess::Unknown
                };
                route.principal_keys = route
                    .filters
                    .iter()
                    .filter_map(|filter| authenticated_filters.get(filter))
                    .flatten()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                routes_by_handler
                    .entry(route.handler.clone())
                    .or_default()
                    .push(route.clone());
                routes_by_file
                    .entry((*path).to_string())
                    .or_default()
                    .push(route);
            }
        }
        for routes in routes_by_handler.values_mut() {
            sort_routes(routes);
        }
        for routes in routes_by_file.values_mut() {
            sort_routes(routes);
        }
        Self {
            routes_by_handler,
            routes_by_file,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) -> Vec<SecurityPath> {
        if language != Language::Cpp {
            return Vec::new();
        }
        let mut paths =
            self.add_route_observations(path, root, comments, conditional, literals, evidence);
        self.add_filter_identity_observations(
            path,
            root,
            comments,
            conditional,
            literals,
            evidence,
        );
        self.add_handler_observations(path, root, comments, conditional, literals, evidence);
        paths.sort_by(|left, right| left.id.cmp(&right.id));
        paths
    }

    #[allow(clippy::too_many_arguments)]
    fn add_route_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        _literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) -> Vec<SecurityPath> {
        let mut paths = Vec::new();
        let source = root.text();
        for route in self.routes_by_file.get(path).into_iter().flatten() {
            if route.end > source.len()
                || comments.is_in_comment(route.start..route.end)
                || !source.is_char_boundary(route.start)
                || !source.is_char_boundary(route.end)
            {
                continue;
            }
            let context = route.context();
            let entrypoint = route_item(
                path,
                source.as_ref(),
                route,
                ENTRYPOINT_RULE,
                EvidenceKind::Entrypoint,
                Capability::HttpRequestHandling,
                BTreeMap::from([
                    (
                        "route".to_string(),
                        range_capture(path, source.as_ref(), route.start, route.end),
                    ),
                    (
                        "handler".to_string(),
                        range_text_capture(path, source.as_ref(), route, &route.handler),
                    ),
                ]),
                &["http", "entrypoint", "cpp", "drogon"],
                &["CWE-306"],
                context.clone(),
                Vec::new(),
                comments,
                conditional,
            );
            evidence.push(entrypoint.clone());
            if !route.needs_authentication_review() {
                continue;
            }
            let requirement = route_item(
                path,
                source.as_ref(),
                route,
                REQUIREMENT_RULE,
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                BTreeMap::from([(
                    "route".to_string(),
                    range_capture(path, source.as_ref(), route.start, route.end),
                )]),
                &["http", "authentication", "route", "cpp", "drogon"],
                &["CWE-306"],
                context.clone(),
                vec![entrypoint.id.clone()],
                comments,
                conditional,
            );
            let guard = (route.access == HttpRouteAccess::Authenticated).then(|| {
                route_item(
                    path,
                    source.as_ref(),
                    route,
                    FILTER_GUARD_RULE,
                    EvidenceKind::Guard,
                    Capability::Authentication,
                    BTreeMap::from([(
                        "filters".to_string(),
                        range_text_capture(path, source.as_ref(), route, &route.filters.join(",")),
                    )]),
                    &[
                        "http",
                        "authentication",
                        "drogon",
                        "verified-token-filter",
                        "not-authorization",
                    ],
                    &["CWE-306"],
                    context,
                    vec![requirement.id.clone()],
                    comments,
                    conditional,
                )
            });
            paths.push(authentication_path(
                &entrypoint,
                &requirement,
                guard.as_ref(),
            ));
            evidence.push(requirement);
            if let Some(guard) = guard {
                evidence.push(guard);
            }
        }
        paths
    }

    #[allow(clippy::too_many_arguments)]
    fn add_handler_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        for function in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "function_definition")
        {
            let Some(handler) = qualified_function_name(&function) else {
                continue;
            };
            let Some(routes) = self.routes_by_handler.get(&handler) else {
                continue;
            };
            let contexts = routes.iter().map(DrogonRoute::context).collect::<Vec<_>>();
            let parameters = function_parameters(&function);
            let request_names = parameters
                .iter()
                .filter(|parameter| parameter.text().contains("HttpRequestPtr"))
                .filter_map(parameter_name)
                .collect::<BTreeSet<_>>();
            let route_parameter_count = routes
                .iter()
                .map(|route| route.path.matches('{').count())
                .max()
                .unwrap_or_default();
            for parameter in parameters
                .iter()
                .filter(|parameter| {
                    let text = parameter.text();
                    !text.contains("HttpRequestPtr")
                        && !text.contains("HttpResponsePtr")
                        && !text.contains("std::function")
                        && !text.contains("FilterCallback")
                        && !text.contains("FilterChainCallback")
                })
                .take(route_parameter_count)
            {
                let text = parameter.text();
                if text.contains("HttpRequestPtr")
                    || text.contains("HttpResponsePtr")
                    || text.contains("std::function")
                    || text.contains("FilterCallback")
                    || text.contains("FilterChainCallback")
                {
                    continue;
                }
                let Some(name) = parameter_name(parameter) else {
                    continue;
                };
                let Some(anchor) = parameter
                    .dfs()
                    .filter(|node| node.kind().as_ref() == "identifier")
                    .find(|node| node.text().trim() == name)
                else {
                    continue;
                };
                push_request_source(
                    path,
                    &anchor,
                    DROGON_PARAMETER_RULE_ID,
                    BTreeMap::from([("parameter".to_string(), capture(path, &anchor))]),
                    contexts.clone(),
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            for call in function
                .dfs()
                .filter(|node| node.kind().as_ref() == "call_expression")
            {
                if comments.is_in_comment(call.range()) {
                    continue;
                }
                let Some(function_node) = call.field("function") else {
                    continue;
                };
                let callee = compact(function_node.text().as_ref());
                let terminal = terminal_name(&callee);
                if !matches!(
                    terminal,
                    "findByPrimaryKey" | "findFutureByPrimaryKey" | "deleteBy"
                ) {
                    continue;
                }
                let arguments = call_arguments(&call);
                let Some(filter) = arguments.first() else {
                    continue;
                };
                if !semantic_identifiers(filter).iter().any(|identifier| {
                    evidence.iter().any(|source| {
                        source.rule_id == DROGON_PARAMETER_RULE_ID
                            && source.enclosing_symbol == enclosing_symbol(&call)
                            && source
                                .captures
                                .get("parameter")
                                .is_some_and(|capture| capture.text == *identifier)
                    })
                }) {
                    continue;
                }
                let route_principal_keys = routes
                    .iter()
                    .flat_map(|route| route.principal_keys.iter().cloned())
                    .collect::<BTreeSet<_>>();
                let owner_guard =
                    principal_attribute_locals(&function, &request_names, &route_principal_keys)
                        .into_iter()
                        .find_map(|principal| {
                            rejecting_owner_guard(&function, &principal, filter, call.range().start)
                        });
                if let Some(guard) = &owner_guard {
                    let mut validation = item(
                        path,
                        guard,
                        OWNER_GUARD_RULE,
                        EvidenceKind::Validation,
                        Capability::Authorization,
                        BTreeMap::from([("guard".to_string(), capture(path, guard))]),
                        &[
                            "authorization",
                            "owner-check",
                            "authenticated-principal",
                            "cpp",
                            "drogon",
                        ],
                        &["CWE-639"],
                        contexts.first().cloned(),
                        Vec::new(),
                        comments,
                        conditional,
                        literals,
                    );
                    validation.context.http_routes = contexts.clone();
                    evidence.push(validation);
                }
                let mut resource = item(
                    path,
                    &call,
                    RESOURCE_RULE,
                    EvidenceKind::Sink,
                    Capability::ResourceAccess,
                    BTreeMap::from([("filter".to_string(), capture(path, filter))]),
                    &[
                        "database",
                        "resource-selection",
                        "cpp",
                        "drogon-orm",
                        "owner-check-unproven",
                    ],
                    &["CWE-639"],
                    contexts.first().cloned(),
                    Vec::new(),
                    comments,
                    conditional,
                    literals,
                );
                resource.context.http_routes = contexts.clone();
                if let Some(guard) = owner_guard {
                    resource.context.resource_policy = Some(ResourcePolicyContext {
                        state: ResourcePolicyState::OwnerScoped,
                        basis: format!(
                            "authenticated Drogon principal is compared with the selected resource before {}",
                            guard.text().trim()
                        ),
                    });
                }
                evidence.push(resource);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_filter_identity_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        for call in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
        {
            let Some(function) = call.field("function") else {
                continue;
            };
            let callee = compact(function.text().as_ref());
            if !matches!(
                terminal_name(&callee),
                "get_payload_claim" | "getPayloadClaim"
            ) {
                continue;
            }
            let Some(argument) = call_arguments(&call).into_iter().next() else {
                continue;
            };
            if !is_quoted_literal(argument.text().trim()) {
                continue;
            }
            evidence.push(item(
                path,
                &call,
                PRINCIPAL_RULE,
                EvidenceKind::Source,
                Capability::Authentication,
                BTreeMap::from([("principal".to_string(), capture(path, &call))]),
                &[
                    "authentication",
                    "identity",
                    "jwt-claim",
                    "cpp",
                    "drogon",
                    "context-only",
                    "not-authorization",
                ],
                &["CWE-639"],
                None,
                Vec::new(),
                comments,
                conditional,
                literals,
            ));
        }
    }
}

fn verified_decoder_names(sources: &[(&str, Language, &str)]) -> BTreeSet<String> {
    let mut implementations: BTreeMap<String, Vec<bool>> = BTreeMap::new();
    for (_, _, source) in sources {
        for function in function_blocks(source) {
            let Some(name) = textual_qualified_function_name(function.header) else {
                continue;
            };
            let terminal = terminal_name(&name).to_string();
            if terminal.to_ascii_lowercase().contains("decode")
                || terminal.to_ascii_lowercase().contains("verify")
            {
                implementations
                    .entry(terminal)
                    .or_default()
                    .push(function.body.contains(".verify("));
            }
        }
    }
    implementations
        .into_iter()
        .filter_map(|(name, states)| {
            (!states.is_empty() && states.iter().all(|state| *state)).then_some(name)
        })
        .collect()
}

fn authenticated_filter_summaries(
    sources: &[(&str, Language, &str)],
    verified_decoders: &BTreeSet<String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut filters = BTreeMap::new();
    for (_, _, source) in sources {
        for function in function_blocks(source) {
            let Some(name) = textual_qualified_function_name(function.header) else {
                continue;
            };
            if terminal_name(&name) != "doFilter"
                || !function.body.contains("getHeader(\"Authorization\")")
                || !function.body.contains("token_verification_exception")
            {
                continue;
            }
            let Some(chain_name) = callback_parameter_name(function.header, "FilterChainCallback")
            else {
                continue;
            };
            let decoder_call = verified_decoders
                .iter()
                .find_map(|decoder| function.body.find(&format!(".{decoder}(")));
            let Some(decoder_position) = decoder_call else {
                continue;
            };
            let Some(chain_relative) =
                function.body[decoder_position..].find(&format!("{chain_name}();"))
            else {
                continue;
            };
            let chain_position = decoder_position + chain_relative;
            if decoder_position < chain_position {
                let principal_keys =
                    attribute_insert_keys(&function.body[decoder_position..chain_position]);
                if let Some((filter, _)) = name.rsplit_once("::") {
                    filters.insert(filter.to_string(), principal_keys.clone());
                    filters.insert(terminal_name(filter).to_string(), principal_keys);
                }
            }
        }
    }
    filters
}

fn attribute_insert_keys(body: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let marker = "->attributes()->insert(";
    let mut cursor = 0usize;
    while let Some(relative) = body[cursor..].find(marker) {
        let open = cursor + relative + marker.len() - 1;
        let Some(close) = matching_delimiter(body, open, '(', ')') else {
            break;
        };
        if let Some(key) = split_top_level(&body[open + 1..close], ',')
            .first()
            .and_then(|value| quoted_value(value.trim()))
        {
            keys.insert(key);
        }
        cursor = close + 1;
    }
    keys
}

fn principal_attribute_locals(
    function: &Node<'_, StrDoc<SupportLang>>,
    request_names: &BTreeSet<String>,
    principal_keys: &BTreeSet<String>,
) -> BTreeSet<String> {
    if principal_keys.is_empty() {
        return BTreeSet::new();
    }
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter_map(|call| {
            let callee = compact(call.field("function")?.text().as_ref());
            let (receiver, method) = callee.split_once("->attributes()->")?;
            if !request_names.contains(receiver) || terminal_template_name(method) != "get" {
                return None;
            }
            let key = call_arguments(&call)
                .first()
                .and_then(|argument| quoted_value(argument.text().trim()))?;
            if !principal_keys.contains(&key) {
                return None;
            }
            assigned_identifier(&call)
        })
        .collect()
}

fn assigned_identifier(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.ancestors()
        .take_while(|ancestor| ancestor.kind().as_ref() != "function_definition")
        .find(|ancestor| ancestor.kind().as_ref() == "init_declarator")
        .and_then(|declaration| declaration.field("declarator"))
        .and_then(|declarator| {
            declarator
                .dfs()
                .filter(|node| node.kind().as_ref() == "identifier")
                .last()
        })
        .map(|identifier| identifier.text().trim().to_string())
        .filter(|identifier| is_identifier(identifier))
}

fn rejecting_owner_guard<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    principal: &str,
    resource: &Node<'_, StrDoc<SupportLang>>,
    sink_start: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let resource_identifiers = semantic_identifiers(resource);
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement" && node.range().end <= sink_start)
        .find(|guard| {
            let Some(condition) = guard.field("condition") else {
                return false;
            };
            let Some(consequence) = guard.field("consequence") else {
                return false;
            };
            if !consequence
                .dfs()
                .any(|node| matches!(node.kind().as_ref(), "return_statement" | "throw_statement"))
            {
                return false;
            }
            let condition_text = compact(condition.text().as_ref());
            let matches_resource = resource_identifiers.iter().any(|resource| {
                condition_text.contains(&format!("{principal}!={resource}"))
                    || condition_text.contains(&format!("{resource}!={principal}"))
            });
            matches_resource
                && !identifier_assigned_between(function, principal, guard.range().end, sink_start)
                && resource_identifiers.iter().all(|resource| {
                    !identifier_assigned_between(function, resource, guard.range().end, sink_start)
                })
        })
}

fn identifier_assigned_between(
    function: &Node<'_, StrDoc<SupportLang>>,
    identifier: &str,
    start: usize,
    end: usize,
) -> bool {
    function
        .dfs()
        .filter(|node| {
            start < node.range().start
                && node.range().end < end
                && matches!(
                    node.kind().as_ref(),
                    "assignment_expression" | "init_declarator"
                )
        })
        .any(|assignment| {
            assignment
                .field("left")
                .or_else(|| assignment.field("declarator"))
                .is_some_and(|left| semantic_identifiers(&left).contains(identifier))
        })
}

fn parse_routes(path: &str, source: &str) -> Vec<DrogonRoute> {
    let masked = mask_comments(source);
    let mut routes = Vec::new();
    for macro_name in ["ADD_METHOD_TO", "METHOD_ADD"] {
        let marker = format!("{macro_name}(");
        let mut cursor = 0usize;
        while let Some(relative) = masked[cursor..].find(&marker) {
            let start = cursor + relative;
            let open = start + macro_name.len();
            let Some(close) = matching_delimiter(&masked, open, '(', ')') else {
                break;
            };
            let arguments = split_top_level(&source[open + 1..close], ',');
            if arguments.len() >= 3 {
                let handler = compact(arguments[0]);
                let route_path = arguments
                    .get(1)
                    .and_then(|value| quoted_value(value.trim()));
                let method = arguments
                    .get(2)
                    .map(|value| terminal_name(compact(value).trim()).to_ascii_uppercase());
                if is_qualified_identifier(&handler)
                    && let (Some(route_path), Some(method)) = (route_path, method)
                {
                    let filters = arguments[3..]
                        .iter()
                        .filter_map(|value| quoted_value(value.trim()))
                        .collect::<Vec<_>>();
                    routes.push(DrogonRoute {
                        registration_path: path.to_string(),
                        start,
                        end: close + 1,
                        handler,
                        method,
                        path: route_path,
                        filters,
                        principal_keys: Vec::new(),
                        access: HttpRouteAccess::Unknown,
                    });
                }
            }
            cursor = close + 1;
        }
    }
    routes
}

fn sort_routes(routes: &mut Vec<DrogonRoute>) {
    routes.sort_by(|left, right| {
        left.registration_path
            .cmp(&right.registration_path)
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.handler.cmp(&right.handler))
    });
    routes.dedup();
}

struct FunctionBlock<'a> {
    header: &'a str,
    body: &'a str,
}

fn function_blocks(source: &str) -> Vec<FunctionBlock<'_>> {
    let masked = mask_comments(source);
    let mut blocks = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = masked[cursor..].find('{') {
        let open = cursor + relative;
        let header_start = masked[..open]
            .rfind([';', '}', '{'])
            .map_or(0, |index| index + 1);
        let header = source[header_start..open].trim();
        let Some(close) = matching_delimiter(&masked, open, '{', '}') else {
            break;
        };
        if header.contains('(') && textual_qualified_function_name(header).is_some() {
            blocks.push(FunctionBlock {
                header,
                body: &source[open + 1..close],
            });
            cursor = close + 1;
        } else {
            cursor = open + 1;
        }
    }
    blocks
}

fn callback_parameter_name(header: &str, callback_type: &str) -> Option<String> {
    let open = header.find('(')?;
    let close = matching_delimiter(header, open, '(', ')')?;
    split_top_level(&header[open + 1..close], ',')
        .into_iter()
        .find(|parameter| parameter.contains(callback_type))
        .and_then(|parameter| {
            parameter
                .split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
                .rfind(|token| is_identifier(token))
                .map(str::to_string)
        })
}

fn textual_qualified_function_name(header: &str) -> Option<String> {
    let before = header.split_once('(')?.0.trim_end();
    let start = before
        .char_indices()
        .rev()
        .find(|(_, character)| {
            !(*character == ':' || *character == '_' || character.is_ascii_alphanumeric())
        })
        .map_or(0, |(index, character)| index + character.len_utf8());
    let name = &before[start..];
    is_qualified_identifier(name).then(|| name.to_string())
}

fn qualified_function_name(function: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let declarator = function.field("declarator")?;
    textual_qualified_function_name(declarator.text().as_ref())
}

fn function_parameters<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    let Some(declarator) = function.field("declarator") else {
        return Vec::new();
    };
    declarator
        .dfs()
        .filter(|node| node.kind().as_ref() == "parameter_declaration")
        .collect()
}

fn parameter_name(parameter: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    parameter
        .dfs()
        .filter(|node| node.kind().as_ref() == "identifier")
        .last()
        .map(|node| node.text().trim().to_string())
        .filter(|name| is_identifier(name))
}

fn terminal_template_name(value: &str) -> &str {
    value.split('<').next().unwrap_or(value)
}

fn call_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .collect()
        })
        .unwrap_or_default()
}

fn semantic_identifiers(node: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    node.dfs()
        .filter(|node| node.kind().as_ref() == "identifier")
        .map(|node| node.text().trim().to_string())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push_request_source<'tree>(
    path: &str,
    anchor: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    captures: BTreeMap<String, Capture>,
    routes: Vec<HttpRouteContext>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(anchor.range())
        || evidence.iter().any(|item| {
            item.rule_id == rule_id && item.location.start.byte_offset == anchor.range().start
        })
    {
        return;
    }
    let mut source = item(
        path,
        anchor,
        rule_id,
        EvidenceKind::Source,
        Capability::HttpRequestData,
        captures,
        &["http", "request", "attacker-controlled", "cpp", "drogon"],
        &["CWE-20"],
        routes.first().cloned(),
        Vec::new(),
        comments,
        conditional,
        literals,
    );
    source.context.http_routes = routes;
    evidence.push(source);
}

#[allow(clippy::too_many_arguments)]
fn item<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: &[&str],
    cwes: &[&str],
    route: Option<HttpRouteContext>,
    related_evidence: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, rule_id, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|value| (*value).to_string()).collect(),
        tags: tags
            .iter()
            .map(|value| (*value).to_string())
            .chain(std::iter::once(
                "parse-recovery:locally-complete".to_string(),
            ))
            .collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            http_routes: route.into_iter().collect(),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    }
}

#[allow(clippy::too_many_arguments)]
fn route_item(
    path: &str,
    source: &str,
    route: &DrogonRoute,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: &[&str],
    cwes: &[&str],
    context: HttpRouteContext,
    related_evidence: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
) -> Evidence {
    let range = route.start..route.end;
    Evidence {
        id: evidence_id(path, rule_id, route.start, route.end),
        kind,
        capability,
        location: range_location(path, source, route.start, route.end),
        enclosing_symbol: None,
        captures,
        cwe_candidates: cwes.iter().map(|value| (*value).to_string()).collect(),
        tags: tags
            .iter()
            .map(|value| (*value).to_string())
            .chain(std::iter::once(
                "parse-recovery:locally-complete".to_string(),
            ))
            .collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(range.clone()),
            availability: Some(conditional.availability_for(range)),
            http_routes: vec![context],
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    }
}

fn authentication_path(
    entrypoint: &Evidence,
    requirement: &Evidence,
    guard: Option<&Evidence>,
) -> SecurityPath {
    let state = if guard.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, entrypoint)];
    if let Some(guard) = guard {
        steps.push(evidence_step(SecurityPathStepKind::Protection, guard));
    }
    steps.push(evidence_step(SecurityPathStepKind::Sink, requirement));
    SecurityPath {
        id: stable_id(
            "path",
            &format!("{}\0{}\0{state:?}\0CWE-306", entrypoint.id, requirement.id),
        ),
        source_evidence_id: entrypoint.id.clone(),
        sink_evidence_id: requirement.id.clone(),
        capability: Capability::Authentication,
        cwe_candidates: vec!["CWE-306".to_string()],
        state,
        steps,
        protection_evidence_ids: guard
            .map(|value| vec![value.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: guard
            .is_none()
            .then_some("credential_validation_not_proven_for_exact_drogon_route".to_string())
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: "mehscan bounded-drogon-route-authentication 1".to_string(),
            maximum_propagation_depth: 0,
        },
    }
}

fn evidence_step(kind: SecurityPathStepKind, item: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: item.location.clone(),
        evidence_id: Some(item.id.clone()),
        symbol: None,
    }
}

fn split_top_level(value: &str, delimiter: char) -> Vec<&str> {
    let bytes = value.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        let character = *byte as char;
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth = depth.saturating_sub(1),
            character if character == delimiter && depth == 0 => {
                parts.push(value_slice(value, start, index));
                start = index + 1;
            }
            _ => {}
        }
    }
    parts.push(value_slice(value, start, value.len()));
    parts
}

fn value_slice(value: &str, start: usize, end: usize) -> &str {
    &value[start..end]
}

fn matching_delimiter(value: &str, open: usize, opening: char, closing: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, character) in value[open..].char_indices() {
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            value if value == opening => depth += 1,
            value if value == closing => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + index);
                }
            }
            _ => {}
        }
    }
    None
}

fn mask_comments(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = bytes.to_vec();
    let mut index = 0usize;
    let mut quote = None;
    let mut escaped = false;
    while index < bytes.len() {
        let character = bytes[index] as char;
        if let Some(active_quote) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == active_quote {
                quote = None;
            }
            index += 1;
            continue;
        }
        if matches!(character, '\'' | '"') {
            quote = Some(character);
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                output[index] = b' ';
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            output[index] = b' ';
            output[index + 1] = b' ';
            index += 2;
            while index + 1 < bytes.len() && &bytes[index..index + 2] != b"*/" {
                if bytes[index] != b'\n' {
                    output[index] = b' ';
                }
                index += 1;
            }
            if index + 1 < bytes.len() {
                output[index] = b' ';
                output[index + 1] = b' ';
                index += 2;
            }
            continue;
        }
        index += 1;
    }
    String::from_utf8(output).expect("comment masking preserves UTF-8 bytes")
}

fn quoted_value(value: &str) -> Option<String> {
    is_quoted_literal(value).then(|| value[1..value.len() - 1].to_string())
}

fn is_quoted_literal(value: &str) -> bool {
    value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
}

fn terminal_name(value: &str) -> &str {
    value
        .rsplit([':', '.', '>'])
        .find(|part| !part.is_empty())
        .unwrap_or(value)
}

fn is_qualified_identifier(value: &str) -> bool {
    !value.is_empty() && value.split("::").all(is_identifier)
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn range_capture(path: &str, source: &str, start: usize, end: usize) -> Capture {
    Capture {
        text: source[start..end].to_string(),
        location: range_location(path, source, start, end),
    }
}

fn range_text_capture(path: &str, source: &str, route: &DrogonRoute, text: &str) -> Capture {
    Capture {
        text: text.to_string(),
        location: range_location(path, source, route.start, route.end),
    }
}

fn range_location(path: &str, source: &str, start: usize, end: usize) -> Location {
    let position = |offset: usize| {
        let prefix = &source[..offset];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
        Position {
            line,
            column: source[line_start..offset].chars().count() + 1,
            byte_offset: offset,
        }
    };
    Location {
        path: path.to_string(),
        start: position(start),
        end: position(end),
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

fn evidence_id(path: &str, rule: &str, start: usize, end: usize) -> String {
    stable_id("ev", &format!("{path}\0{rule}\0{start}\0{end}"))
}

fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

#[cfg(test)]
mod tests {
    use ast_grep_core::AstGrep;

    use super::*;

    #[test]
    fn routes_require_literal_shapes_and_proven_filter_summaries() {
        let decoder = r#"
auto Token::decode(const std::string &token) {
  auto decoded = jwt::decode(token);
  verifier.verify(decoded);
  return decoded;
}
"#;
        let filter = r#"
void AuthFilter::doFilter(const HttpRequestPtr &req, FilterCallback &&fail,
                          FilterChainCallback &&next) {
  try {
    auto token = req->getHeader("Authorization");
    auto decoded = verifier.decode(token);
    next();
  } catch (jwt::token_verification_exception &error) { fail(response); }
}
"#;
        let routes = r#"
ADD_METHOD_TO(Api::open, "/open/{1}", Get);
ADD_METHOD_TO(Api::secure, "/secure/{1}", Put, "AuthFilter");
// ADD_METHOD_TO(Api::commented, "/commented", Get, "AuthFilter");
ADD_METHOD_TO(Api::dynamic, route_value, Get, "AuthFilter");
"#;
        let context = DrogonProjectContext::from_sources(
            [
                ("Token.cc", Language::Cpp, decoder),
                ("AuthFilter.cc", Language::Cpp, filter),
                ("Api.h", Language::Cpp, routes),
            ]
            .into_iter(),
        );
        assert_eq!(context.routes_by_handler.len(), 2);
        assert_eq!(
            context.routes_by_handler["Api::secure"][0].access,
            HttpRouteAccess::Authenticated
        );
        assert_eq!(
            context.routes_by_handler["Api::open"][0].access,
            HttpRouteAccess::Unknown
        );
    }

    #[test]
    fn same_named_unverified_decoder_prevents_authentication_proof() {
        let verified = "auto A::decode(Token t) { verifier.verify(t); return t; }";
        let unverified = "auto B::decode(Token t) { return jwt::decode(t); }";
        let filter = r#"
void AuthFilter::doFilter(const HttpRequestPtr &req, FilterCallback &&fail,
                          FilterChainCallback &&next) {
  try { auto value = decoder.decode(req->getHeader("Authorization")); next(); }
  catch (jwt::token_verification_exception &error) { fail(response); }
}
"#;
        let routes = "ADD_METHOD_TO(Api::write, \"/items/{1}\", Delete, \"AuthFilter\");";
        let context = DrogonProjectContext::from_sources(
            [
                ("A.cc", Language::Cpp, verified),
                ("B.cc", Language::Cpp, unverified),
                ("Filter.cc", Language::Cpp, filter),
                ("Api.h", Language::Cpp, routes),
            ]
            .into_iter(),
        );
        assert_eq!(
            context.routes_by_handler["Api::write"][0].access,
            HttpRouteAccess::Unknown
        );
    }

    #[test]
    fn qualified_cpp_handler_definitions_keep_controller_names() {
        let source = r#"
void JobsController::updateOne(const HttpRequestPtr &req,
                               std::function<void(const HttpResponsePtr &)> &&callback,
                               int jobId, Job &&job) const {
  Mapper<Job> mapper(client);
  auto current = mapper.findFutureByPrimaryKey(jobId).get();
}
"#;
        let document = StrDoc::try_new(source, SupportLang::Cpp).expect("parse C++ handler");
        let ast = AstGrep::doc(document);
        let function = ast
            .root()
            .dfs()
            .find(|node| node.kind().as_ref() == "function_definition")
            .expect("function definition");
        assert_eq!(
            qualified_function_name(&function).as_deref(),
            Some("JobsController::updateOne")
        );
        assert_eq!(
            function_parameters(&function)
                .iter()
                .filter_map(parameter_name)
                .collect::<Vec<_>>(),
            ["req", "callback", "jobId", "job"]
        );
    }

    #[test]
    fn textual_function_names_do_not_slice_inside_non_ascii_separators() {
        assert_eq!(
            textual_qualified_function_name("const char *ßApi::name("),
            Some("Api::name".to_string())
        );
    }
}
