use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

pub(crate) const CONTROLLER_RULE_ID: &str = "csharp-aspnet-controller-parameter-source";
pub(crate) const MINIMAL_RULE_ID: &str = "csharp-aspnet-minimal-parameter-source";
const ENGINE: &str = "mehscan csharp-aspnet-parameter-summary 1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingKind {
    Query,
    Route,
    Body,
    Form,
    Header,
    Model,
}

impl BindingKind {
    fn tag(self) -> &'static str {
        match self {
            Self::Query => "from_query",
            Self::Route => "from_route",
            Self::Body => "from_body",
            Self::Form => "from_form",
            Self::Header => "from_header",
            Self::Model => "from_model",
        }
    }
}

pub(crate) fn add_bound_parameter_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }

    let declared_types = locally_declared_types(root);
    add_controller_sources(path, root, comments, conditional, literals, evidence);
    add_minimal_api_sources(
        path,
        root,
        comments,
        conditional,
        literals,
        &declared_types,
        evidence,
    );
}

fn add_controller_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        if !has_http_action_attribute(&method) && !is_conventional_controller_action(&method) {
            continue;
        }
        let Some(parameters) = method.field("parameters") else {
            continue;
        };
        for parameter in parameters
            .children()
            .filter(|node| node.kind().as_ref() == "parameter")
        {
            if comments.is_in_comment(parameter.range()) {
                continue;
            }
            let binding = controller_parameter_binding(&method, &parameter);
            let Some(binding) = binding else {
                continue;
            };
            push_source(
                path,
                &parameter,
                binding,
                CONTROLLER_RULE_ID,
                enclosing_symbol(&parameter),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

pub(crate) fn is_bound_controller_parameter(
    method: &Node<'_, StrDoc<SupportLang>>,
    parameter: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    (has_http_action_attribute(method) || is_conventional_controller_action(method))
        && controller_parameter_binding(method, parameter).is_some()
}

fn controller_parameter_binding(
    method: &Node<'_, StrDoc<SupportLang>>,
    parameter: &Node<'_, StrDoc<SupportLang>>,
) -> Option<BindingKind> {
    if is_service_parameter(parameter) {
        return None;
    }
    explicit_binding(parameter)
        .or_else(|| is_form_file(parameter).then_some(BindingKind::Form))
        .or_else(|| is_scalar_parameter(parameter).then_some(BindingKind::Query))
        .or_else(|| is_definite_controller_model(method, parameter).then_some(BindingKind::Model))
}

#[allow(clippy::too_many_arguments)]
fn add_minimal_api_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    declared_types: &BTreeSet<String>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        let Some((verb, route, handler)) = minimal_api_call(&invocation) else {
            continue;
        };
        let Some(parameters) = handler.field("parameters") else {
            continue;
        };
        let symbol = Some(format!("{verb} {route}"));
        let parameter_nodes = if parameters.kind().as_ref() == "implicit_parameter" {
            vec![parameters]
        } else {
            parameters
                .children()
                .filter(|node| node.kind().as_ref() == "parameter")
                .collect::<Vec<_>>()
        };
        for parameter in parameter_nodes {
            if comments.is_in_comment(parameter.range()) || is_service_parameter(&parameter) {
                continue;
            }
            let Some(name) = parameter_name(&parameter) else {
                continue;
            };
            let binding = explicit_binding(&parameter)
                .or_else(|| is_form_file(&parameter).then_some(BindingKind::Form))
                .or_else(|| {
                    route_parameter(&route, name.text().as_ref()).then_some(BindingKind::Route)
                })
                .or_else(|| is_scalar_parameter(&parameter).then_some(BindingKind::Query))
                .or_else(|| {
                    implicit_body_parameter(verb, &parameter, declared_types)
                        .then_some(BindingKind::Body)
                });
            let Some(binding) = binding else {
                continue;
            };
            push_source(
                path,
                &parameter,
                binding,
                MINIMAL_RULE_ID,
                symbol.clone(),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_source<'tree>(
    path: &str,
    parameter: &Node<'tree, StrDoc<SupportLang>>,
    binding: BindingKind,
    rule_id: &str,
    symbol: Option<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(name) = parameter_name(parameter) else {
        return;
    };
    let mut captures = BTreeMap::from([(
        "parameter".to_string(),
        Capture {
            text: name.text().into_owned(),
            location: location(path, &name),
        },
    )]);
    if let Some(type_node) = parameter.field("type") {
        captures.insert(
            "type".to_string(),
            Capture {
                text: type_node.text().into_owned(),
                location: location(path, &type_node),
            },
        );
    }
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, name.range().start, name.range().end),
        kind: EvidenceKind::Source,
        capability: Capability::HttpRequestData,
        location: location(path, &name),
        enclosing_symbol: symbol,
        captures,
        cwe_candidates: vec!["CWE-20".to_string()],
        tags: vec![
            "http".to_string(),
            "request".to_string(),
            "attacker-controlled".to_string(),
            "aspnet-core".to_string(),
            "model-binding".to_string(),
            binding.tag().to_string(),
        ],
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(parameter.range()),
            reachability: Some(reachability::classify(parameter, literals)),
            availability: Some(conditional.availability_for(parameter.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn has_http_action_attribute(method: &Node<'_, StrDoc<SupportLang>>) -> bool {
    direct_attribute_names(method).any(|name| {
        matches!(
            name.as_str(),
            "HttpGet"
                | "HttpPost"
                | "HttpPut"
                | "HttpDelete"
                | "HttpPatch"
                | "HttpHead"
                | "HttpOptions"
                | "AcceptVerbs"
        )
    })
}

fn is_conventional_controller_action(method: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if direct_attribute_names(method).any(|name| name == "NonAction") {
        return false;
    }
    let signature = method
        .children()
        .take_while(|child| child.kind().as_ref() != "block")
        .map(|child| child.text().into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    let modifiers = signature.split_whitespace().collect::<BTreeSet<_>>();
    if !modifiers.contains("public") || modifiers.contains("static") {
        return false;
    }
    method
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "class_declaration")
        .is_some_and(|controller| {
            controller
                .field("name")
                .is_some_and(|name| name.text().ends_with("Controller"))
                || controller
                    .children()
                    .find(|child| child.kind().as_ref() == "base_list")
                    .is_some_and(|bases| {
                        bases.dfs().any(|node| {
                            matches!(node.text().trim(), "Controller" | "ControllerBase")
                        })
                    })
        })
}

fn is_definite_controller_model(
    method: &Node<'_, StrDoc<SupportLang>>,
    parameter: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    if parameter_type_name(parameter).is_none() || is_service_parameter(parameter) {
        return false;
    }
    method
        .ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "class_declaration" | "record_declaration"
            )
        })
        .is_some_and(|controller| {
            direct_attribute_names(&controller).any(|name| name == "ApiController")
                || controller
                    .children()
                    .find(|child| child.kind().as_ref() == "base_list")
                    .is_some_and(|bases| {
                        bases.dfs().any(|node| {
                            matches!(node.text().trim(), "Controller" | "ControllerBase")
                        })
                    })
        })
}

fn explicit_binding(parameter: &Node<'_, StrDoc<SupportLang>>) -> Option<BindingKind> {
    direct_attribute_names(parameter).find_map(|name| match name.as_str() {
        "FromQuery" => Some(BindingKind::Query),
        "FromRoute" => Some(BindingKind::Route),
        "FromBody" => Some(BindingKind::Body),
        "FromForm" => Some(BindingKind::Form),
        "FromHeader" => Some(BindingKind::Header),
        _ => None,
    })
}

fn direct_attribute_names(node: &Node<'_, StrDoc<SupportLang>>) -> std::vec::IntoIter<String> {
    node.children()
        .filter(|child| child.kind().as_ref() == "attribute_list")
        .flat_map(|list| list.children().collect::<Vec<_>>())
        .filter(|attribute| attribute.kind().as_ref() == "attribute")
        .filter_map(|attribute| attribute.field("name"))
        .map(|name| normalize_attribute_name(name.text().as_ref()))
        .collect::<Vec<_>>()
        .into_iter()
}

fn normalize_attribute_name(name: &str) -> String {
    name.rsplit(['.', ':'])
        .next()
        .unwrap_or(name)
        .strip_suffix("Attribute")
        .unwrap_or_else(|| name.rsplit(['.', ':']).next().unwrap_or(name))
        .to_string()
}

pub(crate) fn is_service_parameter(parameter: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if direct_attribute_names(parameter)
        .any(|name| matches!(name.as_str(), "FromServices" | "FromKeyedServices"))
    {
        return true;
    }
    let Some(type_name) = parameter_type_name(parameter) else {
        return false;
    };
    is_framework_service_type(&type_name) || looks_like_service_type(&type_name)
}

fn is_framework_service_type(type_name: &str) -> bool {
    matches!(
        type_name,
        "HttpContext"
            | "HttpRequest"
            | "HttpResponse"
            | "ClaimsPrincipal"
            | "CancellationToken"
            | "IServiceProvider"
            | "IConfiguration"
            | "ILogger"
            | "IHostEnvironment"
            | "IWebHostEnvironment"
    )
}

fn looks_like_service_type(type_name: &str) -> bool {
    [
        "Service",
        "Repository",
        "DbContext",
        "Client",
        "Logger",
        "Options",
        "Configuration",
    ]
    .iter()
    .any(|suffix| type_name.ends_with(suffix))
}

fn is_form_file(parameter: &Node<'_, StrDoc<SupportLang>>) -> bool {
    parameter_type_name(parameter).is_some_and(|name| {
        matches!(
            name.as_str(),
            "IFormFile" | "IFormFileCollection" | "IEnumerable<IFormFile>" | "IFormFile[]"
        )
    })
}

fn is_scalar_parameter(parameter: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if parameter.kind().as_ref() == "implicit_parameter" {
        return true;
    }
    parameter_type_name(parameter).is_some_and(|name| {
        matches!(
            name.as_str(),
            "string"
                | "String"
                | "bool"
                | "Boolean"
                | "byte"
                | "sbyte"
                | "short"
                | "ushort"
                | "int"
                | "uint"
                | "long"
                | "ulong"
                | "float"
                | "double"
                | "decimal"
                | "char"
                | "Guid"
                | "DateTime"
                | "DateTimeOffset"
                | "TimeSpan"
        )
    })
}

fn implicit_body_parameter(
    verb: &str,
    parameter: &Node<'_, StrDoc<SupportLang>>,
    declared_types: &BTreeSet<String>,
) -> bool {
    if !matches!(verb, "MapPost" | "MapPut" | "MapPatch") {
        return false;
    }
    parameter_type_name(parameter).is_some_and(|name| declared_types.contains(&name))
}

fn locally_declared_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration" | "record_declaration" | "struct_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .filter(|name| !looks_like_service_type(name))
        .collect()
}

fn parameter_type_name(parameter: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let text = parameter.field("type")?.text();
    let compact = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let compact = compact.trim_end_matches('?');
    Some(
        compact
            .strip_prefix("global::")
            .unwrap_or(compact)
            .rsplit('.')
            .next()
            .unwrap_or(compact)
            .to_string(),
    )
}

fn parameter_name<'tree>(
    parameter: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if parameter.kind().as_ref() == "implicit_parameter" {
        return Some(parameter.clone());
    }
    parameter.field("name")
}

fn minimal_api_call<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(&'static str, String, Node<'tree, StrDoc<SupportLang>>)> {
    let arguments = invocation.field("arguments")?;
    let callee_length = arguments
        .range()
        .start
        .checked_sub(invocation.range().start)?;
    let text = invocation.text();
    let observed = text.get(..callee_length)?.trim();
    let verb = match observed.rsplit('.').next()? {
        "MapGet" => "MapGet",
        "MapPost" => "MapPost",
        "MapPut" => "MapPut",
        "MapDelete" => "MapDelete",
        "MapPatch" => "MapPatch",
        _ => return None,
    };
    let mut arguments = arguments.children().filter(|child| child.is_named());
    let route = argument_expression(arguments.next()?)?;
    let handler = argument_expression(arguments.next()?)?;
    if handler.kind().as_ref() != "lambda_expression" {
        return None;
    }
    Some((verb, exact_string(route.text().as_ref())?, handler))
}

fn argument_expression<'tree>(
    argument: Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if argument.kind().as_ref() != "argument" {
        return Some(argument);
    }
    argument.children().filter(|child| child.is_named()).last()
}

fn exact_string(text: &str) -> Option<String> {
    let text = text.trim();
    for prefix in ["\"", "@\""] {
        if let Some(value) = text
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix('"'))
        {
            return Some(value.to_string());
        }
    }
    None
}

fn route_parameter(route: &str, name: &str) -> bool {
    route
        .split('{')
        .skip(1)
        .filter_map(|part| part.split_once('}'))
        .any(|(parameter, _)| {
            parameter
                .trim_start_matches('*')
                .split([':', '?', '='])
                .next()
                .is_some_and(|candidate| candidate.eq_ignore_ascii_case(name))
        })
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

pub(crate) fn controller_source_evidence_id(location: &Location) -> String {
    evidence_id(
        &location.path,
        CONTROLLER_RULE_ID,
        location.start.byte_offset,
        location.end.byte_offset,
    )
}
