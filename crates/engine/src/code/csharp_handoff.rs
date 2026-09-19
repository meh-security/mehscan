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
use super::csharp_ingress::{controller_source_evidence_id, is_bound_controller_parameter};
use super::literals::LiteralEnvironment;
use super::reachability;

pub(crate) const FORWARDED_PARAMETER_RULE_ID: &str = "csharp-controller-service-parameter-source";
const ENGINE: &str = "mehscan csharp-controller-service-summary 1";

#[derive(Clone, Debug)]
struct MethodRecord {
    owner: String,
    name: String,
    parameters: Vec<ParameterRecord>,
    path: String,
}

#[derive(Clone, Debug)]
struct ParameterRecord {
    name: String,
    location: Location,
}

#[derive(Clone, Debug)]
struct TypeRecord {
    name: String,
    bases: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct PendingCall {
    receiver_type: String,
    method_name: String,
    argument_count: usize,
    parameter_index: usize,
    controller_parameter: String,
    controller_source: Location,
    controller_call: Location,
    controller_symbol: String,
}

#[derive(Clone, Debug)]
struct PendingForwardCall {
    source_owner: String,
    source_method: String,
    source_argument_count: usize,
    source_parameter_index: usize,
    receiver_type: String,
    method_name: String,
    argument_count: usize,
    parameter_index: usize,
    call: Location,
}

#[derive(Clone, Debug)]
struct ParameterHandoff {
    target_owner: String,
    target_argument_count: usize,
    target_parameter_index: usize,
    target_path: String,
    target_parameter: String,
    target_location: Location,
    controller_parameter: String,
    controller_source: Location,
    controller_call: Location,
    controller_symbol: String,
    controller_target_symbol: String,
    forwarding_call: Option<Location>,
    forwarding_symbol: Option<String>,
    target_symbol: String,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CsharpHandoffProjectContext {
    handoffs: Vec<ParameterHandoff>,
}

#[derive(Default)]
pub(crate) struct CsharpHandoffCatalogBuilder {
    methods: Vec<MethodRecord>,
    types: Vec<TypeRecord>,
    calls: Vec<PendingCall>,
    forwards: Vec<PendingForwardCall>,
}

impl CsharpHandoffCatalogBuilder {
    pub(crate) fn add_file(&mut self, path: &str, root: &Node<'_, StrDoc<SupportLang>>) {
        catalog_types_and_methods(
            path,
            root,
            &mut self.types,
            &mut self.methods,
            &mut self.forwards,
        );
        catalog_controller_calls(path, root, &mut self.calls);
    }

    pub(crate) fn finish(self) -> CsharpHandoffProjectContext {
        let direct = self
            .calls
            .into_iter()
            .filter_map(|call| resolve_call(call, &self.types, &self.methods))
            .collect::<Vec<_>>();
        let mut handoffs = direct.clone();
        for handoff in direct {
            handoffs.extend(
                self.forwards
                    .iter()
                    .filter(|forward| {
                        forward.source_owner == handoff.target_owner
                            && forward.source_method == handoff.target_symbol
                            && forward.source_argument_count == handoff.target_argument_count
                            && forward.source_parameter_index == handoff.target_parameter_index
                    })
                    .filter_map(|forward| {
                        resolve_forward(&handoff, forward, &self.types, &self.methods)
                    }),
            );
        }
        handoffs.sort_by(|left, right| {
            left.target_path
                .cmp(&right.target_path)
                .then_with(|| {
                    left.target_location
                        .start
                        .byte_offset
                        .cmp(&right.target_location.start.byte_offset)
                })
                .then_with(|| {
                    left.controller_source
                        .path
                        .cmp(&right.controller_source.path)
                })
                .then_with(|| {
                    left.controller_call
                        .start
                        .byte_offset
                        .cmp(&right.controller_call.start.byte_offset)
                })
        });
        handoffs.dedup_by(|left, right| {
            left.target_path == right.target_path
                && left.target_location == right.target_location
                && left.controller_call == right.controller_call
                && left.controller_source == right.controller_source
        });
        CsharpHandoffProjectContext { handoffs }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_forwarded_parameter_sources<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project_context: &CsharpHandoffProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }
    for handoff in project_context
        .handoffs
        .iter()
        .filter(|handoff| handoff.target_path == path)
    {
        let Some(parameter_node) = root.dfs().find(|node| {
            node.range().start == handoff.target_location.start.byte_offset
                && node.range().end == handoff.target_location.end.byte_offset
        }) else {
            continue;
        };
        if comments.is_in_comment(parameter_node.range()) {
            continue;
        }
        let id = evidence_id(handoff);
        evidence.push(Evidence {
            id,
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: handoff.target_location.clone(),
            enclosing_symbol: Some(handoff.target_symbol.clone()),
            captures: BTreeMap::from([
                (
                    "parameter".to_string(),
                    Capture {
                        text: handoff.target_parameter.clone(),
                        location: handoff.target_location.clone(),
                    },
                ),
                (
                    "controller_source".to_string(),
                    Capture {
                        text: handoff.controller_parameter.clone(),
                        location: handoff.controller_source.clone(),
                    },
                ),
                (
                    "controller_call".to_string(),
                    Capture {
                        text: handoff.controller_target_symbol.clone(),
                        location: handoff.controller_call.clone(),
                    },
                ),
                (
                    "controller_action".to_string(),
                    Capture {
                        text: handoff.controller_symbol.clone(),
                        location: handoff.controller_source.clone(),
                    },
                ),
            ]),
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "http".to_string(),
                "request".to_string(),
                "attacker-controlled".to_string(),
                "aspnet-core".to_string(),
                if handoff.forwarding_call.is_some() {
                    "controller-service-repository-handoff".to_string()
                } else {
                    "controller-service-handoff".to_string()
                },
                if handoff.forwarding_call.is_some() {
                    "two-hop".to_string()
                } else {
                    "single-hop".to_string()
                },
                "unique-syntactic-target".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&parameter_node, literals)),
                availability: Some(conditional.availability_for(parameter_node.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: FORWARDED_PARAMETER_RULE_ID.to_string(),
            related_evidence: vec![controller_source_evidence_id(&handoff.controller_source)],
        });
        if let (Some(call), Some(symbol)) = (&handoff.forwarding_call, &handoff.forwarding_symbol)
            && let Some(item) = evidence.last_mut()
        {
            item.captures.insert(
                "service_call".to_string(),
                Capture {
                    text: symbol.clone(),
                    location: call.clone(),
                },
            );
        }
    }
}

fn catalog_types_and_methods(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    types: &mut Vec<TypeRecord>,
    methods: &mut Vec<MethodRecord>,
    forwards: &mut Vec<PendingForwardCall>,
) {
    for declaration in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "class_declaration" | "record_declaration"
        )
    }) {
        let Some(name) = declaration
            .field("name")
            .and_then(|node| type_name(node.text().as_ref()))
        else {
            continue;
        };
        let bases = declaration
            .children()
            .find(|child| child.kind().as_ref() == "base_list")
            .map(|base_list| {
                base_list
                    .children()
                    .filter(|child| child.is_named())
                    .filter_map(|base| type_name(base.text().as_ref()))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        types.push(TypeRecord {
            name: name.clone(),
            bases,
        });
        for method in declaration
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_declaration")
            .filter(|method| immediate_owner(method).as_deref() == Some(name.as_str()))
        {
            let Some(method_name) = method
                .field("name")
                .and_then(|node| simple_identifier(node.text().as_ref()))
            else {
                continue;
            };
            let parameters = method_parameters(path, &method);
            methods.push(MethodRecord {
                owner: name.clone(),
                name: method_name,
                parameters: parameters.clone(),
                path: path.to_string(),
            });
            catalog_method_forwards(&name, &method, &parameters, path, forwards);
        }
    }
}

fn catalog_method_forwards(
    owner: &str,
    method: &Node<'_, StrDoc<SupportLang>>,
    parameters: &[ParameterRecord],
    path: &str,
    forwards: &mut Vec<PendingForwardCall>,
) {
    let Some(source_method) = method
        .field("name")
        .and_then(|node| simple_identifier(node.text().as_ref()))
    else {
        return;
    };
    let receiver_types = receiver_types(method);
    for invocation in method
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
        .filter(|node| nearest_method(node).is_some_and(|item| item.range() == method.range()))
        .filter(|node| !nested_callable_between(node, method))
    {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if function.kind().as_ref() != "member_access_expression" {
            continue;
        }
        let (Some(receiver), Some(method_name)) = (
            function
                .field("expression")
                .and_then(|node| simple_identifier(node.text().as_ref())),
            function
                .field("name")
                .and_then(|node| simple_identifier(node.text().as_ref())),
        ) else {
            continue;
        };
        let Some(receiver_type) = receiver_types.get(&receiver) else {
            continue;
        };
        if !looks_like_service_type(receiver_type) {
            continue;
        }
        let Some(arguments) = invocation_arguments(&invocation) else {
            continue;
        };
        for (parameter_index, argument) in arguments.iter().enumerate() {
            let Some(source_parameter_index) = parameters
                .iter()
                .position(|parameter| parameter.name == *argument)
            else {
                continue;
            };
            forwards.push(PendingForwardCall {
                source_owner: owner.to_string(),
                source_method: source_method.clone(),
                source_argument_count: parameters.len(),
                source_parameter_index,
                receiver_type: receiver_type.clone(),
                method_name: method_name.clone(),
                argument_count: arguments.len(),
                parameter_index,
                call: node_location(path, &invocation),
            });
        }
    }
}

fn catalog_controller_calls(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    calls: &mut Vec<PendingCall>,
) {
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let source_parameters = method_parameters_nodes(&method)
            .into_iter()
            .filter(|parameter| is_bound_controller_parameter(&method, parameter))
            .filter_map(|parameter| {
                let name = parameter.field("name")?;
                Some((
                    simple_identifier(name.text().as_ref())?,
                    node_location(path, &name),
                ))
            })
            .collect::<BTreeMap<_, _>>();
        if source_parameters.is_empty() {
            continue;
        }
        let Some(controller_symbol) = method
            .field("name")
            .and_then(|name| simple_identifier(name.text().as_ref()))
        else {
            continue;
        };
        let receiver_types = receiver_types(&method);
        for invocation in method
            .dfs()
            .filter(|node| node.kind().as_ref() == "invocation_expression")
            .filter(|node| {
                nearest_method(node).is_some_and(|owner| owner.range() == method.range())
            })
            .filter(|node| !nested_callable_between(node, &method))
        {
            let Some(function) = invocation.field("function") else {
                continue;
            };
            if function.kind().as_ref() != "member_access_expression" {
                continue;
            }
            let (Some(receiver), Some(method_name)) = (
                function
                    .field("expression")
                    .and_then(|node| simple_identifier(node.text().as_ref())),
                function
                    .field("name")
                    .and_then(|node| simple_identifier(node.text().as_ref())),
            ) else {
                continue;
            };
            let Some(receiver_type) = receiver_types.get(&receiver) else {
                continue;
            };
            if !looks_like_service_type(receiver_type) {
                continue;
            }
            let Some(arguments) = invocation_arguments(&invocation) else {
                continue;
            };
            for (parameter_index, argument) in arguments.iter().enumerate() {
                let Some(controller_source) = source_parameters.get(argument) else {
                    continue;
                };
                calls.push(PendingCall {
                    receiver_type: receiver_type.clone(),
                    method_name: method_name.clone(),
                    argument_count: arguments.len(),
                    parameter_index,
                    controller_parameter: argument.clone(),
                    controller_source: controller_source.clone(),
                    controller_call: node_location(path, &invocation),
                    controller_symbol: controller_symbol.clone(),
                });
            }
        }
    }
}

fn resolve_call(
    call: PendingCall,
    types: &[TypeRecord],
    methods: &[MethodRecord],
) -> Option<ParameterHandoff> {
    let target = resolve_method(
        &call.receiver_type,
        &call.method_name,
        call.argument_count,
        types,
        methods,
    )?;
    let parameter = target.parameters.get(call.parameter_index)?;
    Some(ParameterHandoff {
        target_owner: target.owner.clone(),
        target_argument_count: target.parameters.len(),
        target_parameter_index: call.parameter_index,
        target_path: target.path.clone(),
        target_parameter: parameter.name.clone(),
        target_location: parameter.location.clone(),
        controller_parameter: call.controller_parameter,
        controller_source: call.controller_source,
        controller_call: call.controller_call,
        controller_symbol: call.controller_symbol,
        controller_target_symbol: target.name.clone(),
        forwarding_call: None,
        forwarding_symbol: None,
        target_symbol: target.name.clone(),
    })
}

fn resolve_forward(
    source: &ParameterHandoff,
    forward: &PendingForwardCall,
    types: &[TypeRecord],
    methods: &[MethodRecord],
) -> Option<ParameterHandoff> {
    let target = resolve_method(
        &forward.receiver_type,
        &forward.method_name,
        forward.argument_count,
        types,
        methods,
    )?;
    if target.owner == source.target_owner
        && target.name == source.target_symbol
        && target.parameters.len() == source.target_argument_count
    {
        return None;
    }
    let parameter = target.parameters.get(forward.parameter_index)?;
    Some(ParameterHandoff {
        target_owner: target.owner.clone(),
        target_argument_count: target.parameters.len(),
        target_parameter_index: forward.parameter_index,
        target_path: target.path.clone(),
        target_parameter: parameter.name.clone(),
        target_location: parameter.location.clone(),
        controller_parameter: source.controller_parameter.clone(),
        controller_source: source.controller_source.clone(),
        controller_call: source.controller_call.clone(),
        controller_symbol: source.controller_symbol.clone(),
        controller_target_symbol: source.controller_target_symbol.clone(),
        forwarding_call: Some(forward.call.clone()),
        forwarding_symbol: Some(target.name.clone()),
        target_symbol: target.name.clone(),
    })
}

fn resolve_method<'a>(
    receiver_type: &str,
    method_name: &str,
    argument_count: usize,
    types: &[TypeRecord],
    methods: &'a [MethodRecord],
) -> Option<&'a MethodRecord> {
    let owners = if methods.iter().any(|method| method.owner == receiver_type) {
        BTreeSet::from([receiver_type.to_string()])
    } else {
        types
            .iter()
            .filter(|kind| kind.bases.contains(receiver_type))
            .map(|kind| kind.name.clone())
            .collect()
    };
    if owners.is_empty() {
        return None;
    }
    let mut candidates = methods.iter().filter(|method| {
        owners.contains(&method.owner)
            && method.name == method_name
            && method.parameters.len() == argument_count
    });
    let target = candidates.next()?;
    candidates.next().is_none().then_some(target)
}

fn receiver_types(method: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    if let Some(owner) = method.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "class_declaration" | "record_declaration"
        )
    }) {
        for field in owner
            .dfs()
            .filter(|node| node.kind().as_ref() == "field_declaration")
            .filter(|field| immediate_owner(field) == immediate_owner(method))
        {
            let Some(declaration) = field
                .dfs()
                .find(|node| node.kind().as_ref() == "variable_declaration")
            else {
                continue;
            };
            let Some(kind) = declaration
                .field("type")
                .and_then(|node| type_name(node.text().as_ref()))
            else {
                continue;
            };
            for variable in declaration
                .children()
                .filter(|node| node.kind().as_ref() == "variable_declarator")
            {
                if let Some(name) = variable
                    .field("name")
                    .and_then(|node| simple_identifier(node.text().as_ref()))
                {
                    result.insert(name, kind.clone());
                }
            }
        }
        for property in owner
            .dfs()
            .filter(|node| node.kind().as_ref() == "property_declaration")
            .filter(|property| immediate_owner(property) == immediate_owner(method))
        {
            if let (Some(name), Some(kind)) = (
                property
                    .field("name")
                    .and_then(|node| simple_identifier(node.text().as_ref())),
                property
                    .field("type")
                    .and_then(|node| type_name(node.text().as_ref())),
            ) {
                result.insert(name, kind);
            }
        }
    }
    for parameter in method_parameters_nodes(method) {
        if let (Some(name), Some(kind)) = (
            parameter
                .field("name")
                .and_then(|node| simple_identifier(node.text().as_ref())),
            parameter
                .field("type")
                .and_then(|node| type_name(node.text().as_ref())),
        ) {
            result.insert(name, kind);
        }
    }
    for variable in method
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
    {
        if let (Some(name), Some(kind)) = (
            variable
                .field("name")
                .and_then(|node| simple_identifier(node.text().as_ref())),
            variable
                .parent()
                .filter(|parent| parent.kind().as_ref() == "variable_declaration")
                .and_then(|declaration| declaration.field("type"))
                .and_then(|node| type_name(node.text().as_ref()))
                .filter(|kind| kind != "var"),
        ) {
            result.insert(name, kind);
        }
    }
    result
}

fn method_parameters(path: &str, method: &Node<'_, StrDoc<SupportLang>>) -> Vec<ParameterRecord> {
    method_parameters_nodes(method)
        .into_iter()
        .filter_map(|parameter| {
            let name = parameter.field("name")?;
            Some(ParameterRecord {
                name: simple_identifier(name.text().as_ref())?,
                location: node_location(path, &name),
            })
        })
        .collect()
}

fn method_parameters_nodes<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    method
        .field("parameters")
        .map(|parameters| {
            parameters
                .children()
                .filter(|node| node.kind().as_ref() == "parameter")
                .collect()
        })
        .unwrap_or_default()
}

fn invocation_arguments(invocation: &Node<'_, StrDoc<SupportLang>>) -> Option<Vec<String>> {
    invocation
        .field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|node| node.is_named())
                .map(|argument| {
                    let argument_text = argument.text();
                    let trimmed = argument_text.trim();
                    if trimmed.contains(':')
                        || trimmed.starts_with("ref ")
                        || trimmed.starts_with("out ")
                        || trimmed.starts_with("in ")
                    {
                        return None;
                    }
                    if argument.kind().as_ref() == "argument" {
                        Some(
                            argument
                                .children()
                                .filter(|child| child.is_named())
                                .last()
                                .unwrap_or(argument),
                        )
                    } else {
                        Some(argument)
                    }
                })
                .map(|expression| expression.map(|node| node.text().trim().to_string()))
                .collect()
        })
        .unwrap_or_else(|| Some(Vec::new()))
}

fn immediate_owner(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "class_declaration" | "record_declaration"
            )
        })?
        .field("name")
        .and_then(|name| type_name(name.text().as_ref()))
}

fn nearest_method<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
}

fn nested_callable_between(
    node: &Node<'_, StrDoc<SupportLang>>,
    method: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    node.ancestors()
        .take_while(|ancestor| ancestor.range() != method.range())
        .any(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "lambda_expression" | "local_function_statement" | "anonymous_method_expression"
            )
        })
}

fn looks_like_service_type(name: &str) -> bool {
    let name = name.trim_start_matches('I');
    name.ends_with("Repository")
        || name.ends_with("Service")
        || name.ends_with("Store")
        || name.ends_with("Provider")
        || name.ends_with("Manager")
}

fn type_name(text: &str) -> Option<String> {
    let compact = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let compact = compact
        .trim_end_matches('?')
        .strip_prefix("global::")
        .unwrap_or(compact.trim_end_matches('?'));
    let without_generic = compact.split('<').next().unwrap_or(compact);
    simple_identifier(
        without_generic
            .rsplit('.')
            .next()
            .unwrap_or(without_generic),
    )
}

fn simple_identifier(text: &str) -> Option<String> {
    let text = text.trim();
    let mut characters = text.chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_alphabetic())
        || !characters.all(|character| character == '_' || character.is_alphanumeric())
    {
        return None;
    }
    Some(text.to_string())
}

fn node_location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
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

fn evidence_id(handoff: &ParameterHandoff) -> String {
    let input = format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        handoff.target_path,
        FORWARDED_PARAMETER_RULE_ID,
        handoff.target_location.start.byte_offset,
        handoff.controller_source.path,
        handoff.controller_call.start.byte_offset,
        handoff.controller_source.start.byte_offset,
        handoff
            .forwarding_call
            .as_ref()
            .map_or(0, |location| location.start.byte_offset),
    );
    let hash = input.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    format!("ev-{hash:016x}")
}
