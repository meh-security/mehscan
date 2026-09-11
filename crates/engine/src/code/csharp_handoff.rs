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
struct ParameterHandoff {
    target_path: String,
    target_parameter: String,
    target_location: Location,
    controller_parameter: String,
    controller_source: Location,
    controller_call: Location,
    controller_symbol: String,
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
}

impl CsharpHandoffCatalogBuilder {
    pub(crate) fn add_file(&mut self, path: &str, root: &Node<'_, StrDoc<SupportLang>>) {
        catalog_types_and_methods(path, root, &mut self.types, &mut self.methods);
        catalog_controller_calls(path, root, &mut self.calls);
    }

    pub(crate) fn finish(self) -> CsharpHandoffProjectContext {
        let mut handoffs = self
            .calls
            .into_iter()
            .filter_map(|call| resolve_call(call, &self.types, &self.methods))
            .collect::<Vec<_>>();
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
                        text: handoff.target_symbol.clone(),
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
                "controller-service-handoff".to_string(),
                "single-hop".to_string(),
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
    }
}

fn catalog_types_and_methods(
    path: &str,
    root: &Node<'_, StrDoc<SupportLang>>,
    types: &mut Vec<TypeRecord>,
    methods: &mut Vec<MethodRecord>,
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
            methods.push(MethodRecord {
                owner: name.clone(),
                name: method_name,
                parameters: method_parameters(path, &method),
                path: path.to_string(),
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
    let owners = if methods
        .iter()
        .any(|method| method.owner == call.receiver_type)
    {
        BTreeSet::from([call.receiver_type.clone()])
    } else {
        types
            .iter()
            .filter(|kind| kind.bases.contains(&call.receiver_type))
            .map(|kind| kind.name.clone())
            .collect()
    };
    if owners.is_empty() {
        return None;
    }
    let candidates = methods
        .iter()
        .filter(|method| owners.contains(&method.owner))
        .filter(|method| {
            method.name == call.method_name && method.parameters.len() == call.argument_count
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return None;
    }
    let target = candidates[0];
    let parameter = target.parameters.get(call.parameter_index)?;
    Some(ParameterHandoff {
        target_path: target.path.clone(),
        target_parameter: parameter.name.clone(),
        target_location: parameter.location.clone(),
        controller_parameter: call.controller_parameter,
        controller_source: call.controller_source,
        controller_call: call.controller_call,
        controller_symbol: call.controller_symbol,
        target_symbol: target.name.clone(),
    })
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
        "{}\0{}\0{}\0{}\0{}\0{}",
        handoff.target_path,
        FORWARDED_PARAMETER_RULE_ID,
        handoff.target_location.start.byte_offset,
        handoff.controller_source.path,
        handoff.controller_call.start.byte_offset,
        handoff.controller_source.start.byte_offset,
    );
    let hash = input.bytes().fold(0xcbf29ce484222325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3)
    });
    format!("ev-{hash:016x}")
}
