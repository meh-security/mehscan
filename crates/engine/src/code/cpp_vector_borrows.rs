//! Loop-carried element borrows from explicitly typed persistent vectors.
use super::{
    conditional::ConditionalRegions,
    context::enclosing_symbol,
    cpp_flow::{ControlFlow, incompatible_regions, runtime_reachable},
    literals::LiteralEnvironment,
    native_api::NativeApiContext,
};
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Availability, AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceContext,
    EvidenceKind, Language, Location, Position, Provenance, Resolution,
};
use std::collections::{BTreeMap, BTreeSet};

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const RULE: &str = "cpp-vector-loop-borrow-review";
fn compact(node: &N<'_>) -> String {
    node.text().split_whitespace().collect()
}
fn contains(a: &N<'_>, b: &N<'_>) -> bool {
    a.range().start <= b.range().start && b.range().end <= a.range().end
}
fn name<'a>(node: &N<'a>) -> Option<N<'a>> {
    if matches!(node.kind().as_ref(), "identifier" | "field_identifier") {
        return Some(node.clone());
    }
    node.field("declarator").and_then(|n| name(&n)).or_else(|| {
        matches!(
            node.kind().as_ref(),
            "reference_declarator" | "parenthesized_declarator"
        )
        .then(|| {
            node.children()
                .filter(|n| n.is_named())
                .find_map(|n| name(&n))
        })
        .flatten()
    })
}
fn same_function(node: &N<'_>, function: &N<'_>) -> bool {
    !node
        .ancestors()
        .take_while(|n| n.range() != function.range())
        .any(|n| n.kind().as_ref() == "lambda_expression")
        && node
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_definition")
            .is_some_and(|n| n.range() == function.range())
}
fn location(path: &str, node: &N<'_>) -> Location {
    let a = node.start_pos();
    let b = node.end_pos();
    Location {
        path: path.into(),
        start: Position {
            line: a.line() + 1,
            column: a.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: b.line() + 1,
            column: b.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}
fn capture(path: &str, node: &N<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}
fn id(path: &str, node: &N<'_>) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in format!(
        "{path}\0{RULE}\0{}\0{}",
        node.range().start,
        node.range().end
    )
    .bytes()
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
fn joined_availability(values: Vec<Availability>) -> Availability {
    let state = if values
        .iter()
        .any(|v| v.state == AvailabilityState::Excluded)
    {
        AvailabilityState::Excluded
    } else if values.iter().any(|v| v.state == AvailabilityState::Unknown) {
        AvailabilityState::Unknown
    } else if values
        .iter()
        .any(|v| v.state == AvailabilityState::Conditional)
    {
        AvailabilityState::Conditional
    } else {
        AvailabilityState::Always
    };
    let conditions = values
        .into_iter()
        .filter_map(|v| v.condition)
        .collect::<BTreeSet<_>>();
    Availability {
        state,
        condition: (!conditions.is_empty()).then(|| {
            conditions
                .into_iter()
                .map(|s| format!("({s})"))
                .collect::<Vec<_>>()
                .join(" && ")
        }),
    }
}
fn any_availability(values: Vec<Availability>) -> Availability {
    if values.iter().any(|v| v.state == AvailabilityState::Always) {
        return Availability {
            state: AvailabilityState::Always,
            condition: None,
        };
    }
    let unknown = values.iter().any(|v| v.state == AvailabilityState::Unknown);
    let unspecified = values.iter().any(|v| v.condition.is_none());
    let conditions = values
        .into_iter()
        .filter_map(|v| v.condition)
        .collect::<BTreeSet<_>>();
    Availability {
        state: if unknown {
            AvailabilityState::Unknown
        } else {
            AvailabilityState::Conditional
        },
        condition: (!unspecified && !conditions.is_empty()).then(|| {
            conditions
                .into_iter()
                .map(|s| format!("({s})"))
                .collect::<Vec<_>>()
                .join(" || ")
        }),
    }
}
struct Binding<'a> {
    declaration: N<'a>,
    declarator: N<'a>,
    scope: N<'a>,
    vector: bool,
}
fn binding_at<'a, 'b>(
    bindings: &'b BTreeMap<String, Vec<Binding<'a>>>,
    local: &str,
    node: &N<'a>,
) -> Option<&'b Binding<'a>> {
    bindings
        .get(local)?
        .iter()
        .filter(|b| b.declarator.range().start < node.range().start && contains(&b.scope, node))
        .max_by_key(|b| (b.scope.range().start, b.declarator.range().start))
}
fn method<'a>(call: &N<'a>) -> Option<(N<'a>, String)> {
    let callee = call.field("function")?;
    if callee.kind().as_ref() != "field_expression" {
        return None;
    }
    Some((callee.field("argument")?, compact(&callee.field("field")?)))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn add_observations<'a>(
    path: &str,
    root: &N<'a>,
    language: Language,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    api: &NativeApiContext,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Cpp || !root.text().contains("vector") {
        return;
    }
    // Discover the narrow relationship's owners before preparing any function.
    // Most C++ functions contain no persistent vector reference at all.
    let mut owners = BTreeMap::new();
    for declaration in root.dfs().filter(|n| n.kind().as_ref() == "declaration") {
        if !declaration
            .field("type")
            .is_some_and(|ty| api.standard_vector_type(&ty))
            || !declaration.field_children("declarator").any(|d| {
                d.field("declarator")
                    .is_some_and(|n| n.kind().as_ref() == "reference_declarator")
                    && d.field("value")
                        .is_some_and(|n| n.kind().as_ref() == "subscript_expression")
            })
        {
            continue;
        }
        let Some(function) = declaration
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        if declaration
            .ancestors()
            .take_while(|n| n.range() != function.range())
            .any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "for_statement" | "for_range_loop" | "while_statement" | "do_statement"
                )
            })
        {
            owners.entry(function.range().start).or_insert(function);
        }
    }
    for function in owners.into_values() {
        let Some(body) = function.field("body") else {
            continue;
        };
        let nodes = function
            .dfs()
            .filter(|n| same_function(n, &function))
            .collect::<Vec<_>>();
        // These control transfers need facts beyond the selected structured path.
        if nodes.iter().any(|n| {
            matches!(
                n.kind().as_ref(),
                "goto_statement" | "labeled_statement" | "try_statement" | "function_try_block"
            )
        }) {
            continue;
        }
        let mut bindings = BTreeMap::<String, Vec<Binding<'a>>>::new();
        for declaration in nodes
            .iter()
            .filter(|n| matches!(n.kind().as_ref(), "declaration" | "parameter_declaration"))
        {
            let scope = if declaration.kind().as_ref() == "parameter_declaration" {
                body.clone()
            } else {
                let Some(scope) = declaration.ancestors().find(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "compound_statement" | "for_statement" | "for_range_loop" | "if_statement"
                    )
                }) else {
                    continue;
                };
                scope
            };
            let vector = declaration
                .field("type")
                .is_some_and(|ty| api.standard_vector_type(&ty));
            for declarator in declaration.field_children("declarator") {
                let Some(local) = name(&declarator) else {
                    continue;
                };
                bindings
                    .entry(local.text().into_owned())
                    .or_default()
                    .push(Binding {
                        declaration: declaration.clone(),
                        declarator,
                        scope: scope.clone(),
                        vector,
                    });
            }
        }
        let candidates = bindings
            .values()
            .flatten()
            .filter_map(|binding| {
                if !binding.vector
                    || !binding
                        .declarator
                        .field("declarator")
                        .is_some_and(|n| n.kind().as_ref() == "reference_declarator")
                {
                    return None;
                }
                let value = binding.declarator.field("value")?;
                if value.kind().as_ref() != "subscript_expression"
                    || value.dfs().any(|n| n.kind().as_ref() == "call_expression")
                {
                    return None;
                }
                let loop_node = binding
                    .declaration
                    .ancestors()
                    .take_while(|n| n.range() != function.range())
                    .find(|n| {
                        matches!(
                            n.kind().as_ref(),
                            "for_statement" | "for_range_loop" | "while_statement" | "do_statement"
                        )
                    })?;
                if loop_node
                    .field("condition")
                    .and_then(|n| literals.known_bool(&n))
                    == Some(false)
                {
                    return None;
                }
                Some((binding.declarator.range().start, (binding, loop_node)))
            })
            .collect::<BTreeMap<_, _>>();
        if candidates.is_empty() {
            continue;
        }
        let flow = ControlFlow::new(&function, literals);
        let mut mutations = BTreeMap::<usize, Vec<N<'a>>>::new();
        let mut publications = BTreeMap::<usize, Vec<(N<'a>, N<'a>)>>::new();
        for call in nodes
            .iter()
            .filter(|n| n.kind().as_ref() == "call_expression")
        {
            let Some((receiver, operation)) = method(call) else {
                continue;
            };
            if api.macro_precedes(&operation, call.range().start) {
                continue;
            }
            if receiver.kind().as_ref() != "identifier" {
                continue;
            }
            let Some(binding) = binding_at(&bindings, receiver.text().as_ref(), call) else {
                continue;
            };
            let key = binding.declarator.range().start;
            if candidates.contains_key(&key)
                && matches!(
                    operation.as_str(),
                    "resize" | "reserve" | "push_back" | "emplace_back"
                )
            {
                mutations.entry(key).or_default().push(call.clone());
            }
        }
        for borrow in nodes
            .iter()
            .filter(|n| n.kind().as_ref() == "pointer_expression" && compact(n).starts_with('&'))
        {
            let Some(element) = borrow
                .field("argument")
                .filter(|n| n.kind().as_ref() == "subscript_expression")
            else {
                continue;
            };
            let Some(receiver) = element
                .field("argument")
                .filter(|n| n.kind().as_ref() == "identifier")
            else {
                continue;
            };
            let Some(binding) = binding_at(&bindings, receiver.text().as_ref(), borrow) else {
                continue;
            };
            let key = binding.declarator.range().start;
            let Some((_, loop_node)) = candidates.get(&key) else {
                continue;
            };
            let Some(publication) = borrow
                .ancestors()
                .take_while(|n| {
                    n.kind().as_ref() != "expression_statement" && n.range() != loop_node.range()
                })
                .filter(|n| n.kind().as_ref() == "call_expression")
                .last()
            else {
                continue;
            };
            let Some((target, operation)) = method(&publication) else {
                continue;
            };
            if api.macro_precedes(&operation, publication.range().start) {
                continue;
            }
            // The address crosses an outward insertion-like call. The callee's
            // storage effect is a deciding review fact, never inferred here.
            if compact(&target) == compact(&receiver)
                || !matches!(
                    operation.as_str(),
                    "insert" | "emplace" | "push_back" | "emplace_back"
                )
            {
                continue;
            }
            if !contains(loop_node, &publication) {
                continue;
            }
            publications
                .entry(key)
                .or_default()
                .push((borrow.clone(), publication));
        }
        for (key, borrows) in publications {
            let (binding, loop_node) = &candidates[&key];
            let Some(changes) = mutations.get(&key) else {
                continue;
            };
            let mut selected = Vec::new();
            for (borrow, publication) in &borrows {
                if conditional.availability_for(publication.range()).state
                    == AvailabilityState::Excluded
                    || !runtime_reachable(publication, &flow, literals)
                {
                    continue;
                }
                let before =
                    changes.partition_point(|change| change.range().start < borrow.range().start);
                if let Some(change) = changes[..before].iter().rev().find(|change| {
                    change.range().end < borrow.range().start
                        && contains(loop_node, change)
                        && conditional.availability_for(change.range()).state
                            != AvailabilityState::Excluded
                        && runtime_reachable(change, &flow, literals)
                        && !incompatible_regions(change, &flow)
                            .iter()
                            .any(|r| r.contains(&borrow.range().start))
                }) {
                    selected.push((change, borrow, publication));
                }
            }
            let Some((_, anchor, _)) = selected.first() else {
                continue;
            };
            let mut captures = BTreeMap::from([
                (
                    "container_binding".into(),
                    capture(path, &binding.declaration),
                ),
                (
                    "persistent_storage".into(),
                    capture(path, &binding.declarator.field("value").unwrap()),
                ),
            ]);
            for (index, (change, borrow, publication)) in selected.iter().enumerate() {
                captures.insert(format!("mutation_{index}"), capture(path, change));
                captures.insert(format!("borrow_{index}"), capture(path, borrow));
                captures.insert(format!("outward_call_{index}"), capture(path, publication));
            }
            // Preserve the complete entry/duplicate/capacity guards when bounded.
            if function.range().len() <= 32768 {
                captures.insert("operation_definition".into(), capture(path, &function));
            }
            if loop_node.range().len() <= 32768 {
                captures.insert("iteration".into(), capture(path, loop_node));
            }
            let mut alternatives = Vec::new();
            for (change, _, publication) in &selected {
                alternatives.push(joined_availability(vec![
                    conditional.availability_for(change.range()),
                    conditional.availability_for(publication.range()),
                ]));
            }
            let availability = joined_availability(vec![
                conditional.availability_for(binding.declaration.range()),
                any_availability(alternatives),
            ]);
            evidence.push(Evidence {
                id: id(path, anchor),
                kind: EvidenceKind::SensitiveOperation,
                capability: Capability::ContainerBorrowLifetime,
                location: location(path, anchor),
                enclosing_symbol: enclosing_symbol(anchor),
                captures,
                cwe_candidates: vec!["CWE-416".into()],
                tags: [
                    "native-container-borrow-review",
                    "loop-carried-pointer-stability",
                    "storage-effect-and-later-use-require-review",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "bounded C++ persistent-vector borrow relationship".into(),
                    rule_version: 1,
                },
                context: EvidenceContext {
                    availability: Some(availability),
                    ..Default::default()
                },
                symbol_resolution: None,
                rule_id: RULE.into(),
                related_evidence: vec![],
            });
        }
    }
}
