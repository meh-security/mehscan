//! Source navigation for existing native size relationships, never a new proof.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Evidence, Language, Location, OperandFact, OperandFactKind, Position,
};
use std::collections::{BTreeMap, BTreeSet};
type NativeNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(crate) fn annotate(language: Language, root: &NativeNode<'_>, evidence: &mut [Evidence]) {
    if !matches!(language, Language::C | Language::Cpp) {
        return;
    }
    let relevant = |e: &Evidence| {
        matches!(
            e.capability,
            Capability::RemainingInputRead | Capability::LoadedMemoryExtent
        )
    };
    let related_ids = evidence
        .iter()
        .filter(|e| relevant(e))
        .flat_map(|e| e.related_evidence.iter().cloned())
        .collect::<BTreeSet<_>>();
    if !evidence.iter().any(relevant) {
        return;
    }
    let captures = evidence
        .iter()
        .filter(|e| related_ids.contains(&e.id))
        .map(|e| (e.id.clone(), e.captures.clone()))
        .collect::<BTreeMap<_, _>>();
    // Index once. No project traversal or presumed call graph.
    let mut references = BTreeMap::<String, Vec<NativeNode<'_>>>::new();
    for node in root.dfs().filter(|n| n.kind().as_ref() == "identifier") {
        references
            .entry(node.text().into_owned())
            .or_default()
            .push(node);
    }
    for item in evidence.iter_mut().filter(|e| {
        matches!(
            e.capability,
            Capability::RemainingInputRead | Capability::LoadedMemoryExtent
        )
    }) {
        let Some(function) = root.dfs().find(|n| {
            n.kind().as_ref() == "function_definition"
                && n.range().start <= item.location.start.byte_offset
                && n.range().end >= item.location.end.byte_offset
        }) else {
            continue;
        };
        let params = parameters(&function);
        if function.dfs().any(|n| {
            n.kind().as_ref() == "lambda_expression"
                && n.range().start <= item.location.start.byte_offset
                && n.range().end >= item.location.end.byte_offset
        }) {
            add(
                item,
                "extent",
                OperandFactKind::OperandBoundary,
                &function,
                "lambda",
                &["nested_callable_binding"],
            );
            continue;
        }
        let mut operands = BTreeMap::<String, String>::new();
        let own = item.captures.iter();
        let related = item
            .related_evidence
            .iter()
            .filter_map(|id| captures.get(id))
            .flat_map(|c| c.iter());
        for (role, capture) in own.chain(related).filter(|(role, _)| {
            matches!(
                role.as_str(),
                "extent"
                    | "extent_computation"
                    | "loaded_scalar"
                    | "decoded_extent"
                    | "cursor"
                    | "source_cursor"
                    | "authoritative_extent"
            )
        }) {
            if identifier(capture.text.trim()) {
                operands
                    .entry(capture.text.trim().into())
                    .or_insert_with(|| role.clone());
            } else if role == "extent_computation" {
                if let Some(expression) = function.dfs().find(|n| {
                    n.range().start == capture.location.start.byte_offset
                        && n.range().end == capture.location.end.byte_offset
                }) {
                    for name in expression
                        .dfs()
                        .filter(|n| n.kind().as_ref() == "identifier")
                    {
                        // Member expressions require object/field provenance, not a scalar binding.
                        if name
                            .ancestors()
                            .take_while(|n| n.range() != expression.range())
                            .any(|n| {
                                matches!(n.kind().as_ref(), "field_expression" | "call_expression")
                            })
                        {
                            continue;
                        }
                        operands
                            .entry(name.text().into_owned())
                            .or_insert_with(|| role.clone());
                    }
                }
            }
        }
        let caller = single_static_caller(&function, &references);
        for (name, role) in operands {
            let mut declarations = params
                .iter()
                .filter(|(_, p)| scalar_name(p).as_deref() == Some(&name))
                .map(|(_, p)| p.clone())
                .collect::<Vec<_>>();
            declarations.extend(
                function
                    .dfs()
                    .filter(|n| n.kind().as_ref() == "init_declarator")
                    .filter(|n| {
                        n.field("declarator")
                            .is_some_and(|d| d.kind().as_ref() == "identifier" && d.text() == name)
                    })
                    .filter(|n| n.range().start <= item.location.end.byte_offset)
                    .filter(|n| {
                        n.ancestors()
                            .find(|a| {
                                matches!(
                                    a.kind().as_ref(),
                                    "compound_statement"
                                        | "for_statement"
                                        | "for_range_loop"
                                        | "if_statement"
                                        | "switch_statement"
                                        | "while_statement"
                                )
                            })
                            .is_some_and(|a| {
                                a.range().start <= item.location.start.byte_offset
                                    && a.range().end >= item.location.end.byte_offset
                            })
                    })
                    .filter_map(|n| n.ancestors().find(|a| a.kind().as_ref() == "declaration")),
            );
            let [declaration] = declarations.as_slice() else {
                add(
                    item,
                    &role,
                    OperandFactKind::OperandBoundary,
                    &function,
                    &name,
                    &["unique_scalar_declaration"],
                );
                continue;
            };
            if declaration.range().len() > 512 {
                add(
                    item,
                    &role,
                    OperandFactKind::OperandBoundary,
                    declaration,
                    &name,
                    &["bounded_scalar_declaration"],
                );
                continue;
            }
            add(
                item,
                &role,
                OperandFactKind::NativeOperandDeclaration,
                declaration,
                &name,
                &[
                    "effective_type_width_and_conversion",
                    "value_at_operation",
                    "preprocessor_configuration",
                ],
            );
            let Some((slot, _)) = params
                .iter()
                .find(|(_, p)| p.range() == declaration.range())
            else {
                continue;
            };
            if let Some(change) = parameter_change(
                &function,
                &name,
                declaration.range().end,
                item.location.start.byte_offset,
            ) {
                add(
                    item,
                    &role,
                    OperandFactKind::OperandBoundary,
                    &change,
                    &name,
                    &["parameter_mutation_or_escape"],
                );
                continue;
            }
            let Some(call) = caller.as_ref() else {
                add(
                    item,
                    &role,
                    OperandFactKind::OperandBoundary,
                    declaration,
                    &name,
                    &["unique_direct_file_local_caller"],
                );
                continue;
            };
            let args = call
                .field("arguments")
                .map(|args| {
                    args.children()
                        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if args.len() != params.len() {
                add(
                    item,
                    &role,
                    OperandFactKind::OperandBoundary,
                    call,
                    &name,
                    &["exact_caller_argument_slots"],
                );
                continue;
            }
            add(
                item,
                &role,
                OperandFactKind::LocalCallArgument,
                &args[*slot],
                &name,
                &[
                    "argument_conversion",
                    "caller_preconditions_and_reachability",
                    "preprocessor_and_dispatch_identity",
                ],
            );
        }
    }
}

fn parameters<'a>(function: &NativeNode<'a>) -> Vec<(usize, NativeNode<'a>)> {
    function
        .field("declarator")
        .and_then(|d| d.field("parameters"))
        .map(|p| {
            p.children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .enumerate()
                .collect()
        })
        .unwrap_or_default()
}
fn scalar_name(node: &NativeNode<'_>) -> Option<String> {
    let d = node.field("declarator")?;
    (node.kind().as_ref() == "parameter_declaration" && d.kind().as_ref() == "identifier")
        .then(|| d.text().into_owned())
}
fn identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}
fn single_static_caller<'a>(
    function: &NativeNode<'a>,
    references: &BTreeMap<String, Vec<NativeNode<'a>>>,
) -> Option<NativeNode<'a>> {
    if function.parent()?.kind().as_ref() != "translation_unit"
        || !function
            .children()
            .any(|n| n.kind().as_ref() == "storage_class_specifier" && n.text() == "static")
    {
        return None;
    }
    let declarator = function.field("declarator")?;
    if declarator.kind().as_ref() != "function_declarator" {
        return None;
    }
    let name = declarator.field("declarator")?;
    if name.kind().as_ref() != "identifier" {
        return None;
    }
    let uses = references
        .get(name.text().as_ref())?
        .iter()
        .filter(|n| n.range() != name.range())
        .collect::<Vec<_>>();
    let [usage] = uses.as_slice() else {
        return None;
    };
    let call = usage.parent()?;
    if call.kind().as_ref() != "call_expression"
        || call.field("function")?.range() != usage.range()
        || function.range().contains(&call.range().start)
    {
        return None;
    }
    Some(call)
}
fn parameter_change<'a>(
    function: &NativeNode<'a>,
    name: &str,
    after: usize,
    before: usize,
) -> Option<NativeNode<'a>> {
    function
        .dfs()
        .filter(|n| n.range().start >= after && n.range().start < before)
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "assignment_expression"
                    | "update_expression"
                    | "pointer_expression"
                    | "call_expression"
            )
        })
        .find(|n| {
            let subject = if n.kind().as_ref() == "assignment_expression" {
                n.field("left")
            } else if n.kind().as_ref() == "call_expression" {
                n.field("arguments")
            } else {
                Some(n.clone())
            };
            subject.is_some_and(|s| {
                s.dfs()
                    .any(|id| id.kind().as_ref() == "identifier" && id.text() == name)
            })
        })
}
fn add(
    item: &mut Evidence,
    role: &str,
    kind: OperandFactKind,
    node: &NativeNode<'_>,
    name: &str,
    checks: &[&str],
) {
    let start = node.start_pos();
    let end = node.end_pos();
    let fact = OperandFact {
        role: role.into(),
        kind,
        value: name.into(),
        location: Location {
            path: item.location.path.clone(),
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
        },
        remaining_checks: checks.iter().map(|s| (*s).into()).collect(),
    };
    if !item.context.operand_facts.contains(&fact) {
        item.context.operand_facts.push(fact);
    }
}
