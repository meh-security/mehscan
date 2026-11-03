//! Pending pointee ownership across an explicit loop-carried exceptional exit.
use super::{
    conditional::ConditionalRegions,
    context::enclosing_symbol,
    cpp_flow::{ControlFlow, runtime_reachable},
    cpp_vector_borrows::{
        Binding, any_availability, binding_at, capture, contains, id, joined_availability,
        location, method, name, owned_declarator, same_function,
    },
    literals::LiteralEnvironment,
    native_api::NativeApiContext,
};
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    AvailabilityState, Capability, Confidence, Evidence, EvidenceContext, EvidenceKind, Language,
    Provenance, Resolution,
};
use std::collections::BTreeMap;
type N<'a> = Node<'a, StrDoc<SupportLang>>;
const RULE: &str = "cpp-pending-collection-exception-review";

fn loop_node(node: &N<'_>) -> bool {
    matches!(
        node.kind().as_ref(),
        "for_statement" | "for_range_loop" | "while_statement" | "do_statement"
    )
}
fn raw_pointer_vector(ty: &N<'_>, api: &NativeApiContext) -> bool {
    if !api.standard_vector_type(ty) {
        return false;
    }
    ty.dfs()
        .find(|n| n.kind().as_ref() == "template_type")
        .and_then(|n| n.field("arguments"))
        .and_then(|args| args.children().find(|n| n.is_named()))
        .and_then(|arg| arg.field("declarator"))
        .is_some_and(|d| d.kind().as_ref() == "abstract_pointer_declarator")
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
    if language != Language::Cpp || !root.text().contains("throw") {
        return;
    }
    // Only functions with a typed local raw-pointer collection prepare facts.
    let mut owners = BTreeMap::new();
    for declaration in root.dfs().filter(|n| n.kind().as_ref() == "declaration") {
        if !declaration
            .field("type")
            .is_some_and(|ty| raw_pointer_vector(&ty, api))
            || !declaration
                .field_children("declarator")
                .any(|d| owned_declarator(&d))
        {
            continue;
        }
        let Some(function) = declaration
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        owners.entry(function.range().start).or_insert(function);
    }
    for function in owners.into_values() {
        let Some(body) = function.field("body") else {
            continue;
        };
        let nodes = function
            .dfs()
            .filter(|n| same_function(n, &function))
            .collect::<Vec<_>>();
        if nodes.iter().any(|n| {
            matches!(
                n.kind().as_ref(),
                "goto_statement" | "labeled_statement" | "function_try_block"
            )
        }) {
            continue;
        }
        let exits = nodes
            .iter()
            .filter(|n| {
                matches!(n.kind().as_ref(), "throw_statement" | "throw_expression")
                    && n.children().any(|c| c.is_named())
            })
            .collect::<Vec<_>>();
        if exits.is_empty() {
            continue;
        }
        let mut bindings = BTreeMap::<String, Vec<Binding<'a>>>::new();
        for declaration in nodes.iter().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "declaration" | "parameter_declaration" | "for_range_loop"
            )
        }) {
            let scope = if declaration.kind().as_ref() == "parameter_declaration" {
                body.clone()
            } else if declaration.kind().as_ref() == "for_range_loop" {
                declaration.clone()
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
            let vector = declaration.kind().as_ref() == "declaration"
                && declaration
                    .field("type")
                    .is_some_and(|ty| raw_pointer_vector(&ty, api));
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
        let flow = ControlFlow::new(&function, literals);
        let mut questions = BTreeMap::<(usize, usize), (N<'a>, Vec<(N<'a>, N<'a>)>)>::new();
        for publication in nodes
            .iter()
            .filter(|n| n.kind().as_ref() == "call_expression")
        {
            let Some((receiver, operation)) = method(publication) else {
                continue;
            };
            if receiver.kind().as_ref() != "identifier"
                || !matches!(operation.as_str(), "push_back" | "emplace_back")
                || api.macro_precedes(&operation, publication.range().start)
            {
                continue;
            }
            let Some(binding) = binding_at(&bindings, receiver.text().as_ref(), publication)
                .filter(|b| b.vector && owned_declarator(&b.declarator))
            else {
                continue;
            };
            let Some(arguments) = publication.field("arguments") else {
                continue;
            };
            let arguments = arguments
                .children()
                .filter(|n| n.is_named())
                .collect::<Vec<_>>();
            if arguments.len() != 1 || arguments[0].kind().as_ref() != "new_expression" {
                continue;
            }
            let allocation = &arguments[0];
            let text = allocation.text().split_whitespace().collect::<String>();
            // Placement allocation and macro-rewritten allocation need a different contract.
            if text.starts_with("new(")
                || api.macro_precedes("new", allocation.range().start)
                || conditional.availability_for(publication.range()).state
                    == AvailabilityState::Excluded
                || !runtime_reachable(publication, &flow, literals)
            {
                continue;
            }
            for exit in &exits {
                // This selected relationship is a prior-iteration allocation
                // followed by an earlier explicit throw on a later iteration.
                if exit.range().start >= publication.range().start
                    || api.macro_precedes("throw", exit.range().start)
                    || conditional.availability_for(exit.range()).state
                        == AvailabilityState::Excluded
                    || !runtime_reachable(exit, &flow, literals)
                {
                    continue;
                }
                let Some(iteration) = publication
                    .ancestors()
                    .take_while(|n| n.range() != function.range())
                    .find(|n| {
                        loop_node(n) && contains(n, exit) && !contains(n, &binding.declaration)
                    })
                else {
                    continue;
                };
                if iteration
                    .field("condition")
                    .and_then(|n| literals.known_bool(&n))
                    == Some(false)
                {
                    continue;
                }
                questions
                    .entry((binding.declarator.range().start, exit.range().start))
                    .or_insert_with(|| (iteration, Vec::new()))
                    .1
                    .push((allocation.clone(), publication.clone()));
            }
        }
        let by_key = bindings
            .values()
            .flatten()
            .map(|b| (b.declarator.range().start, b))
            .collect::<BTreeMap<_, _>>();
        let exits_by_key = exits
            .iter()
            .map(|n| (n.range().start, *n))
            .collect::<BTreeMap<_, _>>();
        for ((key, exit_start), (iteration, publications)) in questions {
            let binding = by_key[&key];
            let exit = exits_by_key[&exit_start];
            let mut captures = BTreeMap::from([
                (
                    "collection_binding".into(),
                    capture(path, &binding.declaration),
                ),
                ("exceptional_exit".into(), capture(path, exit)),
            ]);
            for (index, (allocation, publication)) in publications.iter().enumerate() {
                captures.insert(format!("allocation_{index}"), capture(path, allocation));
                captures.insert(
                    format!("collection_insert_{index}"),
                    capture(path, publication),
                );
            }
            if iteration.range().len() <= 32768 {
                captures.insert("iteration".into(), capture(path, &iteration));
            }
            if function.range().len() <= 32768 {
                captures.insert("operation_definition".into(), capture(path, &function));
            }
            // The function carries cleanup, capacity/empty guards and successful
            // handoff. No destructor, handler or pointee ownership is guessed.
            let availability = joined_availability(vec![
                conditional.availability_for(binding.declaration.range()),
                conditional.availability_for(exit.range()),
                any_availability(
                    publications
                        .iter()
                        .map(|(_, p)| conditional.availability_for(p.range()))
                        .collect(),
                ),
            ]);
            evidence.push(Evidence {
                id: id(path, exit, &format!("{RULE}:{key}")),
                kind: EvidenceKind::SensitiveOperation,
                capability: Capability::ExceptionalOwnershipCleanup,
                location: location(path, exit),
                enclosing_symbol: enclosing_symbol(exit),
                captures,
                cwe_candidates: vec!["CWE-401".into()],
                tags: vec![
                    "pending-raw-pointer-collection".into(),
                    "explicit-exception-cleanup-review".into(),
                    "ownership-transfer-and-handlers-require-review".into(),
                ],
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "bounded C++ pending collection ownership relationship".into(),
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
