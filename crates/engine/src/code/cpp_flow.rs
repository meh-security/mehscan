//! Prepared C++ branch and termination facts for bounded lifetime reviews.
use super::{literals::LiteralEnvironment, reachability};
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::ReachabilityState;
use std::collections::{BTreeMap, BTreeSet};
type N<'a> = Node<'a, StrDoc<SupportLang>>;
fn named<'a>(node: &N<'a>) -> Vec<N<'a>> {
    node.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
        .collect()
}
fn contains(outer: &N<'_>, inner: &N<'_>) -> bool {
    outer.range().start <= inner.range().start && inner.range().end <= outer.range().end
}
/// Prepare block termination once, rather than scanning every preceding sibling
/// again for each destruction call and selected use.
pub(super) struct ControlFlow {
    returns: BTreeSet<usize>,
    terminated_blocks: BTreeMap<usize, usize>,
}
impl ControlFlow {
    pub(super) fn new<'a>(
        function: &N<'a>,
        literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    ) -> Self {
        let nodes = function.dfs().collect::<Vec<_>>();
        let mut result = Self {
            returns: BTreeSet::new(),
            terminated_blocks: BTreeMap::new(),
        };
        for node in nodes.iter().rev() {
            let children = named(node);
            let returns = match node.kind().as_ref() {
                "return_statement" => true,
                "compound_statement" | "else_clause" => children
                    .last()
                    .is_some_and(|n| result.returns.contains(&n.range().start)),
                "if_statement" => {
                    let a = node.field("consequence");
                    let b = node.field("alternative");
                    let value = node.field("condition").and_then(|n| {
                        let children = named(&n);
                        if n.kind().as_ref() == "condition_clause" && children.len() == 1 {
                            literals.known_bool(&children[0])
                        } else {
                            literals.known_bool(&n)
                        }
                    });
                    let left = a.is_some_and(|n| result.returns.contains(&n.range().start));
                    let right = b.is_some_and(|n| result.returns.contains(&n.range().start));
                    match value {
                        Some(true) => left,
                        Some(false) => right,
                        None => left && right,
                    }
                }
                _ => false,
            };
            if returns {
                result.returns.insert(node.range().start);
            }
            if node.kind().as_ref() == "compound_statement" {
                if let Some(first) = children
                    .iter()
                    .find(|n| result.returns.contains(&n.range().start))
                {
                    result
                        .terminated_blocks
                        .insert(node.range().start, first.range().end);
                }
            }
        }
        result
    }
}

pub(super) fn incompatible_regions<'a>(
    call: &N<'a>,
    flow: &ControlFlow,
) -> Vec<std::ops::Range<usize>> {
    let mut result = Vec::new();
    for branch in call
        .ancestors()
        .take_while(|n| n.kind().as_ref() != "function_definition")
    {
        if branch.kind().as_ref() == "if_statement" {
            let a = branch.field("consequence");
            let b = branch.field("alternative");
            if a.as_ref().is_some_and(|n| contains(n, call)) {
                if let Some(other) = b {
                    result.push(other.range());
                }
            } else if b.as_ref().is_some_and(|n| contains(n, call)) {
                if let Some(other) = a {
                    result.push(other.range());
                }
            }
        }
        if branch.kind().as_ref() == "compound_statement"
            && flow.returns.contains(&branch.range().start)
        {
            result.push(branch.range().end..usize::MAX);
        }
    }
    result
}

pub(super) fn runtime_reachable<'a>(
    node: &N<'a>,
    flow: &ControlFlow,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
) -> bool {
    if reachability::classify(node, literals).state == ReachabilityState::Unreachable {
        return false;
    }
    let mut current = node.clone();
    while let Some(parent) = current.parent() {
        if parent.kind().as_ref() == "function_definition" {
            break;
        }
        if parent.kind().as_ref() == "compound_statement"
            && flow
                .terminated_blocks
                .get(&parent.range().start)
                .is_some_and(|end| *end <= current.range().start)
        {
            return false;
        }
        current = parent;
    }
    for branch in node
        .ancestors()
        .take_while(|n| n.kind().as_ref() != "function_definition")
    {
        if branch.kind().as_ref() != "if_statement" {
            continue;
        }
        let Some(condition) = branch.field("condition") else {
            continue;
        };
        let children = named(&condition);
        let condition = if condition.kind().as_ref() == "condition_clause" && children.len() == 1 {
            &children[0]
        } else {
            &condition
        };
        let Some(value) = literals.known_bool(condition) else {
            continue;
        };
        if (!value
            && branch
                .field("consequence")
                .is_some_and(|b| contains(&b, node)))
            || (value
                && branch
                    .field("alternative")
                    .is_some_and(|b| contains(&b, node)))
        {
            return false;
        }
    }
    true
}
