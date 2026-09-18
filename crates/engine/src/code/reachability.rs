use ast_grep_core::{Doc, Node};
use mehscan_core::{Reachability, ReachabilityReason, ReachabilityState};

use super::comments::is_comment_kind;
use super::literals::LiteralEnvironment;

pub(crate) fn classify<'tree, D: Doc>(
    node: &Node<'tree, D>,
    literals: &LiteralEnvironment<'tree, D>,
) -> Reachability {
    let mut current = node.clone();
    let mut uncertain = false;
    while let Some(parent) = current.parent() {
        if is_function_boundary(current.kind().as_ref()) {
            break;
        }
        if let Some(reason) = excluded_literal_branch(&current, &parent, literals) {
            return unreachable(reason);
        }
        if is_sequential_container(parent.kind().as_ref()) {
            for sibling in parent.children().filter(|child| {
                child.is_named()
                    && !is_comment_kind(child.kind().as_ref())
                    && child.range().end <= current.range().start
            }) {
                if sibling.kind().as_ref() == "goto_statement" {
                    uncertain = true;
                    continue;
                }
                if let Some(reason) = termination_reason(&sibling, literals) {
                    return unreachable(reason);
                }
            }
        }
        current = parent;
    }
    Reachability {
        state: if uncertain {
            ReachabilityState::Unknown
        } else {
            ReachabilityState::Reachable
        },
        reason: None,
    }
}

pub(crate) fn always_terminates<'tree, D: Doc>(
    node: &Node<'tree, D>,
    literals: &LiteralEnvironment<'tree, D>,
) -> bool {
    termination_reason(node, literals).is_some()
}

fn unreachable(reason: ReachabilityReason) -> Reachability {
    Reachability {
        state: ReachabilityState::Unreachable,
        reason: Some(reason),
    }
}

fn termination_reason<'tree, D: Doc>(
    node: &Node<'tree, D>,
    literals: &LiteralEnvironment<'tree, D>,
) -> Option<ReachabilityReason> {
    match node.kind().as_ref() {
        "return_statement" => Some(ReachabilityReason::AfterReturn),
        "jump_expression"
            if node
                .children()
                .any(|child| !child.is_named() && child.text().as_ref() == "return") =>
        {
            Some(ReachabilityReason::AfterReturn)
        }
        "jump_expression"
            if node
                .children()
                .any(|child| !child.is_named() && child.text().as_ref() == "throw") =>
        {
            Some(ReachabilityReason::AfterThrow)
        }
        "throw_statement" => Some(ReachabilityReason::AfterThrow),
        "raise_statement" => Some(ReachabilityReason::AfterRaise),
        "break_statement" => Some(ReachabilityReason::AfterBreak),
        "continue_statement" => Some(ReachabilityReason::AfterContinue),
        kind if is_sequential_container(kind) || is_else_container(kind) => node
            .children()
            .filter(|child| child.is_named() && !is_comment_kind(child.kind().as_ref()))
            .last()
            .and_then(|child| termination_reason(&child, literals)),
        "if_statement" | "elif_clause" => conditional_termination(node, literals),
        _ => None,
    }
}

fn conditional_termination<'tree, D: Doc>(
    node: &Node<'tree, D>,
    literals: &LiteralEnvironment<'tree, D>,
) -> Option<ReachabilityReason> {
    let consequence = node.field("consequence")?;
    let alternative = node.field("alternative");
    match node
        .field("condition")
        .and_then(|condition| literals.known_bool(&condition))
    {
        Some(true) => termination_reason(&consequence, literals),
        Some(false) => alternative
            .as_ref()
            .and_then(|node| termination_reason(node, literals)),
        None => {
            let alternative = alternative?;
            if always_terminates(&consequence, literals)
                && always_terminates(&alternative, literals)
            {
                Some(ReachabilityReason::AfterTerminatingConditional)
            } else {
                None
            }
        }
    }
}

fn excluded_literal_branch<'tree, D: Doc>(
    child: &Node<'tree, D>,
    parent: &Node<'tree, D>,
    literals: &LiteralEnvironment<'tree, D>,
) -> Option<ReachabilityReason> {
    if parent.kind().as_ref() == "if_expression" {
        let condition = parent
            .children()
            .find(|node| node.is_named() && node.kind().as_ref() != "control_structure_body")?;
        let value = literals.known_bool(&condition)?;
        let bodies = parent
            .children()
            .filter(|node| node.kind().as_ref() == "control_structure_body")
            .collect::<Vec<_>>();
        let branch = bodies
            .iter()
            .position(|body| contains(body, &child.range()))?;
        return match (value, branch) {
            (false, 0) => Some(ReachabilityReason::ConditionAlwaysFalse),
            (true, 1) => Some(ReachabilityReason::ConditionAlwaysTrue),
            _ => None,
        };
    }
    if !matches!(parent.kind().as_ref(), "if_statement" | "elif_clause") {
        return None;
    }
    let condition = parent.field("condition")?;
    let value = literals.known_bool(&condition)?;
    let child_range = child.range();
    if let Some(consequence) = parent.field("consequence")
        && contains(&consequence, &child_range)
        && !value
    {
        return Some(ReachabilityReason::ConditionAlwaysFalse);
    }
    if let Some(alternative) = parent.field("alternative")
        && contains(&alternative, &child_range)
        && value
    {
        return Some(ReachabilityReason::ConditionAlwaysTrue);
    }
    None
}

fn contains<D: Doc>(node: &Node<'_, D>, range: &std::ops::Range<usize>) -> bool {
    node.range().start <= range.start && node.range().end >= range.end
}

fn is_sequential_container(kind: &str) -> bool {
    matches!(
        kind,
        "block"
            | "statements"
            | "statement_block"
            | "program"
            | "module"
            | "switch_body"
            | "switch_block"
            | "switch_section"
            | "switch_block_statement_group"
    )
}

fn is_else_container(kind: &str) -> bool {
    matches!(kind, "else_clause")
}

fn is_function_boundary(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration"
            | "function_definition"
            | "method_declaration"
            | "method_definition"
            | "constructor_declaration"
            | "local_function_statement"
            | "arrow_function"
            | "lambda"
            | "lambda_expression"
            | "lambda_literal"
            | "anonymous_function"
    )
}

#[cfg(test)]
mod tests {
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::JavaScript;

    use super::*;

    fn call_reachability(source: &str, call_text: &str) -> Reachability {
        let ast = JavaScript.ast_grep(source);
        let call = ast
            .root()
            .dfs()
            .find(|node| node.kind().as_ref() == "call_expression" && node.text() == call_text)
            .expect("call should parse");
        let root = ast.root();
        let literals = LiteralEnvironment::build(&root, mehscan_core::Language::Javascript);
        classify(&call, &literals)
    }

    #[test]
    fn detects_sequential_and_conditional_termination() {
        let after_return = call_reachability("function f(){ return; danger(); }", "danger()");
        assert_eq!(after_return.state, ReachabilityState::Unreachable);
        assert_eq!(after_return.reason, Some(ReachabilityReason::AfterReturn));

        let after_if = call_reachability(
            "function f(x){ if(x){return;}else{throw x;} danger(); }",
            "danger()",
        );
        assert_eq!(after_if.state, ReachabilityState::Unreachable);
        assert_eq!(
            after_if.reason,
            Some(ReachabilityReason::AfterTerminatingConditional)
        );

        let one_branch = call_reachability("function f(x){ if(x){return;} danger(); }", "danger()");
        assert_eq!(one_branch.state, ReachabilityState::Reachable);
    }

    #[test]
    fn detects_literal_excluded_branches() {
        let false_branch = call_reachability("function f(){ if(false){ danger(); } }", "danger()");
        assert_eq!(false_branch.state, ReachabilityState::Unreachable);
        assert_eq!(
            false_branch.reason,
            Some(ReachabilityReason::ConditionAlwaysFalse)
        );

        let true_alternative = call_reachability(
            "function f(){ if(true){ ok(); } else { danger(); } }",
            "danger()",
        );
        assert_eq!(true_alternative.state, ReachabilityState::Unreachable);
        assert_eq!(
            true_alternative.reason,
            Some(ReachabilityReason::ConditionAlwaysTrue)
        );
    }

    #[test]
    fn does_not_leak_outer_control_flow_into_nested_functions() {
        let nested = call_reachability(
            "function outer(){ return; function inner(){ danger(); } }",
            "danger()",
        );
        assert_eq!(nested.state, ReachabilityState::Reachable);
    }

    #[test]
    fn kotlin_literal_branches_and_jumps_have_bounded_execution_context() {
        use ast_grep_language::SupportLang;
        for (source, expected) in [
            (
                "fun f() { if (false) { danger() } }",
                ReachabilityState::Unreachable,
            ),
            (
                "fun f() { if (true) {} else { danger() } }",
                ReachabilityState::Unreachable,
            ),
            (
                "fun f() { return; danger() }",
                ReachabilityState::Unreachable,
            ),
            (
                "fun f() { throw Error(); danger() }",
                ReachabilityState::Unreachable,
            ),
            (
                "fun f() { if (flag) { danger() } }",
                ReachabilityState::Reachable,
            ),
            (
                "fun f() { return; fun inner() { danger() } }",
                ReachabilityState::Reachable,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let call = root
                .dfs()
                .find(|n| n.kind().as_ref() == "call_expression" && n.text().as_ref() == "danger()")
                .unwrap();
            let literals = LiteralEnvironment::build(&root, mehscan_core::Language::Kotlin);
            assert_eq!(classify(&call, &literals).state, expected, "{source}");
        }
    }

    #[test]
    fn reuses_immutable_boolean_constants_for_literal_branches() {
        let constant_branch = call_reachability(
            "const ENABLED = false; function f(){ if(ENABLED){ danger(); } }",
            "danger()",
        );
        assert_eq!(constant_branch.state, ReachabilityState::Unreachable);
        assert_eq!(
            constant_branch.reason,
            Some(ReachabilityReason::ConditionAlwaysFalse)
        );
    }
}
