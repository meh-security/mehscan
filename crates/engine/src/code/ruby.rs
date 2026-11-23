//! Bounded source evidence for explicit Ruby Open3 capture calls.
use std::collections::BTreeMap;

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceKind, OperandFact, OperandFactKind,
    Provenance, Resolution,
};

use super::context::{enclosing_symbol, unknown_textual_context};
use super::matcher::{evidence_id, location};

type RubyNode<'a> = Node<'a, StrDoc<SupportLang>>;

const RULE_ID: &str = "ruby-open3-command-string";

pub(super) fn add_open3_observations(
    path: &str,
    root: &RubyNode<'_>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(load) = root.children().find(loads_open3) else {
        return;
    };
    if root.dfs().any(|node| replaces_library_binding(&node)) {
        return;
    }
    for call in root.dfs().filter(|node| node.kind() == "call") {
        if call.range().start < load.range().end {
            continue;
        }
        let Some(receiver) = call.field("receiver").filter(is_open3_receiver) else {
            continue;
        };
        if receiver.kind() == "constant"
            && call.ancestors().any(|scope| {
                scope.kind() == "singleton_class"
                    || (scope.kind() == "class" && scope.field("superclass").is_some())
            })
        {
            // An inherited constant can take precedence over the top-level module.
            continue;
        }
        if !call
            .field("method")
            .is_some_and(|method| is_capture_method(method.text().as_ref()))
        {
            continue;
        }
        let Some(command) = sole_argument(&call).filter(|arg| {
            arg.kind() == "string" && arg.children().any(|part| part.kind() == "interpolation")
        }) else {
            continue;
        };
        let anchor = location(path, &call);
        let command = capture(path, &command);
        let mut context = unknown_textual_context();
        context.operand_facts.push(OperandFact {
            role: "command".into(),
            kind: OperandFactKind::ProcessShellMode,
            location: command.location.clone(),
            value: "unresolved".into(),
            remaining_checks: vec![
                "caller_authority".into(),
                "shell_selection_and_child_argument_semantics".into(),
            ],
        });
        evidence.push(Evidence {
            id: evidence_id(
                path,
                RULE_ID,
                anchor.start.byte_offset,
                anchor.end.byte_offset,
            ),
            rule_id: RULE_ID.into(),
            kind: EvidenceKind::Sink,
            capability: Capability::ProcessExecution,
            location: anchor,
            enclosing_symbol: enclosing_symbol(&call),
            captures: BTreeMap::from([
                ("command".into(), command),
                ("library_load".into(), capture(path, &load)),
                ("receiver".into(), capture(path, &receiver)),
            ]),
            cwe_candidates: vec!["CWE-78".into()],
            tags: vec![
                "process".into(),
                "review-origin:decision-critical".into(),
                "review-language:ruby".into(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "tree-sitter Ruby Open3 command string".into(),
                rule_version: 1,
            },
            context,
            symbol_resolution: None,
            related_evidence: Vec::new(),
        });
    }
}

fn loads_open3(node: &RubyNode<'_>) -> bool {
    node.kind() == "call"
        && node.field("receiver").is_none()
        && node.field("block").is_none()
        && node
            .field("method")
            .is_some_and(|method| method.text() == "require")
        && sole_argument(node).is_some_and(|argument| {
            argument.kind() == "string"
                && matches!(argument.text().as_ref(), "'open3'" | "\"open3\"")
        })
}

fn sole_argument<'tree>(call: &RubyNode<'tree>) -> Option<RubyNode<'tree>> {
    let arguments = call.field("arguments")?;
    let mut children = arguments
        .children()
        .filter(|child| child.is_named() && child.kind() != "comment");
    let argument = children.next()?;
    children.next().is_none().then_some(argument)
}

fn is_open3_receiver(node: &RubyNode<'_>) -> bool {
    (node.kind() == "constant" && node.text() == "Open3")
        || (node.kind() == "scope_resolution"
            && node.field("scope").is_none()
            && node
                .field("name")
                .is_some_and(|name| name.text() == "Open3"))
}

fn replaces_library_binding(node: &RubyNode<'_>) -> bool {
    let kind = node.kind();
    if matches!(kind.as_ref(), "method" | "singleton_method" | "alias")
        && node
            .field("name")
            .is_some_and(|name| name.text() == "require")
    {
        return true;
    }
    match kind.as_ref() {
        "module" | "class" => node.field("name"),
        "assignment" | "operator_assignment" => node.field("left"),
        "singleton_method" => node.field("object").filter(is_open3_receiver),
        "singleton_class" => node.field("value").filter(is_open3_receiver),
        _ => None,
    }
    .is_some_and(|target| {
        target
            .dfs()
            .any(|part| part.kind() == "constant" && part.text() == "Open3")
    })
}

fn is_capture_method(method: &str) -> bool {
    matches!(method, "capture2" | "capture2e" | "capture3")
}

fn capture(path: &str, node: &RubyNode<'_>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}
