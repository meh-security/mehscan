//! One local operand initializer or the exact edge where navigation stops.
//! These locations do not establish source control, execution or protection.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Evidence, EvidenceKind, Language, OperandFact, OperandFactKind};
use std::collections::BTreeMap;

type GoNode<'a> = Node<'a, StrDoc<SupportLang>>;

fn owner<'a>(node: &GoNode<'a>) -> Option<GoNode<'a>> {
    node.ancestors().find(|n| {
        matches!(
            n.kind().as_ref(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
    })
}

fn single_named<'a>(list: GoNode<'a>) -> Option<GoNode<'a>> {
    let mut nodes = list.children().filter(|n| n.is_named());
    let first = nodes.next()?;
    nodes.next().is_none().then_some(first)
}

fn record(
    item: &mut Evidence,
    role: &str,
    node: &GoNode<'_>,
    kind: OperandFactKind,
    value: String,
) {
    item.context.operand_facts.push(OperandFact {
        role: role.into(),
        kind,
        location: super::matcher::location(&item.location.path, node),
        value,
        remaining_checks: vec![
            "initializer_and_callable_contract".into(),
            "producer_or_caller_control".into(),
            "exact_interpretation_and_effect".into(),
        ],
    });
}

pub(crate) fn annotate(language: Language, root: &GoNode<'_>, evidence: &mut [Evidence]) {
    if language != Language::Go
        || !evidence.iter().any(|e| {
            e.kind == EvidenceKind::Sink
                && matches!(
                    e.capability,
                    Capability::HtmlOutput
                        | Capability::DatabaseQuery
                        | Capability::ProcessExecution
                )
        })
    {
        return;
    }
    // Index syntax once for this file. Do not walk the file once per capture.
    let mut declarations = BTreeMap::<String, Vec<GoNode<'_>>>::new();
    let mut references = BTreeMap::<String, Vec<GoNode<'_>>>::new();
    for node in root.dfs() {
        if node.kind().as_ref() == "identifier" {
            references
                .entry(node.text().into_owned())
                .or_default()
                .push(node.clone());
        }
        if node.kind().as_ref() == "short_var_declaration"
            && let Some(left) = node.field("left")
        {
            for name in left
                .children()
                .filter(|n| n.kind().as_ref() == "identifier")
            {
                declarations
                    .entry(name.text().into_owned())
                    .or_default()
                    .push(node.clone());
            }
        }
    }
    for item in evidence.iter_mut().filter(|e| e.kind == EvidenceKind::Sink) {
        let role = match item.capability {
            Capability::HtmlOutput => "content",
            Capability::DatabaseQuery => "query",
            Capability::ProcessExecution => "command",
            _ => continue,
        };
        let Some(capture) = item.captures.get(role) else {
            continue;
        };
        let Some(uses) = references.get(capture.text.trim()) else {
            continue;
        };
        let Some(use_node) = uses.iter().find(|n| {
            n.range().start == capture.location.start.byte_offset
                && n.range().end == capture.location.end.byte_offset
        }) else {
            continue;
        };
        let Some(scope) = owner(use_node) else {
            continue;
        };
        if scope.range().len() > 32 * 1024 {
            record(
                item,
                role,
                use_node,
                OperandFactKind::OperandBoundary,
                "callable exceeds local navigation bound".into(),
            );
            continue;
        }
        let candidates: Vec<_> = declarations
            .get(capture.text.trim())
            .into_iter()
            .flatten()
            .filter(|decl| {
                decl.range().end <= use_node.range().start
                    && owner(decl).is_some_and(|o| o.range() == scope.range())
                    && decl
                        .ancestors()
                        .find(|n| n.kind().as_ref() == "block")
                        .is_some_and(|block| {
                            block.range().start <= use_node.range().start
                                && use_node.range().end <= block.range().end
                        })
            })
            .collect();
        let Some(decl) = candidates.first() else {
            continue;
        };
        if candidates.len() != 1 {
            record(
                item,
                role,
                candidates[candidates.len() - 1],
                OperandFactKind::OperandBoundary,
                "multiple visible local declarations".into(),
            );
            continue;
        }
        // If/switch/loop initializer scopes are not ordinary block declarations.
        if !decl
            .parent()
            .is_some_and(|p| p.kind().as_ref() == "statement_list")
        {
            record(
                item,
                role,
                decl,
                OperandFactKind::OperandBoundary,
                "declaration has conditional or loop ownership".into(),
            );
            continue;
        }
        let initializer = decl
            .field("left")
            .and_then(single_named)
            .filter(|n| n.kind().as_ref() == "identifier")
            .and_then(|_| decl.field("right").and_then(single_named));
        let Some(initializer) = initializer else {
            record(
                item,
                role,
                decl,
                OperandFactKind::OperandBoundary,
                "multiple assignment or unknown initializer".into(),
            );
            continue;
        };
        if let Some(edge) = uses.iter().find(|n| {
            decl.range().end <= n.range().start && n.range().start < use_node.range().start
        }) {
            record(
                item,
                role,
                edge,
                OperandFactKind::OperandBoundary,
                "intervening reference, write, capture or handoff".into(),
            );
            continue;
        }
        if initializer.range().len() > 2048 || initializer.dfs().any(|n| n.is_error()) {
            record(
                item,
                role,
                &initializer,
                OperandFactKind::OperandBoundary,
                "oversized or invalid initializer".into(),
            );
            continue;
        }
        record(
            item,
            role,
            &initializer,
            OperandFactKind::LocalOperandOrigin,
            initializer.text().into_owned(),
        );
    }
}
