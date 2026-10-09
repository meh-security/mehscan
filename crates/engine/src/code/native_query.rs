//! Close one unchanged local literal operand, without C/C++ constant folding.
use super::literals::LiteralEnvironment;
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Evidence, EvidenceKind, Language, LiteralEvaluation, LiteralState, LiteralValue,
};
use std::collections::BTreeMap;

type NativeNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(crate) fn annotate<'a>(
    language: Language,
    root: &NativeNode<'a>,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut [Evidence],
) {
    if !matches!(language, Language::C | Language::Cpp)
        || !evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::Sink && e.cwe_candidates == ["CWE-89"])
    {
        return;
    }
    let mut declarations = BTreeMap::<String, Vec<NativeNode<'a>>>::new();
    let mut uses = BTreeMap::<String, Vec<NativeNode<'a>>>::new();
    for node in root.dfs() {
        if node.kind().as_ref() == "identifier" {
            uses.entry(node.text().into_owned())
                .or_default()
                .push(node.clone());
        }
        if node.kind().as_ref() == "init_declarator"
            && let Some(declarator) = node.field("declarator")
            && let Some(name) = declarator.dfs().find(|n| n.kind().as_ref() == "identifier")
        {
            declarations
                .entry(name.text().into_owned())
                .or_default()
                .push(node);
        }
    }
    for item in evidence.iter_mut().filter(|e| {
        e.kind == EvidenceKind::Sink
            && e.capability == Capability::DatabaseQuery
            && e.cwe_candidates == ["CWE-89"]
    }) {
        let Some(query) = item.captures.get("query") else {
            continue;
        };
        let Some(occurrences) = uses.get(query.text.trim()) else {
            continue;
        };
        let Some(target) = occurrences.iter().find(|n| {
            n.range().start == query.location.start.byte_offset
                && n.range().end == query.location.end.byte_offset
        }) else {
            continue;
        };
        let Some(function) = target
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        // Nested callables and file/global state are outside this local contract.
        if target.ancestors().any(|n| {
            matches!(
                n.kind().as_ref(),
                "lambda_expression" | "preproc_if" | "preproc_ifdef"
            )
        }) {
            continue;
        }
        let bindings = declarations
            .get(query.text.trim())
            .into_iter()
            .flatten()
            .filter(|n| {
                n.range().start > function.range().start && n.range().end < target.range().start
            })
            .collect::<Vec<_>>();
        let [binding] = bindings.as_slice() else {
            continue;
        };
        let Some(declaration) = binding
            .parent()
            .filter(|n| n.kind().as_ref() == "declaration")
        else {
            continue;
        };
        let Some(scope) = declaration
            .parent()
            .filter(|n| n.kind().as_ref() == "compound_statement")
        else {
            continue;
        };
        if scope.range().end < target.range().end
            || declaration
                .text()
                .split_whitespace()
                .any(|word| matches!(word, "static" | "extern" | "thread_local"))
            || declaration
                .ancestors()
                .any(|n| n.kind().starts_with("preproc"))
            || declaration
                .field("type")
                .is_none_or(|t| !matches!(t.text().as_ref(), "char" | "auto"))
        {
            continue;
        }
        let Some(value) = binding.field("value") else {
            continue;
        };
        let Some(declarator) = binding.field("declarator") else {
            continue;
        };
        let pointer = declarator.kind().as_ref() == "pointer_declarator"
            && declarator
                .field("declarator")
                .is_some_and(|n| n.kind().as_ref() == "identifier");
        let inferred_pointer = declarator.kind().as_ref() == "identifier"
            && declaration
                .field("type")
                .is_some_and(|n| n.text() == "auto");
        if !pointer && !inferred_pointer {
            continue;
        }
        // Any earlier use outside the declaration vetoes closure: writes,
        // pointer aliases, address escape, array mutation and unknown helpers.
        if occurrences.iter().any(|n| {
            n.range().start >= binding.range().end
                && n.range().start < target.range().start
                && n.range().start > function.range().start
        }) {
            continue;
        }
        let Some(text) = literal_text(&value, literals) else {
            continue;
        };
        item.context.literals.insert(
            "query".into(),
            LiteralEvaluation {
                state: LiteralState::Known,
                value: Some(LiteralValue::String(text)),
                constant_fragments: vec![],
                references: vec![query.text.clone()],
            },
        );
        let origin = super::node_operands::capture_at("", item, &value);
        item.captures.insert("query_origin".into(), origin);
        item.tags.push("query-closure:native-local-literal".into());
    }
}

fn literal_text<'a>(
    node: &NativeNode<'a>,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
) -> Option<String> {
    if node.kind().as_ref() == "concatenated_string" {
        let parts = node
            .children()
            .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
            .map(|n| literal_text(&n, literals))
            .collect::<Option<Vec<_>>>()?;
        return (!parts.is_empty()).then(|| parts.concat());
    }
    if node.kind().as_ref() != "string_literal" || !node.text().starts_with('"') {
        return None;
    }
    match literals.evaluate(node).value {
        Some(LiteralValue::String(value)) => Some(value),
        _ => None,
    }
}
