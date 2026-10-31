//! Narrow compatibility for erased TS exports unsupported by the bundled grammar.
//! No source rewriting: every runtime node and byte offset remains unchanged.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::Language;

pub(super) fn type_only_star_export(statement: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if statement.kind().as_ref() != "export_statement"
        || !statement
            .parent()
            .is_some_and(|p| p.kind().as_ref() == "program")
    {
        return false;
    }
    let mut children = statement
        .children()
        .filter(|n| n.kind().as_ref() != "comment");
    if !children
        .next()
        .is_some_and(|n| n.kind().as_ref() == "export")
    {
        return false;
    }
    if !children
        .next()
        .is_some_and(|n| matches!(n.kind().as_ref(), "type" | "ERROR") && n.text() == "type")
    {
        return false;
    }
    let Some(star) = children.next() else {
        return false;
    };
    if star.kind().as_ref() == "namespace_export" {
        let mut names = star.children().filter(|n| n.kind().as_ref() != "comment");
        if !names.next().is_some_and(|n| n.kind().as_ref() == "*")
            || !names.next().is_some_and(|n| n.kind().as_ref() == "as")
            || !names
                .next()
                .is_some_and(|n| n.kind().as_ref() == "identifier")
            || names.next().is_some()
        {
            return false;
        }
    } else if star.kind().as_ref() != "*" {
        return false;
    }
    if !children.next().is_some_and(|n| n.kind().as_ref() == "from") {
        return false;
    }
    if !children.next().is_some_and(|n| {
        n.kind().as_ref() == "string" && !n.dfs().any(|v| v.is_error() || v.is_missing())
    }) {
        return false;
    }
    match children.next() {
        None => true,
        Some(node) => node.kind().as_ref() == ";" && children.next().is_none(),
    }
}

pub(super) fn unsupported_error(node: &Node<'_, StrDoc<SupportLang>>, language: Language) -> bool {
    if !node.is_error() && !node.is_missing() {
        return false;
    }
    !(matches!(language, Language::Typescript | Language::Tsx)
        && node.is_error()
        && node.text() == "type"
        && node
            .parent()
            .is_some_and(|statement| type_only_star_export(&statement)))
}

pub(crate) fn has_unsupported_errors(
    root: &Node<'_, StrDoc<SupportLang>>,
    language: Language,
) -> bool {
    root.dfs().any(|node| unsupported_error(&node, language))
}
