//! Attribute-scoped Rust configuration without executing Cargo or assuming host features.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::ops::Range;
type AstNode<'a> = Node<'a, StrDoc<SupportLang>>;

#[derive(Clone, Copy)]
enum Truth {
    Yes,
    No,
    Unknown,
}

fn tokens(node: &AstNode<'_>, out: &mut Vec<String>) {
    let kind = node.kind();
    if kind.contains("comment") {
        return;
    }
    if matches!(
        kind.as_ref(),
        "string_literal" | "raw_string_literal" | "char_literal"
    ) {
        out.push(node.text().into_owned());
        return;
    }
    let children: Vec<_> = node.children().collect();
    if children.is_empty() {
        out.push(node.text().into_owned());
    } else {
        for child in children {
            tokens(&child, out);
        }
    }
}

fn expression(
    tokens: &[String],
    cursor: &mut usize,
    depth: usize,
    test: Option<bool>,
) -> Option<Truth> {
    if depth > 32 {
        return None;
    }
    let name = tokens.get(*cursor)?.as_str();
    *cursor += 1;
    if tokens.get(*cursor).is_some_and(|s| s == "=") {
        *cursor += 1;
        tokens.get(*cursor)?;
        *cursor += 1;
        return Some(Truth::Unknown);
    }
    if !tokens.get(*cursor).is_some_and(|s| s == "(") {
        return Some(match (name, test) {
            ("test", Some(true)) => Truth::Yes,
            ("test", Some(false)) => Truth::No,
            _ => Truth::Unknown,
        });
    }
    *cursor += 1;
    let mut values = Vec::new();
    while !tokens.get(*cursor).is_some_and(|s| s == ")") {
        values.push(expression(tokens, cursor, depth + 1, test)?);
        if tokens.get(*cursor).is_some_and(|s| s == ",") {
            *cursor += 1;
        } else if !tokens.get(*cursor).is_some_and(|s| s == ")") {
            return None;
        }
    }
    *cursor += 1;
    Some(match name {
        "all" if values.iter().any(|v| matches!(v, Truth::No)) => Truth::No,
        "all" if values.iter().all(|v| matches!(v, Truth::Yes)) => Truth::Yes,
        "any" if values.iter().any(|v| matches!(v, Truth::Yes)) => Truth::Yes,
        "any" if values.iter().all(|v| matches!(v, Truth::No)) => Truth::No,
        "not" if values.len() == 1 => match values[0] {
            Truth::Yes => Truth::No,
            Truth::No => Truth::Yes,
            Truth::Unknown => Truth::Unknown,
        },
        _ => Truth::Unknown,
    })
}

fn attribute(node: &AstNode<'_>, test: Option<bool>) -> Option<(String, Option<bool>)> {
    let mut parts = Vec::new();
    tokens(node, &mut parts);
    // Inner attributes apply to the complete enclosing module/file.
    if parts.get(1).is_some_and(|s| s == "!") {
        parts.remove(1);
    }
    if parts
        .get(..4)
        .is_some_and(|p| p == ["#", "[", "cfg_attr", "("])
        && parts.windows(2).any(|p| p == ["cfg", "("])
    {
        return Some((node.text().into_owned(), None));
    }
    if parts.get(..4).is_none_or(|p| p != ["#", "[", "cfg", "("]) {
        return None;
    }
    let mut cursor = 4;
    let value = expression(&parts, &mut cursor, 0, test);
    let truth = if parts.get(cursor..).is_some_and(|p| p == [")", "]"]) {
        match value {
            Some(Truth::Yes) => Some(true),
            Some(Truth::No) => Some(false),
            _ => None,
        }
    } else {
        None
    };
    Some((node.text().into_owned(), truth))
}

pub(super) fn test_only(node: &AstNode<'_>) -> bool {
    if node.range().len() > 4096 {
        return false;
    }
    let mut parts = Vec::new();
    tokens(node, &mut parts);
    parts == ["#", "[", "test", "]"]
        || attribute(node, Some(false)).is_some_and(|(_, value)| value == Some(false))
}

pub(super) fn conditions(root: &AstNode<'_>) -> Vec<(Range<usize>, String, Option<bool>)> {
    let mut result = Vec::new();
    for node in root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "attribute_item" | "inner_attribute_item"))
    {
        let Some((condition, truth)) = attribute(&node, None) else {
            continue;
        };
        let Some(parent) = node.parent() else {
            continue;
        };
        let range = if node.kind().as_ref() == "inner_attribute_item" {
            parent.range()
        } else {
            let Some(item) = parent
                .children()
                .filter(|n| n.range().start >= node.range().end)
                .find(|n| {
                    n.is_named()
                        && n.kind().as_ref() != "attribute_item"
                        && !n.kind().contains("comment")
                })
            else {
                continue;
            };
            item.range()
        };
        result.push((range, condition, truth));
    }
    result.sort_by_key(|(range, _, _)| (std::cmp::Reverse(range.len()), range.start));
    result
}
