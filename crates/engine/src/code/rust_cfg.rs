//! Attribute-scoped Rust configuration without executing Cargo or assuming host features.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use std::{collections::BTreeMap, ops::Range};
type AstNode<'a> = Node<'a, StrDoc<SupportLang>>;

#[derive(Default)]
pub(super) struct AttributeIndex<'tree> {
    parents: BTreeMap<usize, AttributeSiblings<'tree>>,
}

struct AttributeSiblings<'tree> {
    items: Vec<(usize, AstNode<'tree>)>,
    group_starts: BTreeMap<usize, usize>,
}

impl<'tree> AttributeIndex<'tree> {
    fn siblings(&mut self, attribute: &AstNode<'tree>) -> Option<&AttributeSiblings<'tree>> {
        let parent = attribute.parent()?;
        Some(self.parents.entry(parent.node_id()).or_insert_with(|| {
            let mut items = Vec::new();
            let mut group_starts = BTreeMap::new();
            let mut start = None;
            for child in parent.children() {
                let kind = child.kind();
                if child.is_named()
                    && kind.as_ref() != "attribute_item"
                    && !kind.contains("comment")
                {
                    items.push((child.range().start, child.clone()));
                }
                if kind.as_ref() == "attribute_item" {
                    let first = *start.get_or_insert(child.range().start);
                    group_starts.insert(child.node_id(), first);
                } else if !kind.contains("comment") {
                    start = None;
                }
            }
            AttributeSiblings {
                items,
                group_starts,
            }
        }))
    }

    pub(super) fn following(&mut self, attribute: &AstNode<'tree>) -> Option<AstNode<'tree>> {
        let siblings = self.siblings(attribute)?;
        let next = siblings
            .items
            .partition_point(|(start, _)| *start < attribute.range().end);
        siblings.items.get(next).map(|(_, node)| node.clone())
    }

    pub(super) fn group_start(&mut self, attribute: &AstNode<'tree>) -> usize {
        self.siblings(attribute)
            .and_then(|siblings| siblings.group_starts.get(&attribute.node_id()))
            .copied()
            .unwrap_or(attribute.range().start)
    }
}

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
            ("true", _) => Truth::Yes,
            ("false", _) => Truth::No,
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
    condition_records(root, None)
        .into_iter()
        .map(|(range, _, text, truth)| (range, text, truth))
        .collect()
}

pub(super) fn condition_records(
    root: &AstNode<'_>,
    test: Option<bool>,
) -> Vec<(Range<usize>, Range<usize>, String, Option<bool>)> {
    scoped_records(root, test, false)
}

pub(super) fn review_condition_records(
    root: &AstNode<'_>,
    test: Option<bool>,
) -> Vec<(Range<usize>, Range<usize>, String, Option<bool>)> {
    scoped_records(root, test, true)
}

fn scoped_records(
    root: &AstNode<'_>,
    test: Option<bool>,
    include_attributes: bool,
) -> Vec<(Range<usize>, Range<usize>, String, Option<bool>)> {
    let mut result = Vec::new();
    let mut attributes = AttributeIndex::default();
    for node in root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "attribute_item" | "inner_attribute_item"))
    {
        let Some((condition, truth)) = attribute(&node, test) else {
            continue;
        };
        let Some(parent) = node.parent() else {
            continue;
        };
        let range = if node.kind().as_ref() == "inner_attribute_item" {
            parent.range()
        } else {
            let Some(item) = attributes.following(&node) else {
                continue;
            };
            if include_attributes {
                attributes.group_start(&node)..item.range().end
            } else {
                item.range()
            }
        };
        result.push((range, node.range(), condition, truth));
    }
    result.sort_by_key(|(range, _, _, _)| (std::cmp::Reverse(range.len()), range.start));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;

    #[test]
    fn indexed_ownership_keeps_attribute_order_comments_and_nested_parent_boundaries() {
        let source = r##"
            #![cfg(feature="package")]
            #[cfg(feature="module")]
            mod nested {
                #![cfg(target_os="linux")]
                #[cfg(unix)]
                // comments and unrelated attributes do not own the cfg
                #[allow(dead_code)]
                #[cfg(feature="first")]
                fn first() { consume(); }
                #[cfg(any())] fn excluded() { absent(); }
                struct Record { #[cfg(feature="field")] field: u8 }
                impl Record { #[cfg(feature="method")] fn method(&self) {} }
            }
            #[cfg_attr(feature="optional",cfg(target_arch="arm"))]
            fn last() { maybe(); }
        "##;
        let ast = SupportLang::Rust.ast_grep(source);
        let root = ast.root();
        assert!(!root.dfs().any(|node| node.kind().as_ref() == "ERROR"));
        // Differential contract against the former sibling search. Keep the
        // complete selected byte ranges and stable condition order, including
        // AST shapes whose attribution is intentionally not expanded here.
        let mut expected = Vec::new();
        for node in root.dfs().filter(|node| {
            matches!(
                node.kind().as_ref(),
                "attribute_item" | "inner_attribute_item"
            )
        }) {
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
                    .filter(|child| child.range().start >= node.range().end)
                    .find(|child| {
                        child.is_named()
                            && child.kind().as_ref() != "attribute_item"
                            && !child.kind().contains("comment")
                    })
                else {
                    continue;
                };
                item.range()
            };
            expected.push((range, condition, truth));
        }
        expected.sort_by_key(|(range, _, _)| (std::cmp::Reverse(range.len()), range.start));
        assert_eq!(conditions(&root), expected);
        assert_eq!(expected.len(), 9);
    }
}
