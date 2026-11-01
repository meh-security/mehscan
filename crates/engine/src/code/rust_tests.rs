//! Provably test-only Rust items; unknown production cfg branches remain visible.
use std::ops::Range;

use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;

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

fn expression(tokens: &[String], cursor: &mut usize, depth: usize) -> Option<Truth> {
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
        return Some(if name == "test" {
            Truth::No
        } else {
            Truth::Unknown
        });
    }
    *cursor += 1;
    let mut values = Vec::new();
    while !tokens.get(*cursor).is_some_and(|s| s == ")") {
        values.push(expression(tokens, cursor, depth + 1)?);
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

fn test_attribute(node: &AstNode<'_>) -> bool {
    if node.range().len() > 4096 {
        return false;
    }
    let mut parts = Vec::new();
    tokens(node, &mut parts);
    if parts == ["#", "[", "test", "]"] {
        return true;
    }
    if parts.get(..4).is_none_or(|p| p != ["#", "[", "cfg", "("]) {
        return false;
    }
    let mut cursor = 4;
    matches!(expression(&parts, &mut cursor, 0), Some(Truth::No))
        && parts.get(cursor..).is_some_and(|p| p == [")", "]"])
}

pub(crate) fn ranges(source: &str) -> Vec<Range<usize>> {
    if !source.contains("test") {
        return Vec::new();
    }
    let Ok(doc) = StrDoc::try_new(source, SupportLang::Rust) else {
        return Vec::new();
    };
    let ast = AstGrep::doc(doc);
    let root = ast.root();
    let mut found: Vec<Range<usize>> = Vec::new();
    for attribute in root.dfs().filter(|n| n.kind().as_ref() == "attribute_item") {
        if found
            .iter()
            .any(|r| r.start <= attribute.range().start && attribute.range().end <= r.end)
        {
            continue;
        }
        if !test_attribute(&attribute) {
            continue;
        }
        let Some(parent) = attribute.parent() else {
            continue;
        };
        let siblings: Vec<_> = parent.children().collect();
        let mut start = attribute.range().start;
        for previous in siblings
            .iter()
            .rev()
            .filter(|n| n.range().end <= attribute.range().start)
        {
            if previous.kind().as_ref() == "attribute_item" {
                start = previous.range().start;
            } else if !previous.kind().contains("comment") {
                break;
            }
        }
        let item = parent
            .children()
            .filter(|n| n.range().start >= attribute.range().end)
            .find(|n| {
                n.is_named()
                    && n.kind().as_ref() != "attribute_item"
                    && !n.kind().contains("comment")
            });
        if let Some(item) = item.filter(|n| !n.dfs().any(|child| child.kind().as_ref() == "ERROR"))
        {
            found.push(start..item.range().end);
        }
    }
    found.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for range in found {
        if let Some(last) = merged.last_mut().filter(|last| last.end >= range.start) {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    merged
}

pub(crate) fn production_source(source: &str) -> Option<String> {
    let excluded = ranges(source);
    if excluded.is_empty() {
        return None;
    }
    let mut bytes = source.as_bytes().to_vec();
    for range in excluded {
        for b in &mut bytes[range] {
            if !matches!(b, b'\n' | b'\r') {
                *b = b' ';
            }
        }
    }
    // Complete AST item ranges contain complete UTF-8 code points. Replacing
    // every non-newline byte preserves all original byte offsets and lines.
    String::from_utf8(bytes).ok()
}

pub(crate) fn restore_location(location: &mut mehscan_core::Location, source: &str) {
    for position in [&mut location.start, &mut location.end] {
        if let Some(before) = source.get(..position.byte_offset) {
            position.line = before.bytes().filter(|b| *b == b'\n').count() + 1;
            position.column = before
                .rsplit('\n')
                .next()
                .unwrap_or_default()
                .chars()
                .count()
                + 1;
        }
    }
}

pub(crate) fn restore_evidence(
    evidence: &mut mehscan_core::Evidence,
    originals: &std::collections::BTreeMap<String, (String, String)>,
) {
    // Secret captures are deliberately redacted and must never be replaced
    // with source bytes. Other normalized/derived captures remain unchanged.
    if evidence.kind == mehscan_core::EvidenceKind::Secret {
        return;
    }
    if let Some((original, _)) = originals.get(&evidence.location.path) {
        restore_location(&mut evidence.location, original);
    }
    for capture in evidence.captures.values_mut() {
        if let Some((original, analysis)) = originals.get(&capture.location.path) {
            let range = capture.location.start.byte_offset..capture.location.end.byte_offset;
            if analysis.get(range.clone()) == Some(capture.text.as_str()) {
                if let Some(text) = original.get(range) {
                    capture.text = text.to_string();
                }
            }
            restore_location(&mut capture.location, original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_ownership_keeps_production_after_test_items_and_utf8_coordinates() {
        let source = "#[allow(dead_code)]\n#[cfg(test)]\n// note\n#[allow(unused)]\nmod suite { fn helper(){ let s=\"🦀\"; } }\nfn production(){ std::fs::read(\"x\"); }";
        let masked = production_source(source).unwrap();
        assert!(!masked.contains("fn helper"));
        assert!(!masked.contains("#[allow"));
        assert!(masked.contains("fn production"));
        assert_eq!(masked.len(), source.len());
        assert_eq!(masked.find("fn production"), source.find("fn production"));
        assert_eq!(masked.lines().count(), source.lines().count());
    }

    #[test]
    fn only_cfgs_proven_false_without_test_are_excluded() {
        for cfg in [
            "test",
            "all(test, feature = \"extra\")",
            "any(test, all(test, unix))",
            "not(not(test))",
            "test /* comment */",
        ] {
            assert_eq!(
                ranges(&format!("#[cfg({cfg})] fn sample() {{}} fn later() {{}} ")).len(),
                1,
                "{cfg}"
            );
        }
        for cfg in [
            "not(test)",
            "any(test, feature = \"server\")",
            "feature = \"test\"",
            "all(unix, feature = \"test\")",
            "not(all(test, unix))",
        ] {
            assert!(
                ranges(&format!("#[cfg({cfg})] fn sample() {{}} ")).is_empty(),
                "{cfg}"
            );
        }
        for source in [
            "// #[cfg(test)]\nfn live() {}",
            "const S: &str = r#\"#[cfg(test)] mod ignored {}\"#; fn live() {}",
            "#[cfg_attr(test, allow(dead_code))] fn live() {}",
            "mod tests { fn live() {} }",
        ] {
            assert!(ranges(source).is_empty(), "{source}");
        }
        assert_eq!(ranges("#[test] fn check() {} fn live() {}").len(), 1);
    }
}
