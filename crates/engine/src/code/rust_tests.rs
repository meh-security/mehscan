//! Provably test-only Rust items; unknown production cfg branches remain visible.
use std::ops::Range;

use ast_grep_core::{AstGrep, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;

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
    for attribute in root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "attribute_item" | "inner_attribute_item"))
    {
        if found
            .iter()
            .any(|r| r.start <= attribute.range().start && attribute.range().end <= r.end)
        {
            continue;
        }
        if !super::rust_cfg::test_only(&attribute) {
            continue;
        }
        let Some(parent) = attribute.parent() else {
            continue;
        };
        if attribute.kind().as_ref() == "inner_attribute_item" {
            if parent.kind().as_ref() == "source_file" {
                found.push(parent.range());
            } else if let Some(module) = parent
                .parent()
                .filter(|node| node.kind().as_ref() == "mod_item")
            {
                found.push(module.range());
            }
            continue;
        }
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

    #[test]
    fn inner_test_cfg_excludes_its_module_without_breaking_following_source() {
        let source = "mod fixture { #![cfg(test)] fn hidden() {} } fn production() {}";
        let masked = production_source(source).expect("test module");
        assert!(!masked.contains("hidden"));
        assert!(!masked.contains("mod fixture"));
        assert!(masked.contains("fn production()"));
        let crate_source = "#![cfg(test)] fn hidden() {}";
        assert_eq!(ranges(crate_source), [0..crate_source.len()]);
    }
}
