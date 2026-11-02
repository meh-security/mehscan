//! Provably test-only Rust items; unknown production cfg branches remain visible.
use std::{ops::Range, sync::OnceLock};

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
    let mut covered_end = 0;
    let mut attributes = super::rust_cfg::AttributeIndex::default();
    for attribute in root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "attribute_item" | "inner_attribute_item"))
    {
        // DFS visits attributes in source order. Every earlier selected range
        // starts before this attribute, so only its furthest end is needed.
        if attribute.range().end <= covered_end {
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
                covered_end = covered_end.max(parent.range().end);
                found.push(parent.range());
            } else if let Some(module) = parent
                .parent()
                .filter(|node| node.kind().as_ref() == "mod_item")
            {
                covered_end = covered_end.max(module.range().end);
                found.push(module.range());
            }
            continue;
        }
        let start = attributes.group_start(&attribute);
        let item = attributes.following(&attribute);
        if let Some(item) = item.filter(|n| !n.dfs().any(|child| child.kind().as_ref() == "ERROR"))
        {
            covered_end = covered_end.max(item.range().end);
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

pub(crate) struct OriginalSource {
    original: String,
    analysis: String,
    coordinates: OnceLock<SourceCoordinates>,
}

impl OriginalSource {
    pub(crate) fn new(original: String, analysis: String) -> Self {
        Self {
            original,
            analysis,
            coordinates: OnceLock::new(),
        }
    }

    pub(crate) fn restore_location(&self, location: &mut mehscan_core::Location) {
        let coordinates = self
            .coordinates
            .get_or_init(|| SourceCoordinates::new(&self.original));
        for position in [&mut location.start, &mut location.end] {
            let offset = position.byte_offset;
            if offset > self.original.len() || !self.original.is_char_boundary(offset) {
                continue;
            }
            let line = coordinates.lines.partition_point(|start| *start <= offset) - 1;
            let start = coordinates.lines[line];
            let extra = coordinates
                .continuations
                .partition_point(|byte| *byte < offset)
                - coordinates
                    .continuations
                    .partition_point(|byte| *byte < start);
            position.line = line + 1;
            position.column = offset - start - extra + 1;
        }
    }
}

struct SourceCoordinates {
    lines: Vec<usize>,
    continuations: Vec<usize>,
}

impl SourceCoordinates {
    fn new(source: &str) -> Self {
        let mut lines = vec![0];
        let mut continuations = Vec::new();
        for (offset, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                lines.push(offset + 1);
            }
            if byte & 0b1100_0000 == 0b1000_0000 {
                continuations.push(offset);
            }
        }
        Self {
            lines,
            continuations,
        }
    }
}

pub(crate) fn restore_evidence(
    evidence: &mut mehscan_core::Evidence,
    originals: &std::collections::BTreeMap<String, OriginalSource>,
) {
    // Secret captures are deliberately redacted and must never be replaced
    // with source bytes. Other normalized/derived captures remain unchanged.
    if evidence.kind == mehscan_core::EvidenceKind::Secret {
        return;
    }
    if let Some(original) = originals.get(&evidence.location.path) {
        original.restore_location(&mut evidence.location);
    }
    for capture in evidence.captures.values_mut() {
        if let Some(original) = originals.get(&capture.location.path) {
            let range = capture.location.start.byte_offset..capture.location.end.byte_offset;
            if original.analysis.get(range.clone()) == Some(capture.text.as_str()) {
                if let Some(text) = original.original.get(range) {
                    capture.text = text.to_string();
                }
            }
            original.restore_location(&mut capture.location);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_coordinates_keep_utf8_crlf_boundaries_and_invalid_offsets() {
        let source = "🦀 e\u{301}\r\nsecond λ\nlast\t字";
        let original = OriginalSource::new(source.to_string(), source.to_string());
        for offset in 0..=source.len() + 1 {
            let mut location = mehscan_core::Location {
                path: "module.rs".to_string(),
                start: mehscan_core::Position {
                    line: 999,
                    column: 999,
                    byte_offset: offset,
                },
                end: mehscan_core::Position {
                    line: 999,
                    column: 999,
                    byte_offset: offset,
                },
            };
            original.restore_location(&mut location);
            let expected = source
                .get(..offset)
                .map(|before| {
                    (
                        before.bytes().filter(|byte| *byte == b'\n').count() + 1,
                        before.rsplit('\n').next().unwrap().chars().count() + 1,
                    )
                })
                .unwrap_or((999, 999));
            assert_eq!(
                (location.start.line, location.start.column),
                expected,
                "{offset}"
            );
            assert_eq!(location.start, location.end);
        }
    }

    #[test]
    fn indexed_masking_keeps_legacy_nested_and_stacked_item_ranges() {
        let source = r##"
            #[allow(dead_code)] // preceding annotation
            #[test] #[cfg(test)] fn first() { let marker="🦀"; }
            fn live() {}
            #[cfg(test)] mod suite { #[test] fn child() {} }
            mod inner { #![cfg(test)] fn hidden() {} }
            #[cfg(any(test,feature="server"))] fn optional() {}
            #[allow(unused)] /* between */ #[test] fn last() {}
        "##;
        let doc = StrDoc::try_new(source, SupportLang::Rust).unwrap();
        let ast = AstGrep::doc(doc);
        let root = ast.root();
        let mut expected: Vec<Range<usize>> = Vec::new();
        for attribute in root.dfs().filter(|node| {
            matches!(
                node.kind().as_ref(),
                "attribute_item" | "inner_attribute_item"
            )
        }) {
            if expected.iter().any(|range| {
                range.start <= attribute.range().start && attribute.range().end <= range.end
            }) || !super::super::rust_cfg::test_only(&attribute)
            {
                continue;
            }
            let parent = attribute.parent().unwrap();
            if attribute.kind().as_ref() == "inner_attribute_item" {
                if parent.kind().as_ref() == "source_file" {
                    expected.push(parent.range());
                } else if let Some(module) = parent
                    .parent()
                    .filter(|node| node.kind().as_ref() == "mod_item")
                {
                    expected.push(module.range());
                }
                continue;
            }
            let siblings: Vec<_> = parent.children().collect();
            let mut start = attribute.range().start;
            for previous in siblings
                .iter()
                .rev()
                .filter(|node| node.range().end <= attribute.range().start)
            {
                if previous.kind().as_ref() == "attribute_item" {
                    start = previous.range().start;
                } else if !previous.kind().contains("comment") {
                    break;
                }
            }
            if let Some(item) = parent
                .children()
                .filter(|node| node.range().start >= attribute.range().end)
                .find(|node| {
                    node.is_named()
                        && node.kind().as_ref() != "attribute_item"
                        && !node.kind().contains("comment")
                })
                .filter(|node| !node.dfs().any(|child| child.kind().as_ref() == "ERROR"))
            {
                expected.push(start..item.range().end);
            }
        }
        expected.sort_by_key(|range| (range.start, range.end));
        let mut merged: Vec<Range<usize>> = Vec::new();
        for range in expected {
            if let Some(last) = merged.last_mut().filter(|last| last.end >= range.start) {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        assert_eq!(ranges(source), merged);
    }

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
