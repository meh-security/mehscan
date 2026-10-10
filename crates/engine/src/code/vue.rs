//! Vue SFC blocks and raw template output; no compiler, reactivity or taint model.
use std::collections::BTreeMap;
use std::ops::Range;

use ast_grep_core::{AstGrep, Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceKind, Language, Location, Position,
    Provenance, Resolution,
};

pub(crate) struct Sfc {
    pub language: Language,
    pub script: String,
    pub evidence: Vec<Evidence>,
    pub gaps: Vec<String>,
}

pub(crate) fn parse(path: &str, source: &str) -> Sfc {
    let mut output = Sfc {
        language: Language::Javascript,
        script: String::new(),
        evidence: Vec::new(),
        gaps: Vec::new(),
    };
    let mut masked: Vec<u8> = source
        .bytes()
        .map(|b| if matches!(b, b'\r' | b'\n') { b } else { b' ' })
        .collect();
    if source.len() > 512 * 1024 {
        output
            .gaps
            .push("Vue SFC exceeds the 512 KiB syntax limit".into());
        output.script = String::from_utf8(masked).unwrap();
        return output;
    }
    let document = match StrDoc::try_new(source, SupportLang::Html) {
        Ok(document) => AstGrep::doc(document),
        Err(error) => {
            output
                .gaps
                .push(format!("Vue SFC HTML parser unavailable: {error}"));
            output.script = String::from_utf8(masked).unwrap();
            return output;
        }
    };
    let root = document.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        output
            .gaps
            .push("Vue SFC contains malformed HTML/block syntax; valid blocks retained".into());
    }
    let mut scripts = Vec::new();
    let mut templates = 0;
    let mut recognized = false;
    for block in root.children().filter(|n| n.is_named()) {
        let Some(open) = block.children().find(|n| n.kind().as_ref() == "start_tag") else {
            continue;
        };
        let Some(name) = open.children().find(|n| n.kind().as_ref() == "tag_name") else {
            continue;
        };
        let name = name.text().to_string();
        if !matches!(name.as_str(), "template" | "script") {
            continue;
        }
        recognized = true;
        if open.dfs().any(|n| n.is_error() || n.is_missing()) {
            output
                .gaps
                .push(format!("Vue {name} opening tag is malformed"));
            continue;
        }
        let Some(close) = block.children().find(|n| n.kind().as_ref() == "end_tag") else {
            output
                .gaps
                .push(format!("Vue {name} closing tag is missing"));
            continue;
        };
        let attributes = attributes(&open);
        if attributes.contains_key("src") {
            output.gaps.push(format!(
                "Vue {name} src block requires external source lookup: {}",
                attributes["src"]
            ));
            continue;
        }
        if name == "script" {
            let language = match attributes.get("lang").map(String::as_str).unwrap_or("js") {
                "js" | "javascript" | "jsx" => Language::Javascript,
                "ts" | "typescript" => Language::Typescript,
                "tsx" => Language::Tsx,
                other => {
                    output
                        .gaps
                        .push(format!("Vue script language {other:?} is unsupported"));
                    continue;
                }
            };
            scripts.push((open.range().end..close.range().start, language));
        } else {
            templates += 1;
            if templates > 1 {
                output
                    .gaps
                    .push("Vue SFC has multiple top-level templates".into());
                continue;
            }
            let language = attributes.get("lang").map(String::as_str).unwrap_or("html");
            if language != "html" {
                output.gaps.push(format!(
                    "Vue template language {language:?} requires preprocessing"
                ));
                continue;
            }
            for attribute in block.dfs().filter(|n| n.kind().as_ref() == "attribute") {
                if attribute.range().start < open.range().end
                    || attribute.range().end > close.range().start
                {
                    continue;
                }
                // A directive written inside script/style/custom blocks is not a template consumer.
                if attribute
                    .ancestors()
                    .take_while(|n| n.range() != block.range())
                    .any(|n| matches!(n.kind().as_ref(), "script_element" | "style_element"))
                {
                    continue;
                }
                let Some(name) = attribute
                    .children()
                    .find(|n| n.kind().as_ref() == "attribute_name")
                else {
                    continue;
                };
                if name.text().as_ref() != "v-html" {
                    continue;
                }
                if attribute.dfs().any(|n| n.is_error() || n.is_missing()) {
                    output.gaps.push("Malformed Vue v-html directive".into());
                    continue;
                }
                let Some(value) = attribute
                    .dfs()
                    .find(|n| n.kind().as_ref() == "attribute_value")
                else {
                    output.gaps.push("Vue v-html has no expression".into());
                    continue;
                };
                let expression = value.text();
                if expression.trim().is_empty() {
                    output
                        .gaps
                        .push("Vue v-html has an empty expression".into());
                    continue;
                }
                let constant = constant_expression(expression.as_ref());
                let rule = if constant {
                    "vue-sfc-static-html-control"
                } else {
                    "vue-sfc-v-html-output"
                };
                let range = attribute.range();
                output.evidence.push(Evidence {
                    id: super::matcher::evidence_id(path, rule, range.start, range.end),
                    kind: if constant {
                        EvidenceKind::Literal
                    } else {
                        EvidenceKind::Sink
                    },
                    capability: Capability::HtmlOutput,
                    location: location(path, source, range),
                    enclosing_symbol: Some("Vue SFC template".into()),
                    captures: BTreeMap::from([(
                        "content".into(),
                        Capture {
                            text: expression.into_owned(),
                            location: location(path, source, value.range()),
                        },
                    )]),
                    cwe_candidates: vec!["CWE-79".into()],
                    tags: vec![
                        "browser".into(),
                        "vue".into(),
                        "vue-sfc".into(),
                        "trusted-markup".into(),
                        "explicit-raw-html".into(),
                        "browser-interpretation:html-markup".into(),
                        "html-boundary:dom-insertion".into(),
                    ],
                    confidence: Confidence::High,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "mehscan-vue-sfc-html".into(),
                        rule_version: 1,
                    },
                    context: super::context::unknown_textual_context(),
                    symbol_resolution: None,
                    rule_id: rule.into(),
                    related_evidence: Vec::new(),
                });
            }
        }
    }
    // Module and setup scripts have different scopes. Do not merge them and invent reaching values.
    if scripts.len() > 1 {
        output.gaps.push(
            "Vue dual/multiple script scopes are not linked in this slice; script analysis omitted"
                .into(),
        );
    } else if let Some((range, language)) = scripts.pop() {
        masked[range.clone()].copy_from_slice(&source.as_bytes()[range]);
        output.language = language;
    }
    output.script = String::from_utf8(masked).unwrap();
    if !recognized {
        output.gaps.push("Vue SFC has no top-level template or script block; bare template/custom-block analysis is unsupported".into());
    }
    output
}

fn attributes(node: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    node.children()
        .filter(|n| n.kind().as_ref() == "attribute")
        .filter_map(|n| {
            let name = n
                .children()
                .find(|n| n.kind().as_ref() == "attribute_name")?;
            let value = n
                .dfs()
                .find(|n| n.kind().as_ref() == "attribute_value")
                .map(|v| v.text().to_string())
                .unwrap_or_default();
            Some((name.text().to_string(), value))
        })
        .collect()
}

fn constant_expression(expression: &str) -> bool {
    let code = format!("const value = ({expression});");
    let Ok(doc) = StrDoc::try_new(&code, SupportLang::JavaScript) else {
        return false;
    };
    let ast = AstGrep::doc(doc);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return false;
    }
    let Some(value) = root
        .dfs()
        .find(|n| n.kind().as_ref() == "variable_declarator")
        .and_then(|n| n.field("value"))
    else {
        return false;
    };
    let mut value = value;
    while value.kind().as_ref() == "parenthesized_expression" {
        let Some(inner) = value.children().find(|n| n.is_named()) else {
            return false;
        };
        value = inner;
    }
    matches!(
        value.kind().as_ref(),
        "string" | "number" | "true" | "false" | "null"
    ) || value.kind().as_ref() == "template_string"
        && !value
            .dfs()
            .any(|n| n.kind().as_ref() == "template_substitution")
}

pub(crate) fn restore_location(location: &mut Location, source: &str) {
    location.start = position(source, location.start.byte_offset);
    location.end = position(source, location.end.byte_offset);
}

fn location(path: &str, source: &str, range: Range<usize>) -> Location {
    Location {
        path: path.into(),
        start: position(source, range.start),
        end: position(source, range.end),
    }
}

fn position(source: &str, offset: usize) -> Position {
    let before = &source[..offset];
    Position {
        line: before.bytes().filter(|b| *b == b'\n').count() + 1,
        column: before
            .rsplit('\n')
            .next()
            .unwrap_or_default()
            .chars()
            .count()
            + 1,
        byte_offset: offset,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vue_blocks_preserve_script_offsets_and_ignore_markup_comments() {
        let source = "<!-- <script>eval(bad)</script> -->\n<template><p>{{ text }}</p><p v-text=\"text\"/><p v-html=\"html\"/></template>\n<script setup lang=\"ts\">const html: string = input; eval(html);</script><style>p {content:'eval(bad)'}</style>";
        let parsed = parse("View.vue", source);
        assert!(parsed.gaps.is_empty(), "{:?}", parsed.gaps);
        assert_eq!(parsed.language, Language::Typescript);
        assert_eq!(parsed.script.len(), source.len());
        assert_eq!(parsed.script.find("eval(html)"), source.find("eval(html)"));
        assert!(!parsed.script.contains("eval(bad)"));
        assert_eq!(parsed.evidence.len(), 1);
        let item = &parsed.evidence[0];
        assert_eq!(
            &source[item.location.start.byte_offset..item.location.end.byte_offset],
            "v-html=\"html\""
        );
        assert_eq!(item.captures["content"].text, "html");
    }

    #[test]
    fn vue_static_raw_output_is_a_control_not_a_sink() {
        let parsed = parse(
            "Static.vue",
            "<template><p v-html=\"'<b>hello</b>'\"/><p v-html=\"markup\"/></template>",
        );
        assert_eq!(parsed.evidence.len(), 2);
        assert_eq!(parsed.evidence[0].kind, EvidenceKind::Literal);
        assert_eq!(parsed.evidence[1].kind, EvidenceKind::Sink);
    }

    #[test]
    fn vue_external_preprocessed_and_dual_scopes_are_visible_gaps() {
        for source in [
            "<script src=\"./logic.ts\"></script>",
            "<template lang=\"pug\">p(v-html='html')</template>",
            "<script>const a=1</script><script setup>eval(a)</script>",
        ] {
            let parsed = parse("Partial.vue", source);
            assert!(!parsed.gaps.is_empty(), "{source}");
            assert!(parsed.script.trim().is_empty());
        }
    }

    #[test]
    fn vue_bare_template_is_not_silently_reported_as_complete() {
        let parsed = parse("Legacy.vue", "<div v-html=\"html\"></div>");
        assert!(!parsed.gaps.is_empty());
    }
}
