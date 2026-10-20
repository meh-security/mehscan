//! URL-prefix facts, never a verdict about endpoint authorization or SSRF.
use ast_grep_core::{Doc, Node};
use mehscan_core::{Capability, Evidence, EvidenceKind, Language};
use std::collections::BTreeMap;

pub(super) fn annotate<D: Doc>(root: &Node<'_, D>, language: Language, evidence: &mut [Evidence]) {
    // Node has its own model. Do not interpret C/C++ pointer arithmetic or
    // another language's operators as string concatenation by AST spelling.
    if !matches!(
        language,
        Language::Csharp | Language::Java | Language::Python
    ) {
        return;
    }
    let targets: BTreeMap<_, _> = evidence
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            if e.kind != EvidenceKind::Sink {
                return None;
            }
            let role = match e.capability {
                Capability::Redirect => "location",
                Capability::OutboundNetworkRequest => "endpoint",
                _ => return None,
            };
            let capture = e.captures.get(role)?;
            Some((
                (
                    capture.location.start.byte_offset,
                    capture.location.end.byte_offset,
                ),
                i,
            ))
        })
        .fold(BTreeMap::<_, Vec<_>>::new(), |mut map, (range, i)| {
            map.entry(range).or_default().push(i);
            map
        });
    if targets.is_empty() {
        return;
    }
    // One pass only for files with relevant sinks, including native sink emitters.
    for node in root.dfs() {
        let Some(indices) = targets.get(&(node.range().start, node.range().end)) else {
            continue;
        };
        let Some(prefix) = leading_literal(&node, 0) else {
            continue;
        };
        for &i in indices {
            let sink = &mut evidence[i];
            if fixed_http_prefix(&prefix)
                && !sink
                    .tags
                    .iter()
                    .any(|t| t == "url-shape:fixed-http-authority")
            {
                sink.tags.push("url-shape:fixed-http-authority".into());
            }
            if sink.capability == Capability::Redirect
                && fixed_navigation_prefix(&prefix)
                && !sink
                    .tags
                    .iter()
                    .any(|t| t == "url-shape:fixed-navigation-prefix")
            {
                sink.tags.push("url-shape:fixed-navigation-prefix".into());
            }
        }
    }
}

fn leading_literal<D: Doc>(node: &Node<'_, D>, depth: usize) -> Option<String> {
    if depth >= 16 {
        return None;
    }
    let kind = node.kind();
    if kind.contains("parenthesized") || matches!(kind.as_ref(), "argument" | "expression_list") {
        let mut children = node.children().filter(|n| n.is_named());
        let child = children.next()?;
        return children
            .next()
            .is_none()
            .then(|| leading_literal(&child, depth + 1))
            .flatten();
    }
    if matches!(
        kind.as_ref(),
        "binary_expression" | "additive_expression" | "binary_operator"
    ) {
        let left = node.field("left")?;
        let right = node.field("right")?;
        let text = node.text();
        let operator = text
            .get(left.range().end - node.range().start..right.range().start - node.range().start)?;
        return (operator.trim() == "+")
            .then(|| leading_literal(&left, depth + 1))
            .flatten();
    }
    // Deliberately exclude aliases, calls, interpolation, raw/multiline strings
    // and escape decoding. No library or mutable binding behavior is inferred.
    if !matches!(kind.as_ref(), "string" | "string_literal") {
        return None;
    }
    let text = node.text();
    let quote = *text.as_bytes().first()?;
    if !matches!(quote, b'\'' | b'"') || text.as_bytes().last() != Some(&quote) {
        return None;
    }
    let body = text.get(1..text.len().checked_sub(1)?)?;
    if body.contains(['\\', '\'', '"', '{', '}']) {
        return None;
    }
    Some(body.into())
}

pub(super) fn fixed_navigation_prefix(prefix: &str) -> bool {
    if !prefix.is_ascii() || prefix.bytes().any(|b| b.is_ascii_control() || b == b'\\') {
        return false;
    }
    if prefix.starts_with('/') && prefix.len() >= 2 && !prefix.starts_with("//") {
        return true;
    }
    if prefix.starts_with('?') || prefix.starts_with('#') {
        return true;
    }
    fixed_http_prefix(prefix)
}

pub(super) fn fixed_http_prefix(prefix: &str) -> bool {
    if !prefix.is_ascii() || prefix.bytes().any(|b| b.is_ascii_control() || b == b'\\') {
        return false;
    }
    let Some(rest) = prefix
        .strip_prefix("https://")
        .or_else(|| prefix.strip_prefix("http://"))
    else {
        return false;
    };
    let Some(end) = rest.find(['/', '?', '#']) else {
        return false;
    };
    let authority = &rest[..end];
    !authority.is_empty()
        && authority
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
}
