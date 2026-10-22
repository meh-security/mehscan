//! URL construction facts over the shared local operand index. No URL object,
//! library-return or branch-join inference. Unknown syntax keeps admission open.
use super::{MAX_PROPAGATION_DEPTH, Node, NodeOperandIndex, Range, StrDoc, SupportLang};
use mehscan_core::{Capability, Evidence, EvidenceKind};

use super::super::url_shape::{fixed_http_prefix, fixed_navigation_prefix};

type Ast<'a> = Node<'a, StrDoc<SupportLang>>;

#[derive(Clone)]
enum Part {
    Literal(String),
    Source,
    Other,
}

pub(super) enum Contribution {
    NoValue,
    QuerySuffix,
    FragmentSuffix,
    Unknown,
}

pub(super) fn intrinsic_link(sink: &Evidence) -> bool {
    sink.capability == Capability::HtmlOutput
        && sink.cwe_candidates == ["CWE-79"]
        && matches!(
            sink.rule_id.as_str(),
            "javascript-react-url-attribute-output"
                | "typescript-react-url-attribute-output"
                | "tsx-react-url-attribute-output"
        )
        && sink
            .tags
            .iter()
            .any(|t| t == "url-consumer:link-navigation")
}

pub(super) fn annotate(evidence: &mut [Evidence], index: &NodeOperandIndex<'_>) {
    for sink in evidence.iter_mut().filter(|e| {
        e.kind == EvidenceKind::Sink
            && (matches!(
                e.capability,
                Capability::Redirect | Capability::OutboundNetworkRequest
            ) || intrinsic_link(e))
    }) {
        let role = if sink.capability == Capability::Redirect {
            "location"
        } else if sink.capability == Capability::HtmlOutput {
            "content"
        } else {
            "endpoint"
        };
        let Some(capture) = sink.captures.get(role) else {
            continue;
        };
        let Some(target) = index.destination_nodes.get(&(
            capture.location.start.byte_offset,
            capture.location.end.byte_offset,
        )) else {
            continue;
        };
        let scope = target
            .ancestors()
            .find(|n| super::is_function_scope(n.kind().as_ref()))
            .map(|n| n.range())
            .unwrap_or_else(|| index.file_scope.clone());
        let Some(shapes) = parts(target, None, index, &scope, 0, &mut 64) else {
            continue;
        };
        if intrinsic_link(sink) {
            if index.custom_jsx_factory {
                continue;
            }
            let Some(element) = target
                .ancestors()
                .find(|n| n.kind().as_ref() == "jsx_attribute")
                .and_then(|n| n.parent())
            else {
                continue;
            };
            // A later spread/duplicate can replace the effective href. Do not
            // let one closed attribute stand for an unresolved effective prop.
            if element
                .children()
                .any(|n| n.kind().as_ref() == "jsx_expression")
                || element
                    .children()
                    .filter(|n| {
                        n.kind().as_ref() == "jsx_attribute"
                            && n.children()
                                .find(|c| c.is_named())
                                .is_some_and(|c| c.text() == "href")
                    })
                    .count()
                    != 1
            {
                continue;
            }
            // React escapes the native attribute value. This closes only the
            // executable-scheme/attribute-breakout question, not destination,
            // mail headers, navigation policy or downstream interpretation.
            if shapes.iter().all(|shape| {
                let prefix = shape
                    .iter()
                    .take_while(|p| matches!(p, Part::Literal(_)))
                    .filter_map(|p| {
                        if let Part::Literal(s) = p {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                    .collect::<String>();
                let normalized = prefix.to_ascii_lowercase();
                prefix.is_ascii()
                    && !prefix.bytes().any(|b| b.is_ascii_control() || b == b'\\')
                    && (["https://", "http://", "mailto:", "tel:"]
                        .iter()
                        .any(|p| normalized.starts_with(p))
                        || prefix.starts_with('#'))
            }) {
                sink.tags.push("html-url:non-executable-link-prefix".into());
            }
            continue;
        }
        // All possible syntax alternatives must establish a fixed navigation
        // origin before any unresolved content. A suffix literal is not a prefix.
        if sink.capability == Capability::OutboundNetworkRequest {
            if shapes.iter().all(|shape| {
                let prefix = shape
                    .iter()
                    .take_while(|p| matches!(p, Part::Literal(_)))
                    .filter_map(|p| {
                        if let Part::Literal(s) = p {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                    .collect::<String>();
                fixed_http_prefix(&prefix)
            }) {
                // This is a construction fact, not a source-supported SSRF
                // closure: paths on a fixed internal host can still matter.
                sink.tags.push("url-shape:fixed-http-authority".to_string());
            }
            if shapes.iter().all(|shape| {
                let prefix = shape
                    .iter()
                    .take_while(|p| matches!(p, Part::Literal(_)))
                    .filter_map(|p| {
                        if let Part::Literal(s) = p {
                            Some(s.as_str())
                        } else {
                            None
                        }
                    })
                    .collect::<String>();
                prefix.starts_with('/')
                    && !prefix.starts_with("//")
                    && fixed_navigation_prefix(&prefix)
            }) && ordinary_request_arguments(sink, target)
            {
                // Only the argument's construction and dispatch signature are
                // known. Client defaults/base/hooks and route authorization
                // remain open; never reuse this tag as a source-flow closure.
                sink.tags
                    .push("url-shape:root-relative-request-target".into());
            }
        } else if shapes
            .iter()
            .all(|shape| shape.iter().all(|part| matches!(part, Part::Literal(_))))
        {
            sink.tags
                .push("redirect-closure:constant-targets".to_string());
        } else if shapes.iter().all(|shape| {
            let prefix = shape
                .iter()
                .take_while(|p| matches!(p, Part::Literal(_)))
                .filter_map(|p| {
                    if let Part::Literal(s) = p {
                        Some(s.as_str())
                    } else {
                        None
                    }
                })
                .collect::<String>();
            fixed_navigation_prefix(&prefix)
        }) {
            sink.tags.push("redirect-closure:fixed-origin".to_string());
        }
    }
}

/// Explicit standard client signatures only. An Axios write's second argument
/// is data, not routing configuration. Unknown/spread config and custom clients
/// stay open. Abort signals cannot replace the target; no other option is
/// inferred here, even if it looks harmless by name.
fn ordinary_request_arguments(sink: &Evidence, target: &Ast<'_>) -> bool {
    let Some(canonical) = sink
        .symbol_resolution
        .as_ref()
        .map(|s| s.canonical.as_str())
    else {
        return false;
    };
    let config_index = match canonical {
        "fetch" | "axios.get" | "axios.head" | "axios.options" | "axios.delete" => 1,
        "axios.post" | "axios.put" | "axios.patch" => 2,
        _ => return false,
    };
    let Some(arguments) = target.parent().filter(|n| n.kind().as_ref() == "arguments") else {
        return false;
    };
    let args = arguments
        .children()
        .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
        .take(4)
        .collect::<Vec<_>>();
    if args.first().is_none_or(|n| n.range() != target.range())
        || args.iter().any(|n| n.kind().as_ref() == "spread_element")
        || args.len() > config_index + 1
    {
        return false;
    }
    args.get(config_index).is_none_or(|config| {
        config.kind().as_ref() == "object"
            && config
                .children()
                .filter(|n| n.is_named() && n.kind().as_ref() != "comment")
                .all(|entry| {
                    entry.kind().as_ref() == "pair"
                        && entry.field("key").is_some_and(|key| key.text() == "signal")
                })
    })
}

pub(super) fn contribution(
    source: &Ast<'_>,
    target: &Ast<'_>,
    index: &NodeOperandIndex<'_>,
    scope: &Range<usize>,
) -> Contribution {
    let Some(shapes) = parts(target, Some(&source.range()), index, scope, 0, &mut 64) else {
        return Contribution::Unknown;
    };
    if shapes
        .iter()
        .all(|shape| shape.iter().all(|p| matches!(p, Part::Literal(_))))
    {
        return Contribution::NoValue;
    }
    let mut suffix = None;
    let mut found = false;
    for shape in shapes {
        let mut prefix = String::new();
        for part in shape {
            match part {
                Part::Literal(s) => prefix.push_str(&s),
                Part::Other => prefix.clear(),
                Part::Source => {
                    found = true;
                    let marker = if prefix.contains('#') {
                        Some('#')
                    } else if prefix.contains('?') {
                        Some('?')
                    } else {
                        None
                    };
                    let Some(marker) = marker else {
                        return Contribution::Unknown;
                    };
                    if suffix.is_some_and(|previous| previous != marker) {
                        return Contribution::Unknown;
                    }
                    suffix = Some(marker);
                    // Later occurrences still follow this delimiter; a query
                    // or fragment fact never declares the unknown base safe.
                }
            }
        }
    }
    match (found, suffix) {
        (true, Some('?')) => Contribution::QuerySuffix,
        (true, Some('#')) => Contribution::FragmentSuffix,
        _ => Contribution::Unknown,
    }
}

// At most four aliases, 64 expression nodes, and eight alternatives. Reuse the
// same indexed assignment/write barriers as guarded operand propagation.
fn parts(
    node: &Ast<'_>,
    source: Option<&Range<usize>>,
    index: &NodeOperandIndex<'_>,
    scope: &Range<usize>,
    depth: usize,
    work: &mut usize,
) -> Option<Vec<Vec<Part>>> {
    if *work == 0 || depth > MAX_PROPAGATION_DEPTH {
        return None;
    }
    *work -= 1;
    if source.is_some_and(|source| node.range() == *source) {
        return Some(vec![vec![Part::Source]]);
    }
    let literal = if node.kind().as_ref() == "string_fragment" {
        Some(node.text().into_owned())
    } else if node.kind().as_ref() == "string" {
        super::simple_string_literal(node.text().as_ref()).map(str::to_string)
    } else {
        None
    };
    if let Some(literal) = literal {
        if literal.len() > 1024 || literal.contains('\\') {
            return None;
        }
        return Some(vec![vec![Part::Literal(literal)]]);
    }
    match node.kind().as_ref() {
        "identifier" => {
            if index
                .nested_binding_writes
                .contains(&((scope.start, scope.end), node.text().into_owned()))
            {
                return None;
            }
            if let Some(assignment) = index.alias_assignment(scope, node) {
                if !assignment.projection.is_empty() {
                    return Some(vec![vec![Part::Other]]);
                }
                parts(&assignment.right, source, index, scope, depth + 1, work)
            } else {
                Some(vec![vec![Part::Other]])
            }
        }
        // Opaque values may be any content. They do not remove a literal
        // prefix outside the call; a call wrapping the whole URL stays unknown.
        "member_expression" | "subscript_expression" | "call_expression" | "new_expression" => {
            Some(vec![vec![Part::Other]])
        }
        "parenthesized_expression"
        | "as_expression"
        | "non_null_expression"
        | "template_substitution" => parts(
            &node.children().find(|n| n.is_named())?,
            source,
            index,
            scope,
            depth,
            work,
        ),
        "ternary_expression" => {
            let mut branches = parts(
                &node.field("consequence")?,
                source,
                index,
                scope,
                depth,
                work,
            )?;
            branches.extend(parts(
                &node.field("alternative")?,
                source,
                index,
                scope,
                depth,
                work,
            )?);
            (branches.len() <= 8).then_some(branches)
        }
        "binary_expression" if node.field("operator").is_some_and(|op| op.text() == "+") => {
            combine(
                parts(&node.field("left")?, source, index, scope, depth, work)?,
                parts(&node.field("right")?, source, index, scope, depth, work)?,
            )
        }
        "template_string" => {
            let mut result = vec![Vec::new()];
            for child in node.children().filter(|n| n.is_named()) {
                result = combine(result, parts(&child, source, index, scope, depth, work)?)?;
            }
            Some(result)
        }
        _ => None,
    }
}

fn combine(left: Vec<Vec<Part>>, right: Vec<Vec<Part>>) -> Option<Vec<Vec<Part>>> {
    if left.len() * right.len() > 8 {
        return None;
    }
    Some(
        left.into_iter()
            .flat_map(|left| {
                right.iter().map(move |right| {
                    let mut value = left.clone();
                    value.extend(right.clone());
                    value
                })
            })
            .collect(),
    )
}
