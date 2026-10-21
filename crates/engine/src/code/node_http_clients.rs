//! Explicit imported Got clients; bounded local aliases/factories, no heap/DI.
use super::{
    comments::CommentRanges,
    conditional::ConditionalRegions,
    context::enclosing_symbol,
    literals::LiteralEnvironment,
    matcher::{evidence_id, location},
    reachability,
    symbols::FileSymbolEnvironment,
};
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::*;
use std::collections::BTreeMap;
type N<'a> = Node<'a, StrDoc<SupportLang>>;

fn args<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.field("arguments")
        .map(|a| {
            a.children()
                .filter(|c| c.is_named() && c.kind().as_ref() != "comment")
                .collect()
        })
        .unwrap_or_default()
}
fn member<'a>(n: &N<'a>) -> Option<(N<'a>, String)> {
    Some((n.field("object")?, n.field("property")?.text().into_owned()))
}
fn function(n: &N<'_>) -> bool {
    matches!(
        n.kind().as_ref(),
        "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "method_definition"
            | "generator_function"
    )
}
fn owner<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.ancestors().find(function)
}
fn peel<'a>(mut n: N<'a>) -> N<'a> {
    while matches!(
        n.kind().as_ref(),
        "parenthesized_expression" | "as_expression" | "type_assertion"
    ) {
        let Some(inner) = n
            .children()
            .find(|c| c.is_named() && c.kind().as_ref() != "comment")
        else {
            break;
        };
        n = inner;
    }
    n
}
fn require_got(n: &N<'_>) -> bool {
    let mut n = peel(n.clone());
    if let Some((object, property)) = member(&n) {
        if property != "default" {
            return false;
        };
        n = peel(object);
    }
    let values = args(&n);
    n.kind().as_ref() == "call_expression"
        && n.field("function")
            .is_some_and(|f| f.text().trim() == "require")
        && values.len() == 1
        && values[0].kind().as_ref() == "string"
        && values[0].text().trim_matches(['\'', '"']) == "got"
}
fn stable(root: &N<'_>, name: &N<'_>) -> bool {
    super::node_api_boundaries::stable_binding(root, name)
        && !name
            .ancestors()
            .filter(function)
            .filter_map(|f| f.field("parameters").or_else(|| f.field("parameter")))
            .any(|p| {
                p.dfs()
                    .any(|n| n.kind().as_ref() == "identifier" && n.text() == name.text())
            })
}
fn client<'a>(
    root: &N<'a>,
    symbols: &FileSymbolEnvironment,
    n: &N<'a>,
    depth: usize,
) -> Option<Vec<N<'a>>> {
    if depth > 3 {
        return None;
    }
    let n = peel(n.clone());
    if require_got(&n) {
        return Some(Vec::new());
    }
    if n.kind().as_ref() == "call_expression" {
        let (base, method) = member(&n.field("function")?)?;
        if method != "extend" {
            return None;
        }
        let mut factories = client(root, symbols, &base, depth + 1)?;
        factories.push(n);
        return Some(factories);
    }
    if n.kind().as_ref() != "identifier" || !stable(root, &n) {
        return None;
    }
    if ["got", "got.default"]
        .iter()
        .any(|api| symbols.resolve_imported(n.text().as_ref(), api).is_some())
    {
        return Some(Vec::new());
    }
    let definitions = root
        .dfs()
        .filter(|d| {
            d.kind().as_ref() == "variable_declarator"
                && d.field("name").is_some_and(|name| name.text() == n.text())
                && owner(d).is_none_or(|f| f.range().contains(&n.range().start))
        })
        .collect::<Vec<_>>();
    let [definition] = definitions.as_slice() else {
        return None;
    };
    if definition.range().end > n.range().start {
        return None;
    }
    client(root, symbols, &definition.field("value")?, depth + 1)
}
fn option<'a>(n: &N<'a>, key: &str) -> Option<N<'a>> {
    if n.kind().as_ref() != "object" {
        return None;
    }
    let fields = n
        .children()
        .filter(|c| c.is_named() && c.kind().as_ref() != "comment")
        .collect::<Vec<_>>();
    if fields.iter().any(|f| f.kind().as_ref() != "pair") {
        return None;
    }
    let matches = fields
        .iter()
        .filter(|f| {
            f.field("key")
                .is_some_and(|k| k.text().trim_matches(['\'', '"']) == key)
        })
        .collect::<Vec<_>>();
    let [field] = matches.as_slice() else {
        return None;
    };
    field.field("value")
}
fn uncertain_options(n: &N<'_>) -> bool {
    if n.kind().as_ref() != "object" {
        return true;
    }
    n.children()
        .filter(|c| c.is_named() && c.kind().as_ref() != "comment")
        .any(|f| {
            f.kind().as_ref() != "pair"
                || f.field("key")
                    .is_some_and(|k| match k.text().trim_matches(['\'', '"']) {
                        "hooks" | "request" => true,
                        "url" | "prefixUrl" => f
                            .field("value")
                            .is_none_or(|v| v.kind().as_ref() != "string"),
                        _ => false,
                    })
        })
}
fn capture(path: &str, n: &N<'_>) -> Capture {
    Capture {
        text: n.text().into_owned(),
        location: location(path, n),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn add<'a>(
    path: &str,
    root: &N<'a>,
    language: Language,
    symbols: &FileSymbolEnvironment,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let prefix = match language {
        Language::Javascript => "javascript",
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => return,
    };
    let source = root.text();
    if !source.contains("'got'") && !source.contains("\"got\"") {
        return;
    }
    for call in root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        if comments.is_in_comment(call.range()) {
            continue;
        }
        let Some(callee) = call.field("function") else {
            continue;
        };
        let (base, method) = member(&callee).unwrap_or_else(|| (callee.clone(), "request".into()));
        let (base, method) = if let Some((owner, property)) = member(&base) {
            if property == "stream" {
                (owner, format!("stream.{method}"))
            } else {
                (base, method)
            }
        } else {
            (base, method)
        };
        if !matches!(
            method.as_str(),
            "request"
                | "get"
                | "post"
                | "put"
                | "patch"
                | "delete"
                | "head"
                | "options"
                | "stream"
                | "stream.get"
                | "stream.post"
                | "stream.put"
                | "stream.patch"
                | "stream.delete"
                | "stream.head"
                | "stream.options"
                | "extend"
        ) {
            continue;
        }
        let Some(factories) = client(root, symbols, &base, 0) else {
            continue;
        };
        let arguments = args(&call);
        let factory = method == "extend";
        let rule = if factory {
            format!("{prefix}-http-client-factory")
        } else {
            format!("{prefix}-outbound-http")
        };
        let id = evidence_id(path, &rule, call.range().start, call.range().end);
        if evidence.iter().any(|e| e.id == id) {
            continue;
        }
        let mut captures = BTreeMap::new();
        let mut values = BTreeMap::new();
        let mut fixed_destination = false;
        let mut options = Vec::new();
        for (i, f) in factories.iter().enumerate() {
            let mut definition = capture(path, f);
            definition.text = "got.extend".into();
            captures.insert(format!("http_client_{i}_definition"), definition);
            options.extend(args(f));
        }
        if factory {
            options.extend(arguments.clone())
        } else if let Some(first) = arguments.first() {
            let mut endpoint = if first.kind().as_ref() == "object" {
                option(first, "url").unwrap_or_else(|| first.clone())
            } else {
                first.clone()
            };
            if first.kind().as_ref() == "object" {
                options.push(first.clone())
            }
            options.extend(arguments.iter().skip(1).cloned());
            // Explicit url in the last options object overrides the first argument.
            if let Some(url) = arguments.get(1).and_then(|o| option(o, "url")) {
                endpoint = url
            }
            if endpoint.kind().as_ref() == "string" && !endpoint.text().contains("://") {
                if let Some(prefix) = options.iter().rev().find_map(|o| option(o, "prefixUrl")) {
                    endpoint = prefix
                }
            }
            let value = literals.evaluate(&endpoint);
            // This is a complete literal URL, unlike the URL-prefix helper's
            // partial fragments which require a delimiter after authority.
            fixed_destination = matches!(value.value.as_ref(), Some(LiteralValue::String(url)) if url.starts_with("https://") || url.starts_with("http://"));
            values.insert("endpoint".into(), value);
            captures.insert("endpoint".into(), capture(path, &endpoint));
            captures.insert("request_target".into(), capture(path, first));
        }
        for (i, o) in options.iter().enumerate() {
            captures.insert(format!("http_options_{i}"), capture(path, o));
        }
        let mut tags = vec![
            "http".into(),
            "network".into(),
            "ssrf".into(),
            "http-client:got".into(),
        ];
        if fixed_destination {
            tags.push("url-shape:fixed-http-authority".into());
        }
        if options.iter().any(uncertain_options) {
            tags.push("outbound-request:unresolved-client-options".into());
        }
        evidence.push(Evidence {
            id,
            kind: if factory {
                EvidenceKind::Resource
            } else {
                EvidenceKind::Sink
            },
            capability: Capability::OutboundNetworkRequest,
            location: location(path, &call),
            enclosing_symbol: enclosing_symbol(&call),
            captures,
            cwe_candidates: if factory {
                vec![]
            } else {
                vec!["CWE-918".into()]
            },
            tags,
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "ast-grep + explicit Got client model".into(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&call, literals)),
                availability: Some(conditional.availability_for(call.range())),
                literals: values,
                ..EvidenceContext::default()
            },
            symbol_resolution: Some(SymbolResolution {
                canonical: format!("got.{method}"),
                observed: callee.text().into_owned(),
                method: SymbolResolutionMethod::Alias,
                confidence: SymbolConfidence::High,
            }),
            rule_id: rule,
            related_evidence: vec![],
        });
    }
}
