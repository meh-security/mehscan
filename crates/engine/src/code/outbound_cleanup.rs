//! Construction preserves destination evidence; dispatch owns the review.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Capture, Evidence, EvidenceKind, Language};

type N<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn annotate<'a>(
    language: Language,
    root: &N<'a>,
    literals: &super::literals::LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::Go | Language::Java | Language::Rust) {
        return;
    }
    let calls = root.dfs().filter(is_call).collect::<Vec<_>>();
    let producers = evidence
        .iter()
        .enumerate()
        .filter_map(|(i, e)| {
            let node = calls.iter().find(|n| {
                n.range() == (e.location.start.byte_offset..e.location.end.byte_offset)
            })?;
            let builder = match e.rule_id.as_str() {
                "java-jdk-http-request-builder" | "java-apache-http-request" => true,
                "go-outbound-http" => matches!(
                    method(node).as_deref(),
                    Some("NewRequest" | "NewRequestWithContext")
                ),
                "rust-outbound-http" => receiver(node).is_some(), // owned Client methods; free get sends
                _ => false,
            };
            builder.then(|| (i, node.clone()))
        })
        .collect::<Vec<_>>();
    if producers.is_empty() && language == Language::Rust {
        return;
    }
    let mut dispatches = Vec::new();
    for call in &calls {
        let operation = method(call);
        let existing = evidence.iter().position(|e| {
            e.capability == Capability::OutboundNetworkRequest
                && e.location.start.byte_offset == call.range().start
                && e.location.end.byte_offset == call.range().end
                && (matches!(
                    e.rule_id.as_str(),
                    "java-jdk-http-client-dispatch" | "java-apache-http-dispatch"
                ) || language == Language::Go && operation.as_deref() == Some("Do"))
        });
        let request = if language == Language::Rust && operation.as_deref() == Some("send") {
            receiver(call)
        } else if language == Language::Rust
            && operation.as_deref() == Some("execute")
            && super::rust_context::is_exact_reqwest_request(root, call)
        {
            call.field("arguments")
                .and_then(|a| a.children().find(|n| n.is_named()))
        } else if existing.is_some() {
            call.field("arguments")
                .and_then(|a| a.children().find(|n| n.is_named()))
        } else {
            continue;
        };
        let Some(request) = request else { continue };
        let origin = origin(root, &request, &producers, 8);
        if existing.is_none() && origin.is_none() {
            continue; // never invent a Reqwest type from an arbitrary send method
        }
        let mut dispatch = if let Some(index) = existing {
            evidence[index].clone()
        } else {
            let mut e = evidence[origin.as_ref().unwrap().0].clone();
            e.rule_id = "rust-reqwest-request-dispatch".into();
            e.location = super::matcher::location(&e.location.path, call);
            e.id = super::matcher::evidence_id(
                &e.location.path,
                &e.rule_id,
                call.range().start,
                call.range().end,
            );
            e.enclosing_symbol = super::context::enclosing_symbol(call);
            e.context.reachability = Some(super::reachability::classify(call, literals));
            e.captures.clear();
            e.context.literals.clear();
            e.context.operand_facts.clear();
            e
        };
        dispatch.kind = EvidenceKind::Sink;
        dispatch.tags.push("outbound-request:dispatch".into());
        dispatch.captures.insert(
            "request".into(),
            Capture {
                text: request.text().into_owned(),
                location: super::matcher::location(&dispatch.location.path, &request),
            },
        );
        // Constructors copied into a dispatch must not retain producer-wide
        // literal or compiler closure. Helpers/mutations may replace authority.
        dispatch.captures.remove("endpoint");
        dispatch.context.literals.remove("endpoint");
        if let Some((index, binding)) = origin {
            let producer = &evidence[index];
            dispatch.related_evidence.push(producer.id.clone());
            if binding
                .as_ref()
                .is_none_or(|(declaration, site)| unchanged(root, declaration, site, call))
            {
                if let Some(endpoint) = producer.captures.get("endpoint") {
                    // An exact inline whole-URL parser preserves authority.
                    // Carry its input, not an opaque URI object's spelling.
                    // Never unwrap a component accessor or a mutable local URI.
                    let parser = evidence
                        .iter()
                        .find(|e| {
                            e.capability == Capability::UrlParsing
                                && e.location == endpoint.location
                                && !e.captures.contains_key("component")
                        })
                        .filter(|e| e.captures.contains_key("value"));
                    let parsed = parser.and_then(|e| e.captures.get("value"));
                    let input = parsed.unwrap_or(endpoint);
                    dispatch.captures.insert("endpoint".into(), input.clone());
                    if parsed.is_some() {
                        dispatch
                            .captures
                            .insert("parsed_endpoint".into(), endpoint.clone());
                    }
                    if let Some(value) = parser
                        .and_then(|e| e.context.literals.get("value"))
                        .or_else(|| {
                            parsed
                                .is_none()
                                .then(|| producer.context.literals.get("endpoint"))
                                .flatten()
                        })
                    {
                        dispatch
                            .context
                            .literals
                            .insert("endpoint".into(), value.clone());
                    }
                }
            } else {
                dispatch
                    .tags
                    .push("request-authority-after-hook-unresolved".into());
            }
        }
        if !dispatch.captures.contains_key("endpoint") {
            dispatch
                .tags
                .push("outbound-request:unresolved-producer".into());
        }
        dispatch
            .provenance
            .engine
            .push_str(" outbound-dispatch-accounting 1");
        dispatch.related_evidence.sort();
        dispatch.related_evidence.dedup();
        if let Some(index) = existing {
            evidence[index] = dispatch;
        } else {
            dispatches.push(dispatch);
        }
    }
    for (index, _) in producers {
        evidence[index].kind = EvidenceKind::Resource;
        evidence[index]
            .tags
            .push("outbound-request:construction-context".into());
    }
    evidence.extend(dispatches);
}

fn origin<'a>(
    root: &N<'a>,
    value: &N<'a>,
    producers: &[(usize, N<'a>)],
    depth: usize,
) -> Option<(usize, Option<(N<'a>, N<'a>)>)> {
    if depth == 0 {
        return None;
    }
    if let Some((index, _)) = producers
        .iter()
        .rev()
        .find(|(_, n)| n.range() == value.range())
    {
        return Some((*index, None));
    }
    if is_call(value)
        && method(value).is_some_and(|m| {
            matches!(
                m.as_str(),
                "build"
                    | "unwrap"
                    | "expect"
                    | "try_clone"
                    | "uri"
                    | "header"
                    | "headers"
                    | "query"
                    | "body"
                    | "json"
                    | "form"
                    | "timeout"
                    | "basic_auth"
                    | "bearer_auth"
                    | "version"
            )
        })
    {
        return origin(root, &receiver(value)?, producers, depth - 1);
    }
    if value.kind().as_ref() != "identifier" {
        return None;
    }
    let (declaration, initializer) = local_initializer(root, value)?;
    let (index, _) = origin(root, &initializer, producers, depth - 1)?;
    // Recursive alias resolution alone is insufficient: every alias must still
    // refer to its producer at the next binding site.
    if initializer.kind().as_ref() == "identifier" {
        let (previous, _) = local_initializer(root, &initializer)?;
        // Keep a known request consumer through aliases, but do not assume
        // shared mutable objects retain the original authority. The alias use
        // vetoes unchanged() and the dispatch retains an unresolved producer.
        return Some((index, Some((previous, initializer))));
    }
    Some((index, Some((declaration, value.clone()))))
}

fn local_initializer<'a>(root: &N<'a>, site: &N<'a>) -> Option<(N<'a>, N<'a>)> {
    root.dfs()
        .filter_map(|n| {
            let (name, value) = match n.kind().as_ref() {
                "let_declaration" => (n.field("pattern")?, n.field("value")?),
                "variable_declarator" => (n.field("name")?, n.field("value")?),
                "short_var_declaration" => (
                    n.field("left")?.children().find(|n| n.is_named())?,
                    n.field("right")?.children().find(|n| n.is_named())?,
                ),
                _ => return None,
            };
            (name.text() == site.text()
                && scope(&n) == scope(site)
                && n.range().end <= site.range().start
                && super::context::lexical_declaration_visible_at(&n, site))
            .then_some((n, value))
        })
        .max_by_key(|(n, _)| n.range().start)
}

fn unchanged(root: &N<'_>, declaration: &N<'_>, site: &N<'_>, consumer: &N<'_>) -> bool {
    root.dfs()
        .filter(|n| {
            n.kind().as_ref() == "identifier"
                && n.text() == site.text()
                && n.range().start >= declaration.range().end
                && n.range().end <= consumer.range().start
                && scope(n) == scope(site)
                && super::context::lexical_declaration_visible_at(declaration, n)
        })
        .all(|n| {
            // Earlier dispatch does not replace a request. All other uses,
            // including field writes, helpers, mutable aliases and conditional
            // URI setters, prevent carrying a fixed authority into this send.
            n.ancestors().find(is_call).is_some_and(|call| {
                matches!(
                    method(&call).as_deref(),
                    Some("Do" | "send" | "sendAsync" | "execute")
                ) && call
                    .field("arguments")
                    .is_some_and(|a| a.children().any(|a| a.range() == n.range()))
            })
        })
}

fn is_call(n: &N<'_>) -> bool {
    matches!(
        n.kind().as_ref(),
        "call_expression" | "method_invocation" | "object_creation_expression"
    )
}
fn method(n: &N<'_>) -> Option<String> {
    n.field("name")
        .or_else(|| {
            n.field("function")
                .and_then(|f| f.field("field").or_else(|| f.field("name")).or(Some(f)))
        })
        .map(|n| n.text().rsplit("::").next().unwrap_or_default().to_string())
}
fn receiver<'a>(n: &N<'a>) -> Option<N<'a>> {
    n.field("object").or_else(|| {
        n.field("function")
            .and_then(|f| f.field("value").or_else(|| f.field("operand")))
    })
}
fn scope(n: &N<'_>) -> Option<usize> {
    n.ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_item"
                    | "function_declaration"
                    | "method_declaration"
                    | "lambda_expression"
                    | "func_literal"
                    | "closure_expression"
            )
        })
        .map(|n| n.range().start)
}
