//! Lazy network objects are context. Their consumers own destination research.
use super::identity::{self, Imports, KNode};
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{Capture, Evidence};
use std::collections::BTreeMap;

pub(in crate::code) fn annotate<'a>(
    root: &KNode<'a>,
    literals: &crate::code::literals::LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut [Evidence],
) {
    if !evidence.iter().any(|e| {
        matches!(
            e.rule_id.as_str(),
            "kotlin-okhttp-dispatch" | "kotlin-url-connection-consumer"
        )
    }) {
        return;
    }
    let calls = root
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "call_expression" | "navigation_expression"
            )
        })
        .map(|n| ((n.range().start, n.range().end), n))
        .collect::<BTreeMap<_, _>>();
    let producers = evidence
        .iter()
        .filter(|e| {
            matches!(
                e.rule_id.as_str(),
                "kotlin-okhttp-request" | "kotlin-url-connection"
            )
        })
        .map(|e| {
            (
                (e.location.start.byte_offset, e.location.end.byte_offset),
                e.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let imports = Imports::build(root);
    for sink in evidence.iter_mut().filter(|e| {
        matches!(
            e.rule_id.as_str(),
            "kotlin-okhttp-dispatch" | "kotlin-url-connection-consumer"
        )
    }) {
        let Some(node) = calls.get(&(
            sink.location.start.byte_offset,
            sink.location.end.byte_offset,
        )) else {
            continue;
        };
        let Some(receiver) = identity::call(node)
            .and_then(|c| c.callee.children().find(|n| n.is_named()))
            .or_else(|| {
                (node.kind().as_ref() == "navigation_expression")
                    .then(|| node.children().find(|n| n.is_named()))
                    .flatten()
            })
        else {
            continue;
        };
        let okhttp = sink.rule_id == "kotlin-okhttp-dispatch";
        sink.tags.push("outbound-request:dispatch".into());
        let Some(producer) = origin(root, &receiver, &producers, 8) else {
            sink.tags
                .push("outbound-request:unresolved-producer".into());
            continue;
        };
        sink.related_evidence.push(producer.id.clone());
        let role = if okhttp { "request" } else { "endpoint" };
        let Some(captured) = producer.captures.get(role) else {
            continue;
        };
        let Some(value) = root.dfs().find(|n| {
            n.range() == (captured.location.start.byte_offset..captured.location.end.byte_offset)
                && n.kind().as_ref() != "value_argument"
        }) else {
            continue;
        };
        let endpoint = if okhttp {
            request_url(root, &imports, &value, 8)
        } else {
            url_input(root, &value, 8)
        };
        if okhttp {
            sink.captures.insert("request".into(), captured.clone());
            if let Some(client) = calls
                .get(&(
                    producer.location.start.byte_offset,
                    producer.location.end.byte_offset,
                ))
                .and_then(identity::call)
                .and_then(|c| c.callee.children().find(|n| n.is_named()))
            {
                sink.captures.insert(
                    "client".into(),
                    Capture {
                        text: client.text().into_owned(),
                        location: crate::code::matcher::location(&sink.location.path, &client),
                    },
                );
            }
        } else {
            sink.captures.insert(
                "connection".into(),
                Capture {
                    text: receiver.text().into_owned(),
                    location: crate::code::matcher::location(&sink.location.path, &receiver),
                },
            );
        }
        if let Some(endpoint) = endpoint {
            let capture = Capture {
                text: endpoint.text().into_owned(),
                location: crate::code::matcher::location(&sink.location.path, &endpoint),
            };
            // The URL in an immutable Request is still only the initial URL
            // when an opaque client/interceptor policy is supplied. Preserve
            // it as context without assigning a fixed effective destination.
            let plain = !okhttp
                || calls
                    .get(&(
                        producer.location.start.byte_offset,
                        producer.location.end.byte_offset,
                    ))
                    .and_then(identity::call)
                    .and_then(|c| c.callee.children().find(|n| n.is_named()))
                    .is_some_and(|client| plain_client(root, &imports, &client, 8));
            if plain {
                sink.context
                    .literals
                    .insert("endpoint".into(), literals.evaluate(&endpoint));
                sink.captures.insert("endpoint".into(), capture);
            } else {
                sink.captures.insert("initial_endpoint".into(), capture);
                sink.context.literals.remove("endpoint");
                sink.tags
                    .push("outbound-request:unresolved-client-policy".into());
            }
        } else {
            sink.tags
                .push("outbound-request:unresolved-producer".into());
        }
    }
}

fn local_value<'a>(root: &KNode<'a>, value: &KNode<'a>) -> Option<KNode<'a>> {
    if value.kind().as_ref() != "simple_identifier"
        || !identity::receiver_unchanged(root, value, &value.text())
    {
        return None;
    }
    let binding = identity::binding(root, value, &value.text())?;
    if identity::callable(&binding).map(|n| n.range())
        != identity::callable(value).map(|n| n.range())
    {
        return None;
    }
    let property = binding
        .parent()
        .filter(|n| n.kind().as_ref() == "property_declaration")?;
    if !property.children().any(|n| n.text().as_ref() == "val") {
        return None;
    }
    property
        .children()
        .filter(|n| n.is_named())
        .last()
        .filter(|n| n.range() != binding.range())
}

fn origin<'a>(
    root: &KNode<'a>,
    value: &KNode<'a>,
    producers: &BTreeMap<(usize, usize), Evidence>,
    depth: usize,
) -> Option<Evidence> {
    if depth == 0 {
        return None;
    }
    if let Some(e) = producers.get(&(value.range().start, value.range().end)) {
        return Some(e.clone());
    }
    if matches!(
        value.kind().as_ref(),
        "as_expression" | "parenthesized_expression"
    ) {
        return origin(
            root,
            &value.children().find(|n| n.is_named())?,
            producers,
            depth - 1,
        );
    }
    if let Some(call) = identity::call(value) {
        if call.callee.text().rsplit('.').next() == Some("clone")
            && call.arguments.is_empty()
            && super::jvm::owned(root, value, "okhttp3.Call", 8)
        {
            return origin(
                root,
                &call.callee.children().find(|n| n.is_named())?,
                producers,
                depth - 1,
            );
        }
        return None;
    }
    origin(root, &local_value(root, value)?, producers, depth - 1)
}

fn url_input<'a>(root: &KNode<'a>, value: &KNode<'a>, depth: usize) -> Option<KNode<'a>> {
    if depth == 0 {
        return None;
    }
    if let Some(local) = local_value(root, value) {
        return url_input(root, &local, depth - 1);
    }
    let operands = super::network::operands(root, value, depth)?;
    if operands.len() != 1 {
        return None;
    }
    let input = operands.into_iter().next()?;
    // URI.toURL retains the URI's input rather than an opaque URI slot.
    if super::network::known(root, &input, "java.net.URI", depth) {
        url_input(root, &input, depth - 1)
    } else {
        Some(input)
    }
}

fn request_url<'a>(
    root: &KNode<'a>,
    imports: &Imports,
    value: &KNode<'a>,
    depth: usize,
) -> Option<KNode<'a>> {
    if depth == 0 {
        return None;
    }
    if let Some(local) = local_value(root, value) {
        return request_url(root, imports, &local, depth - 1);
    }
    let call = identity::call(value)?;
    if call.callee.text().rsplit('.').next() != Some("build") || !call.arguments.is_empty() {
        return None;
    }
    let builder = call.callee.children().find(|n| n.is_named())?;
    builder_url(root, imports, &builder, depth - 1)
}

fn builder_owned(root: &KNode<'_>, imports: &Imports, value: &KNode<'_>, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    let Some(call) = identity::call(value) else {
        return false;
    };
    if call.arguments.is_empty()
        && imports.exact(root, value, &call.callee.text(), "okhttp3.Request.Builder")
    {
        return true;
    }
    let method = call
        .callee
        .text()
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_owned();
    let arity = call.arguments.len();
    let valid = match method.as_str() {
        "url" | "removeHeader" | "post" | "put" | "patch" | "cacheControl" => arity == 1,
        "header" | "addHeader" | "method" => arity == 2,
        "get" | "head" => arity == 0,
        "delete" => arity <= 1,
        "tag" => matches!(arity, 1 | 2),
        _ => false,
    };
    valid
        && call.arguments.iter().all(|a| a.name.is_none())
        && call
            .callee
            .children()
            .find(|n| n.is_named())
            .is_some_and(|r| builder_owned(root, imports, &r, depth - 1))
}

fn builder_url<'a>(
    root: &KNode<'a>,
    imports: &Imports,
    value: &KNode<'a>,
    depth: usize,
) -> Option<KNode<'a>> {
    if !builder_owned(root, imports, value, depth) {
        return None;
    }
    let call = identity::call(value)?;
    if call.callee.text().rsplit('.').next() == Some("url") {
        return call.arguments.first().map(|a| a.value.clone());
    }
    builder_url(
        root,
        imports,
        &call.callee.children().find(|n| n.is_named())?,
        depth - 1,
    )
}

fn plain_client<'a>(root: &KNode<'a>, imports: &Imports, value: &KNode<'a>, depth: usize) -> bool {
    if depth == 0 {
        return false;
    }
    if let Some(local) = local_value(root, value) {
        return plain_client(root, imports, &local, depth - 1);
    }
    let Some(call) = identity::call(value) else {
        return false;
    };
    if !call.arguments.is_empty() {
        return false;
    }
    if imports.exact(root, value, &call.callee.text(), "okhttp3.OkHttpClient") {
        return true;
    }
    if call.callee.text().rsplit('.').next() != Some("build") {
        return false;
    }
    let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    identity::call(&receiver).is_some_and(|c| {
        c.arguments.is_empty()
            && imports.exact(
                root,
                &receiver,
                &c.callee.text(),
                "okhttp3.OkHttpClient.Builder",
            )
    })
}
