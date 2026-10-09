//! Bounded libcurl transfer accounting; options are supporting context.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capture, Evidence, Language};
type N<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn annotate<'a>(language: Language, root: &N<'a>, evidence: &mut Vec<Evidence>) {
    if !matches!(language, Language::C | Language::Cpp) {
        return;
    }
    let calls = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
        .collect::<Vec<_>>();
    let local_api = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "function_definition")
        .filter_map(|n| n.field("declarator"))
        .filter_map(|n| n.field("declarator"))
        .map(|n| n.text().into_owned())
        .collect::<Vec<_>>();
    let at = |e: &Evidence| {
        calls
            .iter()
            .find(|n| n.range() == (e.location.start.byte_offset..e.location.end.byte_offset))
    };
    let configs = evidence
        .iter()
        .filter(|e| {
            matches!(
                e.rule_id.as_str(),
                "c-libcurl-outbound-request" | "cpp-libcurl-outbound-request"
            )
        })
        .filter_map(|e| Some((e.clone(), at(e)?.clone())))
        .collect::<Vec<_>>();
    let mut additions = Vec::new();
    evidence.retain(|e| {
        !matches!(
            e.rule_id.as_str(),
            "c-libcurl-request-dispatch" | "cpp-libcurl-request-dispatch"
        ) || at(e).is_none_or(|n| !local_api.contains(&api(n)))
    });
    for item in evidence.iter_mut().filter(|e| {
        matches!(
            e.rule_id.as_str(),
            "c-libcurl-request-dispatch" | "cpp-libcurl-request-dispatch"
        )
    }) {
        let Some(consumer) = at(item) else {
            continue;
        };
        let args = arguments(consumer);
        let Some(handle) = args.first() else {
            continue;
        };
        if api(consumer) == "curl_easy_perform" {
            attach(root, &calls, &configs, consumer, handle, item);
            continue;
        }
        // A multi pump consumes the easy handles added to that same local multi.
        // No cross-file loop/heap simulation, or inference from wait/info APIs.
        let mut handles = Vec::new();
        for add in calls.iter().filter(|n| {
            api(n) == "curl_multi_add_handle"
                && n.range().end <= consumer.range().start
                && scope(n) == scope(consumer)
        }) {
            let a = arguments(add);
            if a.len() != 2 || !same_binding(root, &a[0], handle) {
                continue;
            }
            if calls.iter().any(|n| {
                api(n) == "curl_multi_remove_handle"
                    && n.range().start > add.range().end
                    && n.range().end < consumer.range().start
                    && scope(n) == scope(consumer)
                    && arguments(n)
                        .first()
                        .is_some_and(|m| same_binding(root, m, handle))
                    && arguments(n)
                        .get(1)
                        .is_some_and(|e| same_binding(root, e, &a[1]))
            }) {
                continue;
            }
            if !handles.iter().any(|h| same_binding(root, h, &a[1])) {
                handles.push(a[1].clone());
            }
        }
        if handles.is_empty() {
            item.tags
                .push("outbound-request:unresolved-producer".into());
            continue;
        }
        let template = item.clone();
        for (index, easy) in handles.iter().enumerate() {
            let mut dispatch = template.clone();
            dispatch.captures.insert(
                "multi".into(),
                Capture {
                    text: handle.text().into_owned(),
                    location: super::matcher::location(&item.location.path, handle),
                },
            );
            attach(root, &calls, &configs, consumer, easy, &mut dispatch);
            if index == 0 {
                *item = dispatch;
            } else {
                dispatch.id = format!("{}:handle:{}", template.id, easy.range().start);
                additions.push(dispatch);
            }
        }
    }
    evidence.extend(additions);
}

fn attach<'a>(
    root: &N<'a>,
    _calls: &[N<'a>],
    configs: &[(Evidence, N<'a>)],
    consumer: &N<'a>,
    handle: &N<'a>,
    item: &mut Evidence,
) {
    item.captures.insert(
        "client".into(),
        Capture {
            text: handle.text().into_owned(),
            location: super::matcher::location(&item.location.path, handle),
        },
    );
    let config = configs
        .iter()
        .filter(|(_, n)| {
            n.range().end <= consumer.range().start
                && scope(n) == scope(consumer)
                && arguments(n)
                    .first()
                    .is_some_and(|h| same_binding(root, h, handle))
        })
        .max_by_key(|(_, n)| n.range().start);
    let Some((producer, setup)) = config else {
        item.tags
            .push("outbound-request:unresolved-producer".into());
        return;
    };
    item.related_evidence.push(producer.id.clone());
    let stable = !setup.ancestors().any(|n| {
        matches!(
            n.kind().as_ref(),
            "if_statement" | "switch_statement" | "conditional_expression"
        )
    }) && root
        .dfs()
        .filter(|n| {
            n.kind().as_ref() == "identifier"
                && n.range().start > binding(root, handle).unwrap_or(setup.range().end)
                && n.range().end < consumer.range().start
                && same_binding(root, n, handle)
        })
        .all(|n| {
            n.ancestors()
                .find(|c| c.kind().as_ref() == "call_expression")
                .is_some_and(|c| {
                    let a = arguments(&c);
                    match api(&c).as_str() {
                        "curl_easy_setopt" => {
                            a.first().is_some_and(|h| h.range() == n.range())
                                && a.get(1).is_some_and(|option| {
                                    matches!(
                                        option.text().as_ref(),
                                        "CURLOPT_URL"
                                            | "CURLOPT_TIMEOUT"
                                            | "CURLOPT_TIMEOUT_MS"
                                            | "CURLOPT_CONNECTTIMEOUT"
                                            | "CURLOPT_CONNECTTIMEOUT_MS"
                                            | "CURLOPT_WRITEFUNCTION"
                                            | "CURLOPT_WRITEDATA"
                                            | "CURLOPT_READFUNCTION"
                                            | "CURLOPT_READDATA"
                                            | "CURLOPT_POST"
                                            | "CURLOPT_POSTFIELDS"
                                            | "CURLOPT_POSTFIELDSIZE"
                                            | "CURLOPT_HTTPHEADER"
                                            | "CURLOPT_NOBODY"
                                            | "CURLOPT_FOLLOWLOCATION"
                                            | "CURLOPT_SSL_VERIFYPEER"
                                            | "CURLOPT_SSL_VERIFYHOST"
                                    )
                                })
                        }
                        "curl_easy_perform" | "curl_easy_getinfo" => {
                            a.first().is_some_and(|h| h.range() == n.range())
                        }
                        "curl_multi_add_handle" => a.get(1).is_some_and(|h| h.range() == n.range()),
                        _ => false,
                    }
                })
        });
    if stable {
        if let Some(endpoint) = producer.captures.get("endpoint") {
            item.captures.insert("endpoint".into(), endpoint.clone());
        }
        if let Some(value) = producer.context.literals.get("endpoint") {
            item.context
                .literals
                .insert("endpoint".into(), value.clone());
        }
    } else {
        item.related_evidence.extend(
            configs
                .iter()
                .filter(|(_, n)| {
                    n.range().end <= consumer.range().start
                        && scope(n) == scope(consumer)
                        && arguments(n)
                            .first()
                            .is_some_and(|h| same_binding(root, h, handle))
                })
                .map(|(e, _)| e.id.clone()),
        );
        item.related_evidence.sort();
        item.related_evidence.dedup();
        item.tags
            .push("outbound-request:unresolved-producer".into());
    }
}
fn api(n: &N<'_>) -> String {
    n.field("function")
        .map(|n| n.text().into_owned())
        .unwrap_or_default()
}
fn arguments<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.field("arguments")
        .map(|a| a.children().filter(|n| n.is_named()).collect())
        .unwrap_or_default()
}
fn scope(n: &N<'_>) -> Option<usize> {
    n.ancestors()
        .find(|n| n.kind().as_ref() == "function_definition")
        .map(|n| n.range().start)
}
fn binding<'a>(root: &N<'a>, site: &N<'a>) -> Option<usize> {
    root.dfs()
        .filter(|n| {
            n.kind().as_ref() == "identifier"
                && n.text() == site.text()
                && n.range().start < site.range().start
                && scope(n) == scope(site)
                && n.parent().is_some_and(|p| {
                    matches!(
                        p.kind().as_ref(),
                        "pointer_declarator" | "init_declarator" | "parameter_declaration"
                    )
                })
        })
        .filter(|n| {
            n.ancestors()
                .any(|p| p.kind().as_ref() == "parameter_declaration")
                || super::context::lexical_declaration_visible_at(n, site)
        })
        .map(|n| n.range().start)
        .max()
}
fn same_binding<'a>(root: &N<'a>, left: &N<'a>, right: &N<'a>) -> bool {
    left.kind().as_ref() == "identifier"
        && right.kind().as_ref() == "identifier"
        && left.text() == right.text()
        && scope(left) == scope(right)
        && binding(root, left) == binding(root, right)
}
