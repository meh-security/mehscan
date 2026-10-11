//! Cut demonstrably unused WebClient setup; returned/escaped publishers stay leads.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capture, Evidence, EvidenceKind, Language};
type N<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn annotate(language: Language, root: &N<'_>, evidence: &mut [Evidence]) {
    if !matches!(language, Language::Java | Language::Kotlin)
        || !evidence.iter().any(|e| {
            matches!(
                e.rule_id.as_str(),
                "java-spring-webclient-outbound-request" | "kotlin-webclient-uri"
            )
        })
    {
        return;
    }
    let identifiers = root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "identifier" | "simple_identifier"))
        .collect::<Vec<_>>();
    let calls = root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "method_invocation" | "call_expression"))
        .collect::<Vec<_>>();
    for item in evidence.iter_mut().filter(|e| {
        matches!(
            e.rule_id.as_str(),
            "java-spring-webclient-outbound-request" | "kotlin-webclient-uri"
        )
    }) {
        let Some(uri) = calls.iter().find(|n| {
            n.range() == (item.location.start.byte_offset..item.location.end.byte_offset)
        }) else {
            continue;
        };
        let mut top = (*uri).clone();
        let mut consumer = None;
        for parent in uri.ancestors() {
            if matches!(
                parent.kind().as_ref(),
                "method_invocation" | "call_expression"
            ) {
                // Follow the receiver chain only; an argument handoff is an escape.
                let receiver = parent.field("object").or_else(|| {
                    parent
                        .children()
                        .find(|n| n.is_named() && n.kind().as_ref() != "call_suffix")
                });
                if receiver.is_none_or(|r| {
                    r.range().start > uri.range().start || r.range().end < uri.range().end
                }) {
                    break;
                }
                if consumes(&method(&parent)) {
                    consumer = Some(parent.clone());
                }
                top = parent;
            } else if matches!(
                parent.kind().as_ref(),
                "navigation_expression"
                    | "postfix_expression"
                    | "parenthesized_expression"
                    | "unary_expression"
            ) {
                top = parent;
            } else {
                break;
            }
        }
        if let Some(consumer) = consumer {
            item.tags
                .push("outbound-request:observed-reactive-consumer".into());
            item.captures.insert(
                "consumer".into(),
                Capture {
                    text: consumer.text().into_owned(),
                    location: super::matcher::location(&item.location.path, &consumer),
                },
            );
            continue;
        }
        let declaration = top.ancestors().take(3).find(|n| {
            matches!(
                n.kind().as_ref(),
                "variable_declarator" | "property_declaration"
            )
        });
        let unused_local = declaration.as_ref().is_some_and(|declaration| {
            let Some(function) = declaration.ancestors().find(|n| {
                matches!(
                    n.kind().as_ref(),
                    "method_declaration" | "function_declaration"
                )
            }) else {
                return false;
            };
            // No field/member initializers. No assumption about aliases or wrappers.
            if declaration
                .ancestors()
                .take_while(|n| n.range() != function.range())
                .any(|n| matches!(n.kind().as_ref(), "class_body" | "field_declaration"))
            {
                return false;
            }
            let name = declaration.field("name").or_else(|| {
                declaration
                    .children()
                    .find(|n| n.kind().as_ref() == "variable_declaration")
                    .and_then(|n| {
                        n.children()
                            .find(|n| n.kind().as_ref() == "simple_identifier")
                    })
            });
            name.is_some_and(|name| {
                identifiers
                    .iter()
                    .filter(|n| {
                        n.text() == name.text()
                            && n.range().start >= function.range().start
                            && n.range().end <= function.range().end
                    })
                    .count()
                    == 1
            })
        });
        let discarded = top
            .parent()
            .is_some_and(|p| p.kind().as_ref() == "expression_statement")
            && top.dfs().any(|n| {
                matches!(n.kind().as_ref(), "method_invocation" | "call_expression")
                    && matches!(
                        method(&n).as_str(),
                        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "method"
                    )
            });
        if unused_local || discarded {
            item.kind = EvidenceKind::Resource;
            item.tags
                .push("outbound-request:unused-reactive-context".into());
        } else {
            item.tags
                .push("outbound-request:subscription-or-handoff-unresolved".into());
        }
    }
}
fn method(n: &N<'_>) -> String {
    n.field("name")
        .or_else(|| {
            n.children()
                .find(|n| n.is_named() && n.kind().as_ref() != "call_suffix")
        })
        .map(|n| n.text().rsplit('.').next().unwrap_or_default().to_owned())
        .unwrap_or_default()
}
fn consumes(method: &str) -> bool {
    matches!(
        method,
        "block"
            | "blockOptional"
            | "blockFirst"
            | "blockLast"
            | "subscribe"
            | "toFuture"
            | "awaitBody"
            | "awaitBodyOrNull"
            | "awaitEntity"
            | "awaitBodilessEntity"
            | "awaitExchange"
            | "awaitSingle"
            | "awaitSingleOrNull"
            | "awaitFirst"
            | "awaitFirstOrNull"
    )
}
