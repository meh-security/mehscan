//! Unused synchronous signing results are context, not issued credentials.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, EvidenceKind, Language};
type N<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn annotate(
    language: Language,
    root: &N<'_>,
    symbols: &super::symbols::FileSymbolEnvironment,
    evidence: &mut [Evidence],
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx | Language::Kotlin
    ) || !evidence.iter().any(|e| issuance_rule(&e.rule_id))
    {
        return;
    }
    let calls = root
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
        .collect::<Vec<_>>();
    let identifiers = root
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "identifier" | "simple_identifier" | "shorthand_property_identifier"
            )
        })
        .collect::<Vec<_>>();
    for item in evidence.iter_mut().filter(|e| issuance_rule(&e.rule_id)) {
        let Some(call) = calls.iter().find(|n| {
            n.range() == (item.location.start.byte_offset..item.location.end.byte_offset)
        }) else {
            continue;
        };
        if language != Language::Kotlin {
            let Some(function) = call.field("function") else {
                continue;
            };
            let observed = function.text().replace(' ', "");
            if symbols.resolve(&observed, "jsonwebtoken.sign").is_none()
                || symbols.has_shadowing_parameter(call, &observed, language)
            {
                continue;
            }
            let Some(arguments) = call.field("arguments") else {
                continue;
            };
            let args = arguments
                .children()
                .filter(|n| n.is_named())
                .collect::<Vec<_>>();
            // jsonwebtoken accepts a callback in position 3 or 4. Unknown options
            // can be callbacks; do not call asynchronous delivery "unused".
            if args.len() != 2 && !(args.len() == 3 && args[2].kind().as_ref() == "object") {
                continue;
            }
            if call
                .parent()
                .is_some_and(|n| n.kind().as_ref() == "expression_statement")
            {
                mark(item);
                continue;
            }
        }
        let mut top = (*call).clone();
        while let Some(parent) = top
            .parent()
            .filter(|n| n.kind().as_ref() == "parenthesized_expression")
        {
            top = parent;
        }
        let Some(declaration) = top.parent().filter(|n| {
            matches!(
                n.kind().as_ref(),
                "variable_declarator" | "property_declaration"
            )
        }) else {
            continue;
        };
        let Some(function) = declaration.ancestors().find(|n| {
            matches!(
                n.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        }) else {
            continue;
        };
        if declaration
            .ancestors()
            .take_while(|n| n.range() != function.range())
            .any(|n| matches!(n.kind().as_ref(), "class_body" | "field_declaration"))
        {
            continue;
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
        if let Some(name) =
            name.filter(|n| matches!(n.kind().as_ref(), "identifier" | "simple_identifier"))
        {
            let uses = identifiers
                .iter()
                .filter(|n| {
                    n.text() == name.text()
                        && n.range().start >= function.range().start
                        && n.range().end <= function.range().end
                })
                .count();
            if uses == 1 {
                mark(item);
            }
        }
    }
}
fn issuance_rule(id: &str) -> bool {
    id.ends_with("-jwt-hardcoded-signing-key")
        || matches!(
            id,
            "javascript-jwt-token-generation"
                | "typescript-jwt-token-generation"
                | "tsx-jwt-token-generation"
                | "kotlin-auth0-jwt-token-generation"
        )
}
fn mark(item: &mut Evidence) {
    item.kind = EvidenceKind::Resource;
    item.tags
        .push("token-issuance:unused-result-context".into());
}
