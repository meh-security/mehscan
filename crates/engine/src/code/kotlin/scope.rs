use super::identity::{self, Imports};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

/// Lexical standard-library scope candidate and its containing function, for
/// source review only. Compiler identity and helper effects are not inferred.
pub(crate) fn facts(path: &str, source: &str, anchor: &Evidence) -> Vec<ReviewNeighborhoodFact> {
    let ast = SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(node) = root.dfs().find(|n| {
        n.range() == (anchor.location.start.byte_offset..anchor.location.end.byte_offset)
    }) else {
        return vec![];
    };
    let imports = Imports::build(&root);
    let mut result = vec![];
    for lambda in node
        .ancestors()
        .filter(|n| n.kind().as_ref() == "lambda_literal")
        .take(4)
    {
        let Some(call_node) = lambda
            .ancestors()
            .skip(1)
            .find(|n| n.kind().as_ref() == "call_expression")
        else {
            continue;
        };
        let Some(call) = identity::call(&call_node) else {
            continue;
        };
        if call
            .arguments
            .last()
            .is_none_or(|a| a.value.range() != lambda.range())
        {
            continue;
        }
        let text = call.callee.text();
        let Some((receiver, method)) = text.rsplit_once('.') else {
            continue;
        };
        // Kotlin members take precedence over imported extensions. A typed
        // application receiver needs compiler/member resolution before we may
        // call its same-named lambda a standard-library scope function.
        if identity::binding_type(&root, &call_node, receiver)
            .is_some_and(|ty| !matches!(ty.as_str(), "String" | "kotlin.String"))
        {
            continue;
        }
        let Some(canonical) = [
            "kotlin.let",
            "kotlin.also",
            "kotlin.apply",
            "kotlin.run",
            "kotlin.takeIf",
            "kotlin.takeUnless",
        ]
        .into_iter()
        .find(|canonical| {
            imports.exact(&root, &call_node, method, canonical)
                || method == canonical.rsplit('.').next().unwrap()
                    && imports.default_extension(&root, &call_node, method, canonical)
        }) else {
            continue;
        };
        let Some(function) = call_node
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_declaration")
        else {
            continue;
        };
        if function.range().len() > 16384 {
            continue;
        }
        result.push(ReviewNeighborhoodFact {
            role: "stdlib_scope_call_context".into(), symbol: canonical.into(),
            location: crate::code::matcher::location(path, &call_node),
            excerpt: format!("The imports and lexical declarations support {canonical} as this lambda's scope-call candidate. Receiver member precedence, inferred receiver types and inherited members still require source review; this is not compiler-resolved identity. Judge receiver binding, explicit/implicit lambda parameters, returned expressions and mutations from the supplied function. This is source context, not an inferred helper effect or native cross-call path.\n{}", call_node.text()),
            evidence_id: Some(anchor.id.clone()),
            provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin lexical standard scope lambda candidate; non-flow context 1".into() },
        });
        result.push(ReviewNeighborhoodFact { role: "stdlib_scope_function_context".into(), symbol: identity::name(&function).unwrap_or_default(), location: crate::code::matcher::location(path, &function), excerpt: function.text().into_owned(), evidence_id: Some(anchor.id.clone()), provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin bounded containing function for exact standard scope lambda; non-flow context 1".into() } });
    }
    result
}
