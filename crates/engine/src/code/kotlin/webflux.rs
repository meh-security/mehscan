use super::identity::{self, Imports, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

const REQUEST: &str = "org.springframework.web.reactive.function.server.ServerRequest";

pub(super) fn accepts<'a>(root: &KNode<'a>, rule: &str, node: &KNode<'a>) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    if call.arguments.len() != 1 || call.arguments[0].name.is_some() {
        return false;
    }
    let text = call.callee.text();
    let Some((_, method)) = text.rsplit_once('.') else {
        return false;
    };
    let expected = match rule {
        "kotlin-webflux-query-source" => "queryParam",
        "kotlin-webflux-path-source" => "pathVariable",
        "kotlin-webflux-text-body-source" => "bodyToMono",
        _ => return false,
    };
    if method != expected {
        return false;
    }
    let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    if !super::jvm::owned(root, &receiver, REQUEST, 8) {
        return false;
    }
    if method == "bodyToMono" {
        let argument = call.arguments[0].value.text();
        return argument
            .strip_suffix("::class.java")
            .is_some_and(|ty| Imports::build(root).exact(root, node, ty, "kotlin.String"));
    }
    true
}

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
    if !anchor.rule_id.starts_with("kotlin-webflux-") {
        let Some(function) = node
            .ancestors()
            .find(|n| n.kind().as_ref() == "function_declaration")
        else {
            return vec![];
        };
        if function.range().len() > 16384
            || !function.dfs().any(|n| {
                n.kind().as_ref() == "call_expression"
                    && [
                        "kotlin-webflux-query-source",
                        "kotlin-webflux-path-source",
                        "kotlin-webflux-text-body-source",
                    ]
                    .iter()
                    .any(|rule| accepts(&root, rule, &n))
            })
        {
            return vec![];
        }
        return vec![ReviewNeighborhoodFact {
            role: "webflux_containing_function_context".into(),
            symbol: identity::name(&function).unwrap_or_default(),
            location: crate::code::matcher::location(path, &function),
            excerpt: format!(
                "Exact containing function for this anchor includes a canonical ServerRequest source. queryParam returns Optional<String>, pathVariable returns String, and bodyToMono(String::class.java) returns Mono<String>. Inspect unwrap/default, operator binding and consumer identity in this function; co-occurrence does not establish flow, subscription or deployed routing. This is not a native cross-lambda path.\n{}",
                function.text()
            ),
            evidence_id: Some(anchor.id.clone()),
            provenance: QueryProvenance {
                resolution: Resolution::Ast,
                engine: "Kotlin WebFlux bounded containing function source context 1".into(),
            },
        }];
    }
    if !accepts(&root, &anchor.rule_id, &node) {
        return vec![];
    }
    let representation = match anchor.rule_id.as_str() {
        "kotlin-webflux-query-source" => {
            "Optional<String>: inspect the shown unwrap/default before treating it as a scalar"
        }
        "kotlin-webflux-path-source" => "String path variable",
        _ => {
            "Mono<String>: subscription and operator binding must be supplied before claiming a scalar consumer"
        }
    };
    vec![ReviewNeighborhoodFact {
        role: "webflux_request_representation_context".into(),
        symbol: representation.into(),
        location: crate::code::matcher::location(path, &node),
        excerpt: format!(
            "Canonical ServerRequest source returns {representation}. Source inventory does not establish a native Optional/Mono unwrap, reactive operator effect, subscription or deployed routing.\n{}",
            node.text()
        ),
        evidence_id: Some(anchor.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin WebFlux canonical request source and explicit representation 1".into(),
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sources_require_owned_receivers_and_exact_text_decoder() {
        for (imports, body, target, rule, expected) in [
            (
                "import org.springframework.web.reactive.function.server.ServerRequest as Req\n",
                "fun f(request: Req) { val alias = request; alias.queryParam(\"url\") }",
                "alias.queryParam(\"url\")",
                "kotlin-webflux-query-source",
                true,
            ),
            (
                "",
                "fun f(request: org.springframework.web.reactive.function.server.ServerRequest) { request.pathVariable(\"p\") }",
                "request.pathVariable(\"p\")",
                "kotlin-webflux-path-source",
                true,
            ),
            (
                "import org.springframework.web.reactive.function.server.ServerRequest\n",
                "fun f(request: ServerRequest) { request.bodyToMono(String::class.java) }",
                "request.bodyToMono(String::class.java)",
                "kotlin-webflux-text-body-source",
                true,
            ),
            (
                "import org.springframework.web.reactive.function.server.ServerRequest\n",
                "fun f(request: ServerRequest) { request.bodyToMono(Int::class.java) }",
                "request.bodyToMono(Int::class.java)",
                "kotlin-webflux-text-body-source",
                false,
            ),
            (
                "import org.springframework.web.reactive.function.server.ServerRequest\n",
                "class String\nfun f(request: ServerRequest) { request.bodyToMono(String::class.java) }",
                "request.bodyToMono(String::class.java)",
                "kotlin-webflux-text-body-source",
                false,
            ),
            (
                "",
                "class ServerRequest\nfun f(request: ServerRequest) { request.queryParam(\"url\") }",
                "request.queryParam(\"url\")",
                "kotlin-webflux-query-source",
                false,
            ),
            (
                "import org.springframework.web.reactive.function.server.ServerRequest\n",
                "fun f(request: ServerRequest) { var alias = request; alias.queryParam(\"url\") }",
                "alias.queryParam(\"url\")",
                "kotlin-webflux-query-source",
                false,
            ),
        ] {
            let source = format!("{imports}{body}");
            let ast = SupportLang::Kotlin.ast_grep(&source);
            let root = ast.root();
            let node = root
                .dfs()
                .find(|n| n.kind().as_ref() == "call_expression" && n.text().as_ref() == target)
                .unwrap();
            assert_eq!(accepts(&root, rule, &node), expected, "{source}");
        }
    }
}
