use super::identity::{self, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

pub(super) fn accepts<'a>(root: &KNode<'a>, node: &KNode<'a>) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    if call.arguments.is_empty()
        || call.arguments.iter().any(|a| a.name.is_some())
        || call.callee.text().rsplit('.').next() != Some("uri")
    {
        return false;
    }
    let target = &call.arguments[0].value;
    if matches!(
        target.kind().as_ref(),
        "integer_literal"
            | "real_literal"
            | "boolean_literal"
            | "character_literal"
            | "null_literal"
    ) {
        return false;
    }
    if let Some(ty) = identity::binding_type(root, target, &target.text()) {
        let imports = super::identity::Imports::build(root);
        if [
            "kotlin.Int",
            "kotlin.Long",
            "kotlin.Double",
            "kotlin.Float",
            "kotlin.Boolean",
            "kotlin.Char",
        ]
        .iter()
        .any(|primitive| imports.exact(root, target, &ty, primitive))
        {
            return false;
        }
    }
    let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    [
        "org.springframework.web.reactive.function.client.WebClient.RequestHeadersUriSpec",
        "org.springframework.web.reactive.function.client.WebClient.RequestBodyUriSpec",
        "org.springframework.web.reactive.function.client.WebClient.UriSpec",
    ]
    .iter()
    .any(|ty| super::jvm::owned(root, &receiver, ty, 12))
}

pub(crate) fn facts(path: &str, source: &str, anchor: &Evidence) -> Vec<ReviewNeighborhoodFact> {
    if anchor.rule_id != "kotlin-webclient-uri" {
        return vec![];
    }
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
    if !accepts(&root, &node) {
        return vec![];
    }
    let Some(function) = node
        .ancestors()
        .find(|n| n.kind().as_ref() == "function_declaration")
    else {
        return vec![];
    };
    if function.range().len() > 16384 {
        return vec![];
    }
    let mut facts = vec![ReviewNeighborhoodFact {
        role: "webclient_containing_function_context".into(),
        symbol: identity::name(&function).unwrap_or_default(),
        location: crate::code::matcher::location(path, &function),
        excerpt: format!(
            "Exact containing function for this owned WebClient URI boundary. Inspect String templates and variable binding, URI or builder overloads, base URI/default-request/filter effects, same-spec replacements and exchange subscription. uri sets a lazy request destination; retrieve alone does not prove subscription. Returned publishers are source consumer context, not deployed dispatch or native reactive flow. Co-occurrence does not prove same-request identity.\n{}",
            function.text()
        ),
        evidence_id: Some(anchor.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin WebClient URI ownership and bounded containing function 1".into(),
        },
    }];
    if let Some(contract) = overload_contract(&root, &node) {
        facts.push(ReviewNeighborhoodFact {
            role: "webclient_uri_overload_context".into(),
            symbol: contract.into(),
            location: crate::code::matcher::location(path, &node),
            excerpt: format!("Argument representation derived from the shown syntax/declaration; verified default Spring WebClient implementation contract: {contract}. A custom implementation or different SDK requires its implementation evidence; this does not prove compiler dispatch, destination approval or subscription.\n{}", node.text()),
            evidence_id: Some(anchor.id.clone()),
            provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin WebClient declared argument representation and default SDK URI entry point 1".into() },
        });
    }
    for helper in helper_candidates(&root, &function) {
        facts.push(ReviewNeighborhoodFact {
            role: "webclient_local_helper_candidate_context".into(),
            symbol: identity::name(&helper).unwrap_or_default(),
            location: crate::code::matcher::location(path, &helper),
            excerpt: format!("Single visible same-file top-level declaration matching a shown direct call's name and arity. Inspect the caller and this body together; lexical candidate context does not prove compiler dispatch, helper effects or native cross-call flow.\n{}", helper.text()),
            evidence_id: Some(anchor.id.clone()),
            provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin bounded direct local helper candidate context 1".into() },
        });
    }
    for node in function
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        let Some(call) = identity::call(&node) else {
            continue;
        };
        if call.callee.text().rsplit('.').next() != Some("url") || call.arguments.len() != 1 {
            continue;
        }
        let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
            continue;
        };
        if !super::jvm::owned(
            &root,
            &receiver,
            "org.springframework.web.reactive.function.client.ClientRequest.Builder",
            8,
        ) {
            continue;
        }
        facts.push(ReviewNeighborhoodFact {
            role: "webclient_request_mutation_context".into(),
            symbol: call.arguments[0].value.text().into_owned(),
            location: crate::code::matcher::location(path, &node),
            excerpt: format!("Shown owned ClientRequest builder URL mutation. This is a candidate filter effect, not proof that the replacement is forwarded or becomes the final exchanged destination; inspect next.exchange identity and filter order in the containing function.\n{}", node.text()),
            evidence_id: Some(anchor.id.clone()),
            provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin owned ClientRequest URL mutation source inventory 1".into() },
        });
        if let Some(exchange) = node.ancestors().find(|ancestor| {
            identity::call(ancestor).is_some_and(|call| {
                call.callee.text().rsplit('.').next() == Some("exchange")
                    && call.arguments.len() == 1
                    && call.arguments[0].value.range().start <= node.range().start
                    && node.range().end <= call.arguments[0].value.range().end
            })
        }) {
            facts.push(ReviewNeighborhoodFact {
                role: "webclient_direct_exchange_argument_context".into(),
                symbol: identity::call(&exchange).unwrap().callee.text().into_owned(),
                location: crate::code::matcher::location(path, &exchange),
                excerpt: format!("Established AST argument relationship: the constructed request containing this URL mutation is passed directly as the sole argument of the shown exchange call. Inspect its receiver binding and enclosing filter chain; for a shown SDK filter next.exchange this is source evidence of forwarding, not an unresolved missing argument. It does not prove runtime dispatch, final filter order, subscription or deployed activation.\n{}", exchange.text()),
                evidence_id: Some(anchor.id.clone()),
                provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin exact enclosing exchange argument relationship 1".into() },
            });
        }
        if facts
            .iter()
            .filter(|f| f.role == "webclient_request_mutation_context")
            .count()
            == 4
        {
            break;
        }
    }
    facts
}

fn overload_contract<'a>(root: &KNode<'a>, node: &KNode<'a>) -> Option<&'static str> {
    let call = identity::call(node)?;
    let target = &call.arguments.first()?.value;
    let imports = super::identity::Imports::build(root);
    let string = target.kind().as_ref() == "string_literal"
        || identity::binding_type(root, target, &target.text())
            .is_some_and(|ty| imports.exact(root, target, &ty, "kotlin.String"));
    if string {
        return Some(
            "String URI templates call the configured UriBuilderFactory.uriString(template), then build or invoke the supplied builder function. The factory's expand overloads are not invoked by this String entry point",
        );
    }
    if super::network::known(root, target, "java.net.URI", 8)
        || identity::binding_type(root, target, &target.text())
            .is_some_and(|ty| imports.exact(root, target, &ty, "java.net.URI"))
    {
        return Some(
            "the URI-valued overload installs the supplied URI directly and does not invoke the configured factory's uriString or expand overrides",
        );
    }
    if target.kind().as_ref() == "lambda_literal" {
        return Some(
            "a URI-function argument receives the configured factory's builder; its shown return value determines the URI, not an assumed fixed factory destination",
        );
    }
    None
}

fn helper_candidates<'a>(root: &KNode<'a>, function: &KNode<'a>) -> Vec<KNode<'a>> {
    let mut helpers = vec![];
    for node in function
        .dfs()
        .filter(|n| n.kind().as_ref() == "call_expression")
    {
        let Some(call) = identity::call(&node) else {
            continue;
        };
        if call.callee.kind().as_ref() != "simple_identifier"
            || call.arguments.iter().any(|a| a.name.is_some())
            || identity::binding(root, &node, &call.callee.text()).is_some()
        {
            continue;
        }
        let candidates = root
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "function_declaration"
                    && identity::name(n).as_deref() == Some(call.callee.text().as_ref())
                    && identity::visible(n, &node)
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            continue;
        }
        let helper = &candidates[0];
        if helper
            .parent()
            .is_none_or(|p| p.kind().as_ref() != "source_file")
            || helper.range().len() > 8192
            || identity::named_child(helper, "receiver_type").is_some()
            || identity::named_child(helper, "function_value_parameters").map_or(0, |p| {
                p.children()
                    .filter(|n| n.kind().as_ref() == "parameter")
                    .count()
            }) != call.arguments.len()
            || helpers
                .iter()
                .any(|n: &KNode<'_>| n.range() == helper.range())
        {
            continue;
        }
        helpers.push(helper.clone());
        if helpers.len() == 4 {
            break;
        }
    }
    helpers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overload_contract_follows_anchor_argument_not_neighboring_calls() {
        let source = "import java.net.URI\nfun f(spec: Any, target: String, uri: URI, unknown: Any) { spec.uri(target); spec.uri(uri); spec.uri(URI.create(target)); spec.uri { b -> URI.create(target) }; spec.uri(unknown) }";
        let ast = SupportLang::Kotlin.ast_grep(source);
        let root = ast.root();
        for (text, expected) in [
            ("spec.uri(target)", Some("String URI templates")),
            ("spec.uri(uri)", Some("the URI-valued overload")),
            (
                "spec.uri(URI.create(target))",
                Some("the URI-valued overload"),
            ),
            (
                "spec.uri { b -> URI.create(target) }",
                Some("a URI-function argument"),
            ),
            ("spec.uri(unknown)", None),
        ] {
            let node = root
                .dfs()
                .find(|n| n.kind().as_ref() == "call_expression" && n.text().as_ref() == text)
                .unwrap();
            assert_eq!(
                overload_contract(&root, &node).map(|s| expected.is_some_and(|e| s.starts_with(e))),
                expected.map(|_| true),
                "{text}"
            );
        }
    }

    #[test]
    fn helper_context_excludes_overloads_local_shadowing_and_unrelated_calls() {
        for (source, expected) in [
            ("fun helper() = 1\nfun consumer() { helper() }", 1),
            (
                "fun helper() = 1\nfun helper(x: Int) = x\nfun consumer() { helper() }",
                0,
            ),
            (
                "fun helper() = 1\nfun consumer(helper: () -> Int) { helper() }",
                0,
            ),
            (
                "fun helper() = 1\nfun other() { helper() }\nfun consumer() { println(1) }",
                0,
            ),
            (
                "class Other { fun helper() = 1 }\nfun consumer(other: Other) { other.helper() }",
                0,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let function = root
                .dfs()
                .find(|n| {
                    n.kind().as_ref() == "function_declaration"
                        && identity::name(n).as_deref() == Some("consumer")
                })
                .unwrap();
            assert_eq!(
                helper_candidates(&root, &function).len(),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn uri_ownership_keeps_factories_aliases_and_foreign_overloads_separate() {
        let imports = "import org.springframework.web.reactive.function.client.WebClient as WC\n";
        for (body, target, expected) in [
            (
                "fun f(s: String) { WC.builder().clone().build().get().uri(s) }",
                "WC.builder().clone().build().get().uri(s)",
                true,
            ),
            (
                "fun f(s: String) { WC.builder().defaultHeader(\"X-Test\").build().get().uri(s) }",
                "WC.builder().defaultHeader(\"X-Test\").build().get().uri(s)",
                true,
            ),
            (
                "fun f(s: String) { WC.builder().defaultCookie(\"test\").build().get().uri(s) }",
                "WC.builder().defaultCookie(\"test\").build().get().uri(s)",
                true,
            ),
            (
                "fun f(s: String) { WC.builder().apply { b -> b.baseUrl(s) }.build().get().uri(s) }",
                "WC.builder().apply { b -> b.baseUrl(s) }.build().get().uri(s)",
                true,
            ),
            (
                "fun f(s: String, strategies: org.springframework.web.reactive.function.client.ExchangeStrategies) { WC.builder().exchangeStrategies(strategies).build().get().uri(s) }",
                "WC.builder().exchangeStrategies(strategies).build().get().uri(s)",
                true,
            ),
            (
                "fun f(s: String) { WC.builder().defaultApiVersion(1).build().get().uri(s) }",
                "WC.builder().defaultApiVersion(1).build().get().uri(s)",
                true,
            ),
            (
                "fun f(s: String, inserter: org.springframework.web.client.ApiVersionInserter) { WC.builder().apiVersionInserter(inserter).build().get().uri(s) }",
                "WC.builder().apiVersionInserter(inserter).build().get().uri(s)",
                true,
            ),
            (
                "fun f(s: String) { WC.builder().defaultStatusHandler({ false }, { reactor.core.publisher.Mono.just(IllegalArgumentException()) }).build().get().uri(s) }",
                "WC.builder().defaultStatusHandler({ false }, { reactor.core.publisher.Mono.just(IllegalArgumentException()) }).build().get().uri(s)",
                true,
            ),
            (
                "fun f(c: WC, s: String) { c.get().uri(s) }",
                "c.get().uri(s)",
                true,
            ),
            (
                "fun f(s: String) { WC.create().post().uri(s) }",
                "WC.create().post().uri(s)",
                true,
            ),
            (
                "fun f(s: String) { val c = WC.builder().baseUrl(s).build(); val spec = c.get(); spec.uri(s) }",
                "spec.uri(s)",
                true,
            ),
            (
                "fun f(c: WC, s: String) { c.mutate().baseUrl(s).build().get().uri(s) }",
                "c.mutate().baseUrl(s).build().get().uri(s)",
                true,
            ),
            (
                "fun f(spec: WC.RequestHeadersUriSpec<*>, s: String) { spec.uri(s) }",
                "spec.uri(s)",
                true,
            ),
            (
                "fun f(c: WC, s: String) { c.get().uri { b -> java.net.URI.create(s) } }",
                "c.get().uri { b -> java.net.URI.create(s) }",
                true,
            ),
            (
                "class Other\nfun f(c: Other, s: String) { c.get().uri(s) }",
                "c.get().uri(s)",
                false,
            ),
            (
                "fun f(s: String) { val c = helper(); c.get().uri(s) }",
                "c.get().uri(s)",
                false,
            ),
            (
                "fun f(s: String) { var c = WC.create(); c.get().uri(s) }",
                "c.get().uri(s)",
                false,
            ),
            (
                "fun f(c: WC) { c.get().uri(123) }",
                "c.get().uri(123)",
                false,
            ),
            (
                "fun f(c: WC) { c.get().uri(true) }",
                "c.get().uri(true)",
                false,
            ),
            (
                "fun f(c: WC) { c.get().uri(null) }",
                "c.get().uri(null)",
                false,
            ),
            (
                "fun f(c: WC) { c.get().uri('x') }",
                "c.get().uri('x')",
                false,
            ),
            (
                "fun f(c: WC, value: Int) { c.get().uri(value) }",
                "c.get().uri(value)",
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
            assert_eq!(accepts(&root, &node), expected, "{source}");
        }
    }
}
