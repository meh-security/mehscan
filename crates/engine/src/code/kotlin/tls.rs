use super::identity::{self, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

pub(super) fn accepts_default<'a>(root: &KNode<'a>, node: &KNode<'a>) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    if call.arguments.len() != 1 || call.arguments.iter().any(|a| a.name.is_some()) {
        return false;
    }
    let text = call.callee.text();
    let Some((head, method)) = text.rsplit_once('.') else {
        return false;
    };
    let canonical = match method {
        "setDefault" => "javax.net.ssl.SSLContext",
        "setDefaultHostnameVerifier" | "setDefaultSSLSocketFactory" => {
            "javax.net.ssl.HttpsURLConnection"
        }
        _ => return false,
    };
    identity::Imports::build(root).exact(root, node, head, canonical)
}

pub(super) fn accepts<'a>(root: &KNode<'a>, node: &KNode<'a>) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    if call.callee.text().rsplit('.').next() != Some("init")
        || call.arguments.len() != 3
        || call.arguments.iter().any(|a| a.name.is_some())
    {
        return false;
    }
    call.callee
        .children()
        .find(|n| n.is_named())
        .is_some_and(|receiver| super::jvm::owned(root, &receiver, "javax.net.ssl.SSLContext", 8))
}

pub(crate) fn facts(path: &str, source: &str, anchor: &Evidence) -> Vec<ReviewNeighborhoodFact> {
    let defaults = anchor.rule_id == "kotlin-tls-default-policy";
    if !defaults && anchor.rule_id != "kotlin-tls-trust-context" {
        return vec![];
    }
    let ast = SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(node) = root.dfs().find(|n| {
        n.kind().as_ref() == "call_expression"
            && n.range() == (anchor.location.start.byte_offset..anchor.location.end.byte_offset)
    }) else {
        return vec![];
    };
    if !(if defaults {
        accepts_default(&root, &node)
    } else {
        accepts(&root, &node)
    }) {
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
    let mut facts = Vec::new();
    if defaults {
        let call = identity::call(&node).expect("validated canonical setter call");
        facts.push(ReviewNeighborhoodFact {
            role: "tls_default_matched_policy_context".into(),
            symbol: call.arguments[0].value.text().into_owned(),
            location: anchor.location.clone(),
            excerpt: format!(
                "This review is for the exact setter at {}:{}: {}. Its installed policy argument is: {}. Other setter calls in the function have different anchors and arguments. Judge this installed policy and consumers occurring after this anchor; do not transfer an earlier callback's body or earlier consumer to this argument. AST argument identity does not resolve an unknown policy value or prove global lifecycle.\n{}",
                path, anchor.location.start.line, call.callee.text(), call.arguments[0].value.text(), node.text()
            ),
            evidence_id: Some(anchor.id.clone()),
            provenance: QueryProvenance {
                resolution: Resolution::Ast,
                engine: "Kotlin exact canonical global TLS setter argument 1".into(),
            },
        });
    }
    facts.push(ReviewNeighborhoodFact {
        role: if defaults {
            "tls_default_containing_function_context"
        } else {
            "tls_trust_containing_function_context"
        }
        .into(),
        symbol: identity::name(&function).unwrap_or_default(),
        location: crate::code::matcher::location(path, &function),
        excerpt: if defaults {
            format!(
                "Exact containing function for this global TLS policy setter. Decide only the policy installed by this exact anchor and its downstream consumed connection. A weakness installed by an earlier different setter does not make a later restoration anchor an unsafe installation; a consumer already used before this anchor does not establish its effect. JDK17 HttpsURLConnection instances copy the then-current default hostname verifier and socket factory when created; later global setters do not retroactively change an existing instance. An instance setter can replace its inherited policy. SSLContext.setDefault affects subsequent SSLContext.getDefault calls, not every client that already holds a context or cached socket factory. Inspect construction order, effective consumer, overrides and restoration; this source context does not prove global execution order, compiler dispatch, concurrency or deployment.\n{}",
                function.text()
            )
        } else {
            format!(
                "Exact containing function for this SSLContext initialization. Inspect the trust-manager array at this anchor, server-certificate validation, manager selection, later initialization and the factory bound to the consumed connection. JDK17 SSLContext.init documents use of only the first manager of each implementation type; standard SunJSSE selects the first X509TrustManager, including its extended subtype, rather than composing all managers or falling through to later validators. Verify different provider semantics when supplied. Null trust managers request provider defaults; they are not an accept-all callback. An unused or wrong context does not alter another connection. This SDK contract does not identify unknown array members or prove compiler dispatch, general lifecycle effects or deployed TLS activation.\n{}",
                function.text()
            )
        },
        evidence_id: Some(anchor.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin SSLContext trust configuration and bounded function context 1".into(),
        },
    });
    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn global_setters_require_exact_static_sdk_ownership() {
        for (source, target, expected) in [
            (
                "import javax.net.ssl.HttpsURLConnection as H\nfun f() { H.setDefaultHostnameVerifier { _, _ -> true } }",
                "H.setDefaultHostnameVerifier { _, _ -> true }",
                true,
            ),
            (
                "fun f(factory: javax.net.ssl.SSLSocketFactory) { javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(factory) }",
                "javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(factory)",
                true,
            ),
            (
                "import javax.net.ssl.SSLContext as C\nfun f(c: C) { C.setDefault(c) }",
                "C.setDefault(c)",
                true,
            ),
            (
                "import javax.net.ssl.HttpsURLConnection as H\nfun f(H: Other) { H.setDefaultHostnameVerifier { _, _ -> true } }",
                "H.setDefaultHostnameVerifier { _, _ -> true }",
                false,
            ),
            (
                "class HttpsURLConnection\nfun f() { HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true } }",
                "HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }",
                false,
            ),
            (
                "import javax.net.ssl.*\nimport other.*\nfun f() { HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true } }",
                "HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }",
                false,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let node = root
                .dfs()
                .find(|n| n.kind().as_ref() == "call_expression" && n.text().as_ref() == target)
                .unwrap();
            assert_eq!(accepts_default(&root, &node), expected, "{source}");
        }
    }
    #[test]
    fn initialization_requires_canonical_context_and_enumerated_factory() {
        for (source, target, expected) in [
            (
                "import javax.net.ssl.SSLContext as C\nfun f(c: C) { c.init(null,null,null) }",
                "c.init(null,null,null)",
                true,
            ),
            (
                "import javax.net.ssl.SSLContext as C\nfun f() { val c = C.getInstance(\"TLS\"); val alias = c; alias.init(null,null,null) }",
                "alias.init(null,null,null)",
                true,
            ),
            (
                "fun f() { javax.net.ssl.SSLContext.getInstance(\"TLS\",\"SunJSSE\").init(null,null,null) }",
                "javax.net.ssl.SSLContext.getInstance(\"TLS\",\"SunJSSE\").init(null,null,null)",
                true,
            ),
            (
                "class SSLContext\nfun f(c: SSLContext) { c.init(null,null,null) }",
                "c.init(null,null,null)",
                false,
            ),
            (
                "import javax.net.ssl.SSLContext as C\nfun f() { var c = C.getInstance(\"TLS\"); c.init(null,null,null) }",
                "c.init(null,null,null)",
                false,
            ),
            (
                "fun f() { val c = helper(); c.init(null,null,null) }",
                "c.init(null,null,null)",
                false,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let node = root
                .dfs()
                .find(|n| n.kind().as_ref() == "call_expression" && n.text().as_ref() == target)
                .unwrap();
            assert_eq!(accepts(&root, &node), expected, "{source}");
        }
    }
}
