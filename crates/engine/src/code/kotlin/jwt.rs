use super::identity::{self, Imports, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

pub(super) fn accepts<'a>(root: &KNode<'a>, rule: &str, node: &KNode<'a>) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    if call.arguments.len() != 1 || call.arguments[0].name.is_some() {
        return false;
    }
    if matches!(rule, "kotlin-auth0-jwt-decode" | "kotlin-auth0-jwt-verify") {
        let value = &call.arguments[0].value;
        if matches!(
            value.kind().as_ref(),
            "integer_literal"
                | "real_literal"
                | "boolean_literal"
                | "null_literal"
                | "lambda_literal"
                | "character_literal"
        ) {
            return false;
        }
        if value.kind().as_ref() == "simple_identifier"
            && let Some(ty) = identity::binding_type(root, value, &value.text())
            && [
                "kotlin.Int",
                "kotlin.Long",
                "kotlin.Short",
                "kotlin.Byte",
                "kotlin.Float",
                "kotlin.Double",
                "kotlin.Boolean",
                "kotlin.Char",
                "kotlin.Any",
                "kotlin.ByteArray",
            ]
            .iter()
            .any(|canonical| Imports::build(root).exact(root, value, &ty, canonical))
        {
            return false;
        }
    }
    let text = call.callee.text();
    let Some((head, method)) = text.rsplit_once('.') else {
        return false;
    };
    if rule == "kotlin-auth0-jwt-decode" && method == "decode" {
        return Imports::build(root).exact(root, node, head, "com.auth0.jwt.JWT");
    }
    let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    match (rule, method) {
        ("kotlin-auth0-jwt-decode", "decodeJwt") => {
            super::jvm::owned(root, &receiver, "com.auth0.jwt.JWT", 12)
        }
        ("kotlin-auth0-jwt-token-generation", "sign") => {
            super::jvm::owned(root, &receiver, "com.auth0.jwt.JWTCreator.Builder", 12)
        }
        ("kotlin-auth0-jwt-verify", "verify") => [
            "com.auth0.jwt.JWTVerifier",
            "com.auth0.jwt.interfaces.JWTVerifier",
        ]
        .iter()
        .any(|ty| super::jvm::owned(root, &receiver, ty, 12)),
        _ => false,
    }
}

pub(crate) fn facts(path: &str, source: &str, anchor: &Evidence) -> Vec<ReviewNeighborhoodFact> {
    if !matches!(
        anchor.rule_id.as_str(),
        "kotlin-auth0-jwt-decode" | "kotlin-auth0-jwt-verify" | "kotlin-auth0-jwt-token-generation"
    ) {
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
    if !accepts(&root, &anchor.rule_id, &node) {
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
    vec![ReviewNeighborhoodFact {
        role: "jwt_containing_function_context".into(),
        symbol: identity::name(&function).unwrap_or_default(),
        location: crate::code::matcher::location(path, &function),
        excerpt: format!(
            "Exact containing function for this JWT operation: {}. Auth0 java-jwt decode/decodeJwt parse claims without signature verification. A verifier checks its configured algorithm and requirements; Algorithm.none intentionally does not provide signature authentication. Signing does not automatically add expiry. JWTCreator builder claim setters replace that claim on the same builder; withPayload merges supplied claims and can replace an earlier exp. Inspect the effective signed builder, later overrides and separate builders, required credential lifetime and any consumer maximum-age or revocation policy. Signature authentication does not itself bound credential lifetime. Judge whether this exact token or decoded object controls credential acceptance, and whether the same token is verified before trust. Logging or display of untrusted claims is not credential acceptance. Inspect failure propagation, ignored verification results, different token values and issuer/audience/expiry policy. This is bounded source context, not compiler dispatch, native authentication flow or deployed endpoint proof.\n{}",
            node.text(),
            function.text()
        ),
        evidence_id: Some(anchor.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin canonical Auth0 JWT operation and bounded policy context 1".into(),
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jwt_ownership_rejects_shadowed_types_foreign_builders_and_non_string_decoding() {
        for (source, rule, target, expected) in [
            (
                "import com.auth0.jwt.JWT as J\nfun f(token: String) { J.decode(token) }",
                "kotlin-auth0-jwt-decode",
                "J.decode(token)",
                true,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(token: Int) { JWT.decode(token) }",
                "kotlin-auth0-jwt-decode",
                "JWT.decode(token)",
                false,
            ),
            (
                "import com.auth0.jwt.JWT\ntypealias Token = String\nfun f(token: Token) { JWT.decode(token) }",
                "kotlin-auth0-jwt-decode",
                "JWT.decode(token)",
                true,
            ),
            (
                "import com.auth0.jwt.interfaces.JWTVerifier as V\nfun f(v: V, token: Int) { v.verify(token) }",
                "kotlin-auth0-jwt-verify",
                "v.verify(token)",
                false,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(JWT: Other, token: String) { JWT.decode(token) }",
                "kotlin-auth0-jwt-decode",
                "JWT.decode(token)",
                false,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(token: String) { val jwt = JWT(); val alias = jwt; alias.decodeJwt(token) }",
                "kotlin-auth0-jwt-decode",
                "alias.decodeJwt(token)",
                true,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(token: String) { var jwt = JWT(); jwt.decodeJwt(token) }",
                "kotlin-auth0-jwt-decode",
                "jwt.decodeJwt(token)",
                false,
            ),
            (
                "import com.auth0.jwt.interfaces.JWTVerifier as V\nfun f(v: V, token: String) { v.verify(token) }",
                "kotlin-auth0-jwt-verify",
                "v.verify(token)",
                true,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(a: com.auth0.jwt.algorithms.Algorithm, token: String) { JWT.require(a).withIssuer(\"owned\").build().verify(token) }",
                "kotlin-auth0-jwt-verify",
                "JWT.require(a).withIssuer(\"owned\").build().verify(token)",
                true,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(a: com.auth0.jwt.algorithms.Algorithm, token: String) { JWT.require(a).foreign().build().verify(token) }",
                "kotlin-auth0-jwt-verify",
                "JWT.require(a).foreign().build().verify(token)",
                false,
            ),
            (
                "class JWTVerifier\nfun f(v: JWTVerifier, token: String) { v.verify(token) }",
                "kotlin-auth0-jwt-verify",
                "v.verify(token)",
                false,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(a: com.auth0.jwt.algorithms.Algorithm) { JWT.create().withSubject(\"owned\").sign(a) }",
                "kotlin-auth0-jwt-token-generation",
                "JWT.create().withSubject(\"owned\").sign(a)",
                true,
            ),
            (
                "import com.auth0.jwt.JWTCreator.Builder as B\nfun f(b: B, a: com.auth0.jwt.algorithms.Algorithm) { b.sign(a) }",
                "kotlin-auth0-jwt-token-generation",
                "b.sign(a)",
                true,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(a: com.auth0.jwt.algorithms.Algorithm) { val b = JWT.create(); val alias = b; alias.sign(a) }",
                "kotlin-auth0-jwt-token-generation",
                "alias.sign(a)",
                true,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(a: com.auth0.jwt.algorithms.Algorithm) { var b = JWT.create(); b.sign(a) }",
                "kotlin-auth0-jwt-token-generation",
                "b.sign(a)",
                false,
            ),
            (
                "import com.auth0.jwt.JWT\nfun f(a: com.auth0.jwt.algorithms.Algorithm) { JWT.create().foreign().sign(a) }",
                "kotlin-auth0-jwt-token-generation",
                "JWT.create().foreign().sign(a)",
                false,
            ),
            (
                "class Builder\nfun f(b: Builder, a: com.auth0.jwt.algorithms.Algorithm) { b.sign(a) }",
                "kotlin-auth0-jwt-token-generation",
                "b.sign(a)",
                false,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let node = root
                .dfs()
                .find(|n| n.kind().as_ref() == "call_expression" && n.text().as_ref() == target)
                .unwrap();
            assert_eq!(accepts(&root, rule, &node), expected, "{source}");
        }
    }
}
