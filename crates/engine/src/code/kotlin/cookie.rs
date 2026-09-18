use super::identity::{self, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

pub(super) fn accepts<'a>(root: &KNode<'a>, rule: &str, node: &KNode<'a>) -> bool {
    let expected = match rule {
        "kotlin-cookie-secure-flag" => ("setSecure", "secure"),
        "kotlin-cookie-httponly-flag" => ("setHttpOnly", "isHttpOnly"),
        _ => return false,
    };
    let receiver = if let Some(call) = identity::call(node) {
        if call.arguments.len() != 1
            || call.arguments[0].name.is_some()
            || call.callee.text().rsplit('.').next() != Some(expected.0)
        {
            return false;
        }
        call.callee.children().find(|n| n.is_named())
    } else {
        if !node.children().any(|n| n.text().as_ref() == "=") {
            return false;
        }
        let Some(left) = node.children().find(|n| n.is_named()) else {
            return false;
        };
        let left = if left.kind().as_ref() == "directly_assignable_expression" {
            let navigation = left
                .children()
                .find(|n| n.kind().as_ref() == "navigation_expression");
            navigation.unwrap_or(left)
        } else {
            left
        };
        if !matches!(
            left.kind().as_ref(),
            "navigation_expression" | "directly_assignable_expression"
        ) || left.text().rsplit('.').next() != Some(expected.1)
        {
            return false;
        }
        left.children().find(|n| n.is_named())
    };
    receiver.is_some_and(|n| {
        ["jakarta.servlet.http.Cookie", "javax.servlet.http.Cookie"]
            .iter()
            .any(|ty| super::jvm::owned(root, &n, ty, 12))
    })
}

pub(crate) fn facts(path: &str, source: &str, anchor: &Evidence) -> Vec<ReviewNeighborhoodFact> {
    if !anchor.rule_id.starts_with("kotlin-cookie-") {
        return vec![];
    }
    let ast = SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(node) = root.dfs().find(|n| {
        n.range() == (anchor.location.start.byte_offset..anchor.location.end.byte_offset)
            && accepts(&root, &anchor.rule_id, n)
    }) else {
        return vec![];
    };
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
        role: "cookie_containing_function_context".into(),
        symbol: identity::name(&function).unwrap_or_default(),
        location: crate::code::matcher::location(path, &function),
        excerpt: format!(
            "Exact cookie-policy operation: {}. Servlet Cookie defaults Secure and HttpOnly to false. Kotlin secure/isHttpOnly assignments call the corresponding Java setters. Inspect the same cookie, later mutations and its actual response emission; a different cookie's flags do not protect this one. These excerpts do not establish deployed proxy rewriting or browser exposure.\n{}",
            node.text(),
            function.text()
        ),
        evidence_id: Some(anchor.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin owned Servlet cookie and exact containing-function context 1".into(),
        },
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cookie_properties_require_sdk_ownership() {
        for (source, expected) in [
            (
                "import jakarta.servlet.http.Cookie as C\nfun f(c: C) { c.secure = false }",
                true,
            ),
            (
                "class Cookie { var secure = false }\nfun f(c: Cookie) { c.secure = false }",
                false,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let node = root
                .dfs()
                .find(|n| {
                    n.kind().as_ref() == "assignment" && n.text().as_ref() == "c.secure = false"
                })
                .unwrap();
            assert_eq!(
                accepts(&root, "kotlin-cookie-secure-flag", &node),
                expected,
                "{}: {:?}",
                node.kind(),
                node.children()
                    .map(|n| (n.kind().into_owned(), n.text().into_owned()))
                    .collect::<Vec<_>>()
            );
        }
    }
}
