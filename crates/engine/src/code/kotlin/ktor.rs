use super::identity::{self, Imports, KNode};

pub(super) const SOURCES: [&str; 3] = [
    "kotlin-ktor-query-source",
    "kotlin-ktor-path-source",
    "kotlin-ktor-body-source",
];

fn extension_receiver(root: &KNode<'_>, function: &KNode<'_>, canonical: &str) -> bool {
    let children = function.children().collect::<Vec<_>>();
    children.windows(2).any(|pair| {
        matches!(pair[0].kind().as_ref(), "user_type" | "receiver_type")
            && pair[1].text().as_ref() == "."
            && Imports::build(root).exact(root, function, &pair[0].text(), canonical)
    })
}

fn application_call<'a>(root: &KNode<'a>, expression: &KNode<'a>) -> bool {
    if super::jvm::owned(
        root,
        expression,
        "io.ktor.server.application.ApplicationCall",
        8,
    ) {
        return true;
    }
    // Unknown receiver scopes and local call bindings stop implicit ownership.
    if expression.text().as_ref() != "call" || identity::binding(root, expression, "call").is_some()
    {
        return false;
    }
    let imports = Imports::build(root);
    let mut callable = identity::callable(expression);
    let mut routed = false;
    for _ in 0..6 {
        let Some(current) = callable else {
            return false;
        };
        if current.kind().as_ref() == "function_declaration" {
            return extension_receiver(root, &current, "io.ktor.server.routing.Route")
                || routed
                    && extension_receiver(
                        root,
                        &current,
                        "io.ktor.server.application.Application",
                    );
        }
        if current.kind().as_ref() != "lambda_literal" {
            return false;
        }
        let Some(container) = current
            .ancestors()
            .find(|n| n.kind().as_ref() == "call_expression")
        else {
            return false;
        };
        let Some(callee) = container
            .children()
            .find(|n| n.is_named() && n.kind().as_ref() != "call_suffix")
        else {
            return false;
        };
        let text = callee.text();
        if imports.exact(root, &container, &text, "io.ktor.server.routing.routing") {
            routed = true;
        } else if ![
            "get", "post", "put", "delete", "patch", "head", "options", "route",
        ]
        .iter()
        .any(|method| {
            imports.exact(
                root,
                &container,
                &text,
                &format!("io.ktor.server.routing.{method}"),
            )
        }) {
            return false;
        }
        callable = identity::callable(&container);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    #[test]
    fn implicit_call_stops_at_unknown_receivers_and_local_bindings() {
        for body in [
            "fun Application.routes() { routing { get(\"/\") { other.apply { call.request.queryParameters[\"x\"] } } } }",
            "fun Application.routes() { routing { get(\"/\") { val call = other; call.request.queryParameters[\"x\"] } } }",
            "fun Other.routes() { routing { get(\"/\") { call.request.queryParameters[\"x\"] } } }",
        ] {
            let source = format!(
                "import io.ktor.server.application.Application\nimport io.ktor.server.routing.routing\nimport io.ktor.server.routing.get\n{body}"
            );
            let ast = SupportLang::Kotlin.ast_grep(&source);
            let root = ast.root();
            assert!(
                !root
                    .dfs()
                    .any(|n| accepts(&root, "kotlin-ktor-query-source", &n)),
                "{source}"
            );
        }
    }
}

pub(super) fn accepts<'a>(root: &KNode<'a>, rule: &str, node: &KNode<'a>) -> bool {
    let imports = Imports::build(root);
    if matches!(rule, "kotlin-ktor-query-source" | "kotlin-ktor-path-source") {
        if node.kind().as_ref() != "indexing_expression" {
            return false;
        }
        let Some(collection) = node.children().find(|n| n.is_named()) else {
            return false;
        };
        let Some(base) = collection
            .dfs()
            .find(|n| n.kind().as_ref() == "simple_identifier")
        else {
            return false;
        };
        let suffix = if rule == "kotlin-ktor-query-source" {
            ".request.queryParameters"
        } else {
            ".parameters"
        };
        return collection.text().as_ref() == format!("{}{suffix}", base.text())
            && application_call(root, &base);
    }
    let Some(call) = identity::call(node) else {
        return false;
    };
    let text = call.callee.text();
    let Some((_, method)) = text.rsplit_once('.') else {
        return false;
    };
    let parameter_names: &[&str] = match rule {
        "kotlin-ktor-body-source" => &[],
        "kotlin-ktor-redirect" => &["url", "permanent"],
        "kotlin-ktor-html-output" if method == "respondBytes" => &["bytes", "contentType"],
        "kotlin-ktor-html-output" => &["text", "contentType"],
        "kotlin-ktor-client-request" => &["urlString"],
        _ => return false,
    };
    let mut positions = std::collections::BTreeSet::new();
    for (index, argument) in call.arguments.iter().enumerate() {
        let position = match &argument.name {
            Some(name) => parameter_names.iter().position(|p| *p == name),
            None => (index < parameter_names.len()).then_some(index),
        };
        if !position.is_some_and(|p| positions.insert(p)) {
            return false;
        }
    }
    let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    let (canonical, extension) = match rule {
        "kotlin-ktor-body-source" if method == "receiveText" && call.arguments.is_empty() => (
            "io.ktor.server.application.ApplicationCall",
            "io.ktor.server.request.receiveText",
        ),
        "kotlin-ktor-redirect" if method == "respondRedirect" => (
            "io.ktor.server.application.ApplicationCall",
            "io.ktor.server.response.respondRedirect",
        ),
        "kotlin-ktor-html-output"
            if matches!(method, "respondText" | "respondBytes") && call.arguments.len() == 2 =>
        {
            let content_type = call
                .arguments
                .iter()
                .enumerate()
                .find(|(i, a)| {
                    a.name.as_deref() == Some("contentType") || a.name.is_none() && *i == 1
                })
                .map(|(_, a)| a.value.clone());
            let Some(content_type) = content_type else {
                return false;
            };
            let mime = if let Some(charset_call) = identity::call(&content_type) {
                if charset_call.arguments.len() != 1 {
                    return false;
                }
                let text = charset_call.callee.text();
                let Some((head, charset_method)) = text.rsplit_once('.') else {
                    return false;
                };
                if !imports.exact(root, node, charset_method, "io.ktor.http.withCharset") {
                    return false;
                }
                head.to_string()
            } else {
                content_type.text().to_string()
            };
            let Some(head) = mime.strip_suffix(".Text.Html") else {
                return false;
            };
            if !imports.exact(root, node, head, "io.ktor.http.ContentType") {
                return false;
            }
            (
                "io.ktor.server.application.ApplicationCall",
                if method == "respondBytes" {
                    "io.ktor.server.response.respondBytes"
                } else {
                    "io.ktor.server.response.respondText"
                },
            )
        }
        "kotlin-ktor-client-request"
            if matches!(method, "get" | "post" | "put" | "delete" | "patch" | "head") =>
        {
            (
                "io.ktor.client.HttpClient",
                match method {
                    "get" => "io.ktor.client.request.get",
                    "post" => "io.ktor.client.request.post",
                    "put" => "io.ktor.client.request.put",
                    "delete" => "io.ktor.client.request.delete",
                    "patch" => "io.ktor.client.request.patch",
                    _ => "io.ktor.client.request.head",
                },
            )
        }
        _ => return false,
    };
    imports.exact(root, node, method, extension)
        && if canonical == "io.ktor.server.application.ApplicationCall" {
            application_call(root, &receiver)
        } else {
            super::jvm::owned(root, &receiver, canonical, 8)
        }
}
