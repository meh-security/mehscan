use super::identity::{self, Imports, KNode};

pub(super) fn file_operands<'a>(
    root: &KNode<'a>,
    expression: &KNode<'a>,
) -> Option<Vec<KNode<'a>>> {
    let call = identity::call(expression)?;
    (matches!(call.arguments.len(), 1 | 2)
        && call.arguments.iter().all(|a| a.name.is_none())
        && Imports::build(root).exact(root, expression, &call.callee.text(), "java.io.File"))
    .then(|| call.arguments.into_iter().map(|a| a.value).collect())
}

/// Bounded JVM identities. Only exact declarations, immutable local aliases and
/// enumerated library factories contribute identity; helper return types do not.
pub(super) fn owned<'a>(
    root: &KNode<'a>,
    expression: &KNode<'a>,
    canonical: &str,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let imports = Imports::build(root);
    let symbol = expression.text();
    if expression.kind().as_ref() == "simple_identifier"
        || symbol
            .strip_prefix("this.")
            .is_some_and(|s| !s.contains('.'))
    {
        if !identity::receiver_unchanged(root, expression, &symbol) {
            return false;
        }
        if let Some(ty) = identity::binding_type(root, expression, &symbol) {
            return imports.exact(root, expression, &ty, canonical);
        }
        let Some(binding) = identity::binding(root, expression, &symbol) else {
            return false;
        };
        if identity::callable(&binding).is_none()
            || identity::callable(&binding).map(|n| n.range())
                != identity::callable(expression).map(|n| n.range())
        {
            return false;
        }
        let Some(property) = binding
            .parent()
            .filter(|n| n.kind().as_ref() == "property_declaration")
        else {
            return false;
        };
        return property.children().any(|n| n.text().as_ref() == "val")
            && property
                .children()
                .filter(|n| n.is_named())
                .last()
                .is_some_and(|value| {
                    value.range() != binding.range() && owned(root, &value, canonical, depth - 1)
                });
    }
    let Some(call) = identity::call(expression) else {
        return false;
    };
    if call.arguments.iter().any(|a| a.name.is_some()) {
        return false;
    }
    let text = call.callee.text();
    let constructors = match canonical {
        "java.lang.ProcessBuilder" => !call.arguments.is_empty(),
        "java.io.File" => matches!(call.arguments.len(), 1 | 2),
        "java.io.ObjectInputStream" => call.arguments.len() == 1,
        _ => false,
    };
    if constructors && imports.exact(root, expression, &text, canonical) {
        return true;
    }
    let Some((head, method)) = text.rsplit_once('.') else {
        return false;
    };
    if call.arguments.is_empty()
        && matches!(method, "newInstance" | "newDefaultInstance")
        && matches!(
            canonical,
            "javax.xml.parsers.DocumentBuilderFactory" | "javax.xml.parsers.SAXParserFactory"
        )
        && imports.exact(root, expression, head, canonical)
    {
        return true;
    }
    let factory = match (canonical, method, call.arguments.len()) {
        ("javax.xml.parsers.DocumentBuilder", "newDocumentBuilder", 0) => {
            "javax.xml.parsers.DocumentBuilderFactory"
        }
        ("javax.xml.parsers.SAXParser", "newSAXParser", 0) => "javax.xml.parsers.SAXParserFactory",
        ("java.net.URLConnection", "openConnection", 0) => "java.net.URL",
        _ => return false,
    };
    let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    if factory == "java.net.URL" {
        super::network::known(root, &receiver, factory, depth - 1)
    } else {
        owned(root, &receiver, factory, depth - 1)
    }
}

pub(super) fn accepts<'a>(root: &KNode<'a>, rule: &str, node: &KNode<'a>) -> bool {
    let Some(call) = identity::call(node) else {
        return false;
    };
    let text = call.callee.text();
    let Some((_, method)) = text.rsplit_once('.') else {
        return false;
    };
    let methods: &[&str] = match rule {
        "kotlin-process-builder" => &["start"],
        "kotlin-file-read" => &["readText", "readBytes", "inputStream"],
        "kotlin-file-write" => &["writeText", "writeBytes", "outputStream"],
        "kotlin-object-deserialization" => &["readObject", "readUnshared"],
        "kotlin-jackson-deserialization" => &["readValue"],
        "kotlin-xml-parse" => &["parse"],
        "kotlin-xml-configuration" => &["setFeature", "setAttribute", "setExpandEntityReferences"],
        "kotlin-tls-hostname-verifier" => &["setHostnameVerifier"],
        "kotlin-servlet-redirect" => &["sendRedirect"],
        "kotlin-url-connection-consumer" => &["connect", "getInputStream", "getContent"],
        "kotlin-http-client-request" => &["send", "sendAsync"],
        "kotlin-okhttp-request" => &["newCall"],
        _ => return false,
    };
    if !methods.contains(&method) {
        return false;
    }
    if matches!(rule, "kotlin-file-read" | "kotlin-file-write") {
        let text = call.callee.text();
        let Some((_, method)) = text.rsplit_once('.') else {
            return false;
        };
        if !Imports::build(root).default_extension(
            root,
            node,
            method,
            &format!("kotlin.io.{method}"),
        ) {
            return false;
        }
    }
    let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
        return false;
    };
    let types: &[&str] = match rule {
        "kotlin-process-builder" => &["java.lang.ProcessBuilder"],
        "kotlin-file-read" | "kotlin-file-write" => &["java.io.File"],
        "kotlin-object-deserialization" => &["java.io.ObjectInputStream"],
        "kotlin-jackson-deserialization" => &[
            "com.fasterxml.jackson.databind.ObjectMapper",
            "tools.jackson.databind.ObjectMapper",
        ],
        "kotlin-xml-parse" => &[
            "javax.xml.parsers.DocumentBuilder",
            "javax.xml.parsers.SAXParser",
        ],
        "kotlin-xml-configuration" => &[
            "javax.xml.parsers.DocumentBuilderFactory",
            "javax.xml.parsers.SAXParserFactory",
        ],
        "kotlin-tls-hostname-verifier" => &["javax.net.ssl.HttpsURLConnection"],
        "kotlin-servlet-redirect" => &[
            "jakarta.servlet.http.HttpServletResponse",
            "javax.servlet.http.HttpServletResponse",
        ],
        "kotlin-url-connection-consumer" => &[
            "java.net.URLConnection",
            "java.net.HttpURLConnection",
            "javax.net.ssl.HttpsURLConnection",
        ],
        "kotlin-http-client-request" => &["java.net.http.HttpClient"],
        "kotlin-okhttp-request" => &["okhttp3.OkHttpClient"],
        _ => return false,
    };
    types.iter().any(|canonical| {
        !(rule == "kotlin-xml-configuration"
            && *canonical == "javax.xml.parsers.SAXParserFactory"
            && method != "setFeature")
            && owned(root, &receiver, canonical, 8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    #[test]
    fn factories_and_receivers_require_exact_unmodified_identity() {
        for (source, expected) in [
            (
                "import java.io.ObjectInputStream\nfun f(input: ObjectInputStream) { input.readObject() }",
                true,
            ),
            (
                "import java.io.ObjectInputStream\nfun f(stream: InputStream) { val input = ObjectInputStream(stream); input.readObject() }",
                true,
            ),
            (
                "import java.io.ObjectInputStream\nfun <ObjectInputStream : Other> f(input: ObjectInputStream) { input.readObject() }",
                false,
            ),
            (
                "import java.io.ObjectInputStream\nfun f(stream: InputStream) { var input = ObjectInputStream(stream); input.readObject() }",
                false,
            ),
            (
                "import java.io.ObjectInputStream\nfun f(input: ObjectInputStream, other: ObjectInputStream) { input = other; input.readObject() }",
                false,
            ),
            (
                "import java.io.ObjectInputStream\nfun f(stream: InputStream) { val input = helper(stream); input.readObject() }",
                false,
            ),
        ] {
            let ast = SupportLang::Kotlin.ast_grep(source);
            let root = ast.root();
            let read = root
                .dfs()
                .find(|n| {
                    n.kind().as_ref() == "call_expression"
                        && n.text().as_ref() == "input.readObject()"
                })
                .unwrap();
            assert_eq!(
                accepts(&root, "kotlin-object-deserialization", &read),
                expected,
                "{source}"
            );
        }
    }

    #[test]
    fn foreign_or_local_file_extensions_are_not_stdlib_effects() {
        for prefix in [
            "import elsewhere.readText\n",
            "import elsewhere.*\n",
            "fun java.io.File.readText() = \"fixed\"\n",
        ] {
            let source = format!("{prefix}fun f(file: java.io.File) {{ file.readText() }}");
            let ast = SupportLang::Kotlin.ast_grep(&source);
            let root = ast.root();
            let read = root
                .dfs()
                .find(|n| {
                    n.kind().as_ref() == "call_expression" && n.text().as_ref() == "file.readText()"
                })
                .unwrap();
            assert!(!accepts(&root, "kotlin-file-read", &read), "{source}");
        }
    }
}
