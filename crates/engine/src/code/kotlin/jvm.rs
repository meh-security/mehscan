use super::identity::{self, Imports, KNode};

pub(in crate::code) fn process_command<'a>(
    root: &KNode<'a>,
    start: &KNode<'a>,
) -> Option<KNode<'a>> {
    let call = identity::call(start)?;
    let receiver = call.callee.children().find(|n| n.is_named())?;
    if !owned(root, &receiver, "java.lang.ProcessBuilder", 8) {
        return None;
    }
    fn operand<'a>(root: &KNode<'a>, value: KNode<'a>, depth: usize) -> Option<KNode<'a>> {
        if depth == 0 {
            return None;
        }
        let Some(call) = identity::call(&value) else {
            return Some(value);
        };
        let text = call.callee.text();
        if Imports::build(root).exact(root, &value, &text, "java.lang.ProcessBuilder")
            || text.rsplit('.').next() == Some("command") && !call.arguments.is_empty()
        {
            return call.arguments.first().map(|a| a.value.clone());
        }
        operand(
            root,
            call.callee.children().find(|n| n.is_named())?,
            depth - 1,
        )
    }
    operand(root, receiver, 8)
}

pub(crate) fn okhttp_facts(
    path: &str,
    source: &str,
    sink: &mehscan_core::Evidence,
) -> Vec<mehscan_core::ReviewNeighborhoodFact> {
    use ast_grep_core::tree_sitter::LanguageExt;
    use mehscan_core::{QueryProvenance, Resolution, ReviewNeighborhoodFact};
    if sink.rule_id != "kotlin-okhttp-request" {
        return vec![];
    }
    let ast = ast_grep_language::SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(anchor) = root.dfs().find(|n| {
        n.kind().as_ref() == "call_expression"
            && n.range() == (sink.location.start.byte_offset..sink.location.end.byte_offset)
    }) else {
        return vec![];
    };
    let Some(scope) = identity::callable(&anchor) else {
        return vec![];
    };
    fn origin<'a>(root: &KNode<'a>, expression: &KNode<'a>, depth: usize) -> Option<KNode<'a>> {
        if depth == 0 {
            return None;
        }
        if let Some(call) = identity::call(expression) {
            if call.callee.text().rsplit('.').next() == Some("newCall")
                && accepts(root, "kotlin-okhttp-request", expression)
            {
                return Some(expression.clone());
            }
            return None;
        }
        if expression.kind().as_ref() != "simple_identifier"
            || !identity::receiver_unchanged(root, expression, &expression.text())
        {
            return None;
        }
        let binding = identity::binding(root, expression, &expression.text())?;
        if identity::callable(&binding).map(|n| n.range())
            != identity::callable(expression).map(|n| n.range())
        {
            return None;
        }
        let property = binding
            .parent()
            .filter(|n| n.kind().as_ref() == "property_declaration")?;
        if !property.children().any(|n| n.text().as_ref() == "val") {
            return None;
        }
        origin(
            root,
            &property.children().filter(|n| n.is_named()).last()?,
            depth - 1,
        )
    }
    scope.dfs().filter(|n| n.kind().as_ref() == "call_expression" && identity::callable(n).is_some_and(|f| f.range() == scope.range()))
        .filter_map(|node| {
            let call = identity::call(&node)?;
            let text = call.callee.text();
            let method = text.rsplit('.').next()?;
            if !((method == "execute" && call.arguments.is_empty()) || (method == "enqueue" && call.arguments.len() == 1)) { return None; }
            let receiver = call.callee.children().find(|n| n.is_named())?;
            if origin(&root, &receiver, 8)?.range() != anchor.range() || node.range().len() > 4096 { return None; }
            Some(ReviewNeighborhoodFact { role: "okhttp_call_execution_context".into(), symbol: receiver.text().into_owned(), location: crate::code::matcher::location(path, &node), excerpt: node.text().into_owned(), evidence_id: Some(sink.id.clone()), provenance: QueryProvenance { resolution: Resolution::Ast, engine: "Kotlin exact same-callable immutable OkHttp call origin and consumer; source context 1".into() } })
        }).take(8).collect()
}

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
            if matches!(
                canonical,
                "org.springframework.web.reactive.function.client.WebClient.RequestHeadersUriSpec"
                    | "org.springframework.web.reactive.function.client.WebClient.RequestBodyUriSpec"
                    | "org.springframework.web.reactive.function.client.WebClient.UriSpec"
            ) {
                return imports.exact(
                    root,
                    expression,
                    ty.split('<').next().unwrap_or(&ty),
                    canonical,
                );
            }
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
        "jakarta.servlet.http.Cookie" | "javax.servlet.http.Cookie" => call.arguments.len() == 2,
        "javax.script.ScriptEngineManager" => call.arguments.is_empty(),
        "okhttp3.OkHttpClient" | "okhttp3.OkHttpClient.Builder" | "com.auth0.jwt.JWT" => {
            call.arguments.is_empty()
        }
        "io.ktor.client.HttpClient" => {
            call.arguments.len() <= 1
                || call.arguments.len() == 2
                    && call
                        .arguments
                        .last()
                        .is_some_and(|a| a.value.kind().as_ref() == "lambda_literal")
        }
        _ => false,
    };
    if constructors && imports.exact(root, expression, &text, canonical) {
        return true;
    }
    let Some((head, method)) = text.rsplit_once('.') else {
        return false;
    };
    if let Some(receiver) = call.callee.children().find(|n| n.is_named()) {
        let request = match canonical {
            "jakarta.servlet.http.Part" => Some("jakarta.servlet.http.HttpServletRequest"),
            "javax.servlet.http.Part" => Some("javax.servlet.http.HttpServletRequest"),
            _ => None,
        };
        if method == "getPart"
            && call.arguments.len() == 1
            && request.is_some_and(|ty| owned(root, &receiver, ty, depth - 1))
        {
            return true;
        }
        if canonical == "javax.script.ScriptEngine"
            && call.arguments.len() == 1
            && matches!(
                method,
                "getEngineByName" | "getEngineByExtension" | "getEngineByMimeType"
            )
            && owned(
                root,
                &receiver,
                "javax.script.ScriptEngineManager",
                depth - 1,
            )
        {
            return true;
        }
    }
    const VERIFICATION: &str = "com.auth0.jwt.interfaces.Verification";
    const CREATOR: &str = "com.auth0.jwt.JWTCreator.Builder";
    if canonical == CREATOR {
        if method == "create"
            && call.arguments.is_empty()
            && imports.exact(root, expression, head, "com.auth0.jwt.JWT")
        {
            return true;
        }
        let count = call.arguments.len();
        let fluent = match method {
            "withAudience" => true,
            "withHeader" | "withKeyId" | "withIssuer" | "withSubject" | "withExpiresAt"
            | "withNotBefore" | "withIssuedAt" | "withJWTId" | "withPayload" | "withNullClaim" => {
                count == 1
            }
            "withClaim" | "withArrayClaim" => count == 2,
            _ => false,
        };
        if fluent {
            return call
                .callee
                .children()
                .find(|n| n.is_named())
                .is_some_and(|receiver| owned(root, &receiver, CREATOR, depth - 1));
        }
    }
    if canonical == VERIFICATION {
        if method == "require"
            && call.arguments.len() == 1
            && imports.exact(root, expression, head, "com.auth0.jwt.JWT")
        {
            return true;
        }
        let count = call.arguments.len();
        let fluent = match method {
            "withIssuer" | "withAudience" | "withAnyOfAudience" => true,
            "withSubject" | "withJWTId" | "withClaimPresence" | "withNullClaim"
            | "acceptLeeway" | "acceptExpiresAt" | "acceptNotBefore" | "acceptIssuedAt" => {
                count == 1
            }
            "withClaim" => count == 2,
            "withArrayClaim" => count >= 1,
            "ignoreIssuedAt" => count == 0,
            _ => false,
        };
        if fluent {
            return call
                .callee
                .children()
                .find(|n| n.is_named())
                .is_some_and(|receiver| owned(root, &receiver, VERIFICATION, depth - 1));
        }
    }
    if matches!(
        canonical,
        "com.auth0.jwt.JWTVerifier" | "com.auth0.jwt.interfaces.JWTVerifier"
    ) && method == "build"
        && call.arguments.is_empty()
    {
        return call
            .callee
            .children()
            .find(|n| n.is_named())
            .is_some_and(|receiver| owned(root, &receiver, VERIFICATION, depth - 1));
    }
    if canonical == "javax.net.ssl.SSLContext"
        && method == "getInstance"
        && matches!(call.arguments.len(), 1 | 2)
        && imports.exact(root, expression, head, canonical)
    {
        return true;
    }
    const WEBCLIENT: &str = "org.springframework.web.reactive.function.client.WebClient";
    if canonical == "org.springframework.web.reactive.function.client.ClientRequest.Builder"
        && ((method == "from" && call.arguments.len() == 1)
            || (method == "create" && call.arguments.len() == 2))
        && imports.exact(
            root,
            expression,
            head,
            "org.springframework.web.reactive.function.client.ClientRequest",
        )
    {
        return true;
    }
    const WEBCLIENT_BUILDER: &str =
        "org.springframework.web.reactive.function.client.WebClient.Builder";
    if ((canonical == WEBCLIENT && method == "create" && call.arguments.len() <= 1)
        || (canonical == WEBCLIENT_BUILDER && method == "builder" && call.arguments.is_empty()))
        && imports.exact(root, expression, head, WEBCLIENT)
    {
        return true;
    }
    if call.arguments.is_empty()
        && ((canonical == "java.net.http.HttpClient" && method == "newHttpClient")
            || (canonical == "java.net.http.HttpClient.Builder" && method == "newBuilder"))
        && imports.exact(root, expression, head, "java.net.http.HttpClient")
    {
        return true;
    }
    if let Some(receiver) = call.callee.children().find(|n| n.is_named()) {
        if method == "build" && call.arguments.is_empty() {
            let builder = match canonical {
                "java.net.http.HttpClient" => Some("java.net.http.HttpClient.Builder"),
                "okhttp3.OkHttpClient" => Some("okhttp3.OkHttpClient.Builder"),
                WEBCLIENT => Some(WEBCLIENT_BUILDER),
                _ => None,
            };
            if builder.is_some_and(|builder| owned(root, &receiver, builder, depth - 1)) {
                return true;
            }
        }
        if canonical == WEBCLIENT_BUILDER
            && ((method == "mutate"
                && call.arguments.is_empty()
                && owned(root, &receiver, WEBCLIENT, depth - 1))
                || (matches!(
                    method,
                    "baseUrl"
                        | "uriBuilderFactory"
                        | "defaultUriVariables"
                        | "defaultHeaders"
                        | "defaultCookies"
                        | "defaultRequest"
                        | "filter"
                        | "filters"
                        | "exchangeFunction"
                        | "clientConnector"
                        | "codecs"
                        | "observationRegistry"
                        | "observationConvention"
                        | "apply"
                        | "exchangeStrategies"
                        | "defaultApiVersion"
                        | "apiVersionInserter"
                ) && call.arguments.len() == 1
                    || matches!(method, "defaultHeader" | "defaultCookie")
                        && !call.arguments.is_empty()
                    || method == "defaultStatusHandler" && call.arguments.len() == 2
                    || method == "clone" && call.arguments.is_empty())
                    && owned(root, &receiver, WEBCLIENT_BUILDER, depth - 1))
        {
            return true;
        }
        if matches!(
            canonical,
            "org.springframework.web.reactive.function.client.WebClient.RequestHeadersUriSpec"
                | "org.springframework.web.reactive.function.client.WebClient.RequestBodyUriSpec"
                | "org.springframework.web.reactive.function.client.WebClient.UriSpec"
        ) && (matches!(
            method,
            "get" | "head" | "delete" | "options" | "post" | "put" | "patch"
        ) && call.arguments.is_empty()
            || method == "method" && call.arguments.len() == 1)
            && owned(root, &receiver, WEBCLIENT, depth - 1)
        {
            // Both URI-spec families share UriSpec; this is boundary ownership,
            // not a claim of the exact generic return type of each HTTP method.
            return true;
        }
        if canonical == "java.net.http.HttpClient.Builder"
            && call.arguments.len() == 1
            && matches!(
                method,
                "authenticator"
                    | "connectTimeout"
                    | "cookieHandler"
                    | "executor"
                    | "followRedirects"
                    | "priority"
                    | "proxy"
                    | "sslContext"
                    | "sslParameters"
                    | "version"
            )
            && owned(root, &receiver, canonical, depth - 1)
        {
            return true;
        }
        if canonical == "java.lang.ProcessBuilder"
            && ((method == "command" && !call.arguments.is_empty())
                || (method == "inheritIO" && call.arguments.is_empty())
                || (matches!(
                    method,
                    "directory"
                        | "redirectErrorStream"
                        | "redirectInput"
                        | "redirectOutput"
                        | "redirectError"
                ) && call.arguments.len() == 1))
            && owned(root, &receiver, canonical, depth - 1)
        {
            return true;
        }
    }
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

pub(in crate::code) fn file_content<'a>(node: &KNode<'a>) -> Option<KNode<'a>> {
    let call = identity::call(node)?;
    call.arguments
        .into_iter()
        .enumerate()
        .find_map(|(index, arg)| {
            (arg.name
                .as_deref()
                .is_some_and(|name| matches!(name, "text" | "array"))
                || arg.name.is_none() && index == 0)
                .then_some(arg.value)
        })
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
        "kotlin-file-write" => &[
            "writeText",
            "writeBytes",
            "appendText",
            "appendBytes",
            "outputStream",
        ],
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
        let parameters: &[&str] = match method {
            "readText" => &["charset"],
            "writeText" | "appendText" => &["text", "charset"],
            "writeBytes" | "appendBytes" => &["array"],
            _ => &[],
        };
        let mut positions = std::collections::BTreeSet::new();
        for (index, arg) in call.arguments.iter().enumerate() {
            let position = match arg.name.as_deref() {
                Some(name) => parameters.iter().position(|p| *p == name),
                None => (index < parameters.len()).then_some(index),
            };
            if !position.is_some_and(|p| positions.insert(p)) {
                return false;
            }
        }
        if matches!(
            method,
            "writeText" | "appendText" | "writeBytes" | "appendBytes"
        ) && !positions.contains(&0)
        {
            return false;
        }
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
