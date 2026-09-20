use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution, SymbolConfidence,
    SymbolResolution, SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const FASTIFY_ENGINE: &str = "ast-grep 0.45.1 + bounded-fastify-boundary";

#[derive(Default)]
struct FastifyIdentity {
    imports: BTreeMap<String, String>,
    instances: BTreeSet<String>,
}

#[derive(Clone)]
struct FastifyRoute<'tree> {
    call: Node<'tree, StrDoc<SupportLang>>,
    handler: Node<'tree, StrDoc<SupportLang>>,
    request: Option<String>,
    reply: Option<String>,
    method: String,
    path: String,
    guards: Vec<String>,
    schema: Option<Node<'tree, StrDoc<SupportLang>>>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_fastify_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) {
        return;
    }
    let identity = fastify_identity(root);
    add_exported_plugin_observations(
        path,
        root,
        language,
        &identity,
        comments,
        conditional,
        literals,
        evidence,
    );
    if identity.instances.is_empty() {
        return;
    }

    add_plugin_registration_observations(
        path,
        root,
        language,
        &identity,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_hook_observations(
        path,
        root,
        language,
        &identity,
        comments,
        conditional,
        literals,
        evidence,
    );

    let routes = fastify_routes(root, &identity);
    for route in &routes {
        let context = route_context(route);
        push_evidence(
            path,
            language,
            &route.call,
            EvidenceKind::Entrypoint,
            Capability::HttpRequestHandling,
            "fastify-http-entrypoint",
            Vec::new(),
            BTreeMap::from([("route".to_string(), capture(path, &route.call))]),
            vec!["http", "entrypoint", "fastify"],
            Some(context.clone()),
            Some(("fastify.route", route.method.as_str())),
            comments,
            conditional,
            literals,
            evidence,
        );
        if let Some(schema) = &route.schema {
            let mut tags = vec![
                "http",
                "validation",
                "fastify",
                "json-schema",
                "context-only",
            ];
            let schema_text = compact(&schema.text());
            for (needle, tag) in [
                ("body:", "body-schema"),
                ("querystring:", "query-schema"),
                ("params:", "params-schema"),
                ("headers:", "headers-schema"),
                ("response:", "response-schema"),
            ] {
                if schema_text.contains(needle) {
                    tags.push(tag);
                }
            }
            push_evidence(
                path,
                language,
                schema,
                EvidenceKind::Validation,
                Capability::HttpRequestData,
                "fastify-route-schema",
                Vec::new(),
                BTreeMap::from([("schema".to_string(), capture(path, schema))]),
                tags,
                Some(context.clone()),
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if !route.guards.is_empty() {
            let capability = if route
                .guards
                .iter()
                .any(|guard| looks_like_role_guard(guard))
            {
                Capability::Authorization
            } else {
                Capability::Authentication
            };
            push_evidence(
                path,
                language,
                &route.call,
                EvidenceKind::Guard,
                capability,
                "fastify-route-pre-handler",
                Vec::new(),
                BTreeMap::from([(
                    "guards".to_string(),
                    text_capture(path, &route.call, route.guards.join(",")),
                )]),
                vec![
                    "http",
                    "guard",
                    "fastify",
                    "pre-handler",
                    "needs-verification",
                ],
                Some(context.clone()),
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        add_route_sources(
            path,
            language,
            route,
            &context,
            comments,
            conditional,
            literals,
            evidence,
        );
        add_reply_observations(
            path,
            language,
            route,
            &context,
            comments,
            conditional,
            literals,
            evidence,
        );

        for item in evidence.iter_mut().filter(|item| {
            item.location.path == path
                && item.location.start.byte_offset >= route.handler.range().start
                && item.location.end.byte_offset <= route.handler.range().end
        }) {
            if !item.context.http_routes.contains(&context) {
                item.context.http_routes.push(context.clone());
            }
        }
    }
}

fn fastify_identity(root: &Node<'_, StrDoc<SupportLang>>) -> FastifyIdentity {
    let mut identity = FastifyIdentity::default();
    for node in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "import_statement")
    {
        let text = node.text();
        let Some((clause, module)) = text
            .trim()
            .strip_prefix("import ")
            .and_then(|rest| rest.rsplit_once(" from "))
        else {
            continue;
        };
        let Some(module) = exact_quoted(module.trim().trim_end_matches(';')) else {
            continue;
        };
        if module != "fastify" && module != "fastify-plugin" && !module.starts_with("@fastify/") {
            continue;
        }
        let clause = clause.trim().strip_prefix("type ").unwrap_or(clause.trim());
        if !clause.starts_with('{')
            && !clause.starts_with("* as ")
            && let Some(local) = clause
                .split(',')
                .next()
                .map(str::trim)
                .filter(|name| !name.is_empty())
        {
            identity
                .imports
                .insert(local.to_string(), module.to_string());
        }
        if clause.starts_with('{') {
            for entry in clause.trim_matches(['{', '}']).split(',') {
                let words = entry.split_whitespace().collect::<Vec<_>>();
                let words = words.strip_prefix(&["type"]).unwrap_or(words.as_slice());
                let Some(imported) = words.first().copied() else {
                    continue;
                };
                let local = if words.get(1) == Some(&"as") {
                    words.get(2).copied().unwrap_or(imported)
                } else {
                    imported
                };
                identity
                    .imports
                    .insert(local.to_string(), format!("{module}.{imported}"));
            }
        }
    }
    for call in root.dfs().filter_map(call_site) {
        if identity.imports.get(&call.callee).map(String::as_str) != Some("fastify") {
            continue;
        }
        if let Some(parent) = call.node.parent()
            && parent.kind().as_ref() == "variable_declarator"
            && let Some(name) = parent.field("name")
        {
            identity.instances.insert(name.text().trim().to_string());
        }
    }
    for call in root.dfs().filter_map(call_site) {
        if identity.imports.get(&call.callee).map(String::as_str) != Some("fastify-plugin") {
            continue;
        }
        let Some(callback) = call
            .arguments
            .first()
            .filter(|argument| is_function(argument.kind().as_ref()))
        else {
            continue;
        };
        if let Some(parameters) = callback.field("parameters")
            && let Some(parameter) = parameters.children().find(|child| child.is_named())
            && let Some(name) = parameter_identifier(&parameter)
        {
            identity.instances.insert(name);
        }
    }
    for function in root.dfs().filter(|node| is_function(node.kind().as_ref())) {
        let function_text = compact(&function.text());
        let declaration_text = function
            .parent()
            .map(|parent| compact(&parent.text()))
            .unwrap_or_default();
        let typed_instance = function_text.contains(":FastifyInstance")
            || function_text.contains(":FastifyPlugin")
            || function_text.contains(":FastifyPluginAsyncTypebox")
            || function_text.contains(":FastifyPluginCallbackTypebox")
            || declaration_text.contains(":FastifyPlugin");
        if !typed_instance {
            continue;
        }
        if let Some(parameters) = function.field("parameters")
            && let Some(parameter) = parameters.children().find(|child| child.is_named())
            && let Some(name) = parameter_identifier(&parameter)
        {
            identity.instances.insert(name);
        }
    }
    identity
}

fn fastify_routes<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    identity: &FastifyIdentity,
) -> Vec<FastifyRoute<'tree>> {
    let mut routes = Vec::new();
    for call in root.dfs().filter_map(call_site) {
        let Some((receiver, terminal)) = call.callee.rsplit_once('.') else {
            continue;
        };
        if !identity.instances.contains(receiver)
            || !matches!(
                terminal,
                "get" | "post" | "put" | "patch" | "delete" | "options" | "head"
            )
        {
            continue;
        }
        let Some(handler) = call
            .arguments
            .iter()
            .rev()
            .find(|node| is_function(node.kind().as_ref()))
            .cloned()
        else {
            continue;
        };
        let parameters = handler
            .field("parameters")
            .map(|parameters| {
                parameters
                    .children()
                    .filter(|child| child.is_named())
                    .filter_map(|parameter| parameter_identifier(&parameter))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let options = call
            .arguments
            .iter()
            .skip(1)
            .find(|argument| argument.kind().as_ref() == "object");
        let schema = options.and_then(|options| object_property_value(options, "schema"));
        let guards = options
            .and_then(|options| object_property_value(options, "preHandler"))
            .map(|value| vec![compact(&value.text())])
            .unwrap_or_default();
        routes.push(FastifyRoute {
            call: call.node,
            handler,
            request: parameters.first().cloned(),
            reply: parameters.get(1).cloned(),
            method: terminal.to_ascii_uppercase(),
            path: call
                .arguments
                .first()
                .and_then(|argument| exact_quoted(&argument.text()).map(str::to_string))
                .unwrap_or_else(|| "<dynamic>".to_string()),
            guards,
            schema,
        });
    }
    routes
}

#[allow(clippy::too_many_arguments)]
fn add_route_sources<'tree>(
    path: &str,
    language: Language,
    route: &FastifyRoute<'tree>,
    context: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(request) = route.request.as_deref() else {
        return;
    };
    for node in route.handler.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "member_expression" | "subscript_expression"
        )
    }) {
        let observed = compact(&node.text()).replace("?.", ".");
        let Some(field) = request_field(&observed, request) else {
            continue;
        };
        if node.parent().is_some_and(|parent| {
            matches!(
                parent.kind().as_ref(),
                "member_expression" | "subscript_expression"
            ) && request_field(&compact(&parent.text()).replace("?.", "."), request).is_some()
        }) {
            continue;
        }
        push_evidence(
            path,
            language,
            &node,
            EvidenceKind::Source,
            Capability::HttpRequestData,
            "fastify-request-data",
            vec!["CWE-20"],
            BTreeMap::from([
                ("value".to_string(), capture(path, &node)),
                (
                    "field".to_string(),
                    text_capture(path, &node, field.to_string()),
                ),
            ]),
            vec!["http", "request", "attacker-controlled", "fastify"],
            Some(context.clone()),
            Some(("fastify.FastifyRequest", request)),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    for call in route.handler.dfs().filter_map(call_site) {
        if matches!(call.callee.as_str(), callee if callee == format!("{request}.file") || callee == format!("{request}.files"))
        {
            push_evidence(
                path,
                language,
                &call.node,
                EvidenceKind::Source,
                Capability::UploadedFileContent,
                "fastify-uploaded-file",
                vec!["CWE-434"],
                BTreeMap::from([("file".to_string(), capture(path, &call.node))]),
                vec![
                    "http",
                    "request",
                    "upload",
                    "attacker-controlled",
                    "fastify",
                ],
                Some(context.clone()),
                Some(("fastify.FastifyRequest.file", &call.callee)),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_reply_observations<'tree>(
    path: &str,
    language: Language,
    route: &FastifyRoute<'tree>,
    context: &HttpRouteContext,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(reply) = route.reply.as_deref() else {
        return;
    };
    let handler_text = compact(&route.handler.text()).to_ascii_lowercase();
    let explicit_html = handler_text.contains(&format!("{reply}.type('text/html')"))
        || handler_text.contains(&format!("{reply}.type(\"text/html\")"))
        || handler_text.contains("content-type','text/html")
        || handler_text.contains("content-type\",\"text/html");
    for call in route.handler.dfs().filter_map(call_site) {
        let terminal = call
            .callee
            .rsplit_once('.')
            .map(|(_, terminal)| terminal)
            .unwrap_or(&call.callee);
        let receiver_owned = call.callee.split('.').next().unwrap_or_default();
        if receiver_owned != reply {
            continue;
        }
        match terminal {
            "redirect" => {
                if let Some(location) = call.arguments.last() {
                    push_evidence(
                        path,
                        language,
                        &call.node,
                        EvidenceKind::Sink,
                        Capability::Redirect,
                        "fastify-reply-redirect",
                        vec!["CWE-601"],
                        BTreeMap::from([("location".to_string(), capture(path, location))]),
                        vec!["http", "response", "redirect", "fastify"],
                        Some(context.clone()),
                        Some(("fastify.FastifyReply.redirect", &call.callee)),
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
            "send"
                if explicit_html
                    && (call.callee == format!("{reply}.send")
                        || (call.callee.starts_with(&format!("{reply}.type("))
                            && call.callee.ends_with(".send"))) =>
            {
                if let Some(content) = call.arguments.first() {
                    push_evidence(
                        path,
                        language,
                        &call.node,
                        EvidenceKind::Sink,
                        Capability::HtmlOutput,
                        "fastify-reply-html-output",
                        vec!["CWE-79"],
                        BTreeMap::from([("content".to_string(), capture(path, content))]),
                        vec![
                            "http",
                            "response",
                            "html",
                            "fastify",
                            "explicit-content-type",
                        ],
                        Some(context.clone()),
                        Some(("fastify.FastifyReply.send", &call.callee)),
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
            "header" if call.arguments.len() >= 2 => {
                let name_text = call.arguments[0].text();
                let name = exact_quoted(&name_text);
                let value = &call.arguments[1];
                if name.is_some_and(|name| name.eq_ignore_ascii_case("content-type"))
                    && exact_quoted(&value.text()).is_some()
                {
                    push_evidence(
                        path,
                        language,
                        &call.node,
                        EvidenceKind::SecurityConfiguration,
                        Capability::HttpHeaderOutput,
                        "fastify-reply-content-type",
                        Vec::new(),
                        BTreeMap::from([("content_type".to_string(), capture(path, value))]),
                        vec![
                            "http",
                            "response",
                            "content-type",
                            "fastify",
                            "context-only",
                        ],
                        Some(context.clone()),
                        Some(("fastify.FastifyReply.header", &call.callee)),
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                } else if exact_quoted(&value.text()).is_none() {
                    push_evidence(
                        path,
                        language,
                        &call.node,
                        EvidenceKind::Sink,
                        Capability::HttpHeaderOutput,
                        "fastify-reply-header-output",
                        vec!["CWE-113"],
                        BTreeMap::from([("value".to_string(), capture(path, value))]),
                        vec!["http", "response", "header", "fastify"],
                        Some(context.clone()),
                        Some(("fastify.FastifyReply.header", &call.callee)),
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
            "type"
                if call.arguments.first().is_some_and(|argument| {
                    let text = argument.text();
                    exact_quoted(&text).is_some()
                }) =>
            {
                let value = &call.arguments[0];
                push_evidence(
                    path,
                    language,
                    &call.node,
                    EvidenceKind::SecurityConfiguration,
                    Capability::HttpHeaderOutput,
                    "fastify-reply-content-type",
                    Vec::new(),
                    BTreeMap::from([("content_type".to_string(), capture(path, value))]),
                    vec![
                        "http",
                        "response",
                        "content-type",
                        "fastify",
                        "context-only",
                    ],
                    Some(context.clone()),
                    Some(("fastify.FastifyReply.type", &call.callee)),
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            "sendFile" | "download" => {
                if let Some(file) = call.arguments.first() {
                    push_evidence(
                        path,
                        language,
                        &call.node,
                        EvidenceKind::Sink,
                        Capability::FilesystemRead,
                        "fastify-reply-file",
                        vec!["CWE-22"],
                        BTreeMap::from([("path".to_string(), capture(path, file))]),
                        vec!["http", "response", "file", "fastify"],
                        Some(context.clone()),
                        Some(("fastify.FastifyReply.sendFile", &call.callee)),
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_plugin_registration_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    identity: &FastifyIdentity,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        let Some((receiver, terminal)) = call.callee.rsplit_once('.') else {
            continue;
        };
        if terminal != "register" || !identity.instances.contains(receiver) {
            continue;
        }
        let Some(plugin) = call.arguments.first() else {
            continue;
        };
        let plugin_name = compact(&plugin.text());
        let Some(module) = identity.imports.get(&plugin_name) else {
            continue;
        };
        let Some((capability, suffix, tags)) = plugin_fact(module) else {
            continue;
        };
        push_evidence(
            path,
            language,
            &call.node,
            EvidenceKind::SecurityConfiguration,
            capability,
            suffix,
            Vec::new(),
            BTreeMap::from([("plugin".to_string(), capture(path, plugin))]),
            tags,
            None,
            Some((module, &plugin_name)),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_exported_plugin_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    identity: &FastifyIdentity,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for export in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "export_statement")
    {
        let compact_export = compact(&export.text());
        let Some(value) = compact_export
            .strip_prefix("exportdefault")
            .map(|value| value.trim_end_matches(';'))
        else {
            continue;
        };
        let Some(module) = identity.imports.get(value) else {
            continue;
        };
        let Some((capability, suffix, mut tags)) = plugin_fact(module) else {
            continue;
        };
        tags.push("exported-plugin");
        tags.push("needs-registration-scope-verification");
        if path.replace('\\', "/").contains("/plugins/") {
            tags.push("autoload-candidate");
        }
        push_evidence(
            path,
            language,
            &export,
            EvidenceKind::SecurityConfiguration,
            capability,
            suffix,
            Vec::new(),
            BTreeMap::from([(
                "plugin".to_string(),
                text_capture(path, &export, value.to_string()),
            )]),
            tags,
            None,
            Some((module, value)),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn plugin_fact(module: &str) -> Option<(Capability, &'static str, Vec<&'static str>)> {
    match module {
        "@fastify/helmet" => Some((
            Capability::HttpHeaderOutput,
            "fastify-helmet-registration",
            vec!["http", "headers", "helmet", "fastify", "context-only"],
        )),
        "@fastify/cors" => Some((
            Capability::CorsConfiguration,
            "fastify-cors-registration",
            vec![
                "http",
                "cors",
                "fastify",
                "context-only",
                "needs-effective-policy-review",
            ],
        )),
        "@fastify/session" | "@fastify/cookie" => Some((
            Capability::CookieConfiguration,
            "fastify-cookie-session-registration",
            vec!["http", "cookie", "session", "fastify", "context-only"],
        )),
        "@fastify/rate-limit" => Some((
            Capability::HttpRequestHandling,
            "fastify-rate-limit-registration",
            vec!["http", "rate-limit", "fastify", "context-only"],
        )),
        "@fastify/multipart" => Some((
            Capability::FileUpload,
            "fastify-multipart-registration",
            vec!["http", "upload", "multipart", "fastify", "context-only"],
        )),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn add_hook_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    identity: &FastifyIdentity,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        let Some((receiver, terminal)) = call.callee.rsplit_once('.') else {
            continue;
        };
        if terminal != "addHook" || !identity.instances.contains(receiver) {
            continue;
        }
        let Some(stage_argument) = call.arguments.first() else {
            continue;
        };
        let stage_text = stage_argument.text();
        let Some(stage) = exact_quoted(&stage_text) else {
            continue;
        };
        if !matches!(stage, "onRequest" | "preValidation" | "preHandler") {
            continue;
        }
        let Some(handler) = call.arguments.get(1) else {
            continue;
        };
        if !looks_like_auth_guard(&handler.text()) {
            continue;
        }
        let role = looks_like_role_guard(&handler.text());
        push_evidence(
            path,
            language,
            &call.node,
            EvidenceKind::Guard,
            if role {
                Capability::Authorization
            } else {
                Capability::Authentication
            },
            "fastify-lifecycle-guard",
            Vec::new(),
            BTreeMap::from([(
                "hook".to_string(),
                text_capture(path, &call.node, stage.to_string()),
            )]),
            vec![
                "http",
                "guard",
                "fastify",
                "lifecycle-hook",
                "needs-scope-verification",
            ],
            None,
            Some(("fastify.addHook", &call.callee)),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn route_context(route: &FastifyRoute<'_>) -> HttpRouteContext {
    HttpRouteContext {
        method: route.method.clone(),
        path: route.path.clone(),
        // Hooks are custom code. Keep exact attachments without inferring
        // authentication or authorization from their names.
        access: HttpRouteAccess::Unknown,
        guards: route.guards.clone(),
    }
}

fn request_field<'a>(observed: &'a str, request: &str) -> Option<&'a str> {
    let rest = observed.strip_prefix(request)?.strip_prefix('.')?;
    let field = rest.split(['.', '[']).next()?;
    matches!(
        field,
        "body" | "query" | "params" | "headers" | "cookies" | "ip" | "url" | "hostname"
    )
    .then_some(field)
}

fn looks_like_auth_guard(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    [
        "auth",
        "session",
        "user",
        "jwt",
        "role",
        "admin",
        "moderator",
        "permission",
        "access",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn looks_like_role_guard(text: &str) -> bool {
    let text = text.to_ascii_lowercase();
    [
        "role",
        "admin",
        "moderator",
        "permission",
        "isallowed",
        "verifyaccess",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

fn object_property_value<'tree>(
    object: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    object
        .children()
        .filter(|child| child.is_named())
        .find_map(|child| {
            if !matches!(child.kind().as_ref(), "pair" | "property_signature") {
                return None;
            }
            let key = child.field("key").or_else(|| child.field("name"))?;
            (compact(&key.text()).trim_matches(['\'', '"']) == name)
                .then(|| {
                    child
                        .field("value")
                        .or_else(|| child.children().filter(|node| node.is_named()).last())
                })
                .flatten()
        })
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let callee = compact(&node.field("function")?.text()).replace("?.", ".");
    let arguments = node
        .field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .collect();
    Some(CallSite {
        node,
        callee,
        arguments,
    })
}

fn is_function(kind: &str) -> bool {
    matches!(
        kind,
        "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
    )
}

fn parameter_identifier(parameter: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if parameter.kind().as_ref() == "identifier" {
        return Some(parameter.text().trim().to_string());
    }
    parameter
        .field("pattern")
        .or_else(|| parameter.field("name"))
        .and_then(|node| {
            node.dfs()
                .find(|child| child.kind().as_ref() == "identifier")
        })
        .map(|node| node.text().trim().to_string())
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    language: Language,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    suffix: &str,
    cwes: Vec<&str>,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    route: Option<HttpRouteContext>,
    symbol: Option<(&str, &str)>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range()) {
        return;
    }
    let rule_id = format!("{}-{suffix}", language_prefix(language));
    let id = evidence_id(path, &rule_id, node.range().start, node.range().end);
    if let Some(existing) = evidence.iter_mut().find(|item| item.id == id) {
        if let Some(route) = route
            && !existing.context.http_routes.contains(&route)
        {
            existing.context.http_routes.push(route);
        }
        return;
    }
    let mut context = EvidenceContext {
        comment: false,
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        ..EvidenceContext::default()
    };
    if let Some(route) = route {
        context.http_routes.push(route)
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.into_iter().map(str::to_string).collect(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: FASTIFY_ENGINE.to_string(),
            rule_version: 1,
        },
        context,
        symbol_resolution: symbol.map(|(canonical, observed)| SymbolResolution {
            canonical: canonical.to_string(),
            observed: observed.to_string(),
            method: SymbolResolutionMethod::Alias,
            confidence: SymbolConfidence::High,
        }),
        rule_id,
        related_evidence: Vec::new(),
    });
}

fn language_prefix(language: Language) -> &'static str {
    match language {
        Language::Javascript => "javascript",
        Language::Typescript => "typescript",
        Language::Tsx => "tsx",
        _ => unreachable!(),
    }
}

fn exact_quoted(text: &str) -> Option<&str> {
    let text = text.trim();
    let quote = text.chars().next()?;
    let inner = matches!(quote, '\'' | '"' | '`')
        .then(|| text.strip_prefix(quote)?.strip_suffix(quote))
        .flatten()?;
    (!(quote == '`' && inner.contains("${"))).then_some(inner)
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn text_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: String) -> Capture {
    Capture {
        text,
        location: location(path, node),
    }
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
