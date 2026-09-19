use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, enclosing_type_start, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan java-network-transport-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_network_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }
    // Replace name-only Java network and destination-validation seeds. All
    // observations below require an exact import plus a typed/static receiver.
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "java-outbound-http" | "java-url-destination-validation"
        )
    });

    let imports = imports(root);
    let declarations = declared_types(root);
    add_outbound_observations(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_destination_controls(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_transport_policy(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_outbound_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rest_template = imported_exact(
        imports,
        declarations,
        "org.springframework.web.client.RestTemplate",
        "RestTemplate",
    );
    let request_entity = imported_exact(
        imports,
        declarations,
        "org.springframework.http.RequestEntity",
        "RequestEntity",
    );
    let web_client = imported_exact(
        imports,
        declarations,
        "org.springframework.web.reactive.function.client.WebClient",
        "WebClient",
    );
    let jdk_request = imported_exact(
        imports,
        declarations,
        "java.net.http.HttpRequest",
        "HttpRequest",
    );
    let jdk_client = imported_exact(
        imports,
        declarations,
        "java.net.http.HttpClient",
        "HttpClient",
    );
    let uri = imported_exact(imports, declarations, "java.net.URI", "URI");
    let url = imported_exact(imports, declarations, "java.net.URL", "URL");
    let apache4_request = imported_any_exact(
        imports,
        declarations,
        &[
            "org.apache.http.client.methods.HttpGet",
            "org.apache.http.client.methods.HttpPost",
            "org.apache.http.client.methods.HttpPut",
            "org.apache.http.client.methods.HttpDelete",
            "org.apache.http.client.methods.HttpPatch",
        ],
    );
    let apache5_request = imported_any_exact(
        imports,
        declarations,
        &[
            "org.apache.hc.client5.http.classic.methods.HttpGet",
            "org.apache.hc.client5.http.classic.methods.HttpPost",
            "org.apache.hc.client5.http.classic.methods.HttpPut",
            "org.apache.hc.client5.http.classic.methods.HttpDelete",
            "org.apache.hc.client5.http.classic.methods.HttpPatch",
        ],
    );
    let apache4_client = imported_any_exact(
        imports,
        declarations,
        &[
            "org.apache.http.client.HttpClient",
            "org.apache.http.impl.client.CloseableHttpClient",
        ],
    );
    let apache5_client = imported_exact(
        imports,
        declarations,
        "org.apache.hc.client5.http.classic.HttpClient",
        "HttpClient",
    ) || imported_exact(
        imports,
        declarations,
        "org.apache.hc.client5.http.impl.classic.CloseableHttpClient",
        "CloseableHttpClient",
    );

    for invocation in invocations(root) {
        let Some(operation) = invocation
            .field("name")
            .map(|name| name.text().into_owned())
        else {
            continue;
        };
        let args = arguments(&invocation);
        let object = invocation.field("object");

        if rest_template
            && rest_template_methods().contains(&operation.as_str())
            && object
                .as_ref()
                .is_some_and(|object| receiver_is_at(&invocation, object, "RestTemplate"))
            && let Some(endpoint) = args.first()
            && !(operation == "exchange"
                && request_entity
                && receiver_is_at(&invocation, endpoint, "RequestEntity"))
        {
            push(
                path,
                &invocation,
                endpoint,
                "java-spring-resttemplate-outbound-request",
                EvidenceKind::Sink,
                Capability::OutboundNetworkRequest,
                "endpoint",
                &["CWE-918"],
                &[
                    "http",
                    "ssrf",
                    "spring",
                    "rest-template",
                    operation.as_str(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if rest_template
            && request_entity
            && operation == "exchange"
            && object
                .as_ref()
                .is_some_and(|object| receiver_is_at(&invocation, object, "RestTemplate"))
            && let Some(request) = args
                .first()
                .filter(|request| receiver_is_at(&invocation, request, "RequestEntity"))
        {
            push(
                path,
                &invocation,
                request,
                "java-spring-requestentity-dispatch",
                EvidenceKind::SensitiveOperation,
                Capability::OutboundNetworkRequest,
                "request",
                &["CWE-918"],
                &["http", "spring", "rest-template", "request-object-dispatch"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if jdk_request
            && operation == "newBuilder"
            && object.as_ref().is_some_and(|object| {
                matches!(
                    object.text().trim(),
                    "HttpRequest" | "java.net.http.HttpRequest"
                )
            })
            && let Some(endpoint) = args.first()
        {
            push(
                path,
                &invocation,
                endpoint,
                "java-jdk-http-request-builder",
                EvidenceKind::Sink,
                Capability::OutboundNetworkRequest,
                "endpoint",
                &["CWE-918"],
                &["http", "ssrf", "jdk-http-client", "request-builder"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if jdk_request
            && operation == "uri"
            && object
                .as_ref()
                .is_some_and(|object| jdk_request_builder_receiver(root, object))
            && let Some(endpoint) = args.first()
        {
            push(
                path,
                &invocation,
                endpoint,
                "java-jdk-http-request-builder",
                EvidenceKind::Sink,
                Capability::OutboundNetworkRequest,
                "endpoint",
                &["CWE-918"],
                &[
                    "http",
                    "ssrf",
                    "jdk-http-client",
                    "request-builder-uri-mutation",
                    "typed-receiver",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if jdk_client
            && matches!(operation.as_str(), "send" | "sendAsync")
            && object
                .as_ref()
                .is_some_and(|object| receiver_is_at(&invocation, object, "HttpClient"))
            && let Some(request) = args.first()
        {
            push(
                path,
                &invocation,
                request,
                "java-jdk-http-client-dispatch",
                EvidenceKind::SensitiveOperation,
                Capability::OutboundNetworkRequest,
                "request",
                &["CWE-918"],
                &[
                    "http",
                    "jdk-http-client",
                    "request-dispatch",
                    operation.as_str(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if (apache4_client || apache5_client)
            && operation == "execute"
            && object.as_ref().is_some_and(|object| {
                receiver_is_at(&invocation, object, "HttpClient")
                    || receiver_is_at(&invocation, object, "CloseableHttpClient")
            })
            && let Some(request) = args.first()
        {
            push(
                path,
                &invocation,
                request,
                "java-apache-http-dispatch",
                EvidenceKind::SensitiveOperation,
                Capability::OutboundNetworkRequest,
                "request",
                &["CWE-918"],
                &["http", "apache-http-client", "request-dispatch"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if web_client
            && operation == "uri"
            && object
                .as_ref()
                .and_then(|node| root_receiver(node.clone()))
                .is_some_and(|receiver| receiver_is_at(&invocation, &receiver, "WebClient"))
            && let Some(endpoint) = args.first()
        {
            push(
                path,
                &invocation,
                endpoint,
                "java-spring-webclient-outbound-request",
                EvidenceKind::Sink,
                Capability::OutboundNetworkRequest,
                "endpoint",
                &["CWE-918"],
                &["http", "ssrf", "spring", "web-client"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if operation == "openConnection"
            && let Some(object) = object
        {
            let endpoint = if uri {
                uri_connection_endpoint(&invocation, &object)
            } else {
                None
            }
            .or_else(|| {
                if url {
                    url_connection_endpoint(&invocation, &object)
                } else {
                    None
                }
            });
            if let Some(endpoint) = endpoint {
                push(
                    path,
                    &invocation,
                    &endpoint,
                    "java-outbound-http",
                    EvidenceKind::Sink,
                    Capability::OutboundNetworkRequest,
                    "endpoint",
                    &["CWE-918"],
                    &["http", "ssrf", "jdk", "url-connection"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }

    if apache4_request || apache5_request {
        for creation in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "object_creation_expression")
        {
            let Some(kind) = creation.field("type") else {
                continue;
            };
            let kind_text = kind.text();
            let short = short_type(kind_text.as_ref());
            if !matches!(
                short,
                "HttpGet" | "HttpPost" | "HttpPut" | "HttpDelete" | "HttpPatch"
            ) || !(type_imported_for_short(imports, short, 4) && apache4_request
                || type_imported_for_short(imports, short, 5) && apache5_request)
            {
                continue;
            }
            let Some(endpoint) = creation
                .field("arguments")
                .and_then(|args| args.children().find(|child| child.is_named()))
            else {
                continue;
            };
            push(
                path,
                &creation,
                &endpoint,
                "java-apache-http-request",
                EvidenceKind::Sink,
                Capability::OutboundNetworkRequest,
                "endpoint",
                &["CWE-918"],
                &["http", "ssrf", "apache-http-client", short],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn jdk_request_builder_receiver(
    root: &Node<'_, StrDoc<SupportLang>>,
    expression: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    if expression.kind().as_ref() == "method_invocation" {
        return expression
            .field("name")
            .is_some_and(|name| name.text().as_ref() == "newBuilder")
            && expression.field("object").is_some_and(|object| {
                matches!(
                    object.text().trim(),
                    "HttpRequest" | "java.net.http.HttpRequest"
                )
            });
    }
    let name = expression.text();
    if !name
        .chars()
        .all(|character| character.is_alphanumeric() || matches!(character, '_' | '$'))
    {
        return false;
    }
    let bindings = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter(|binding| {
            binding.range().end <= expression.range().start
                && binding
                    .field("name")
                    .is_some_and(|field| field.text() == name)
                && binding.ancestors().any(|scope| {
                    matches!(scope.kind().as_ref(), "block" | "method_declaration")
                        && scope.range().start <= expression.range().start
                        && expression.range().end <= scope.range().end
                })
        })
        .collect::<Vec<_>>();
    let Some(binding) = bindings.last() else {
        return false;
    };
    let declared_builder = binding
        .parent()
        .and_then(|declaration| declaration.field("type"));
    if declared_builder.is_some_and(|kind| {
        matches!(
            kind.text().as_ref(),
            "HttpRequest.Builder" | "java.net.http.HttpRequest.Builder"
        )
    }) {
        return true;
    }
    binding
        .field("value")
        .is_some_and(|value| jdk_request_builder_receiver(root, &value))
}

#[allow(clippy::too_many_arguments)]
fn add_destination_controls<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let uri = imported_exact(imports, declarations, "java.net.URI", "URI");
    let inet = imported_exact(imports, declarations, "java.net.InetAddress", "InetAddress");
    let set = imported_exact(imports, declarations, "java.util.Set", "Set");
    let list = imported_exact(imports, declarations, "java.util.List", "List");
    for invocation in invocations(root) {
        let Some(operation) = invocation
            .field("name")
            .map(|name| name.text().into_owned())
        else {
            continue;
        };
        let args = arguments(&invocation);
        let text = compact(invocation.text().as_ref());

        if uri
            && operation == "equals"
            && (text.contains(".getScheme().equals(\"https\")")
                || text.starts_with("\"https\".equals(") && text.contains(".getScheme())"))
            && let Some(endpoint) = nested_receiver_with_method(&invocation, "getScheme")
            && receiver_is_at(&invocation, &endpoint, "URI")
        {
            push(
                path,
                &invocation,
                &endpoint,
                "java-uri-https-scheme-control",
                EvidenceKind::Validation,
                Capability::UrlDestinationValidation,
                "endpoint",
                &["CWE-918"],
                &["url", "ssrf", "scheme", "https"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if uri
            && matches!(operation.as_str(), "contains" | "equals")
            && invocation.text().contains("getHost()")
            && let Some(endpoint) = nested_receiver_with_method(&invocation, "getHost")
            && receiver_is_at(&invocation, &endpoint, "URI")
            && (operation == "equals"
                || invocation.field("object").is_some_and(|object| {
                    set && receiver_is_at(&invocation, &object, "Set")
                        || list && receiver_is_at(&invocation, &object, "List")
                }))
        {
            push(
                path,
                &invocation,
                &endpoint,
                "java-uri-host-policy-control",
                EvidenceKind::Validation,
                Capability::UrlDestinationValidation,
                "endpoint",
                &["CWE-918"],
                &["url", "ssrf", "host-policy", operation.as_str()],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if inet
            && matches!(
                operation.as_str(),
                "isAnyLocalAddress"
                    | "isLoopbackAddress"
                    | "isLinkLocalAddress"
                    | "isSiteLocalAddress"
            )
            && let Some(object) = invocation.field("object")
            && receiver_is_at(&invocation, &object, "InetAddress")
        {
            push(
                path,
                &invocation,
                &object,
                "java-inet-private-address-check",
                EvidenceKind::Validation,
                Capability::UrlDestinationValidation,
                "address",
                &["CWE-918"],
                &["url", "ssrf", "private-address", operation.as_str()],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if operation == "disableRedirectHandling"
            && imports.contains("org.apache.http.impl.client.HttpClients")
            && invocation.text().contains("HttpClients")
        {
            push_without_capture(
                path,
                &invocation,
                "java-apache-redirect-disabled-control",
                EvidenceKind::Validation,
                Capability::UrlDestinationValidation,
                &["CWE-918"],
                &["http", "ssrf", "redirect", "disabled"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        let _ = args;
    }
}

#[allow(clippy::too_many_arguments)]
fn add_transport_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let trust_all = imported_exact(
        imports,
        declarations,
        "org.apache.http.conn.ssl.TrustAllStrategy",
        "TrustAllStrategy",
    );
    let noop_hostname = imported_exact(
        imports,
        declarations,
        "org.apache.http.conn.ssl.NoopHostnameVerifier",
        "NoopHostnameVerifier",
    ) || imported_exact(
        imports,
        declarations,
        "org.apache.hc.client5.http.ssl.NoopHostnameVerifier",
        "NoopHostnameVerifier",
    );
    let default_hostname = imported_exact(
        imports,
        declarations,
        "org.apache.http.conn.ssl.DefaultHostnameVerifier",
        "DefaultHostnameVerifier",
    ) || imported_exact(
        imports,
        declarations,
        "org.apache.hc.client5.http.ssl.DefaultHostnameVerifier",
        "DefaultHostnameVerifier",
    );
    let hostname_verifier = imported_exact(
        imports,
        declarations,
        "javax.net.ssl.HostnameVerifier",
        "HostnameVerifier",
    );
    let trust_strategy = imported_exact(
        imports,
        declarations,
        "org.apache.http.ssl.TrustStrategy",
        "TrustStrategy",
    ) || imported_exact(
        imports,
        declarations,
        "org.apache.http.conn.ssl.TrustStrategy",
        "TrustStrategy",
    );
    let x509_trust_manager = imported_exact(
        imports,
        declarations,
        "javax.net.ssl.X509TrustManager",
        "X509TrustManager",
    );

    for creation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "object_creation_expression")
    {
        let Some(kind) = creation.field("type") else {
            continue;
        };
        let kind_text = kind.text();
        let short = short_type(kind_text.as_ref());
        if trust_all && short == "TrustAllStrategy" {
            push_without_capture(
                path,
                &creation,
                "java-apache-trust-all-certificates",
                EvidenceKind::SecurityConfiguration,
                Capability::TlsConfiguration,
                &["CWE-295"],
                &[
                    "tls",
                    "certificate-validation",
                    "trust-all",
                    "apache-http-client",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if default_hostname && short == "DefaultHostnameVerifier" {
            push_without_capture(
                path,
                &creation,
                "java-apache-default-hostname-verifier-control",
                EvidenceKind::Validation,
                Capability::TlsConfiguration,
                &["CWE-295"],
                &["tls", "hostname-verification", "default-verifier"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if noop_hostname
            && creation
                .field("arguments")
                .is_some_and(|args| args.text().contains("NoopHostnameVerifier.INSTANCE"))
        {
            push_without_capture(
                path,
                &creation,
                "java-apache-hostname-verification-disabled",
                EvidenceKind::SecurityConfiguration,
                Capability::TlsConfiguration,
                &["CWE-295"],
                &[
                    "tls",
                    "hostname-verification",
                    "disabled",
                    "apache-http-client",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if x509_trust_manager
            && short == "X509TrustManager"
            && creation.dfs().any(|method| {
                method.kind().as_ref() == "method_declaration"
                    && method
                        .field("name")
                        .is_some_and(|name| name.text().as_ref() == "checkServerTrusted")
                    && method
                        .field("body")
                        .is_some_and(|body| !body.children().any(|child| child.is_named()))
            })
        {
            push_without_capture(
                path,
                &creation,
                "java-x509-trust-manager-empty-server-check",
                EvidenceKind::SecurityConfiguration,
                Capability::TlsConfiguration,
                &["CWE-295"],
                &["tls", "certificate-validation", "empty-server-check"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    if hostname_verifier {
        for declaration in root.dfs().filter(|node| {
            node.kind().as_ref() == "local_variable_declaration"
                && node
                    .field("type")
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == "HostnameVerifier")
        }) {
            if declaration.text().contains("-> true")
                || compact(declaration.text().as_ref()).contains("->true")
            {
                push_without_capture(
                    path,
                    &declaration,
                    "java-hostname-verifier-always-accepts",
                    EvidenceKind::SecurityConfiguration,
                    Capability::TlsConfiguration,
                    &["CWE-295"],
                    &["tls", "hostname-verification", "always-true-callback"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
    if trust_strategy {
        for declaration in root.dfs().filter(|node| {
            node.kind().as_ref() == "local_variable_declaration"
                && node
                    .field("type")
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == "TrustStrategy")
        }) {
            if compact(declaration.text().as_ref()).contains("->true") {
                push_without_capture(
                    path,
                    &declaration,
                    "java-apache-trust-strategy-always-accepts",
                    EvidenceKind::SecurityConfiguration,
                    Capability::TlsConfiguration,
                    &["CWE-295"],
                    &["tls", "certificate-validation", "always-true-callback"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

fn rest_template_methods() -> &'static [&'static str] {
    &[
        "getForObject",
        "getForEntity",
        "postForObject",
        "postForEntity",
        "patchForObject",
        "exchange",
        "execute",
        "put",
        "delete",
    ]
}

fn uri_connection_endpoint<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    object: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if object.kind().as_ref() != "method_invocation"
        || object.field("name")?.text().as_ref() != "toURL"
    {
        return None;
    }
    let endpoint = object.field("object")?;
    receiver_is_at(invocation, &endpoint, "URI").then_some(endpoint)
}

fn url_connection_endpoint<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    object: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if object.kind().as_ref() == "object_creation_expression"
        && object
            .field("type")
            .is_some_and(|kind| short_type(kind.text().as_ref()) == "URL")
    {
        return object
            .field("arguments")
            .and_then(|args| args.children().find(|child| child.is_named()));
    }
    if receiver_is_at(invocation, object, "URL") {
        return initializer_before(invocation, object.text().trim()).and_then(|initializer| {
            initializer
                .field("arguments")
                .and_then(|args| args.children().find(|child| child.is_named()))
        });
    }
    None
}

fn nested_receiver_with_method<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    method: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    invocation.dfs().find_map(|node| {
        (node.kind().as_ref() == "method_invocation"
            && node
                .field("name")
                .is_some_and(|name| name.text().as_ref() == method))
        .then(|| node.field("object"))
        .flatten()
    })
}

fn root_receiver<'tree>(
    mut node: Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    loop {
        if node.kind().as_ref() != "method_invocation" {
            return Some(node);
        }
        node = node.field("object")?;
    }
}

fn receiver_is_at(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    expected: &str,
) -> bool {
    let text = receiver.text();
    let name = text.trim();
    if receiver.kind().as_ref() == "object_creation_expression" {
        return receiver
            .field("type")
            .is_some_and(|kind| short_type(kind.text().as_ref()) == expected);
    }
    let Some(method) = use_site.ancestors().find(|node| {
        matches!(
            node.kind().as_ref(),
            "method_declaration" | "constructor_declaration"
        )
    }) else {
        return false;
    };
    let mut found = None;
    for node in method
        .dfs()
        .filter(|node| node.range().start <= use_site.range().start)
    {
        if matches!(node.kind().as_ref(), "parameter" | "formal_parameter")
            && node
                .field("name")
                .is_some_and(|value| value.text().trim() == name)
            && let Some(kind) = node.field("type")
        {
            found = Some(kind.text().into_owned());
        }
        if node.kind().as_ref() == "local_variable_declaration"
            && lexical_declaration_visible_at(&node, use_site)
            && node.children().any(|child| {
                child.kind().as_ref() == "variable_declarator"
                    && child
                        .field("name")
                        .is_some_and(|value| value.text().trim() == name)
            })
            && let Some(kind) = node.field("type")
        {
            found = Some(kind.text().into_owned());
        }
    }
    if found.is_some_and(|kind| short_type(&kind) == expected) {
        return true;
    }
    let Some(root) = use_site.ancestors().last() else {
        return false;
    };
    let owner = enclosing_type_start(use_site);
    root.dfs().any(|node| {
        node.kind().as_ref() == "field_declaration"
            && enclosing_type_start(&node) == owner
            && node
                .field("type")
                .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
            && node.children().any(|child| {
                child.kind().as_ref() == "variable_declarator"
                    && child
                        .field("name")
                        .is_some_and(|value| value.text().trim() == name)
            })
    })
}

fn initializer_before<'tree>(
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let method = use_site.ancestors().find(|node| {
        matches!(
            node.kind().as_ref(),
            "method_declaration" | "constructor_declaration"
        )
    })?;
    method
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && node.range().start < use_site.range().start
        })
        .filter(|node| {
            node.field("name")
                .is_some_and(|value| value.text().trim() == name)
        })
        .filter_map(|node| node.field("value"))
        .last()
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> impl Iterator<Item = Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
}

fn arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .map(|import| {
            import
                .text()
                .trim()
                .trim_start_matches("import ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .to_string()
        })
        .collect()
}

fn declared_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
                    | "annotation_type_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .collect()
}

fn imported_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonical: &str,
    short: &str,
) -> bool {
    let namespace = canonical
        .rsplit_once('.')
        .map(|(namespace, _)| namespace)
        .unwrap_or_default();
    !declarations.contains(short)
        && (imports.contains(canonical) || imports.contains(&format!("{namespace}.*")))
}

fn imported_any_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonicals: &[&str],
) -> bool {
    canonicals.iter().any(|canonical| {
        let short = canonical.rsplit('.').next().unwrap_or(canonical);
        imported_exact(imports, declarations, canonical, short)
    })
}

fn type_imported_for_short(imports: &BTreeSet<String>, short: &str, major: u8) -> bool {
    let prefix = if major == 4 {
        "org.apache.http.client.methods."
    } else {
        "org.apache.hc.client5.http.classic.methods."
    };
    imports.contains(&format!("{prefix}{short}")) || imports.contains(&format!("{prefix}*"))
}

fn short_type(kind: &str) -> &str {
    kind.trim()
        .rsplit('.')
        .next()
        .unwrap_or(kind.trim())
        .split('<')
        .next()
        .unwrap_or(kind.trim())
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    captured: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        node,
        rule_id,
        kind,
        capability,
        BTreeMap::from([(
            role.to_string(),
            Capture {
                text: captured.text().into_owned(),
                location: location(path, captured),
            },
        )]),
        BTreeMap::from([(role.to_string(), literals.evaluate(captured))]),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_without_capture<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        node,
        rule_id,
        kind,
        capability,
        BTreeMap::new(),
        BTreeMap::new(),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    literal_values: BTreeMap<String, mehscan_core::LiteralEvaluation>,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    );
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: literal_values,
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let range = node.range();
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: range.start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: range.end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}
