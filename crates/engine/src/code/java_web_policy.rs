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
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan java-spring-web-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_web_policy_observations<'tree>(
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
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "java-cookie-secure-flag" | "java-cookie-httponly-flag"
        )
    });
    let imports = imports(root);
    let declarations = declared_types(root);
    add_spring_security_policy(
        path,
        root,
        &imports,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_cors_policy(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_cookie_policy(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_headers_and_proxy(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_logging_policy(
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
fn add_spring_security_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !imports.contains("org.springframework.security.config.annotation.web.builders.HttpSecurity")
    {
        return;
    }
    for invocation in invocations(root).filter(|node| inside_http_security_method(node)) {
        let Some(name) = invocation
            .field("name")
            .map(|node| node.text().into_owned())
        else {
            continue;
        };
        let args = arguments(&invocation);
        if name == "disable"
            && let Some(configurer) = invocation.field("object")
            && configurer.kind().as_ref() == "method_invocation"
            && configurer
                .field("name")
                .is_some_and(|node| node.text().trim() == "csrf")
        {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Authorization,
                "java-spring-csrf-disabled-review",
                &["CWE-352"],
                &[
                    "spring-security",
                    "csrf",
                    "disabled",
                    "verify-cookie-authentication",
                    "review-not-automatic-fix",
                ],
                &[],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if name == "csrf" && !args.is_empty() {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Authorization,
                "java-spring-csrf-configured-control",
                &[],
                &["spring-security", "csrf", "configured", "control"],
                &[],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if name == "cors" {
            let defaults = args.first().is_some_and(|arg| {
                compact(arg.text().as_ref()).ends_with("Customizer.withDefaults()")
            });
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                if defaults {
                    "java-spring-cors-defaults-review"
                } else {
                    "java-spring-cors-configured-review"
                },
                &[],
                &[
                    "spring-security",
                    "cors",
                    if defaults {
                        "configuration-source-review"
                    } else {
                        "configured"
                    },
                    "review-effective-origins",
                ],
                &[],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if name == "sessionCreationPolicy"
            && let Some(policy) = args.first()
        {
            let text = compact(policy.text().as_ref());
            let stateless = text.ends_with("SessionCreationPolicy.STATELESS");
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                if stateless {
                    "java-spring-stateless-session-control"
                } else {
                    "java-spring-session-creation-review"
                },
                &[],
                &[
                    "spring-security",
                    "session",
                    if stateless {
                        "stateless"
                    } else {
                        "stateful-review"
                    },
                ],
                &[("policy", policy)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if matches!(
            name.as_str(),
            "none" | "migrateSession" | "changeSessionId" | "newSession"
        ) && invocation.field("object").is_some_and(|object| {
            object.kind().as_ref() == "method_invocation"
                && object
                    .field("name")
                    .is_some_and(|node| node.text().trim() == "sessionFixation")
        }) {
            let disabled = name == "none";
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Authentication,
                if disabled {
                    "java-spring-session-fixation-disabled"
                } else {
                    "java-spring-session-fixation-control"
                },
                if disabled { &["CWE-384"] } else { &[] },
                &[
                    "spring-security",
                    "session-fixation",
                    if disabled {
                        "disabled"
                    } else {
                        "rotation-control"
                    },
                ],
                &[],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_cors_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !imported_exact(
        imports,
        declarations,
        "org.springframework.web.cors.CorsConfiguration",
        "CorsConfiguration",
    ) {
        return;
    }
    for credentials in invocations(root).filter(|node| {
        node.field("name")
            .is_some_and(|name| name.text().trim() == "setAllowCredentials")
            && arguments(node)
                .first()
                .is_some_and(|arg| compact(arg.text().as_ref()) == "true")
    }) {
        let Some(receiver) = credentials.field("object") else {
            continue;
        };
        if !receiver_is_at(&credentials, &receiver, "CorsConfiguration") {
            continue;
        }
        let Some(method) = credentials
            .ancestors()
            .find(|node| node.kind().as_ref() == "method_declaration")
        else {
            continue;
        };
        let receiver_name = receiver.text();
        let origin = invocations(root).find(|candidate| {
            candidate.range().start >= method.range().start
                && candidate.range().end <= method.range().end
                && candidate
                    .field("object")
                    .is_some_and(|object| object.text().trim() == receiver_name.trim())
                && candidate.field("name").is_some_and(|name| {
                    matches!(
                        name.text().as_ref(),
                        "setAllowedOrigins" | "setAllowedOriginPatterns"
                    )
                })
        });
        let wildcard = origin
            .as_ref()
            .is_some_and(|node| node.text().contains("\"*\""));
        push(
            path,
            &credentials,
            EvidenceKind::SecurityConfiguration,
            Capability::HttpRequestHandling,
            if wildcard {
                "java-spring-credentialed-wildcard-cors"
            } else {
                "java-spring-credentialed-cors-review"
            },
            if wildcard { &["CWE-942"] } else { &[] },
            &[
                "spring",
                "cors",
                "credentials",
                if wildcard {
                    "wildcard-origin"
                } else {
                    "verify-explicit-origins"
                },
            ],
            &[],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_cookie_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let servlet_cookie = imported_any_exact(
        imports,
        declarations,
        &["jakarta.servlet.http.Cookie", "javax.servlet.http.Cookie"],
    );
    let response_cookie = imported_exact(
        imports,
        declarations,
        "org.springframework.http.ResponseCookie",
        "ResponseCookie",
    );
    for invocation in invocations(root) {
        let Some(name) = invocation
            .field("name")
            .map(|node| node.text().into_owned())
        else {
            continue;
        };
        let args = arguments(&invocation);
        if servlet_cookie
            && matches!(name.as_str(), "setSecure" | "setHttpOnly" | "setAttribute")
            && let Some(receiver) = invocation.field("object")
            && receiver_is_at(&invocation, &receiver, "Cookie")
        {
            let (rule, cwes, tag) = if name == "setSecure"
                && args
                    .first()
                    .is_some_and(|arg| compact(arg.text().as_ref()) == "false")
            {
                (
                    "java-cookie-missing-secure",
                    &["CWE-614"][..],
                    "missing-secure",
                )
            } else if name == "setSecure" {
                ("java-cookie-secure-control", &[][..], "secure")
            } else if name == "setHttpOnly"
                && args
                    .first()
                    .is_some_and(|arg| compact(arg.text().as_ref()) == "false")
            {
                (
                    "java-cookie-missing-http-only",
                    &["CWE-1004"][..],
                    "missing-http-only",
                )
            } else if name == "setHttpOnly" {
                ("java-cookie-http-only-control", &[][..], "http-only")
            } else if name == "setAttribute"
                && args.first().is_some_and(|arg| {
                    literal_string(arg.text().as_ref())
                        .is_some_and(|value| value.eq_ignore_ascii_case("SameSite"))
                })
            {
                ("java-cookie-same-site-policy", &[][..], "same-site")
            } else {
                continue;
            };
            let captures = if name == "setSecure" {
                args.first()
                    .map(|value| vec![("secure", value)])
                    .unwrap_or_default()
            } else if name == "setHttpOnly" {
                args.first()
                    .map(|value| vec![("http_only", value)])
                    .unwrap_or_default()
            } else {
                args.get(1)
                    .map(|value| vec![("same_site", value)])
                    .unwrap_or_default()
            };
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::CookieConfiguration,
                rule,
                cwes,
                &["cookie", tag],
                &captures,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if response_cookie
            && matches!(name.as_str(), "secure" | "httpOnly" | "sameSite")
            && invocation.text().contains("ResponseCookie")
        {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::CookieConfiguration,
                "java-spring-response-cookie-policy",
                &[],
                &["spring", "cookie", name.as_str()],
                &[],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_headers_and_proxy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let response = imported_any_exact(
        imports,
        declarations,
        &[
            "jakarta.servlet.http.HttpServletResponse",
            "javax.servlet.http.HttpServletResponse",
        ],
    );
    let request = imported_any_exact(
        imports,
        declarations,
        &[
            "jakarta.servlet.http.HttpServletRequest",
            "javax.servlet.http.HttpServletRequest",
        ],
    );
    for invocation in invocations(root) {
        let Some(name) = invocation
            .field("name")
            .map(|node| node.text().into_owned())
        else {
            continue;
        };
        let args = arguments(&invocation);
        let Some(receiver) = invocation.field("object") else {
            continue;
        };
        if response
            && matches!(name.as_str(), "setHeader" | "addHeader")
            && receiver_is_at(&invocation, &receiver, "HttpServletResponse")
            && args.len() >= 2
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::HttpHeaderOutput,
                "java-servlet-raw-response-header",
                &["CWE-113"],
                &["servlet", "http-header", "raw-header-value"],
                &[("header_name", &args[0]), ("header_value", &args[1])],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if request
            && name == "getHeader"
            && receiver_is_at(&invocation, &receiver, "HttpServletRequest")
            && let Some(header) = args.first()
            && let Some(header_name) = literal_string(header.text().as_ref())
            && matches!(
                header_name.to_ascii_lowercase().as_str(),
                "x-forwarded-host" | "x-forwarded-proto" | "x-forwarded-for" | "forwarded"
            )
        {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                "java-forwarded-header-trust-review",
                &["CWE-346"],
                &[
                    "http",
                    "forwarded-header",
                    "verify-trusted-proxy",
                    "deployment-or-application-fix",
                ],
                &[("header", header)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_logging_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let logger = imported_any_exact(
        imports,
        declarations,
        &["org.slf4j.Logger", "org.apache.logging.log4j.Logger"],
    );
    let lombok_logger = imports.iter().any(|import| {
        matches!(
            import.as_str(),
            "lombok.extern.slf4j.Slf4j" | "lombok.extern.log4j.Log4j2"
        )
    }) && (root.text().contains("@Slf4j") || root.text().contains("@Log4j2"));
    if !logger && !lombok_logger {
        return;
    }
    for invocation in invocations(root) {
        let Some(name) = invocation
            .field("name")
            .map(|node| node.text().into_owned())
        else {
            continue;
        };
        if !matches!(name.as_str(), "trace" | "debug" | "info" | "warn" | "error") {
            continue;
        }
        let Some(receiver) = invocation.field("object") else {
            continue;
        };
        if !(logger && receiver_is_at(&invocation, &receiver, "Logger")
            || lombok_logger && matches!(receiver.text().trim(), "log" | "logger"))
        {
            continue;
        }
        let args = arguments(&invocation);
        let Some(message) = args.first() else {
            continue;
        };
        let rendered = message.kind().as_ref() == "binary_expression"
            || literal_string(message.text().as_ref()).is_none() && args.len() == 1;
        if rendered {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::Logging,
                "java-rendered-log-message",
                &["CWE-117"],
                &["logging", "rendered-message", "application-fix"],
                &[("message", message)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if args
            .iter()
            .skip(1)
            .any(|arg| sensitive_name(arg.text().as_ref()))
            || rendered && sensitive_name(message.text().as_ref())
        {
            push(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Logging,
                "java-sensitive-value-logging-review",
                &["CWE-532"],
                &["logging", "sensitive-value", "review-data-classification"],
                &[("message", message)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn sensitive_name(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password",
        "secret",
        "apikey",
        "api_key",
        "token",
        "privatekey",
        "jwk",
        "credential",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn inside_http_security_method(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
        .and_then(|method| method.field("parameters"))
        .is_some_and(|parameters| {
            parameters
                .children()
                .filter(|node| node.kind().as_ref() == "formal_parameter")
                .any(|parameter| {
                    parameter
                        .field("type")
                        .is_some_and(|kind| short_type(kind.text().as_ref()) == "HttpSecurity")
                })
        })
}

fn receiver_is_at(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    expected: &str,
) -> bool {
    let name_text = receiver.text();
    let name = name_text.trim();
    let Some(method) = use_site
        .ancestors()
        .find(|node| node.kind().as_ref() == "method_declaration")
    else {
        return false;
    };
    if method
        .dfs()
        .filter(|node| node.range().start <= use_site.range().start)
        .any(|node| {
            matches!(
                node.kind().as_ref(),
                "formal_parameter" | "local_variable_declaration"
            ) && node
                .field("type")
                .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
                && (node
                    .field("name")
                    .is_some_and(|candidate| candidate.text().trim() == name)
                    || node.children().any(|child| {
                        child
                            .field("name")
                            .is_some_and(|candidate| candidate.text().trim() == name)
                    }))
        })
    {
        return true;
    }
    use_site.ancestors().last().is_some_and(|root| {
        root.dfs().any(|node| {
            node.kind().as_ref() == "field_declaration"
                && node
                    .field("type")
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
                && node.children().any(|child| {
                    child
                        .field("name")
                        .is_some_and(|candidate| candidate.text().trim() == name)
                })
        })
    })
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> impl Iterator<Item = Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
}
fn arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}
fn imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .map(|node| {
            node.text()
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
    canonicals
        .iter()
        .any(|canonical| imported_exact(imports, declarations, canonical, short_type(canonical)))
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
fn literal_string(text: &str) -> Option<String> {
    let text = text.trim();
    text.strip_prefix('"')?
        .strip_suffix('"')
        .map(str::to_string)
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    captures: &[(&str, &Node<'tree, StrDoc<SupportLang>>)],
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
    let mut literal_values = BTreeMap::new();
    let captures = captures
        .iter()
        .map(|(role, capture)| {
            literal_values.insert((*role).to_string(), literals.evaluate(capture));
            (
                (*role).to_string(),
                Capture {
                    text: capture.text().into_owned(),
                    location: location(path, capture),
                },
            )
        })
        .collect();
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
