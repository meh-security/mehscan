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

const ENGINE: &str = "mehscan go-identity-web-policy 1";
const IDENTITY_RULES: &[&str] = &[
    "go-query-string-credential",
    "go-jwt-parse-unverified-review",
    "go-remote-token-verification-request",
    "go-remote-token-verification-status-control",
    "go-unverified-claims-remote-verification-gate",
    "go-verified-identity-database-lookup",
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_go_policy_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Go {
        return;
    }
    let source = root.text();
    let uses_http = source.contains("\"net/http\"");
    let uses_io = source.contains("\"io\"");

    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        if uses_http && is_header_set(&call, "Access-Control-Allow-Origin", "*") {
            let credentialed = enclosing_function(&call.node).is_some_and(|function| {
                let compact = compact(function.text().as_ref());
                compact.contains("Header().Set(\"Access-Control-Allow-Credentials\",\"true\")")
            });
            push(
                path,
                &call.node,
                if credentialed {
                    "go-credentialed-wildcard-cors"
                } else {
                    "go-cors-wildcard-origin-review"
                },
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                captures(path, &call, &["header", "value"]),
                &["CWE-942"],
                &[
                    "cors",
                    "wildcard-origin",
                    if credentialed {
                        "credentials-enabled"
                    } else {
                        "credential-mode-not-observed"
                    },
                    "review-gateway-ownership",
                    "review-not-automatic-fix",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if uses_http
            && terminal_name(&call.callee) == "Handler"
            && call.node.text().contains(".PathPrefix(\"/debug/pprof/\")")
            && call
                .arguments
                .first()
                .is_some_and(|argument| argument.text().trim() == "http.DefaultServeMux")
        {
            let mut values = BTreeMap::from([(
                "route".to_string(),
                Capture {
                    text: "/debug/pprof/".to_string(),
                    location: location(path, &call.node),
                },
            )]);
            if let Some(condition) = enclosing_if_condition(&call.node) {
                values.insert("condition".to_string(), capture(path, &condition));
            }
            push(
                path,
                &call.node,
                "go-debug-pprof-route-review",
                EvidenceKind::SensitiveOperation,
                Capability::HttpRequestHandling,
                values,
                &["CWE-489"],
                &["debug", "pprof", "runtime-conditional", "review-exposure"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if uses_io && call.callee == "io.ReadAll" && is_request_body(call.arguments.first()) {
            let protected = enclosing_function(&call.node).is_some_and(|function| {
                let text = function.text();
                text.contains("http.MaxBytesReader(") || text.contains("io.LimitReader(")
            });
            push(
                path,
                &call.node,
                if protected {
                    "go-request-body-size-limit-control"
                } else {
                    "go-unbounded-request-body-read-review"
                },
                if protected {
                    EvidenceKind::Validation
                } else {
                    EvidenceKind::SensitiveOperation
                },
                Capability::HttpRequestHandling,
                captures(path, &call, &["body"]),
                if protected { &[] } else { &["CWE-400"] },
                &[
                    "http",
                    "request-body",
                    if protected {
                        "bounded"
                    } else {
                        "unbounded-read"
                    },
                    if protected {
                        "control"
                    } else {
                        "review-proxy-body-limit"
                    },
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if uses_http
            && call.callee == "http.Post"
            && enclosing_symbol(&call.node).as_deref() == Some("ExtractTokenID")
        {
            push(
                path,
                &call.node,
                "go-remote-token-verification-request",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                captures(path, &call, &["endpoint", "media_type", "token_body"]),
                &[],
                &[
                    "authentication",
                    "token",
                    "remote-verifier",
                    "control-dependency",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if terminal_name(&call.callee) == "CheckTokenInDB"
            && enclosing_symbol(&call.node).as_deref() == Some("ExtractTokenID")
        {
            let mut values = captures(path, &call, &["identity", "database"]);
            if let Some(condition) = enclosing_if_condition(&call.node) {
                values.insert("condition".to_string(), capture(path, &condition));
            }
            push(
                path,
                &call.node,
                "go-verified-identity-database-lookup",
                EvidenceKind::SensitiveOperation,
                Capability::Authentication,
                values,
                &[],
                &[
                    "authentication",
                    "identity",
                    "database-lookup",
                    "post-verification",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if uses_http
            && matches!(
                terminal_name(&call.callee),
                "ListenAndServe" | "ListenAndServeTLS"
            )
        {
            let tls = terminal_name(&call.callee) == "ListenAndServeTLS";
            push(
                path,
                &call.node,
                if tls {
                    "go-http-server-tls-control"
                } else {
                    "go-http-server-plaintext-fallback-review"
                },
                EvidenceKind::SecurityConfiguration,
                Capability::TlsConfiguration,
                captures(path, &call, if tls { &["certificate", "key"] } else { &[] }),
                if tls { &[] } else { &["CWE-319"] },
                &[
                    "http-server",
                    if tls { "tls" } else { "plaintext" },
                    if tls {
                        "control"
                    } else {
                        "runtime-configuration"
                    },
                    "review-proxy-termination",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for node in root.dfs() {
        let text = node.text();
        if node.kind().as_ref() == "binary_expression"
            && text.contains("StatusCode")
            && (text.contains("== 200") || text.contains("== http.StatusOK"))
        {
            push(
                path,
                &node,
                "go-remote-token-verification-status-control",
                EvidenceKind::Guard,
                Capability::Authentication,
                BTreeMap::from([("condition".to_string(), capture(path, &node))]),
                &[],
                &[
                    "authentication",
                    "remote-verifier",
                    "status-code",
                    "control",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if node.kind().as_ref() == "if_statement"
            && node
                .field("condition")
                .is_some_and(|condition| condition.text().contains("tokenValid"))
            && text.contains("claims[")
        {
            let condition = node.field("condition").unwrap();
            push(
                path,
                &condition,
                "go-unverified-claims-remote-verification-gate",
                EvidenceKind::Guard,
                Capability::Authentication,
                BTreeMap::from([("condition".to_string(), capture(path, &condition))]),
                &[],
                &[
                    "authentication",
                    "jwt",
                    "claims",
                    "remote-verification-gate",
                    "control",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if node.kind().as_ref() == "composite_literal"
            && compact(text.as_ref()).starts_with("http.Server{")
        {
            let compact_text = compact(text.as_ref());
            let read = compact_text.contains("ReadTimeout:");
            let write = compact_text.contains("WriteTimeout:");
            push(
                path,
                &node,
                if read && write {
                    "go-http-server-timeout-control"
                } else {
                    "go-http-server-timeout-review"
                },
                EvidenceKind::SecurityConfiguration,
                Capability::HttpRequestHandling,
                BTreeMap::from([("server".to_string(), capture(path, &node))]),
                if read && write { &[] } else { &["CWE-400"] },
                &[
                    "http-server",
                    "timeouts",
                    if read && write {
                        "read-write-configured"
                    } else {
                        "incomplete"
                    },
                    if read && write {
                        "control"
                    } else {
                        "review-deployment-timeouts"
                    },
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if node.kind().as_ref() == "composite_literal"
            && (compact(text.as_ref()).starts_with("sessions.Options{")
                || compact(text.as_ref()).starts_with("http.Cookie{"))
        {
            let compact_text = compact(text.as_ref());
            if compact_text.starts_with("http.Cookie{")
                && (compact_text.contains("HttpOnly:")
                    || compact_text.contains("Secure:")
                    || compact_text.contains("SameSite:"))
            {
                continue;
            }
            let http_only = compact_text.contains("HttpOnly:true");
            let secure = compact_text.contains("Secure:true");
            let same_site = compact_text.contains("SameSite:");
            let weak = !http_only || !secure || !same_site;
            push(
                path,
                &node,
                if weak {
                    "go-cookie-security-policy-review"
                } else {
                    "go-cookie-security-policy-control"
                },
                EvidenceKind::SecurityConfiguration,
                Capability::CookieConfiguration,
                BTreeMap::from([("cookie".to_string(), capture(path, &node))]),
                if weak { &["CWE-614", "CWE-1004"] } else { &[] },
                &[
                    "cookie",
                    if http_only {
                        "httponly"
                    } else {
                        "missing-httponly"
                    },
                    if secure { "secure" } else { "missing-secure" },
                    if same_site {
                        "samesite"
                    } else {
                        "missing-samesite"
                    },
                    "review-proxy-tls-and-cookie-purpose",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if node.kind().as_ref() == "interpreted_string_literal" && text.contains("sslmode=disable")
        {
            push(
                path,
                &node,
                "go-postgres-sslmode-disabled-review",
                EvidenceKind::SecurityConfiguration,
                Capability::TlsConfiguration,
                BTreeMap::from([("connection".to_string(), capture(path, &node))]),
                &["CWE-319"],
                &[
                    "database",
                    "postgresql",
                    "tls-disabled",
                    "review-network-boundary",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if node.kind().as_ref() == "interpreted_string_literal"
            && text.contains("mongodb://%s:%s@%s:%s")
        {
            push(
                path,
                &node,
                "go-mongodb-plaintext-uri-review",
                EvidenceKind::SecurityConfiguration,
                Capability::TlsConfiguration,
                BTreeMap::from([("connection".to_string(), capture(path, &node))]),
                &["CWE-319"],
                &[
                    "database",
                    "mongodb",
                    "plaintext-uri",
                    "review-network-boundary",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
    relate_identity_evidence(path, evidence);
}

fn relate_identity_evidence(path: &str, evidence: &mut [Evidence]) {
    let ids = evidence
        .iter()
        .filter(|item| {
            item.location.path == path && IDENTITY_RULES.contains(&item.rule_id.as_str())
        })
        .map(|item| item.id.clone())
        .collect::<BTreeSet<_>>();
    if ids.len() < 2 {
        return;
    }
    for item in evidence.iter_mut().filter(|item| {
        item.location.path == path && IDENTITY_RULES.contains(&item.rule_id.as_str())
    }) {
        item.related_evidence = ids.iter().filter(|id| **id != item.id).cloned().collect();
    }
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
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let callee = node.text().get(..callee_length)?.trim().to_string();
    let arguments = arguments
        .children()
        .filter(|child| child.is_named())
        .collect();
    Some(CallSite {
        node,
        callee,
        arguments,
    })
}

fn is_header_set(call: &CallSite<'_>, header: &str, value: &str) -> bool {
    terminal_name(&call.callee) == "Set"
        && call.callee.contains(".Header()")
        && call
            .arguments
            .first()
            .is_some_and(|argument| argument.text().trim_matches('"') == header)
        && call
            .arguments
            .get(1)
            .is_some_and(|argument| argument.text().trim_matches('"') == value)
}

fn is_request_body(argument: Option<&Node<'_, StrDoc<SupportLang>>>) -> bool {
    argument.is_some_and(|argument| {
        matches!(
            compact(argument.text().as_ref()).as_str(),
            "r.Body" | "req.Body" | "request.Body"
        )
    })
}

fn terminal_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee).trim()
}

fn enclosing_function<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "function_declaration" | "method_declaration" | "func_literal"
        )
    })
}

fn enclosing_if_condition<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "if_statement")?
        .field("condition")
}

fn captures(path: &str, call: &CallSite<'_>, roles: &[&str]) -> BTreeMap<String, Capture> {
    roles
        .iter()
        .zip(&call.arguments)
        .map(|(role, argument)| ((*role).to_string(), capture(path, argument)))
        .collect()
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    cwes: &[&str],
    tags: &[&str],
    confidence: Confidence,
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
        confidence,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: node.range().start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: node.range().end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
