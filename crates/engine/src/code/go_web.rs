use std::collections::BTreeMap;

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

const ENGINE: &str = "mehscan go-web-boundary 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_go_web_observations<'tree>(
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
    let uses_text_template = source.contains("\"text/template\"");
    let uses_html_template = source.contains("\"html/template\"");
    let calls = root.dfs().filter_map(call_site).collect::<Vec<_>>();

    add_cookie_store_context(
        path,
        root,
        &calls,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_route_policy_context(
        path,
        root,
        &calls,
        comments,
        conditional,
        literals,
        evidence,
    );

    for function in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "function_declaration" | "method_declaration"
        )
    }) {
        add_authentication_context(path, &function, comments, conditional, literals, evidence);
    }

    for call in calls {
        if comments.is_in_comment(call.node.range())
            || !matches!(terminal_name(&call.callee), "Execute" | "ExecuteTemplate")
        {
            continue;
        }
        let content_index = usize::from(terminal_name(&call.callee) == "ExecuteTemplate") + 1;
        let Some(content) = call.arguments.get(content_index) else {
            continue;
        };
        if content.text().trim() == "nil" {
            continue;
        }
        if uses_text_template {
            push(
                path,
                &call.node,
                "go-text-template-html-output",
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                BTreeMap::from([("content".to_string(), capture(path, content))]),
                &["CWE-79"],
                &[
                    "http",
                    "html",
                    "template",
                    "text-template",
                    "unescaped-output",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if uses_html_template {
            push(
                path,
                &call.node,
                "go-html-template-contextual-encoding-control",
                EvidenceKind::Sanitizer,
                Capability::HtmlEncoding,
                BTreeMap::from([("value".to_string(), capture(path, content))]),
                &[],
                &["http", "html", "template", "contextual-encoding", "control"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_cookie_store_context<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    calls: &[CallSite<'tree>],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in calls
        .iter()
        .filter(|call| call.callee == "sessions.NewCookieStore")
    {
        if let Some(key) = call
            .arguments
            .first()
            .and_then(|argument| hardcoded_byte_string(root, argument, call.node.range().start))
        {
            push(
                path,
                &call.node,
                "go-cookie-store-hardcoded-key",
                EvidenceKind::SecurityConfiguration,
                Capability::CookieConfiguration,
                BTreeMap::from([(
                    "key_material".to_string(),
                    Capture {
                        text: "[hardcoded byte-string literal]".to_string(),
                        location: location(path, &key),
                    },
                )]),
                &["CWE-321"],
                &[
                    "session",
                    "cookie-store",
                    "hardcoded-key",
                    "secret-redacted",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if !root.text().contains("sessions.Options{") && !root.text().contains(".Options =") {
            push(
                path,
                &call.node,
                "go-cookie-store-default-options-review",
                EvidenceKind::SecurityConfiguration,
                Capability::CookieConfiguration,
                BTreeMap::from([("store".to_string(), capture(path, &call.node))]),
                &["CWE-614", "CWE-1004"],
                &[
                    "session",
                    "cookie-store",
                    "default-options",
                    "review-effective-cookie-policy",
                ],
                Confidence::Medium,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn hardcoded_byte_string<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    argument: &Node<'tree, StrDoc<SupportLang>>,
    before: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if contains_direct_byte_string(argument.text().as_ref()) {
        return string_literal(argument);
    }
    let identifier = argument.text();
    if !valid_identifier(identifier.trim()) {
        return None;
    }
    root.dfs()
        .filter(|node| node.range().end <= before)
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "var_spec" | "const_spec" | "short_var_declaration"
            ) && contains_direct_byte_string(node.text().as_ref())
        })
        .filter(|node| {
            node.field("name")
                .is_some_and(|name| name.text().trim() == identifier.trim())
                || node
                    .field("left")
                    .is_some_and(|name| name.text().trim() == identifier.trim())
        })
        .filter_map(|node| string_literal(&node))
        .last()
}

fn contains_direct_byte_string(text: &str) -> bool {
    let compact = compact(text);
    let Some((_, value)) = compact.split_once("[]byte(") else {
        return false;
    };
    value.starts_with('"') || value.starts_with('`')
}

fn string_literal<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.dfs().find(|child| {
        matches!(
            child.kind().as_ref(),
            "interpreted_string_literal" | "raw_string_literal"
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn add_authentication_context<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(symbol) = function
        .field("name")
        .map(|name| name.text().into_owned())
        .or_else(|| enclosing_symbol(function))
    else {
        return;
    };
    let text = function.text();
    let lower = text.to_ascii_lowercase();
    if symbol.to_ascii_lowercase().contains("login")
        && lower.contains("username")
        && compact(text.as_ref()).contains("Values[\"authenticated\"]=true")
        && !lower.contains("password")
        && let Some(assignment) = function.dfs().find(|node| {
            compact(node.text().as_ref()).contains("Values[\"authenticated\"]=true")
                && matches!(
                    node.kind().as_ref(),
                    "assignment_statement" | "short_var_declaration"
                )
        })
    {
        push(
            path,
            &assignment,
            "go-passwordless-session-establishment-review",
            EvidenceKind::SensitiveOperation,
            Capability::Authentication,
            BTreeMap::from([("session".to_string(), capture(path, &assignment))]),
            &["CWE-306"],
            &[
                "authentication",
                "session",
                "username-only",
                "no-password-observed",
            ],
            Confidence::High,
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for branch in function
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
    {
        let Some(condition) = branch.field("condition") else {
            continue;
        };
        let condition_text = compact(condition.text().as_ref());
        let variable = condition_text
            .strip_suffix("==nil")
            .or_else(|| condition_text.strip_prefix("nil=="));
        let Some(variable) = variable.filter(|value| valid_identifier(value)) else {
            continue;
        };
        let Some(consequence) = branch.field("consequence") else {
            continue;
        };
        if !consequence.text().contains("http.Redirect(")
            || consequence
                .dfs()
                .any(|node| node.kind().as_ref() == "return_statement")
        {
            continue;
        }
        let used_after = function.dfs().any(|node| {
            node.range().start >= branch.range().end
                && node.text().trim().starts_with(&format!("{variable}."))
        });
        if used_after {
            push(
                path,
                &condition,
                "go-auth-redirect-without-return-review",
                EvidenceKind::SensitiveOperation,
                Capability::HttpRequestHandling,
                BTreeMap::from([
                    ("condition".to_string(), capture(path, &condition)),
                    ("continued_value".to_string(), capture(path, &condition)),
                ]),
                &["CWE-476"],
                &[
                    "authentication",
                    "redirect",
                    "missing-return",
                    "nil-dereference",
                    "request-triggered",
                ],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[derive(Clone)]
struct RouteRegistration<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    route: Node<'tree, StrDoc<SupportLang>>,
    handler: Node<'tree, StrDoc<SupportLang>>,
    security_wrapped: bool,
    get_only: bool,
}

#[allow(clippy::too_many_arguments)]
fn add_route_policy_context<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    calls: &[CallSite<'tree>],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let security_middleware_present = root.text().contains("secure.New(");
    let routes = calls
        .iter()
        .filter(|call| matches!(terminal_name(&call.callee), "Handle" | "HandleFunc"))
        .filter_map(|call| {
            let route = call.arguments.first()?.clone();
            let handler = call.arguments.get(1)?.clone();
            let ancestor_text = call
                .node
                .ancestors()
                .take(3)
                .map(|node| node.text().into_owned())
                .collect::<Vec<_>>()
                .join("");
            Some(RouteRegistration {
                node: call.node.clone(),
                route,
                security_wrapped: security_middleware_present
                    && handler.text().contains(".Handler("),
                get_only: compact(&ancestor_text).contains(".Methods(\"GET\")"),
                handler,
            })
        })
        .collect::<Vec<_>>();

    if routes.iter().any(|route| route.security_wrapped)
        && let Some(unwrapped) = routes.iter().find(|route| !route.security_wrapped)
    {
        let protected = routes
            .iter()
            .filter(|route| route.security_wrapped)
            .map(|route| route.route.text().trim_matches('"').to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let unprotected_count = routes
            .iter()
            .filter(|route| !route.security_wrapped)
            .count();
        push(
            path,
            &unwrapped.node,
            "go-route-security-middleware-coverage-review",
            EvidenceKind::SecurityConfiguration,
            Capability::HttpRequestHandling,
            BTreeMap::from([
                (
                    "protected_routes".to_string(),
                    Capture {
                        text: protected,
                        location: location(path, &unwrapped.route),
                    },
                ),
                (
                    "unwrapped_route_count".to_string(),
                    Capture {
                        text: unprotected_count.to_string(),
                        location: location(path, &unwrapped.route),
                    },
                ),
            ]),
            &["CWE-693"],
            &[
                "http",
                "routes",
                "security-middleware",
                "partial-coverage",
                "review-authoritative-response-layer",
            ],
            Confidence::High,
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for route in routes.iter().filter(|route| route.get_only) {
        let handler_name = handler_name(&route.handler);
        if !handler_name.as_deref().is_some_and(looks_mutating_handler) {
            continue;
        }
        push(
            path,
            &route.node,
            "go-state-changing-get-route-review",
            EvidenceKind::SensitiveOperation,
            Capability::HttpRequestHandling,
            BTreeMap::from([
                ("route".to_string(), capture(path, &route.route)),
                ("handler".to_string(), capture(path, &route.handler)),
            ]),
            &["CWE-352"],
            &[
                "http",
                "route",
                "get",
                "state-change-name",
                "review-handler-effect",
            ],
            Confidence::Medium,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn handler_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.dfs()
        .filter(|child| child.kind().as_ref() == "identifier")
        .map(|child| child.text().into_owned())
        .filter(|name| !matches!(name.as_str(), "http" | "HandlerFunc"))
        .last()
}

fn looks_mutating_handler(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    ["add", "create", "update", "delete", "remove", "unfriend"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
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

fn terminal_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee).trim()
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphabetic()
                || (index > 0 && character.is_ascii_digit())
        })
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
