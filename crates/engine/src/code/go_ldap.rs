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

const ENGINE: &str = "mehscan go-ldap-output-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_go_ldap_observations<'tree>(
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
    let ldap_qualifiers = ldap_qualifiers(root);
    let request_names = typed_parameter_names(root, "*http.Request");
    let writer_names = typed_parameter_names(root, "http.ResponseWriter");
    let form_aliases = form_value_aliases(root, &request_names);
    let uses_ldap = !ldap_qualifiers.is_empty();
    let uses_http = source.contains("\"net/http\"");

    for node in root.dfs() {
        if comments.is_in_comment(node.range()) {
            continue;
        }
        if node.kind().as_ref() == "index_expression"
            && request_form_access(node.text().as_ref(), &request_names)
        {
            push(
                path,
                &node,
                "go-http-form-map-value-source",
                EvidenceKind::Source,
                Capability::HttpRequestData,
                BTreeMap::from([("value".to_string(), capture(path, &node))]),
                &["CWE-20"],
                &["http", "request", "form", "map-index"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if node.kind().as_ref() == "index_expression"
            && extracted_form_value(node.text().as_ref(), &form_aliases)
        {
            push(
                path,
                &node,
                "go-http-form-indexed-value-source",
                EvidenceKind::Source,
                Capability::HttpRequestData,
                BTreeMap::from([("value".to_string(), capture(path, &node))]),
                &["CWE-20"],
                &["http", "request", "form", "indexed-value", "local-alias"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if uses_ldap
            && node.kind().as_ref() == "selector_expression"
            && matches!(terminal_selector(node.text().as_ref()), "DN" | "Values")
        {
            push(
                path,
                &node,
                "go-ldap-result-value-source",
                EvidenceKind::Source,
                Capability::StoredUserContent,
                BTreeMap::from([("content".to_string(), capture(path, &node))]),
                &["CWE-79"],
                &["ldap", "result", "stored-content", "output-review"],
                Confidence::Medium,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        match ldap_function(&call.callee, &ldap_qualifiers) {
            Some("NewSearchRequest") => {
                let Some(filter) = call.arguments.get(6) else {
                    continue;
                };
                push(
                    path,
                    &call.node,
                    "go-ldap-search-request-filter",
                    EvidenceKind::Sink,
                    Capability::LdapQuery,
                    BTreeMap::from([("filter".to_string(), capture(path, filter))]),
                    &["CWE-90"],
                    &["ldap", "search", "filter", "exact-api"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            Some("EscapeFilter") => {
                let Some(value) = call.arguments.first() else {
                    continue;
                };
                push(
                    path,
                    &call.node,
                    "go-ldap-filter-encoding-control",
                    EvidenceKind::Sanitizer,
                    Capability::LdapFilterEncoding,
                    BTreeMap::from([("value".to_string(), capture(path, value))]),
                    &["CWE-90"],
                    &["ldap", "filter", "encoding", "exact-context", "control"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            Some("Dial") if tcp_transport(&call) => {
                push(
                    path,
                    &call.node,
                    "go-ldap-plaintext-transport-review",
                    EvidenceKind::SecurityConfiguration,
                    Capability::TlsConfiguration,
                    BTreeMap::from([("endpoint".to_string(), capture(path, &call.node))]),
                    &["CWE-319"],
                    &[
                        "ldap",
                        "transport",
                        "tcp",
                        "plaintext",
                        "review-deployment-boundary",
                    ],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            Some("DialTLS") | Some("DialURL") if tls_transport(&call) => {
                push(
                    path,
                    &call.node,
                    "go-ldap-tls-transport-control",
                    EvidenceKind::Validation,
                    Capability::TlsConfiguration,
                    BTreeMap::from([("endpoint".to_string(), capture(path, &call.node))]),
                    &[],
                    &["ldap", "transport", "tls", "control"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            _ => {}
        }

        if uses_http
            && call.callee == "fmt.Fprintf"
            && call
                .arguments
                .first()
                .is_some_and(|writer| writer_names.contains(writer.text().trim()))
            && let Some(content) = formatted_content(&call)
        {
            push(
                path,
                &call.node,
                "go-fprintf-http-html-output",
                EvidenceKind::Sink,
                Capability::HtmlOutput,
                BTreeMap::from([("content".to_string(), capture(path, &content))]),
                &["CWE-79"],
                &["http", "response", "fmt-fprintf", "html", "context-review"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if logging_call(&call.callee)
            && call.arguments.iter().any(|argument| {
                let lower = argument.text().to_ascii_lowercase();
                lower.contains("bindpassword") || lower.contains("bind_password")
            })
        {
            push(
                path,
                &call.node,
                "go-ldap-bind-password-logging-review",
                EvidenceKind::Sink,
                Capability::Logging,
                BTreeMap::from([("message".to_string(), capture(path, &call.node))]),
                &["CWE-532"],
                &["ldap", "credential", "logging", "debug-configuration"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn ldap_qualifiers(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_spec")
        .filter(|node| {
            let text = node.text();
            text.contains("gopkg.in/ldap.v2") || text.contains("go-ldap/ldap")
        })
        .filter_map(|node| {
            node.field("name")
                .map(|name| name.text().trim().to_string())
                .or_else(|| {
                    let text = node.text();
                    let quote = text.rfind('"')?;
                    let open = text[..quote].rfind('"')?;
                    let prefix = text[..open].trim();
                    (!prefix.is_empty()).then(|| prefix.to_string())
                })
                .or_else(|| Some("ldap".to_string()))
        })
        .filter(|qualifier| qualifier != "." && qualifier != "_")
        .collect()
}

fn typed_parameter_names(
    root: &Node<'_, StrDoc<SupportLang>>,
    type_marker: &str,
) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "parameter_declaration" && node.text().contains(type_marker)
        })
        .filter_map(|node| {
            node.children()
                .find(|child| child.kind().as_ref() == "identifier")
                .map(|name| name.text().into_owned())
        })
        .collect()
}

fn request_form_access(text: &str, requests: &BTreeSet<String>) -> bool {
    let compact = compact(text);
    requests
        .iter()
        .any(|request| compact.starts_with(&format!("{request}.Form[")))
}

fn form_value_aliases(
    root: &Node<'_, StrDoc<SupportLang>>,
    requests: &BTreeSet<String>,
) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "short_var_declaration" | "assignment_statement"
            ) && requests
                .iter()
                .any(|request| compact(node.text().as_ref()).contains(&format!("{request}.Form[")))
        })
        .filter_map(|node| {
            let left = node
                .field("left")
                .map(|left| left.text().into_owned())
                .or_else(|| {
                    node.text()
                        .split_once(":=")
                        .map(|(left, _)| left.to_string())
                })?;
            let first = left.split(',').next()?.trim();
            (!first.is_empty()).then(|| first.to_string())
        })
        .collect()
}

fn extracted_form_value(text: &str, aliases: &BTreeSet<String>) -> bool {
    let compact = compact(text);
    aliases.iter().any(|alias| {
        compact
            .strip_prefix(&format!("{alias}["))
            .is_some_and(|index| index.ends_with(']'))
    })
}

fn terminal_selector(text: &str) -> &str {
    text.rsplit('.').next().unwrap_or(text).trim()
}

fn ldap_function<'a>(callee: &'a str, qualifiers: &BTreeSet<String>) -> Option<&'a str> {
    let (qualifier, function) = callee.split_once('.')?;
    qualifiers.contains(qualifier).then_some(function)
}

fn tcp_transport(call: &CallSite<'_>) -> bool {
    call.arguments
        .first()
        .is_some_and(|argument| argument.text().trim_matches('"') == "tcp")
}

fn tls_transport(call: &CallSite<'_>) -> bool {
    call.callee.ends_with(".DialTLS")
        || call.arguments.iter().any(|argument| {
            let text = argument.text();
            text.contains("ldaps://") || text.contains("StartTLS") || text.contains("tls.Config")
        })
}

fn formatted_content<'tree>(call: &CallSite<'tree>) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let format = call.arguments.get(1)?;
    if matches!(
        format.kind().as_ref(),
        "interpreted_string_literal" | "raw_string_literal"
    ) {
        format
            .text()
            .contains('%')
            .then(|| call.arguments.get(2).cloned())
            .flatten()
    } else {
        Some(format.clone())
    }
}

fn logging_call(callee: &str) -> bool {
    matches!(
        callee.rsplit('.').next().unwrap_or(callee),
        "Debug" | "Debugf" | "Info" | "Infof" | "Print" | "Printf" | "Warn" | "Warnf"
    )
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
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
