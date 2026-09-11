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

pub(crate) const GO_GRPC_REQUEST_RULE_ID: &str = "go-grpc-request-accessor-source";
const ENGINE: &str = "mehscan go-grpc-context 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_go_grpc_observations<'tree>(
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
    let grpc_imported = source.contains("\"google.golang.org/grpc\"");
    let protobuf_server = source.contains("Unimplemented") && source.contains("Server");

    if grpc_imported && protobuf_server {
        for method in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_declaration")
        {
            let request_parameters = grpc_request_parameters(&method);
            if request_parameters.is_empty() {
                continue;
            }
            for call in method.dfs().filter_map(call_site) {
                if comments.is_in_comment(call.node.range())
                    || !request_parameters
                        .iter()
                        .any(|parameter| call.callee.starts_with(&format!("{parameter}.")))
                {
                    continue;
                }
                let terminal = call.callee.rsplit('.').next().unwrap_or_default();
                if !terminal.starts_with("Get") || terminal.len() <= 3 {
                    continue;
                }
                push(
                    path,
                    &call.node,
                    GO_GRPC_REQUEST_RULE_ID,
                    EvidenceKind::Source,
                    Capability::RpcRequestData,
                    BTreeMap::from([("value".to_string(), capture(path, &call.node))]),
                    &["CWE-20"],
                    &["rpc", "grpc", "protobuf", "request", "attacker-controlled"],
                    Confidence::High,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }

    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        if matches!(terminal_name(&call.callee), "Prepare" | "PrepareContext")
            && let Some(query) = prepare_query_argument(&call)
            && !is_string_literal(query)
        {
            push(
                path,
                &call.node,
                "go-dynamic-sql-prepare",
                EvidenceKind::Sink,
                Capability::DatabaseQuery,
                BTreeMap::from([("query".to_string(), capture(path, query))]),
                &["CWE-89"],
                &["database", "sql", "prepare", "dynamic-query"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if grpc_imported && call.callee == "grpc.WithInsecure" {
            push(
                path,
                &call.node,
                "go-grpc-insecure-transport",
                EvidenceKind::SecurityConfiguration,
                Capability::TlsConfiguration,
                BTreeMap::from([("option".to_string(), capture(path, &call.node))]),
                &["CWE-319"],
                &["grpc", "transport", "plaintext", "client"],
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if grpc_imported && call.callee == "grpc.NewServer" {
            let protected = call
                .arguments
                .iter()
                .any(|argument| argument.text().contains("grpc.Creds("));
            push(
                path,
                &call.node,
                if protected {
                    "go-grpc-server-transport-credentials-control"
                } else {
                    "go-grpc-server-plaintext-transport-review"
                },
                if protected {
                    EvidenceKind::Validation
                } else {
                    EvidenceKind::SecurityConfiguration
                },
                Capability::TlsConfiguration,
                BTreeMap::from([("server".to_string(), capture(path, &call.node))]),
                if protected { &[] } else { &["CWE-319"] },
                if protected {
                    &["grpc", "transport", "server", "credentials", "control"]
                } else {
                    &["grpc", "transport", "server", "plaintext", "review"]
                },
                Confidence::High,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn grpc_request_parameters(method: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let text = method.text();
    if !text.contains("context.Context") {
        return BTreeSet::new();
    }
    let Some(parameters) = method.field("parameters") else {
        return BTreeSet::new();
    };
    parameters
        .children()
        .filter(|node| node.is_named())
        .filter_map(|parameter| {
            let text = parameter.text();
            if text.contains("context.Context") || !text.contains('*') || !text.contains('.') {
                return None;
            }
            let name = text.split_whitespace().next()?.trim_end_matches(',');
            valid_identifier(name).then(|| name.to_string())
        })
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
    let callee = node.field("function")?.text().trim().to_string();
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

fn prepare_query_argument<'call, 'tree>(
    call: &'call CallSite<'tree>,
) -> Option<&'call Node<'tree, StrDoc<SupportLang>>> {
    match terminal_name(&call.callee) {
        "PrepareContext" => call.arguments.get(1),
        "Prepare" => call.arguments.first(),
        _ => None,
    }
}

fn terminal_name(callee: &str) -> &str {
    callee.rsplit('.').next().unwrap_or(callee).trim()
}

fn is_string_literal(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "interpreted_string_literal" | "raw_string_literal"
    )
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphabetic()
                || (index > 0 && character.is_ascii_digit())
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
