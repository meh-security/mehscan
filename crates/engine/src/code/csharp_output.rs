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

const ENGINE: &str = "mehscan csharp-output-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_output_policy_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }
    add_header_observations(path, root, comments, conditional, literals, evidence);
    add_logging_observations(path, root, comments, conditional, literals, evidence);
}

fn add_header_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        if !(function_text.ends_with("Headers.Append") || function_text.ends_with("Headers.Add"))
            || !response_header_receiver(&function_text)
        {
            continue;
        }
        let args = arguments(&invocation);
        if args.len() < 2 {
            continue;
        }
        add_header_value(
            path,
            &invocation,
            &args[1],
            header_name(args.first()),
            comments,
            conditional,
            literals,
            evidence,
        );
    }

    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        if comments.is_in_comment(assignment.range()) {
            continue;
        }
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let left_text = compact(left.text().as_ref());
        if response_header_index(&left_text) {
            add_header_value(
                path,
                &assignment,
                &right,
                header_name_from_index(&left_text),
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if left_text.ends_with(".FileNameStar")
            && typed_content_disposition_in_scope(root, &assignment)
        {
            push(
                path,
                &right,
                &assignment,
                EvidenceKind::Validation,
                Capability::HttpHeaderOutput,
                "csharp-typed-content-disposition-control",
                "header_value",
                &["CWE-113"],
                &[
                    "http-header",
                    "content-disposition",
                    "typed-header-api",
                    "encoded-filename",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_header_value<'tree>(
    path: &str,
    operation: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    name: Option<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let content_disposition = name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case("content-disposition"));
    if has_prior_newline_rejection(operation, value, literals) {
        push(
            path,
            value,
            operation,
            EvidenceKind::Validation,
            Capability::HttpHeaderOutput,
            "csharp-http-header-newline-rejection",
            "header_value",
            &["CWE-113"],
            &[
                "http-header",
                "newline-rejection",
                "same-value",
                "terminating-guard",
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
        return;
    }
    let mut tags = vec!["http-header", "raw-header-value"];
    if content_disposition {
        tags.extend(["content-disposition", "filename-review"]);
    }
    push(
        path,
        value,
        operation,
        EvidenceKind::Sink,
        Capability::HttpHeaderOutput,
        if content_disposition {
            "csharp-raw-content-disposition"
        } else {
            "csharp-raw-response-header"
        },
        "header_value",
        &["CWE-113"],
        &tags,
        comments,
        conditional,
        literals,
        evidence,
    );
}

fn add_logging_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        if !is_logging_call(root, &function_text) {
            continue;
        }
        let args = arguments(&invocation);
        let Some((message_index, message)) = message_argument(&args) else {
            continue;
        };
        let message_text = message.text();
        let dynamic = message_text.trim_start().starts_with('$') || !is_string_literal(message);
        if dynamic {
            push(
                path,
                message,
                &invocation,
                EvidenceKind::Sink,
                Capability::Logging,
                "csharp-rendered-log-message",
                "message",
                &["CWE-117"],
                &["logging", "rendered-message", "needs-verification"],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if args.len() > message_index + 1 {
            push(
                path,
                message,
                &invocation,
                EvidenceKind::Validation,
                Capability::Logging,
                "csharp-structured-log-template-control",
                "message",
                &["CWE-117"],
                &["logging", "static-template", "structured-arguments"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if let Some(sensitive) = args
            .iter()
            .skip(message_index + 1)
            .find(|arg| sensitive_name(arg.text().as_ref()))
            .or_else(|| {
                dynamic
                    .then_some(message)
                    .filter(|arg| sensitive_name(arg.text().as_ref()))
            })
        {
            push(
                path,
                sensitive,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::Logging,
                "csharp-sensitive-value-logging-review",
                "sensitive_value",
                &["CWE-532"],
                &[
                    "logging",
                    "sensitive-data",
                    "needs-verification",
                    "verify-redaction-and-access",
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn response_header_receiver(function: &str) -> bool {
    function.starts_with("Response.Headers.")
        || function.contains(".Response.Headers.")
        || function.starts_with("HttpContext.Response.Headers.")
}

fn response_header_index(left: &str) -> bool {
    (left.starts_with("Response.Headers[") || left.contains(".Response.Headers["))
        && left.ends_with(']')
}

fn header_name(node: Option<&Node<'_, StrDoc<SupportLang>>>) -> Option<String> {
    node.and_then(|node| string_literal_value(node.text().as_ref()))
}

fn header_name_from_index(left: &str) -> Option<String> {
    let start = left.rfind('[')? + 1;
    string_literal_value(left.get(start..left.len().saturating_sub(1))?)
}

fn string_literal_value(text: &str) -> Option<String> {
    let text = text.trim();
    (text.len() >= 2 && text.starts_with('"') && text.ends_with('"'))
        .then(|| text[1..text.len() - 1].to_string())
}

fn typed_content_disposition_in_scope(
    root: &Node<'_, StrDoc<SupportLang>>,
    assignment: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    root.dfs().any(|node| {
        node.range().start < assignment.range().start
            && node.kind().as_ref() == "object_creation_expression"
            && compact(node.text().as_ref()).starts_with("newContentDispositionHeaderValue(")
    })
}

fn has_prior_newline_rejection<'tree>(
    operation: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> bool {
    let value = compact(value.text().as_ref());
    if !is_simple_value(&value) {
        return false;
    }
    let mut current = operation.clone();
    while let Some(parent) = current.parent() {
        if parent.kind().as_ref() == "block" {
            for prior in parent
                .children()
                .filter(|child| child.is_named() && child.range().end <= current.range().start)
            {
                if prior.kind().as_ref() != "if_statement" {
                    continue;
                }
                let Some(condition) = prior.field("condition") else {
                    continue;
                };
                let Some(consequence) = prior.field("consequence") else {
                    continue;
                };
                let condition = compact(condition.text().as_ref());
                let contains_cr = condition.contains(&format!("{value}.Contains('\\r')"));
                let contains_lf = condition.contains(&format!("{value}.Contains('\\n')"));
                let index_of_any = condition.contains(&format!("{value}.IndexOfAny("))
                    && condition.contains("'\\r'")
                    && condition.contains("'\\n'");
                if ((contains_cr && contains_lf) || index_of_any)
                    && reachability::always_terminates(&consequence, literals)
                {
                    return true;
                }
            }
            return false;
        }
        if matches!(
            parent.kind().as_ref(),
            "method_declaration" | "lambda_expression"
        ) {
            break;
        }
        current = parent;
    }
    false
}

fn is_simple_value(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
}

fn is_logging_call(root: &Node<'_, StrDoc<SupportLang>>, function: &str) -> bool {
    const METHODS: [&str; 11] = [
        "LogTrace",
        "LogDebug",
        "LogInformation",
        "LogWarning",
        "LogError",
        "LogCritical",
        "Verbose",
        "Debug",
        "Information",
        "Warning",
        "Error",
    ];
    let Some((receiver, method)) = function.rsplit_once('.') else {
        return false;
    };
    if !METHODS.contains(&method) {
        return false;
    }
    let receiver = receiver.rsplit('.').next().unwrap_or(receiver);
    let source = root.text();
    (receiver.eq_ignore_ascii_case("log") && source.contains("using Serilog"))
        || source.lines().any(|line| {
            line.contains("ILogger")
                && line
                    .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .any(|word| word == receiver)
        })
}

fn message_argument<'a, 'tree>(
    args: &'a [Node<'tree, StrDoc<SupportLang>>],
) -> Option<(usize, &'a Node<'tree, StrDoc<SupportLang>>)> {
    if let Some(explicit) = args.iter().enumerate().find(|(_, arg)| {
        let text = arg.text();
        let text = text.trim();
        text.starts_with('"')
            || text.starts_with("@\"")
            || text.starts_with("$\"")
            || text.starts_with("$@\"")
            || text.starts_with("@$\"")
    }) {
        return Some(explicit);
    }
    args.iter().enumerate().find(|(_, arg)| {
        let text = arg.text();
        let text = text.trim();
        !text.is_empty()
            && !text.chars().all(|c| c.is_ascii_digit())
            && !text.starts_with("LogLevel.")
            && !text.starts_with("new EventId")
            && !matches!(
                text.to_ascii_lowercase().as_str(),
                "exception" | "ex" | "e" | "eventid" | "event_id"
            )
    })
}

fn is_string_literal(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let text = node.text();
    let text = text.trim();
    string_literal_value(text).is_some()
        || text
            .strip_prefix('@')
            .is_some_and(|text| string_literal_value(text).is_some())
}

fn sensitive_name(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "apikey",
        "api_key",
        "authorization",
        "cookie",
        "ssn",
        "socialsecurity",
        "creditcard",
        "credit_card",
        "passport",
        "dateofbirth",
        "date_of_birth",
    ]
    .iter()
    .any(|term| lower.contains(term))
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
        .collect()
}

fn arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    capture_node: &Node<'tree, StrDoc<SupportLang>>,
    evidence_node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = evidence_id(
        rule_id,
        path,
        evidence_node.range().start,
        evidence_node.range().end,
    );
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, evidence_node),
        enclosing_symbol: enclosing_symbol(evidence_node),
        captures: BTreeMap::from([(
            role.to_string(),
            Capture {
                text: capture_node.text().into_owned(),
                location: location(path, capture_node),
            },
        )]),
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.into(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(evidence_node.range()),
            reachability: Some(reachability::classify(evidence_node, literals)),
            availability: Some(conditional.availability_for(evidence_node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.into(),
        related_evidence: vec![],
    });
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.into(),
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

fn evidence_id(rule_id: &str, path: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
