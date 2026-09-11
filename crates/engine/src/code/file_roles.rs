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

const ENGINE: &str = "ast-grep 0.45.1 + bounded-node-file-roles";

pub(crate) fn add_file_role_observations<'tree>(
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
    add_unsafe_archive_extraction(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_poison_null_byte_file_serving(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_unsafe_archive_extraction<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for loop_node in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "for_in_statement" | "for_of_statement"
        ) && node.text().contains("directory.files")
    }) {
        if comments.is_in_comment(loop_node.range()) {
            continue;
        }
        let Some(body) = loop_node.field("body") else {
            continue;
        };
        let Some(entry_path) = body
            .dfs()
            .find(|node| compact(node.text().as_ref()) == "entry.path")
        else {
            continue;
        };
        let Some(file_name_declaration) = declaration_for_value(&body, "fileName", "entry.path")
        else {
            continue;
        };
        let Some(resolved_target) = declaration_with_prefix(&body, "absolutePath", "path.resolve(")
        else {
            continue;
        };
        if !compact(resolved_target.text().as_ref()).contains("fileName") {
            continue;
        }
        let Some(containment) = body.dfs().find(|node| {
            node.kind().as_ref() == "if_statement"
                && node.field("condition").is_some_and(|condition| {
                    compact(condition.text().as_ref())
                        .contains("absolutePath.includes(path.resolve('.'))")
                })
        }) else {
            continue;
        };
        let Some(condition) = containment.field("condition") else {
            continue;
        };
        let Some(consequence) = containment.field("consequence") else {
            continue;
        };
        let Some((write_call, write_path)) = consequence.dfs().find_map(|node| {
            let call = call_site(node)?;
            (compact(&call.callee) == "fs.createWriteStream" && call.arguments.len() == 1)
                .then(|| (call.node, call.arguments[0].clone()))
        }) else {
            continue;
        };
        let write_text = compact(write_path.text().as_ref());
        if !write_text.contains("fileName") || write_text == "absolutePath" {
            continue;
        }

        let source_rule = language_rule(language, "archive-entry-path");
        let source_id = evidence_id(
            path,
            source_rule,
            entry_path.range().start,
            entry_path.range().end,
        );
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: Capability::UploadedFilePath,
            location: location(path, &entry_path),
            enclosing_symbol: enclosing_symbol(&entry_path),
            captures: BTreeMap::from([("path".to_string(), capture(path, &entry_path))]),
            cwe_candidates: vec!["CWE-22".to_string(), "CWE-434".to_string()],
            tags: vec![
                "archive".to_string(),
                "zip-entry".to_string(),
                "attacker-controlled".to_string(),
                "maximum-depth-1".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&entry_path, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule.to_string(),
            related_evidence: Vec::new(),
        });

        let sink_rule = language_rule(language, "archive-raw-path-write");
        evidence.push(Evidence {
            id: evidence_id(
                path,
                sink_rule,
                write_call.range().start,
                write_call.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::FilesystemWrite,
            location: location(path, &write_call),
            enclosing_symbol: enclosing_symbol(&write_call),
            captures: BTreeMap::from([
                ("path".to_string(), capture(path, &write_path)),
                (
                    "entry_assignment".to_string(),
                    capture(path, &file_name_declaration),
                ),
                (
                    "resolved_target".to_string(),
                    capture(path, &resolved_target),
                ),
                ("containment_check".to_string(), capture(path, &condition)),
                ("write_path".to_string(), capture(path, &write_path)),
            ]),
            cwe_candidates: vec!["CWE-22".to_string(), "CWE-434".to_string()],
            tags: vec![
                "archive".to_string(),
                "zip-slip".to_string(),
                "substring-containment".to_string(),
                "raw-entry-write".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&write_call, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: sink_rule.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_poison_null_byte_file_serving<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let root_text = compact(root.text().as_ref());
    if !root_text.contains("params.file") || !root_text.contains("verify(file,") {
        return;
    }
    for function in root.dfs().filter(|node| {
        node.kind().as_ref() == "function_declaration"
            && node
                .field("name")
                .is_some_and(|name| name.text().trim() == "verify")
    }) {
        let Some(parameter) = function
            .field("parameters")
            .and_then(|parameters| parameters.dfs().find(|node| node.text().trim() == "file"))
        else {
            continue;
        };
        let Some(body) = function.field("body") else {
            continue;
        };
        let Some(transform) = body.dfs().find(|node| {
            node.kind().as_ref() == "assignment_expression"
                && compact(node.text().as_ref()) == "file=security.cutOffPoisonNullByte(file)"
        }) else {
            continue;
        };
        let Some(suffix_check) = body.dfs().find_map(|candidate| {
            if candidate.kind().as_ref() != "if_statement"
                || !candidate
                    .field("consequence")
                    .is_some_and(|branch| contains_range(branch.range(), transform.range()))
            {
                return None;
            }
            candidate.field("condition").filter(|condition| {
                condition.range().start < transform.range().start
                    && compact(condition.text().as_ref())
                        .contains("endsWithAllowlistedFileType(file)")
            })
        }) else {
            continue;
        };
        let Some((send_call, served_path)) = body.dfs().find_map(|node| {
            let call = call_site(node)?;
            (call.callee.ends_with(".sendFile")
                && call.arguments.len() == 1
                && call.node.range().start > transform.range().end
                && compact(call.arguments[0].text().as_ref()).starts_with("path.resolve("))
            .then(|| (call.node, call.arguments[0].clone()))
        }) else {
            continue;
        };
        if !compact(served_path.text().as_ref()).contains("file") {
            continue;
        }

        let source_rule = language_rule(language, "forwarded-file-parameter");
        let source_id = evidence_id(
            path,
            source_rule,
            parameter.range().start,
            parameter.range().end,
        );
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location(path, &parameter),
            enclosing_symbol: enclosing_symbol(&parameter),
            captures: BTreeMap::from([("name".to_string(), capture(path, &parameter))]),
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "http".to_string(),
                "express".to_string(),
                "forwarded-parameter".to_string(),
                "maximum-depth-1".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&parameter, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule.to_string(),
            related_evidence: Vec::new(),
        });

        let sink_rule = language_rule(language, "poison-null-byte-send-file");
        evidence.push(Evidence {
            id: evidence_id(
                path,
                sink_rule,
                send_call.range().start,
                send_call.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::FilesystemRead,
            location: location(path, &send_call),
            enclosing_symbol: enclosing_symbol(&send_call),
            captures: BTreeMap::from([
                ("path".to_string(), capture(path, &served_path)),
                ("suffix_check".to_string(), capture(path, &suffix_check)),
                ("null_byte_transform".to_string(), capture(path, &transform)),
                ("served_path".to_string(), capture(path, &served_path)),
            ]),
            cwe_candidates: vec!["CWE-22".to_string()],
            tags: vec![
                "express".to_string(),
                "send-file".to_string(),
                "poison-null-byte".to_string(),
                "check-before-transform".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&send_call, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: sink_rule.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if !matches!(
        node.kind().as_ref(),
        "call_expression" | "invocation_expression"
    ) {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let text = node.text();
    let callee = text.get(..callee_length)?.trim().to_string();
    Some(CallSite {
        node,
        callee,
        arguments: arguments
            .children()
            .filter(|child| child.is_named())
            .collect(),
    })
}

fn declaration_for_value<'tree>(
    body: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    value: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    body.dfs().find(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node
                .field("name")
                .is_some_and(|field| field.text().trim() == name)
            && node
                .field("value")
                .is_some_and(|field| compact(field.text().as_ref()) == value)
    })
}

fn declaration_with_prefix<'tree>(
    body: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
    prefix: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    body.dfs().find_map(|node| {
        (node.kind().as_ref() == "variable_declarator"
            && node
                .field("name")
                .is_some_and(|field| field.text().trim() == name))
        .then(|| node.field("value"))
        .flatten()
        .filter(|value| compact(value.text().as_ref()).starts_with(prefix))
    })
}

fn language_rule(language: Language, suffix: &str) -> &'static str {
    match (language, suffix) {
        (Language::Javascript, "archive-entry-path") => "javascript-archive-entry-path",
        (Language::Typescript, "archive-entry-path") => "typescript-archive-entry-path",
        (Language::Tsx, "archive-entry-path") => "tsx-archive-entry-path",
        (Language::Javascript, "archive-raw-path-write") => "javascript-archive-raw-path-write",
        (Language::Typescript, "archive-raw-path-write") => "typescript-archive-raw-path-write",
        (Language::Tsx, "archive-raw-path-write") => "tsx-archive-raw-path-write",
        (Language::Javascript, "forwarded-file-parameter") => "javascript-forwarded-file-parameter",
        (Language::Typescript, "forwarded-file-parameter") => "typescript-forwarded-file-parameter",
        (Language::Tsx, "forwarded-file-parameter") => "tsx-forwarded-file-parameter",
        (Language::Javascript, "poison-null-byte-send-file") => {
            "javascript-poison-null-byte-send-file"
        }
        (Language::Typescript, "poison-null-byte-send-file") => {
            "typescript-poison-null-byte-send-file"
        }
        (Language::Tsx, "poison-null-byte-send-file") => "tsx-poison-null-byte-send-file",
        _ => unreachable!(),
    }
}

fn evidence_context<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> EvidenceContext {
    EvidenceContext {
        comment: comments.is_in_comment(node.range()),
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        ..EvidenceContext::default()
    }
}

fn provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: ENGINE.to_string(),
        rule_version: 1,
    }
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
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

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn contains_range(outer: std::ops::Range<usize>, inner: std::ops::Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}
