use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind,
    Language, Location, Position, Provenance, Resolution, SecurityPath, SecurityPathProvenance,
    SecurityPathState, SecurityPathStep, SecurityPathStepKind,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const CONVERSION_RULE_ID: &str = "c-family-signed-to-size-conversion";
const MEMORY_RULE_ID: &str = "c-family-signed-size-memory-operation";
const VALIDATION_RULE_ID: &str = "c-family-nonnegative-size-validation";
const ENGINE: &str = "tree-sitter c-family signed-size relationship";

pub(crate) fn add_native_signedness_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) -> Vec<SecurityPath> {
    if !matches!(language, Language::C | Language::Cpp) {
        return Vec::new();
    }

    let mut additions = Vec::new();
    let mut paths = Vec::new();
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some((operation, extent)) = memory_extent(&call) else {
            continue;
        };
        let Some(conversion) = signed_size_cast(&extent) else {
            continue;
        };
        let Some((source_type, nominal_type)) =
            signed_declaration(&call, conversion.value.as_str())
        else {
            continue;
        };

        let source = conversion_evidence(
            path,
            &conversion,
            &source_type,
            nominal_type,
            comments,
            conditional,
            literals,
        );
        if excluded(&source) {
            continue;
        }
        let mut sink = memory_evidence(
            path,
            &call,
            &extent,
            operation,
            &source,
            comments,
            conditional,
            literals,
        );
        let protection_node =
            nonnegative_guard(root, &call, conversion.value.as_str(), conditional);
        let protection = protection_node.as_ref().map(|guard| {
            validation_evidence(
                path,
                guard,
                conversion.value.as_str(),
                &sink,
                comments,
                conditional,
                literals,
            )
        });
        if let Some(protection) = &protection {
            sink.tags.push("signed-size:nonnegative-proven".to_string());
            sink.related_evidence.push(protection.id.clone());
        } else {
            sink.tags.push("signed-size:negative-unproven".to_string());
        }
        paths.push(signedness_path(&source, &sink, protection.as_ref()));
        additions.push(source);
        if let Some(protection) = protection {
            additions.push(protection);
        }
        additions.push(sink);
    }
    evidence.extend(additions);
    paths
}

struct SignedSizeCast<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    value: String,
}

fn memory_extent<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(&'static str, Node<'tree, StrDoc<SupportLang>>)> {
    let function = call.field("function")?;
    let operation = match function.text().trim() {
        "memcpy" => "memcpy",
        "memmove" => "memmove",
        "memset" => "memset",
        "bcopy" => "bcopy",
        "malloc" => "malloc",
        "realloc" => "realloc",
        "calloc" => "calloc",
        _ => return None,
    };
    let arguments = call.field("arguments")?;
    let values = arguments
        .children()
        .filter(|child| child.is_named())
        .collect::<Vec<_>>();
    let indexes: &[usize] = match operation {
        "malloc" => &[0],
        "realloc" => &[1],
        "calloc" => &[0, 1],
        _ => &[2],
    };
    indexes
        .iter()
        .filter_map(|index| values.get(*index))
        .find(|argument| signed_size_cast(argument).is_some())
        .cloned()
        .map(|extent| (operation, extent))
}

fn signed_size_cast<'tree>(
    extent: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<SignedSizeCast<'tree>> {
    if let Some(cast) = std::iter::once(extent.clone())
        .chain(extent.dfs())
        .find(|node| {
            node.kind().as_ref() == "cast_expression"
                && node
                    .field("type")
                    .is_some_and(|kind| compact(kind.text().as_ref()) == "size_t")
        })
    {
        let operand = unwrap_parentheses(cast.field("value")?);
        let value = simple_identifier(operand.text().trim())?.to_string();
        return Some(SignedSizeCast { node: cast, value });
    }

    std::iter::once(extent.clone())
        .chain(extent.dfs())
        .find_map(|node| {
            let text = compact(node.text().as_ref());
            let value = text
                .strip_prefix("static_cast<size_t>(")?
                .strip_suffix(')')?;
            let value = simple_identifier(value)?.to_string();
            Some(SignedSizeCast { node, value })
        })
}

fn signed_declaration(call: &Node<'_, StrDoc<SupportLang>>, value: &str) -> Option<(String, bool)> {
    let scope = call
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")?;
    scope
        .dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "parameter_declaration" | "declaration"
            ) && node.range().start < call.range().start
        })
        .filter_map(|declaration| {
            let declared = if declaration.kind().as_ref() == "parameter_declaration" {
                declaration.field("declarator")
            } else {
                declaration.children().find_map(|child| {
                    (child.kind().as_ref() == "init_declarator")
                        .then(|| child.field("declarator"))
                        .flatten()
                        .or_else(|| (child.kind().as_ref() == "identifier").then_some(child))
                })
            }?;
            if declarator_identifier(&declared).as_deref() != Some(value) {
                return None;
            }
            let source_type = declaration
                .field("type")
                .map(|node| normalize_type(node.text().as_ref()))
                .unwrap_or_else(|| declaration_prefix_type(&declaration, &declared));
            signed_type(&source_type).map(|nominal| (source_type, nominal))
        })
        .last()
}

fn declarator_identifier(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if node.kind().as_ref() == "identifier" {
        return Some(node.text().trim().to_string());
    }
    node.dfs()
        .find(|child| child.kind().as_ref() == "identifier")
        .map(|child| child.text().trim().to_string())
}

fn signed_type(value: &str) -> Option<bool> {
    if value.contains("unsigned") || value.contains("uint") {
        return None;
    }
    if matches!(
        value,
        "int"
            | "signed"
            | "signed int"
            | "long"
            | "long int"
            | "signed long"
            | "signed long int"
            | "long long"
            | "long long int"
            | "signed long long"
            | "signed long long int"
            | "ssize_t"
            | "ptrdiff_t"
            | "int32_t"
            | "int64_t"
    ) {
        Some(false)
    } else if value.contains("int") && !value.contains('*') {
        Some(true)
    } else {
        None
    }
}

fn nonnegative_guard<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    call: &Node<'tree, StrDoc<SupportLang>>,
    value: &str,
    conditional: &ConditionalRegions,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    for statement in call.ancestors() {
        if statement.kind().as_ref() == "if_statement" {
            let condition = statement.field("condition")?;
            let consequence = statement.field("consequence")?;
            if contains(&consequence, call)
                && positive_condition(condition.text().as_ref(), value)
                && availability_compatible(call, &condition, conditional)
            {
                return Some(condition);
            }
        }
    }
    let scope = call
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")?;
    root.dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| scope.range().start <= node.range().start)
        .filter(|node| node.range().end <= scope.range().end)
        .filter(|node| node.range().end < call.range().start)
        .filter(dominates_function_tail)
        .find_map(|statement| {
            let condition = statement.field("condition")?;
            let consequence = statement.field("consequence")?;
            (availability_compatible(call, &condition, conditional)
                && negative_condition(condition.text().as_ref(), value)
                && consequence
                    .dfs()
                    .any(|node| node.kind().as_ref() == "return_statement"))
            .then_some(condition)
        })
}

fn contains(parent: &Node<'_, StrDoc<SupportLang>>, child: &Node<'_, StrDoc<SupportLang>>) -> bool {
    parent.range().start <= child.range().start && child.range().end <= parent.range().end
}

fn dominates_function_tail(statement: &Node<'_, StrDoc<SupportLang>>) -> bool {
    !statement
        .ancestors()
        .take_while(|ancestor| ancestor.kind().as_ref() != "function_definition")
        .any(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "if_statement"
                    | "for_statement"
                    | "while_statement"
                    | "do_statement"
                    | "switch_statement"
            )
        })
}

fn availability_compatible(
    sink: &Node<'_, StrDoc<SupportLang>>,
    guard: &Node<'_, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
) -> bool {
    let sink = conditional.availability_for(sink.range());
    let guard = conditional.availability_for(guard.range());
    match guard.state {
        AvailabilityState::Always => true,
        AvailabilityState::Conditional | AvailabilityState::Unknown => guard == sink,
        AvailabilityState::Excluded => false,
    }
}

fn positive_condition(text: &str, value: &str) -> bool {
    let text = compact(text);
    if text.contains("||") {
        return false;
    }
    text.split("&&").any(|part| {
        let part = trim_parentheses(part);
        matches!(part.as_str(), candidate if candidate == format!("{value}>0")
            || candidate == format!("0<{value}")
            || candidate == format!("{value}>=0")
            || candidate == format!("0<={value}"))
    })
}

fn negative_condition(text: &str, value: &str) -> bool {
    let text = compact(text);
    if text.contains("&&") {
        return false;
    }
    text.split("||").any(|part| {
        let part = trim_parentheses(part);
        matches!(part.as_str(), candidate if candidate == format!("{value}<0")
            || candidate == format!("0>{value}")
            || candidate == format!("{value}<1")
            || candidate == format!("1>{value}")
            || candidate == format!("{value}<=0")
            || candidate == format!("0>={value}")
            || candidate == format!("{value}<=-1")
            || candidate == format!("-1>={value}"))
    })
}

#[allow(clippy::too_many_arguments)]
fn conversion_evidence<'tree>(
    path: &str,
    conversion: &SignedSizeCast<'tree>,
    source_type: &str,
    nominal_type: bool,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, CONVERSION_RULE_ID, &conversion.node),
        kind: EvidenceKind::Source,
        capability: Capability::SignedSizeConversion,
        location: location(path, &conversion.node),
        enclosing_symbol: enclosing_symbol(&conversion.node),
        captures: BTreeMap::from([
            (
                "value".to_string(),
                Capture {
                    text: conversion.value.clone(),
                    location: location(path, &conversion.node),
                },
            ),
            (
                "source_type".to_string(),
                Capture {
                    text: source_type.to_string(),
                    location: location(path, &conversion.node),
                },
            ),
            (
                "target_type".to_string(),
                Capture {
                    text: "size_t".to_string(),
                    location: location(path, &conversion.node),
                },
            ),
        ]),
        cwe_candidates: vec!["CWE-195".to_string(), "CWE-681".to_string()],
        tags: vec![
            "native".to_string(),
            "signed-to-unsigned-size".to_string(),
            "parse-recovery:locally-complete".to_string(),
            if nominal_type {
                "source-signedness:nominal"
            } else {
                "source-signedness:exact"
            }
            .to_string(),
        ],
        confidence: if nominal_type {
            Confidence::Medium
        } else {
            Confidence::High
        },
        provenance: provenance(),
        context: evidence_context(&conversion.node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: CONVERSION_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn memory_evidence<'tree>(
    path: &str,
    call: &Node<'tree, StrDoc<SupportLang>>,
    extent: &Node<'tree, StrDoc<SupportLang>>,
    operation: &str,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, MEMORY_RULE_ID, call),
        kind: EvidenceKind::Sink,
        capability: Capability::SignedSizeMemoryOperation,
        location: location(path, call),
        enclosing_symbol: enclosing_symbol(call),
        captures: BTreeMap::from([
            (
                "operation".to_string(),
                capture(path, call.field("function").as_ref().expect("call")),
            ),
            ("extent".to_string(), capture(path, extent)),
        ]),
        cwe_candidates: vec!["CWE-195".to_string(), "CWE-681".to_string()],
        tags: vec![
            "native".to_string(),
            "signed-size-memory-extent".to_string(),
            "parse-recovery:locally-complete".to_string(),
            if matches!(operation, "malloc" | "calloc" | "realloc") {
                "allocation"
            } else {
                "buffer-operation"
            }
            .to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(call, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: MEMORY_RULE_ID.to_string(),
        related_evidence: vec![source.id.clone()],
    }
}

#[allow(clippy::too_many_arguments)]
fn validation_evidence<'tree>(
    path: &str,
    guard: &Node<'tree, StrDoc<SupportLang>>,
    value: &str,
    sink: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, VALIDATION_RULE_ID, guard),
        kind: EvidenceKind::Validation,
        capability: Capability::NonnegativeSizeValidation,
        location: location(path, guard),
        enclosing_symbol: enclosing_symbol(guard),
        captures: BTreeMap::from([(
            "value".to_string(),
            Capture {
                text: value.to_string(),
                location: location(path, guard),
            },
        )]),
        cwe_candidates: vec!["CWE-195".to_string()],
        tags: vec![
            "native".to_string(),
            "exact-nonnegative-size-guard".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(guard, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: VALIDATION_RULE_ID.to_string(),
        related_evidence: vec![sink.id.clone()],
    }
}

fn signedness_path(
    source: &Evidence,
    sink: &Evidence,
    protection: Option<&Evidence>,
) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
    if let Some(protection) = protection {
        steps.push(evidence_step(SecurityPathStepKind::Protection, protection));
    }
    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::SignedSizeMemoryOperation,
        cwe_candidates: vec!["CWE-195".to_string(), "CWE-681".to_string()],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: protection
            .is_none()
            .then(|| "negative_signed_size_not_rejected".to_string())
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family signed-size relationship 1".to_string(),
            maximum_propagation_depth: 0,
        },
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

fn normalize_type(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile" | "register" | "static"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(['(', ')'])
        .to_string()
}

fn declaration_prefix_type(
    declaration: &Node<'_, StrDoc<SupportLang>>,
    declarator: &Node<'_, StrDoc<SupportLang>>,
) -> String {
    normalize_type(
        declaration
            .text()
            .get(
                ..declarator
                    .range()
                    .start
                    .saturating_sub(declaration.range().start),
            )
            .unwrap_or_default(),
    )
}

fn unwrap_parentheses(mut node: Node<'_, StrDoc<SupportLang>>) -> Node<'_, StrDoc<SupportLang>> {
    while node.kind().as_ref() == "parenthesized_expression" {
        let Some(child) = node.children().find(|child| child.is_named()) else {
            break;
        };
        node = child;
    }
    node
}

fn trim_parentheses(value: &str) -> String {
    value.trim_matches(['(', ')']).to_string()
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn simple_identifier(value: &str) -> Option<&str> {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        .then_some(())?;
    characters
        .all(|character| character == '_' || character.is_ascii_alphanumeric())
        .then_some(value)
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

fn provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: ENGINE.to_string(),
        rule_version: 1,
    }
}

fn evidence_id(path: &str, rule_id: &str, node: &Node<'_, StrDoc<SupportLang>>) -> String {
    stable_id(
        "ev",
        &format!(
            "{path}\0{rule_id}\0{}\0{}",
            node.range().start,
            node.range().end
        ),
    )
}

fn path_id(
    source: &Evidence,
    sink: &Evidence,
    state: SecurityPathState,
    steps: &[SecurityPathStep],
) -> String {
    let mut input = format!("{}\0{}\0{state:?}", source.id, sink.id);
    for step in steps {
        input.push_str(&format!(
            "\0{:?}\0{}\0{}",
            step.kind, step.location.start.byte_offset, step.location.end.byte_offset
        ));
    }
    stable_id("path", &input)
}

fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

fn evidence_step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: evidence.location.clone(),
        evidence_id: Some(evidence.id.clone()),
        symbol: None,
    }
}

fn excluded(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|availability| availability.state == AvailabilityState::Excluded)
}
