use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, SecurityPath, SecurityPathProvenance, SecurityPathState,
    SecurityPathStep, SecurityPathStepKind,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const SOURCE_RULE_ID: &str = "c-family-decoded-input-extent";
const SINK_RULE_ID: &str = "c-family-remaining-input-read";
const VALIDATION_RULE_ID: &str = "c-family-remaining-input-validation";
const ENGINE: &str = "tree-sitter c-family remaining-input relationship";
const PATH_ENGINE: &str = "mehscan c-family remaining-input relationship 1";

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckKind {
    WrappingAddition,
    NonWrappingSubtraction,
}

struct BoundsCheck<'tree> {
    statement: Node<'tree, StrDoc<SupportLang>>,
    comparison: Node<'tree, StrDoc<SupportLang>>,
    length: String,
    cursor: String,
    total: String,
    kind: CheckKind,
}

pub(crate) fn add_native_remaining_input_observations<'tree>(
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
    for statement in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        if !statement
            .field("consequence")
            .is_some_and(|branch| branch_terminates(&branch))
        {
            continue;
        }
        let Some(check) = bounds_check(&statement) else {
            continue;
        };
        let Some(scope) = statement
            .ancestors()
            .find(|node| node.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        if !decoded_extent_origin(&scope, &check) {
            continue;
        }
        let Some(sink_call) = downstream_read(&scope, &check, comments) else {
            continue;
        };
        if reassigned_between(
            &scope,
            &check.cursor,
            statement.range().end,
            sink_call.range().start,
        ) || reassigned_between(
            &scope,
            &check.length,
            statement.range().end,
            sink_call.range().start,
        ) {
            continue;
        }
        let effective =
            check.kind == CheckKind::NonWrappingSubtraction && cursor_within_total(&scope, &check);

        let source = make_evidence(
            path,
            &check.comparison,
            SOURCE_RULE_ID,
            EvidenceKind::Source,
            Capability::DecodedInputExtent,
            BTreeMap::from([
                (
                    "decoded_extent".to_string(),
                    text_capture(path, &check.comparison, &check.length),
                ),
                (
                    "cursor".to_string(),
                    text_capture(path, &check.comparison, &check.cursor),
                ),
                (
                    "authoritative_extent".to_string(),
                    text_capture(path, &check.comparison, &check.total),
                ),
                (
                    "bounds_comparison".to_string(),
                    capture(path, &check.comparison),
                ),
            ]),
            vec![
                "native",
                "decoded-extent-and-cursor-boundary",
                if check.kind == CheckKind::WrappingAddition {
                    "bounds-arithmetic:wrapping-addition"
                } else {
                    "bounds-arithmetic:subtraction-form"
                },
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            Vec::new(),
        );
        let validation = make_evidence(
            path,
            &check.statement,
            VALIDATION_RULE_ID,
            EvidenceKind::Validation,
            Capability::RemainingInputValidation,
            BTreeMap::from([
                (
                    "decoded_extent".to_string(),
                    text_capture(path, &check.statement, &check.length),
                ),
                (
                    "cursor".to_string(),
                    text_capture(path, &check.statement, &check.cursor),
                ),
                (
                    "authoritative_extent".to_string(),
                    text_capture(path, &check.statement, &check.total),
                ),
                ("rejection".to_string(), capture(path, &check.statement)),
            ]),
            vec![
                "native",
                if effective {
                    "effective-remaining-input-subtraction-check"
                } else if check.kind == CheckKind::WrappingAddition {
                    "ineffective-wrapping-addition-check"
                } else {
                    "subtraction-check-without-cursor-bound"
                },
                "pre-read-rejection",
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            vec![source.id.clone()],
        );
        let mut related = vec![source.id.clone(), validation.id.clone()];
        related.sort();
        let sink = make_evidence(
            path,
            &sink_call,
            SINK_RULE_ID,
            EvidenceKind::Sink,
            Capability::RemainingInputRead,
            BTreeMap::from([
                (
                    "decoded_extent".to_string(),
                    text_capture(path, &sink_call, &check.length),
                ),
                (
                    "source_cursor".to_string(),
                    text_capture(path, &sink_call, &check.cursor),
                ),
                ("buffer_operation".to_string(), capture(path, &sink_call)),
            ]),
            vec![
                "native",
                "remaining-input-sensitive-read",
                if effective {
                    "remaining-input:validated"
                } else {
                    "remaining-input:wrapping-check"
                },
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            related,
        );
        paths.push(remaining_path(&source, &sink, &validation, effective));
        additions.extend([source, validation, sink]);
    }
    evidence.extend(additions);
    paths
}

fn bounds_check<'tree>(statement: &Node<'tree, StrDoc<SupportLang>>) -> Option<BoundsCheck<'tree>> {
    let condition = statement.field("condition")?;
    condition.dfs().find_map(|comparison| {
        if comparison.kind().as_ref() != "binary_expression"
            || binary_operator(&comparison).as_deref() != Some(">")
        {
            return None;
        }
        let left = comparison.field("left")?;
        let right = comparison.field("right")?;
        if binary_operator(&left).as_deref() == Some("+") {
            let cursor = compact(left.field("left")?.text().as_ref());
            let length = compact(left.field("right")?.text().as_ref());
            let total = compact(right.text().as_ref());
            return valid_roles(&cursor, &length, &total).then(|| BoundsCheck {
                statement: statement.clone(),
                comparison,
                length,
                cursor,
                total,
                kind: CheckKind::WrappingAddition,
            });
        }
        if binary_operator(&right).as_deref() == Some("-") {
            let length = compact(left.text().as_ref());
            let total = compact(right.field("left")?.text().as_ref());
            let cursor = compact(right.field("right")?.text().as_ref());
            return valid_roles(&cursor, &length, &total).then(|| BoundsCheck {
                statement: statement.clone(),
                comparison,
                length,
                cursor,
                total,
                kind: CheckKind::NonWrappingSubtraction,
            });
        }
        None
    })
}

fn valid_roles(cursor: &str, length: &str, total: &str) -> bool {
    !cursor.is_empty()
        && !length.is_empty()
        && !total.is_empty()
        && cursor != length
        && cursor != total
        && length != total
        && !cursor.contains(['+', '-'])
        && !length.contains(['+', '-'])
        && !total.contains(['+', '-'])
}

fn cursor_within_total(scope: &Node<'_, StrDoc<SupportLang>>, check: &BoundsCheck<'_>) -> bool {
    let current_condition = compact(
        check
            .statement
            .field("condition")
            .expect("if condition")
            .text()
            .as_ref(),
    );
    if current_condition.contains(&format!("{}>{}", check.cursor, check.total))
        || current_condition.contains(&format!("{}<{}", check.total, check.cursor))
    {
        return true;
    }
    let prior_rejections = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| node.range().end < check.statement.range().start)
        .filter(|node| {
            node.field("consequence")
                .is_some_and(|branch| branch_terminates(&branch))
        })
        .collect::<Vec<_>>();
    if prior_rejections.iter().any(|statement| {
        let text = compact(
            statement
                .field("condition")
                .expect("if condition")
                .text()
                .as_ref(),
        );
        text.contains(&format!("{}>{}", check.cursor, check.total))
            || text.contains(&format!("{}<{}", check.total, check.cursor))
    }) {
        return true;
    }
    let Some(cursor) = simple_identifier(&check.cursor) else {
        return false;
    };
    let Some(initializer) = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .filter(|node| node.range().start < check.statement.range().start)
        .find_map(|node| {
            node.field("declarator")
                .is_some_and(|declarator| declarator.text().trim() == cursor)
                .then(|| node.field("value"))
                .flatten()
        })
    else {
        return false;
    };
    let bound = compact(initializer.text().as_ref());
    let mut bound_spellings = vec![bound.clone()];
    if let Some((left, right)) = bound.split_once('+') {
        bound_spellings.push(format!("{right}+{left}"));
    }
    let initial_bound_is_safe = |before: usize| {
        prior_rejections.iter().any(|statement| {
            if statement.range().end >= before {
                return false;
            }
            let text = compact(
                statement
                    .field("condition")
                    .expect("if condition")
                    .text()
                    .as_ref(),
            );
            bound_spellings.iter().any(|spelling| {
                text.contains(&format!("{}<{spelling}", check.total))
                    || text.contains(&format!("{spelling}>{}", check.total))
            })
        })
    };
    let updates = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| {
            node.range().start > initializer.range().end
                && node.range().end < check.statement.range().start
                && node
                    .field("left")
                    .is_some_and(|left| left.text().trim() == cursor)
        })
        .collect::<Vec<_>>();
    if updates.is_empty() {
        return initial_bound_is_safe(check.statement.range().start);
    }
    if updates.len() != 1 {
        return false;
    }
    let update = &updates[0];
    let update_text = compact(update.text().as_ref());
    let Some(delta) = update_text.strip_prefix(&format!("{cursor}+=")) else {
        return false;
    };
    initial_bound_is_safe(update.range().start)
        && prior_rejections.iter().any(|statement| {
            statement.range().start > initializer.range().end
                && statement.range().end < update.range().start
                && compact(
                    statement
                        .field("condition")
                        .expect("if condition")
                        .text()
                        .as_ref(),
                )
                .contains(&format!("{delta}>{}-{}", check.total, check.cursor))
        })
}

fn decoded_extent_origin(scope: &Node<'_, StrDoc<SupportLang>>, check: &BoundsCheck<'_>) -> bool {
    if check.length.contains('.') || check.length.contains("->") {
        return true;
    }
    let Some(length) = simple_identifier(&check.length) else {
        return false;
    };
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .filter(|node| node.range().start < check.statement.range().start)
        .any(|node| {
            node.field("declarator")
                .is_some_and(|declarator| declarator.text().trim() == length)
                && node.field("value").is_some_and(|value| {
                    value
                        .dfs()
                        .filter(|child| child.kind().as_ref() == "call_expression")
                        .filter_map(|call| call.field("function"))
                        .any(|function| {
                            let name = function.text().to_ascii_lowercase();
                            ["get", "read", "load", "decode", "parse"]
                                .iter()
                                .any(|part| name.contains(part))
                                && ["8", "16", "32", "64", "int", "uint", "length", "len"]
                                    .iter()
                                    .any(|part| name.contains(part))
                        })
                })
        })
}

fn downstream_read<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    check: &BoundsCheck<'tree>,
    comments: &CommentRanges,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| {
            node.range().start > check.statement.range().end
                && node
                    .range()
                    .start
                    .saturating_sub(check.statement.range().end)
                    < 16_384
                && !comments.is_in_comment(node.range())
        })
        .find(|call| {
            if !is_buffer_consumer(call) {
                return false;
            }
            let arguments = named_arguments(call);
            arguments
                .iter()
                .any(|argument| compact(argument.text().as_ref()) == check.length)
                && arguments.iter().any(|argument| {
                    let text = compact(argument.text().as_ref());
                    text.contains(&check.cursor) && text.contains('+')
                })
        })
}

fn is_buffer_consumer(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|function| {
        let name = function.text().to_ascii_lowercase();
        matches!(name.as_str(), "memcpy" | "memmove" | "bcopy")
            || name.contains("copyfrom")
            || name.contains("addnametostring")
            || name.contains("readbuffer")
    })
}

fn reassigned_between(
    scope: &Node<'_, StrDoc<SupportLang>>,
    expression: &str,
    after: usize,
    before: usize,
) -> bool {
    let Some(name) = simple_identifier(expression) else {
        return false;
    };
    scope
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "assignment_expression"
                && node.range().start > after
                && node.range().end < before
        })
        .any(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == name)
        })
}

fn binary_operator(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.children()
        .filter(|child| !child.is_named())
        .map(|child| child.text().trim().to_string())
        .find(|text| matches!(text.as_str(), ">" | "<" | "+" | "-"))
}

fn branch_terminates(branch: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let terminal = if branch.kind().as_ref() == "compound_statement" {
        branch.children().filter(|node| node.is_named()).last()
    } else {
        Some(branch.clone())
    };
    terminal.is_some_and(|node| {
        matches!(
            node.kind().as_ref(),
            "return_statement" | "goto_statement" | "continue_statement" | "break_statement"
        )
    })
}

fn named_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|node| node.is_named())
                .collect()
        })
        .unwrap_or_default()
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && !matches!(*character, '(' | ')'))
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

fn remaining_path(
    source: &Evidence,
    sink: &Evidence,
    validation: &Evidence,
    effective: bool,
) -> SecurityPath {
    let state = if effective {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
    steps.push(evidence_step(
        if effective {
            SecurityPathStepKind::Protection
        } else {
            SecurityPathStepKind::IneffectiveProtection
        },
        validation,
    ));
    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: stable_id(
            "path",
            &format!("{}\0{}\0{state:?}\0CWE-125", source.id, sink.id),
        ),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::RemainingInputRead,
        cwe_candidates: cwes(),
        state,
        steps,
        protection_evidence_ids: if effective {
            vec![validation.id.clone()]
        } else {
            Vec::new()
        },
        uncertainty_reasons: (!effective)
            .then(|| "offset_plus_extent_check_can_wrap_before_comparison".to_string())
            .into_iter()
            .chain(["effective_integer_widths_require_confirmation".to_string()])
            .collect(),
        provenance: SecurityPathProvenance {
            engine: PATH_ENGINE.to_string(),
            maximum_propagation_depth: 1,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn make_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
) -> Evidence {
    Evidence {
        id: stable_id(
            "ev",
            &format!(
                "{path}\0{rule_id}\0{}\0{}",
                node.range().start,
                node.range().end
            ),
        ),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes(),
        tags: tags.into_iter().map(str::to_string).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    }
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}
fn text_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: &str) -> Capture {
    Capture {
        text: text.to_string(),
        location: location(path, node),
    }
}
fn evidence_step(kind: SecurityPathStepKind, item: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: item.location.clone(),
        evidence_id: Some(item.id.clone()),
        symbol: None,
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
fn cwes() -> Vec<String> {
    vec!["CWE-190".to_string(), "CWE-125".to_string()]
}
fn stable_id(prefix: &str, value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}_{hash:016x}")
}
